//! Compact LoRa frame format for low-bandwidth transport.
//!
//! The standard Mycelium envelope header is 106 bytes — too large for LoRa
//! where MTU can be 51 bytes at SF10-12. This module provides a compact
//! 27-byte header that fits within LoRa constraints.
//!
//! ## Compact header layout (27 bytes)
//!
//! | Field           | Size  | Description                                |
//! |-----------------|-------|--------------------------------------------|
//! | source          | 8 B   | Truncated NodeId (first 8 bytes)           |
//! | destination     | 8 B   | Truncated NodeId (first 8 bytes)           |
//! | message_id      | 4 B   | Truncated MessageId (first 4 bytes)        |
//! | ttl             | 1 B   | Hop limit                                  |
//! | hop_count       | 1 B   | Current hop                                |
//! | flags           | 1 B   | Message flags (truncated to u8)            |
//! | lamport_clock   | 2 B   | Logical clock (u16, wrapping)              |
//! | payload_length  | 1 B   | Payload length (max 222, fits u8)          |
//! | sf_hint         | 1 B   | Spreading factor used for this frame       |
//! | **Total**       | **27 B** |                                         |
//!
//! With a 51-byte MTU (SF10-12), this leaves **24 bytes** for payload.
//! With 222-byte MTU (SF7-8), this leaves **195 bytes** for payload.
//!
//! ## Node ID resolution
//!
//! Truncated 8-byte IDs are resolved to full 32-byte NodeIds via a local
//! mapping table populated during discovery. Collisions are statistically
//! negligible (birthday problem: ~2^32 nodes for 50% collision probability).

use crate::codec::{CodecError, Envelope};
use crate::types::{MessageFlags, MessageId, NodeId, ProtocolVersion};

/// Compact LoRa frame header size in bytes.
pub const LORA_HEADER_SIZE: usize = 27;

/// Maximum payload that fits in a compact frame at the given MTU.
pub const fn max_payload_for_mtu(mtu: usize) -> usize {
    mtu.saturating_sub(LORA_HEADER_SIZE)
}

/// A compact LoRa frame optimized for low-bandwidth transport.
#[derive(Debug, Clone)]
pub struct LoraFrame {
    /// First 8 bytes of source NodeId.
    pub source_short: [u8; 8],
    /// First 8 bytes of destination NodeId.
    pub dest_short: [u8; 8],
    /// First 4 bytes of MessageId.
    pub message_id_short: [u8; 4],
    /// Hop limit.
    pub ttl: u8,
    /// Current hop count.
    pub hop_count: u8,
    /// Flags (truncated to u8).
    pub flags: u8,
    /// Lamport clock (u16, wrapping).
    pub lamport_clock: u16,
    /// Spreading factor hint for the receiver's ADR.
    pub sf_hint: u8,
    /// Payload data.
    pub payload: Vec<u8>,
}

impl LoraFrame {
    /// Serialize the compact frame to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let payload_len = self.payload.len().min(255) as u8;
        let mut buf = Vec::with_capacity(LORA_HEADER_SIZE + self.payload.len());

        buf.extend_from_slice(&self.source_short);
        buf.extend_from_slice(&self.dest_short);
        buf.extend_from_slice(&self.message_id_short);
        buf.push(self.ttl);
        buf.push(self.hop_count);
        buf.push(self.flags);
        buf.extend_from_slice(&self.lamport_clock.to_le_bytes());
        buf.push(payload_len);
        buf.push(self.sf_hint);
        buf.extend_from_slice(&self.payload[..payload_len as usize]);

        buf
    }

    /// Deserialize a compact frame from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() < LORA_HEADER_SIZE {
            return Err(CodecError::BufferTooShort {
                expected: LORA_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let mut offset = 0;

        let mut source_short = [0u8; 8];
        source_short.copy_from_slice(&data[offset..offset + 8]);
        offset += 8;

        let mut dest_short = [0u8; 8];
        dest_short.copy_from_slice(&data[offset..offset + 8]);
        offset += 8;

        let mut message_id_short = [0u8; 4];
        message_id_short.copy_from_slice(&data[offset..offset + 4]);
        offset += 4;

        let ttl = data[offset];
        offset += 1;

        let hop_count = data[offset];
        offset += 1;

        let flags = data[offset];
        offset += 1;

        let lamport_clock = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let payload_len = data[offset] as usize;
        offset += 1;

        let sf_hint = data[offset];
        offset += 1;

        if data.len() < offset + payload_len {
            return Err(CodecError::PayloadLengthMismatch {
                header: payload_len,
                actual: data.len() - offset,
            });
        }

        let payload = data[offset..offset + payload_len].to_vec();

        Ok(Self {
            source_short,
            dest_short,
            message_id_short,
            ttl,
            hop_count,
            flags,
            lamport_clock,
            sf_hint,
            payload,
        })
    }

    /// Create a compact frame from a full envelope.
    ///
    /// Truncates NodeIds to 8 bytes, MessageId to 4 bytes,
    /// flags to u8, and lamport clock to u16.
    pub fn from_envelope(envelope: &Envelope, sf_hint: u8) -> Self {
        let mut source_short = [0u8; 8];
        source_short.copy_from_slice(&envelope.source.as_bytes()[..8]);

        let mut dest_short = [0u8; 8];
        dest_short.copy_from_slice(&envelope.destination.as_bytes()[..8]);

        let mut message_id_short = [0u8; 4];
        message_id_short.copy_from_slice(&envelope.message_id.as_bytes()[..4]);

        Self {
            source_short,
            dest_short,
            message_id_short,
            ttl: envelope.ttl,
            hop_count: envelope.hop_count,
            flags: (envelope.flags.0 & 0xFF) as u8,
            lamport_clock: (envelope.lamport_clock & 0xFFFF) as u16,
            sf_hint,
            payload: envelope.payload.clone(),
        }
    }

    /// Expand a compact frame back to a full envelope.
    ///
    /// Requires a resolver function that maps truncated 8-byte IDs to full
    /// 32-byte NodeIds. If the resolver returns `None`, the truncated ID
    /// is zero-padded (the remaining 24 bytes are zeros).
    pub fn to_envelope<F>(&self, resolve_node_id: F) -> Envelope
    where
        F: Fn(&[u8; 8]) -> Option<NodeId>,
    {
        let source = resolve_node_id(&self.source_short).unwrap_or_else(|| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&self.source_short);
            NodeId(bytes)
        });

        let destination = resolve_node_id(&self.dest_short).unwrap_or_else(|| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&self.dest_short);
            NodeId(bytes)
        });

        let mut msg_bytes = [0u8; 16];
        msg_bytes[..4].copy_from_slice(&self.message_id_short);

        Envelope {
            source,
            destination,
            message_id: MessageId(msg_bytes),
            ttl: self.ttl,
            hop_count: self.hop_count,
            flags: MessageFlags(self.flags as u16),
            lamport_clock: self.lamport_clock as u64,
            device_timestamp: 0,
            protocol_version: ProtocolVersion::CURRENT,
            payload: self.payload.clone(),
        }
    }

    /// Decrement TTL and increment hop count for forwarding.
    pub fn forward(&mut self) {
        if self.ttl > 0 {
            self.ttl -= 1;
        }
        self.hop_count = self.hop_count.saturating_add(1);
    }

    /// Total serialized size in bytes.
    pub fn wire_size(&self) -> usize {
        LORA_HEADER_SIZE + self.payload.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lora_frame_roundtrip() {
        let frame = LoraFrame {
            source_short: [1, 2, 3, 4, 5, 6, 7, 8],
            dest_short: [9, 10, 11, 12, 13, 14, 15, 16],
            message_id_short: [0xAA, 0xBB, 0xCC, 0xDD],
            ttl: 5,
            hop_count: 2,
            flags: 0x01,
            lamport_clock: 1234,
            sf_hint: 10,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let bytes = frame.serialize();
        assert_eq!(bytes.len(), LORA_HEADER_SIZE + 4);

        let decoded = LoraFrame::deserialize(&bytes).unwrap();
        assert_eq!(decoded.source_short, frame.source_short);
        assert_eq!(decoded.dest_short, frame.dest_short);
        assert_eq!(decoded.message_id_short, frame.message_id_short);
        assert_eq!(decoded.ttl, 5);
        assert_eq!(decoded.hop_count, 2);
        assert_eq!(decoded.flags, 0x01);
        assert_eq!(decoded.lamport_clock, 1234);
        assert_eq!(decoded.sf_hint, 10);
        assert_eq!(decoded.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_lora_frame_empty_payload() {
        let frame = LoraFrame {
            source_short: [0; 8],
            dest_short: [0; 8],
            message_id_short: [0; 4],
            ttl: 0,
            hop_count: 0,
            flags: 0,
            lamport_clock: 0,
            sf_hint: 12,
            payload: vec![],
        };

        let bytes = frame.serialize();
        assert_eq!(bytes.len(), LORA_HEADER_SIZE);

        let decoded = LoraFrame::deserialize(&bytes).unwrap();
        assert!(decoded.payload.is_empty());
        assert_eq!(decoded.sf_hint, 12);
    }

    #[test]
    fn test_lora_frame_truncated() {
        let result = LoraFrame::deserialize(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_lora_frame_from_envelope() {
        let envelope = Envelope {
            source: NodeId([0xAA; 32]),
            destination: NodeId([0xBB; 32]),
            message_id: MessageId([0xCC; 16]),
            ttl: 8,
            hop_count: 1,
            flags: MessageFlags(0x0003),
            lamport_clock: 0x1234_5678_9ABC_DEF0,
            device_timestamp: 999,
            protocol_version: ProtocolVersion::CURRENT,
            payload: vec![1, 2, 3],
        };

        let frame = LoraFrame::from_envelope(&envelope, 10);
        assert_eq!(frame.source_short, [0xAA; 8]);
        assert_eq!(frame.dest_short, [0xBB; 8]);
        assert_eq!(frame.message_id_short, [0xCC; 4]);
        assert_eq!(frame.ttl, 8);
        assert_eq!(frame.hop_count, 1);
        assert_eq!(frame.flags, 0x03); // Truncated to u8
        assert_eq!(frame.lamport_clock, 0xDEF0); // Truncated to u16
        assert_eq!(frame.sf_hint, 10);
        assert_eq!(frame.payload, vec![1, 2, 3]);
    }

    #[test]
    fn test_lora_frame_to_envelope_with_resolver() {
        let full_source = NodeId([0xAA; 32]);
        let full_dest = NodeId([0xBB; 32]);

        let frame = LoraFrame {
            source_short: [0xAA; 8],
            dest_short: [0xBB; 8],
            message_id_short: [0xCC; 4],
            ttl: 5,
            hop_count: 2,
            flags: 0x01,
            lamport_clock: 42,
            sf_hint: 9,
            payload: vec![10, 20],
        };

        let envelope = frame.to_envelope(|short_id| {
            if short_id == &[0xAA; 8] {
                Some(full_source)
            } else if short_id == &[0xBB; 8] {
                Some(full_dest)
            } else {
                None
            }
        });

        assert_eq!(envelope.source, full_source);
        assert_eq!(envelope.destination, full_dest);
        assert_eq!(envelope.ttl, 5);
        assert_eq!(envelope.hop_count, 2);
        assert_eq!(envelope.lamport_clock, 42);
        assert_eq!(envelope.payload, vec![10, 20]);
    }

    #[test]
    fn test_lora_frame_to_envelope_without_resolver() {
        let frame = LoraFrame {
            source_short: [1, 2, 3, 4, 5, 6, 7, 8],
            dest_short: [9, 10, 11, 12, 13, 14, 15, 16],
            message_id_short: [0; 4],
            ttl: 1,
            hop_count: 0,
            flags: 0,
            lamport_clock: 0,
            sf_hint: 12,
            payload: vec![],
        };

        // Resolver returns None — should zero-pad
        let envelope = frame.to_envelope(|_| None);
        assert_eq!(&envelope.source.as_bytes()[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&envelope.source.as_bytes()[8..], &[0u8; 24]);
    }

    #[test]
    fn test_lora_frame_envelope_roundtrip() {
        let original = Envelope {
            source: NodeId([0x11; 32]),
            destination: NodeId([0x22; 32]),
            message_id: MessageId([0x33; 16]),
            ttl: 10,
            hop_count: 0,
            flags: MessageFlags(0x0001),
            lamport_clock: 100,
            device_timestamp: 0,
            protocol_version: ProtocolVersion::CURRENT,
            payload: vec![42; 20],
        };

        let frame = LoraFrame::from_envelope(&original, 10);
        let bytes = frame.serialize();
        let decoded = LoraFrame::deserialize(&bytes).unwrap();

        // Resolve back with known IDs
        let restored = decoded.to_envelope(|short_id| {
            if short_id == &[0x11; 8] {
                Some(NodeId([0x11; 32]))
            } else if short_id == &[0x22; 8] {
                Some(NodeId([0x22; 32]))
            } else {
                None
            }
        });

        assert_eq!(restored.source, original.source);
        assert_eq!(restored.destination, original.destination);
        assert_eq!(restored.ttl, original.ttl);
        assert_eq!(restored.payload, original.payload);
    }

    #[test]
    fn test_lora_frame_forward() {
        let mut frame = LoraFrame {
            source_short: [0; 8],
            dest_short: [0; 8],
            message_id_short: [0; 4],
            ttl: 3,
            hop_count: 1,
            flags: 0,
            lamport_clock: 0,
            sf_hint: 10,
            payload: vec![],
        };

        frame.forward();
        assert_eq!(frame.ttl, 2);
        assert_eq!(frame.hop_count, 2);
    }

    #[test]
    fn test_max_payload_for_mtu() {
        assert_eq!(max_payload_for_mtu(51), 24); // SF10-12
        assert_eq!(max_payload_for_mtu(115), 88); // SF9
        assert_eq!(max_payload_for_mtu(222), 195); // SF7-8
        assert_eq!(max_payload_for_mtu(10), 0); // Too small
    }

    #[test]
    fn test_lora_frame_wire_size() {
        let frame = LoraFrame {
            source_short: [0; 8],
            dest_short: [0; 8],
            message_id_short: [0; 4],
            ttl: 0,
            hop_count: 0,
            flags: 0,
            lamport_clock: 0,
            sf_hint: 10,
            payload: vec![0; 24],
        };
        assert_eq!(frame.wire_size(), 51); // Fits in SF10 MTU
    }
}
