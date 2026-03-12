use crate::types::{MessageFlags, MessageId, NodeId, ProtocolVersion};

/// Routing envelope — the on-the-wire format for all mesh messages.
///
/// Binary layout matches the spec Section 4.3 routing header:
/// - Source (32 bytes) + Destination (32 bytes) + MessageId (16 bytes)
/// - TTL (1) + HopCount (1) + Flags (2) + LamportClock (8) + DeviceTimestamp (8)
/// - ProtocolVersion (2) + PayloadLength (4) + Payload (variable)
///
/// Total header: 106 bytes fixed + variable payload.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub source: NodeId,
    pub destination: NodeId,
    pub message_id: MessageId,
    pub ttl: u8,
    pub hop_count: u8,
    pub flags: MessageFlags,
    pub lamport_clock: u64,
    pub device_timestamp: u64,
    pub protocol_version: ProtocolVersion,
    pub payload: Vec<u8>,
}

const HEADER_SIZE: usize = 32 + 32 + 16 + 1 + 1 + 2 + 8 + 8 + 2 + 4; // 106 bytes

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("buffer too short: expected at least {expected} bytes, got {actual}")]
    BufferTooShort { expected: usize, actual: usize },
    #[error("payload length mismatch: header says {header} but {actual} available")]
    PayloadLengthMismatch { header: usize, actual: usize },
}

impl Envelope {
    pub fn serialize(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());

        buf.extend_from_slice(self.source.as_bytes());
        buf.extend_from_slice(self.destination.as_bytes());
        buf.extend_from_slice(self.message_id.as_bytes());
        buf.push(self.ttl);
        buf.push(self.hop_count);
        buf.extend_from_slice(&self.flags.0.to_le_bytes());
        buf.extend_from_slice(&self.lamport_clock.to_le_bytes());
        buf.extend_from_slice(&self.device_timestamp.to_le_bytes());
        buf.extend_from_slice(&self.protocol_version.0.to_le_bytes());
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&self.payload);

        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() < HEADER_SIZE {
            return Err(CodecError::BufferTooShort {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        let mut offset = 0;

        let source = {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            NodeId(bytes)
        };

        let destination = {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            NodeId(bytes)
        };

        let message_id = {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[offset..offset + 16]);
            offset += 16;
            MessageId(bytes)
        };

        let ttl = data[offset];
        offset += 1;

        let hop_count = data[offset];
        offset += 1;

        let flags = MessageFlags(u16::from_le_bytes([data[offset], data[offset + 1]]));
        offset += 2;

        let lamport_clock = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let device_timestamp = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let protocol_version =
            ProtocolVersion(u16::from_le_bytes([data[offset], data[offset + 1]]));
        offset += 2;

        let payload_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if data.len() < offset + payload_len {
            return Err(CodecError::PayloadLengthMismatch {
                header: payload_len,
                actual: data.len() - offset,
            });
        }

        let payload = data[offset..offset + payload_len].to_vec();

        Ok(Envelope {
            source,
            destination,
            message_id,
            ttl,
            hop_count,
            flags,
            lamport_clock,
            device_timestamp,
            protocol_version,
            payload,
        })
    }

    /// Decrement TTL and increment hop count for forwarding.
    pub fn forward(&mut self) {
        if self.ttl > 0 {
            self.ttl -= 1;
        }
        self.hop_count = self.hop_count.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_roundtrip() {
        let original = Envelope {
            source: NodeId([1u8; 32]),
            destination: NodeId([2u8; 32]),
            message_id: MessageId([3u8; 16]),
            ttl: 10,
            hop_count: 2,
            flags: MessageFlags::DTN,
            lamport_clock: 42,
            device_timestamp: 1234567890,
            protocol_version: ProtocolVersion::CURRENT,
            payload: b"hello encrypted world".to_vec(),
        };

        let bytes = original.serialize();
        assert_eq!(bytes.len(), HEADER_SIZE + 21);

        let decoded = Envelope::deserialize(&bytes).expect("deserialization failed");

        assert_eq!(original.source, decoded.source);
        assert_eq!(original.destination, decoded.destination);
        assert_eq!(original.message_id, decoded.message_id);
        assert_eq!(original.ttl, decoded.ttl);
        assert_eq!(original.hop_count, decoded.hop_count);
        assert_eq!(original.flags, decoded.flags);
        assert_eq!(original.lamport_clock, decoded.lamport_clock);
        assert_eq!(original.device_timestamp, decoded.device_timestamp);
        assert_eq!(original.protocol_version, decoded.protocol_version);
        assert_eq!(original.payload, decoded.payload);
    }

    #[test]
    fn test_empty_payload() {
        let env = Envelope {
            source: NodeId([0u8; 32]),
            destination: NodeId([0u8; 32]),
            message_id: MessageId([0u8; 16]),
            ttl: 0,
            hop_count: 0,
            flags: MessageFlags::NONE,
            lamport_clock: 0,
            device_timestamp: 0,
            protocol_version: ProtocolVersion::CURRENT,
            payload: vec![],
        };

        let bytes = env.serialize();
        assert_eq!(bytes.len(), HEADER_SIZE);

        let decoded = Envelope::deserialize(&bytes).unwrap();
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_truncated_buffer() {
        let result = Envelope::deserialize(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_forward() {
        let mut env = Envelope {
            source: NodeId([1u8; 32]),
            destination: NodeId([2u8; 32]),
            message_id: MessageId([3u8; 16]),
            ttl: 10,
            hop_count: 2,
            flags: MessageFlags::NONE,
            lamport_clock: 0,
            device_timestamp: 0,
            protocol_version: ProtocolVersion::CURRENT,
            payload: vec![],
        };

        env.forward();
        assert_eq!(env.ttl, 9);
        assert_eq!(env.hop_count, 3);
    }
}
