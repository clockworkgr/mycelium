use serde::{Deserialize, Serialize};
use std::fmt;

/// 32-byte node identity derived from SHA-256 of Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub const ZERO: NodeId = NodeId([0u8; 32]);

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Short hex representation for display (first 8 bytes).
    pub fn short_hex(&self) -> String {
        hex_encode(&self.0[..8])
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({}..)", self.short_hex())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short_hex())
    }
}

/// 16-byte random message identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub [u8; 16]);

impl MessageId {
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MsgId({})", hex_encode(&self.0[..4]))
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex_encode(&self.0))
    }
}

/// Lamport logical clock for causal ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LamportClock(pub u64);

impl LamportClock {
    pub fn new() -> Self {
        Self(0)
    }

    /// Increment on local event (send).
    pub fn tick(&mut self) -> Self {
        self.0 += 1;
        *self
    }

    /// Update on receiving a remote clock value.
    pub fn merge(&mut self, other: LamportClock) -> Self {
        self.0 = self.0.max(other.0) + 1;
        *self
    }
}

impl Default for LamportClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Message flags bitfield.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageFlags(pub u16);

impl MessageFlags {
    pub const NONE: Self = Self(0);
    pub const DTN: Self = Self(1 << 0);
    pub const PRIORITY: Self = Self(1 << 1);
    pub const URGENT: Self = Self(1 << 2);
    pub const CRITICAL: Self = Self(1 << 3);
    pub const RECEIPT: Self = Self(1 << 4);
    pub const GROUP: Self = Self(1 << 5);
    pub const SYSTEM: Self = Self(1 << 6);

    pub fn contains(&self, flag: MessageFlags) -> bool {
        self.0 & flag.0 == flag.0
    }

    pub fn set(&mut self, flag: MessageFlags) {
        self.0 |= flag.0;
    }
}

/// Link quality metrics for a transport link.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LinkQuality {
    /// Received signal strength indicator (dBm). None if not applicable.
    pub rssi: Option<i16>,
    /// Estimated throughput in bytes per second.
    pub throughput_bps: u32,
    /// Packet loss ratio 0.0 to 1.0.
    pub packet_loss: f32,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u32,
}

impl LinkQuality {
    /// Composite score for transport selection (higher is better).
    pub fn score(&self) -> f64 {
        let throughput_score = (self.throughput_bps as f64).ln().max(0.0);
        let loss_penalty = 1.0 - self.packet_loss as f64;
        let latency_penalty = 1.0 / (1.0 + self.latency_ms as f64 / 100.0);
        throughput_score * loss_penalty * latency_penalty
    }
}

/// Protocol version identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    pub const V0_1: Self = Self(1);
    pub const CURRENT: Self = Self::V0_1;
}

/// Content type for messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    Text,
    Image,
    File,
    GpsPin,
    VoiceNote,
    Receipt,
    System,
}

/// Node type in the mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    Phone,
    Supernode,
    ExternalRadio,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_display() {
        let id = NodeId([0xab; 32]);
        assert_eq!(id.short_hex(), "abababababababab");
    }

    #[test]
    fn test_message_id_random() {
        let a = MessageId::random();
        let b = MessageId::random();
        assert_ne!(a, b);
    }

    #[test]
    fn test_lamport_clock_tick() {
        let mut clock = LamportClock::new();
        assert_eq!(clock.0, 0);
        clock.tick();
        assert_eq!(clock.0, 1);
        clock.tick();
        assert_eq!(clock.0, 2);
    }

    #[test]
    fn test_lamport_clock_merge() {
        let mut clock = LamportClock(5);
        clock.merge(LamportClock(10));
        assert_eq!(clock.0, 11);

        let mut clock2 = LamportClock(20);
        clock2.merge(LamportClock(3));
        assert_eq!(clock2.0, 21);
    }

    #[test]
    fn test_message_flags() {
        let mut flags = MessageFlags::NONE;
        assert!(!flags.contains(MessageFlags::DTN));
        flags.set(MessageFlags::DTN);
        assert!(flags.contains(MessageFlags::DTN));
        flags.set(MessageFlags::PRIORITY);
        assert!(flags.contains(MessageFlags::DTN));
        assert!(flags.contains(MessageFlags::PRIORITY));
    }

    #[test]
    fn test_link_quality_score() {
        let good = LinkQuality {
            rssi: Some(-50),
            throughput_bps: 1_000_000,
            packet_loss: 0.01,
            latency_ms: 10,
        };
        let bad = LinkQuality {
            rssi: Some(-90),
            throughput_bps: 1_000,
            packet_loss: 0.3,
            latency_ms: 500,
        };
        assert!(good.score() > bad.score());
    }
}
