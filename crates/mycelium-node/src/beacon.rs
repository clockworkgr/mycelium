use mycelium_protocol::types::{NodeId, NodeType, ProtocolVersion};

/// Beacon message broadcast to neighbors for discovery.
#[derive(Debug, Clone)]
pub struct Beacon {
    pub node_id: NodeId,
    pub node_type: NodeType,
    pub display_name: String,
    pub protocol_version: ProtocolVersion,
    pub battery_level: u8,
    pub neighbor_count: u16,
    pub lamport_clock: u64,
}

impl Beacon {
    /// Serialize beacon to bytes for broadcast.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);

        // Magic bytes
        buf.extend_from_slice(b"MYCO");

        buf.extend_from_slice(self.node_id.as_bytes());

        buf.push(match self.node_type {
            NodeType::Phone => 0,
            NodeType::Supernode => 1,
            NodeType::ExternalRadio => 2,
        });

        // Display name (length-prefixed)
        let name_bytes = self.display_name.as_bytes();
        buf.push(name_bytes.len().min(255) as u8);
        buf.extend_from_slice(&name_bytes[..name_bytes.len().min(255)]);

        buf.extend_from_slice(&self.protocol_version.0.to_le_bytes());
        buf.push(self.battery_level);
        buf.extend_from_slice(&self.neighbor_count.to_le_bytes());
        buf.extend_from_slice(&self.lamport_clock.to_le_bytes());

        buf
    }

    /// Deserialize beacon from bytes.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 48 || &data[..4] != b"MYCO" {
            return None;
        }

        let mut offset = 4;

        let mut nid = [0u8; 32];
        nid.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let node_type = match data[offset] {
            0 => NodeType::Phone,
            1 => NodeType::Supernode,
            2 => NodeType::ExternalRadio,
            _ => return None,
        };
        offset += 1;

        let name_len = data[offset] as usize;
        offset += 1;
        if offset + name_len > data.len() {
            return None;
        }
        let display_name = String::from_utf8_lossy(&data[offset..offset + name_len]).to_string();
        offset += name_len;

        if offset + 13 > data.len() {
            return None;
        }

        let protocol_version =
            ProtocolVersion(u16::from_le_bytes([data[offset], data[offset + 1]]));
        offset += 2;

        let battery_level = data[offset];
        offset += 1;

        let neighbor_count = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let lamport_clock = u64::from_le_bytes(
            data[offset..offset + 8].try_into().ok()?,
        );

        Some(Beacon {
            node_id: NodeId(nid),
            node_type,
            display_name,
            protocol_version,
            battery_level,
            neighbor_count,
            lamport_clock,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beacon_roundtrip() {
        let beacon = Beacon {
            node_id: NodeId([0xaa; 32]),
            node_type: NodeType::Supernode,
            display_name: "TestNode".to_string(),
            protocol_version: ProtocolVersion::CURRENT,
            battery_level: 75,
            neighbor_count: 5,
            lamport_clock: 42,
        };

        let bytes = beacon.serialize();
        let decoded = Beacon::deserialize(&bytes).unwrap();

        assert_eq!(beacon.node_id, decoded.node_id);
        assert_eq!(beacon.node_type, decoded.node_type);
        assert_eq!(beacon.display_name, decoded.display_name);
        assert_eq!(beacon.battery_level, decoded.battery_level);
        assert_eq!(beacon.neighbor_count, decoded.neighbor_count);
        assert_eq!(beacon.lamport_clock, decoded.lamport_clock);
    }

    #[test]
    fn test_beacon_deserialize_too_short() {
        assert!(Beacon::deserialize(&[0; 10]).is_none());
        assert!(Beacon::deserialize(&[]).is_none());
    }

    #[test]
    fn test_beacon_deserialize_bad_magic() {
        let mut data = vec![0u8; 64];
        data[..4].copy_from_slice(b"NOPE");
        assert!(Beacon::deserialize(&data).is_none());
    }

    #[test]
    fn test_beacon_deserialize_bad_node_type() {
        let beacon = Beacon {
            node_id: NodeId([0x11; 32]),
            node_type: NodeType::Phone,
            display_name: "Test".to_string(),
            protocol_version: ProtocolVersion::CURRENT,
            battery_level: 50,
            neighbor_count: 2,
            lamport_clock: 100,
        };
        let mut data = beacon.serialize();
        // Corrupt node_type byte (offset 4 + 32 = 36)
        data[36] = 0xFF;
        assert!(Beacon::deserialize(&data).is_none());
    }

    #[test]
    fn test_beacon_long_display_name_truncated() {
        let long_name = "A".repeat(300);
        let beacon = Beacon {
            node_id: NodeId([0x22; 32]),
            node_type: NodeType::Supernode,
            display_name: long_name,
            protocol_version: ProtocolVersion::CURRENT,
            battery_level: 90,
            neighbor_count: 10,
            lamport_clock: 42,
        };
        let data = beacon.serialize();
        let decoded = Beacon::deserialize(&data).unwrap();
        // Display name should be truncated to 255 bytes
        assert_eq!(decoded.display_name.len(), 255);
    }

    #[test]
    fn test_beacon_empty_display_name() {
        let beacon = Beacon {
            node_id: NodeId([0x33; 32]),
            node_type: NodeType::ExternalRadio,
            display_name: String::new(),
            protocol_version: ProtocolVersion::CURRENT,
            battery_level: 0,
            neighbor_count: 0,
            lamport_clock: 0,
        };
        let data = beacon.serialize();
        let decoded = Beacon::deserialize(&data).unwrap();
        assert_eq!(decoded.display_name, "");
        assert_eq!(decoded.battery_level, 0);
    }
}
