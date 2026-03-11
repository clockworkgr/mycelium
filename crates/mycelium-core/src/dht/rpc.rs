//! DHT RPC message types for Kademlia operations.
//!
//! Messages are serialized as length-prefixed JSON over TCP connections.
//! This is a simple wire format suitable for the initial implementation.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use mycelium_protocol::types::NodeId;

/// DHT request messages sent between nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMessage {
    /// Ping a node to check if it's alive.
    Ping {
        sender_id: NodeId,
        sender_addr: SocketAddr,
    },
    /// Find the K closest nodes to a target.
    FindNode {
        sender_id: NodeId,
        sender_addr: SocketAddr,
        target: NodeId,
    },
    /// Store a key-value pair (NodeId → SocketAddr).
    Store {
        sender_id: NodeId,
        sender_addr: SocketAddr,
        key: NodeId,
        value: SocketAddr,
    },
    /// Look up the address for a node.
    FindValue {
        sender_id: NodeId,
        sender_addr: SocketAddr,
        key: NodeId,
    },
}

/// DHT response messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtResponse {
    /// Response to Ping.
    Pong {
        responder_id: NodeId,
    },
    /// Response to FindNode or FindValue (when value not found).
    FoundNodes {
        responder_id: NodeId,
        nodes: Vec<(NodeId, SocketAddr)>,
    },
    /// Response to FindValue when value was found.
    FoundValue {
        responder_id: NodeId,
        value: SocketAddr,
    },
    /// Response to Store.
    Stored {
        responder_id: NodeId,
    },
}

/// Wire format for messages exchanged over TCP.
/// Wraps both mesh data and DHT protocol messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InternetWireMessage {
    /// Mesh envelope data (forwarded between nodes).
    MeshData {
        sender_id: NodeId,
        data: Vec<u8>,
    },
    /// DHT protocol message.
    Dht(DhtMessage),
    /// DHT protocol response.
    DhtReply(DhtResponse),
    /// Handshake: first message after connecting.
    Hello {
        node_id: NodeId,
        listen_port: u16,
    },
}

/// Serialize a wire message to bytes (4-byte length prefix + JSON).
pub fn serialize_wire_message(msg: &InternetWireMessage) -> Vec<u8> {
    let json = serde_json::to_vec(msg).expect("wire message serialization");
    let len = json.len() as u32;
    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&json);
    buf
}

/// Deserialize a wire message from a byte buffer (excluding the length prefix).
pub fn deserialize_wire_message(data: &[u8]) -> Result<InternetWireMessage, serde_json::Error> {
    serde_json::from_slice(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_node_id() -> NodeId {
        use rand::Rng;
        NodeId::from_bytes(rand::thread_rng().gen())
    }

    #[test]
    fn test_serialize_roundtrip() {
        let msg = InternetWireMessage::Hello {
            node_id: random_node_id(),
            listen_port: 9736,
        };
        let bytes = serialize_wire_message(&msg);
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(len, bytes.len() - 4);
        let decoded = deserialize_wire_message(&bytes[4..]).unwrap();
        match decoded {
            InternetWireMessage::Hello { listen_port, .. } => {
                assert_eq!(listen_port, 9736);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_dht_message_serialization() {
        let msg = InternetWireMessage::Dht(DhtMessage::Ping {
            sender_id: random_node_id(),
            sender_addr: "127.0.0.1:5000".parse().unwrap(),
        });
        let bytes = serialize_wire_message(&msg);
        let decoded = deserialize_wire_message(&bytes[4..]).unwrap();
        assert!(matches!(decoded, InternetWireMessage::Dht(DhtMessage::Ping { .. })));
    }
}
