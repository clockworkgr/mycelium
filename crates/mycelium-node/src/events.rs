//! Events emitted by the node for external consumers (API server, WebSocket clients).

use mycelium_protocol::types::{MessageId, NodeId};

/// Events emitted by the node when significant state changes occur.
///
/// These are consumed by the API server and broadcast to WebSocket clients.
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// A new message was received and stored.
    MessageReceived {
        source: NodeId,
        message_id: MessageId,
        data: Vec<u8>,
        content_type: u8,
        timestamp: u64,
    },
    /// A delivery/read receipt was processed.
    ReceiptUpdated {
        message_id: MessageId,
        status: String, // "delivered" or "read"
    },
    /// A neighbor was discovered via transport.
    PeerDiscovered {
        peer_id: NodeId,
        transport: String,
    },
    /// A neighbor was lost.
    PeerLost {
        peer_id: NodeId,
        transport: String,
    },
}
