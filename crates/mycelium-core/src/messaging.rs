use mycelium_protocol::types::{LamportClock, MessageId, NodeId};

/// Message status in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MessageStatus {
    /// Message is queued for sending.
    Pending,
    /// Message was sent via AODV real-time route.
    Sent,
    /// Message entered DTN store-and-forward.
    DtnPending,
    /// Delivery receipt received from destination.
    Delivered,
    /// Read receipt received from destination.
    Read,
    /// Message delivery failed permanently.
    Failed,
}

/// A stored message record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredMessage {
    pub message_id: MessageId,
    pub source: NodeId,
    pub destination: NodeId,
    pub content_type: mycelium_protocol::types::ContentType,
    pub plaintext: Vec<u8>,
    pub lamport_clock: LamportClock,
    pub device_timestamp: u64,
    pub status: MessageStatus,
    pub is_incoming: bool,
}

/// Conversation summary for listing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConversationSummary {
    pub peer: NodeId,
    pub last_message_preview: String,
    pub last_message_time: u64,
    pub unread_count: u32,
    pub last_status: MessageStatus,
}
