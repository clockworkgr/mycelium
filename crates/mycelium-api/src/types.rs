//! API request and response types.
//!
//! Uses serde JSON for Phase 1. Protobuf encoding (prost) will be added
//! in a future phase when `protoc` is available in the build environment.

use serde::{Deserialize, Serialize};

// --- Node ---

#[derive(Debug, Serialize)]
pub struct NodeStatusResponse {
    pub node_id: String,
    pub display_name: String,
    pub uptime_secs: u64,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct NodeIdentityResponse {
    pub node_id: String,
    pub public_key: String,
}

// --- Messages ---

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    pub destination: String,
    pub data: String,
    #[serde(default = "default_content_type")]
    pub content_type: String,
    #[serde(default)]
    pub protocol_id: String,
}

fn default_content_type() -> String {
    "text".to_string()
}

#[derive(Debug, Serialize)]
pub struct SendMessageResponse {
    pub message_id: String,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message_id: String,
    pub source: String,
    pub destination: String,
    pub content_type: String,
    pub data: String,
    pub timestamp: u64,
    pub status: String,
    pub is_incoming: bool,
}

#[derive(Debug, Deserialize)]
pub struct MessageQueryParams {
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

fn default_limit() -> u32 {
    50
}

// --- Conversations ---

#[derive(Debug, Serialize)]
pub struct ConversationSummary {
    pub peer_id: String,
    pub display_name: Option<String>,
    pub last_message_time: u64,
    pub message_count: u32,
    pub has_unread: bool,
}

#[derive(Debug, Serialize)]
pub struct UnreadCountResponse {
    pub total_unread: u32,
}

// --- Contacts ---

#[derive(Debug, Deserialize)]
pub struct AddContactRequest {
    pub node_id: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct ContactResponse {
    pub node_id: String,
    pub display_name: String,
    pub trust_score: f32,
    pub is_verified: bool,
    pub last_seen: Option<u64>,
}

// --- Groups ---

#[derive(Debug, Serialize)]
pub struct GroupSummary {
    pub group_id: String,
    pub member_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct AddGroupMemberRequest {
    pub node_id: String, // hex
}

#[derive(Debug, Deserialize)]
pub struct SendGroupMessageRequest {
    pub data: String,
    pub content_type: Option<u8>,
}

#[derive(Debug, Serialize)]
pub struct CreateGroupResponse {
    pub group_id: String,
}

// --- Network / Diagnostics ---

#[derive(Debug, Serialize)]
pub struct NetworkStatusResponse {
    pub neighbor_count: usize,
    pub is_connected: bool,
    pub dtn_queue_size: usize,
    pub dtn_storage_used: usize,
    pub dtn_storage_max: usize,
    pub pending_messages: usize,
    pub pending_routes: usize,
}

#[derive(Debug, Serialize)]
pub struct TransportInfo {
    pub name: String,
    pub registered: bool,
    pub peer_count: usize,
    pub peers: Vec<TransportPeerInfo>,
    pub mtu: usize,
}

#[derive(Debug, Serialize)]
pub struct TransportPeerInfo {
    pub node_id: String,
    pub rssi: Option<i16>,
    pub throughput_bps: u32,
    pub latency_ms: u32,
}

#[derive(Debug, Serialize)]
pub struct TransportStatusResponse {
    pub transports: Vec<TransportInfo>,
}

#[derive(Debug, Serialize)]
pub struct RouteEntryResponse {
    pub destination: String,
    pub next_hop: String,
    pub hop_count: u8,
    pub sequence_number: u32,
    pub is_valid: bool,
    pub expires_in_secs: i64,
}

#[derive(Debug, Serialize)]
pub struct DtnBundleResponse {
    pub message_id: String,
    pub destination: String,
    pub source: String,
    pub copies_remaining: u8,
    pub size: usize,
    pub expires_in_secs: i64,
}

// --- WebSocket ---

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsClientMessage {
    #[serde(rename = "subscribe")]
    Subscribe { protocol_ids: Vec<String> },
    #[serde(rename = "send")]
    SendData {
        destination: String,
        data: String,
        protocol_id: String,
        #[serde(default)]
        content_type: String,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum WsServerMessage {
    #[serde(rename = "message")]
    IncomingMessage {
        source: String,
        message_id: String,
        data: String,
        protocol_id: String,
        content_type: String,
        timestamp: u64,
    },
    #[serde(rename = "peer")]
    PeerEvent {
        event: String, // "discovered" or "lost"
        peer_id: String,
        transport: String,
    },
    #[serde(rename = "network")]
    NetworkEvent {
        neighbor_count: usize,
        is_connected: bool,
        dtn_queue_size: usize,
    },
    #[serde(rename = "receipt")]
    DeliveryReceipt {
        message_id: String,
        status: String, // "sent", "delivered", "read", "failed"
    },
}

// --- Error ---

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
    pub code: u16,
}
