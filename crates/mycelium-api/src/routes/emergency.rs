//! Emergency broadcast endpoints.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use mycelium_protocol::codec::Envelope;
use mycelium_protocol::types::{MessageFlags, MessageId, NodeId, ProtocolVersion};
use mycelium_protocol::wire;

use crate::state::AppState;
use crate::types::{
    ApiError, EmergencyBroadcastRequest, EmergencyBroadcastResponse, EmergencyHistoryEntry,
};

/// POST /v1/emergency/broadcast — Send an emergency broadcast
pub async fn broadcast(
    State(state): State<AppState>,
    Json(req): Json<EmergencyBroadcastRequest>,
) -> Result<(StatusCode, Json<EmergencyBroadcastResponse>), (StatusCode, Json<ApiError>)> {
    let level = wire::EmergencyLevel::from_byte(req.level).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: format!("Invalid emergency level: {} (must be 1-3)", req.level),
                code: 400,
            }),
        )
    })?;

    let message_id = MessageId::random();
    let payload = wire::serialize_emergency_broadcast(level, req.message.as_bytes(), &[]);

    let envelope = Envelope {
        source: state.node.node_id,
        destination: NodeId::ZERO, // broadcast
        message_id,
        ttl: 20, // higher TTL for emergencies
        hop_count: 0,
        flags: MessageFlags::NONE,
        lamport_clock: 0,
        device_timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        protocol_version: ProtocolVersion::CURRENT,
        payload,
    };

    // Flood to all connected peers
    let data = envelope.serialize();
    let peers = state.node.transport_manager.known_peers().await;
    for p in peers {
        let _ = state.node.transport_manager.send(&p, &data).await;
    }

    // Record in event log
    state.record_event(
        "emergency_sent".to_string(),
        format!("level {} — {}", req.level, req.message),
    );

    // Broadcast to local WebSocket clients
    state.broadcast(crate::types::WsServerMessage::EmergencyBroadcast {
        source: hex::encode(state.node.node_id.as_bytes()),
        level: req.level,
        message: req.message.clone(),
    });

    Ok((
        StatusCode::CREATED,
        Json(EmergencyBroadcastResponse {
            message_id: hex::encode(message_id.as_bytes()),
            level: req.level,
        }),
    ))
}

/// GET /v1/emergency/history — Recent emergency events from the event log
pub async fn history(
    State(state): State<AppState>,
) -> Json<Vec<EmergencyHistoryEntry>> {
    let log = state.event_log.lock().unwrap_or_else(|e| e.into_inner());
    let entries: Vec<EmergencyHistoryEntry> = log
        .iter()
        .filter(|e| e.event_type == "emergency" || e.event_type == "emergency_sent")
        .map(|e| EmergencyHistoryEntry {
            uptime_secs: e.uptime_secs,
            event_type: e.event_type.clone(),
            detail: e.detail.clone(),
        })
        .collect();
    Json(entries)
}
