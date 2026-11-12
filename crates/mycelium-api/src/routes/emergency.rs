//! Emergency broadcast endpoints.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

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

    // The node signs and floods it: the identity lives there, and the
    // signature covers the approval list, so only the originator can produce
    // one (ADR-014). `signed_at` is what bounds replay of this alert at every
    // receiver (ADR-013). Co-signature collection is ROADMAP T-05, so the
    // list is empty and a level-3 alert is still refused by every receiver.
    let draft = state.node.draft_emergency(level, req.message.as_bytes());
    let message_id = state.node.raise_emergency(draft, &[]).await.map_err(|e| {
        // An alert too large for the smallest transport an emergency must
        // cross is refused here rather than flooded to the subset of the
        // mesh that can carry it (ROADMAP T-39).
        (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: e.to_string(),
                code: 400,
            }),
        )
    })?;

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
pub async fn history(State(state): State<AppState>) -> Json<Vec<EmergencyHistoryEntry>> {
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
