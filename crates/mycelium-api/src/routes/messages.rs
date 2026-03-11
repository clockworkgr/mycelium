//! Message CRUD endpoints.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

use mycelium_protocol::types::ContentType;

use crate::state::AppState;
use crate::types::{
    ApiError, MessageQueryParams, MessageResponse, SendMessageRequest, SendMessageResponse,
};
use crate::util::parse_node_id;

/// POST /v1/messages — Send a message
pub async fn send_message(
    State(state): State<AppState>,
    Json(req): Json<SendMessageRequest>,
) -> Result<(StatusCode, Json<SendMessageResponse>), (StatusCode, Json<ApiError>)> {
    let destination = parse_node_id(&req.destination)?;

    let content_type = match req.content_type.as_str() {
        "text" => ContentType::Text,
        "image" => ContentType::Image,
        "file" => ContentType::File,
        "gps_pin" => ContentType::GpsPin,
        "voice_note" => ContentType::VoiceNote,
        _ => ContentType::Text,
    };

    let message_id = state
        .node
        .send_message(destination, req.data.as_bytes(), content_type)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;

    Ok((
        StatusCode::CREATED,
        Json(SendMessageResponse {
            message_id: hex::encode(message_id.as_bytes()),
        }),
    ))
}

/// GET /v1/messages/:peer_id — Get conversation messages
pub async fn get_messages(
    State(state): State<AppState>,
    Path(peer_id): Path<String>,
    Query(params): Query<MessageQueryParams>,
) -> Result<Json<Vec<MessageResponse>>, (StatusCode, Json<ApiError>)> {
    let peer = parse_node_id(&peer_id)?;
    let local_id = state.node.node_id;

    let records = state
        .node
        .db
        .get_conversation(&local_id, &peer, params.limit, params.offset)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;

    let messages: Vec<MessageResponse> = records
        .into_iter()
        .map(|r| MessageResponse {
            message_id: hex::encode(r.message_id.as_bytes()),
            source: hex::encode(r.source.as_bytes()),
            destination: hex::encode(r.destination.as_bytes()),
            content_type: r.content_type,
            data: String::from_utf8_lossy(&r.plaintext).to_string(),
            timestamp: r.device_timestamp,
            status: r.status,
            is_incoming: r.is_incoming,
        })
        .collect();

    Ok(Json(messages))
}

/// DELETE /v1/messages/:peer_id — Delete conversation
pub async fn delete_conversation(
    State(state): State<AppState>,
    Path(peer_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let peer = parse_node_id(&peer_id)?;
    let local_id = state.node.node_id;

    state.node.db.delete_conversation(&local_id, &peer).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /v1/messages/:peer_id/read — Mark messages as read and send read receipts
pub async fn mark_read(
    State(state): State<AppState>,
    Path(peer_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let peer = parse_node_id(&peer_id)?;

    let count = state.node.mark_read_and_notify(peer).await;

    Ok(Json(serde_json::json!({ "marked_read": count })))
}
