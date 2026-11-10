//! Channel management and messaging endpoints.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use mycelium_protocol::types::MessageId;

use crate::state::AppState;
use crate::types::{
    ApiError, ChannelMessageResponse, ChannelResponse, CreateChannelRequest, CreateChannelResponse,
    MessageQueryParams, PostChannelMessageRequest, SendMessageResponse,
};

/// Helper: parse a hex-encoded 32-byte channel ID.
/// Reject operations on channels this node has never heard of, instead of
/// creating orphan subscriptions/messages for an id nobody created.
fn ensure_channel_exists(
    state: &AppState,
    channel_id: &[u8; 32],
) -> Result<(), (StatusCode, Json<ApiError>)> {
    state
        .node
        .db
        .get_channel(channel_id)
        .map(|_| ())
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                Json(ApiError {
                    error: "channel not found".to_string(),
                    code: 404,
                }),
            )
        })
}

fn parse_channel_id(hex_str: &str) -> Result<[u8; 32], (StatusCode, Json<ApiError>)> {
    let bytes = hex::decode(hex_str).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: format!("Invalid hex channel ID: {}", hex_str),
                code: 400,
            }),
        )
    })?;

    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: format!(
                    "Channel ID must be 32 bytes (64 hex chars), got {}",
                    bytes.len()
                ),
                code: 400,
            }),
        ));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// POST /v1/channels — Create a new channel
pub async fn create_channel(
    State(state): State<AppState>,
    Json(req): Json<CreateChannelRequest>,
) -> Result<(StatusCode, Json<CreateChannelResponse>), (StatusCode, Json<ApiError>)> {
    let mut channel_id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut channel_id);

    state
        .node
        .db
        .create_channel(&channel_id, &req.name, &state.node.node_id)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;

    // Auto-subscribe to our own channel
    let _ = state.node.db.subscribe_channel(&channel_id);

    Ok((
        StatusCode::CREATED,
        Json(CreateChannelResponse {
            channel_id: hex::encode(channel_id),
        }),
    ))
}

/// GET /v1/channels — List all known channels
pub async fn list_channels(
    State(state): State<AppState>,
) -> Result<Json<Vec<ChannelResponse>>, (StatusCode, Json<ApiError>)> {
    let channels = state.node.db.list_channels().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;

    let result: Vec<ChannelResponse> = channels
        .into_iter()
        .map(|ch| {
            let subscribed = state.node.db.is_subscribed(&ch.channel_id).unwrap_or(false);
            ChannelResponse {
                channel_id: hex::encode(ch.channel_id),
                name: ch.name,
                creator_id: hex::encode(ch.creator_id.as_bytes()),
                created_at: ch.created_at,
                subscribed,
            }
        })
        .collect();

    Ok(Json(result))
}

/// POST /v1/channels/:channel_id/subscribe — Subscribe to a channel
pub async fn subscribe(
    State(state): State<AppState>,
    Path(channel_id_hex): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let channel_id = parse_channel_id(&channel_id_hex)?;
    ensure_channel_exists(&state, &channel_id)?;

    state.node.db.subscribe_channel(&channel_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;

    Ok(StatusCode::OK)
}

/// DELETE /v1/channels/:channel_id/subscribe — Unsubscribe from a channel
pub async fn unsubscribe(
    State(state): State<AppState>,
    Path(channel_id_hex): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let channel_id = parse_channel_id(&channel_id_hex)?;

    state
        .node
        .db
        .unsubscribe_channel(&channel_id)
        .map_err(|e| {
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

/// GET /v1/channels/:channel_id/messages — Get channel messages
pub async fn get_messages(
    State(state): State<AppState>,
    Path(channel_id_hex): Path<String>,
    axum::extract::Query(params): axum::extract::Query<MessageQueryParams>,
) -> Result<Json<Vec<ChannelMessageResponse>>, (StatusCode, Json<ApiError>)> {
    let channel_id = parse_channel_id(&channel_id_hex)?;

    let messages = state
        .node
        .db
        .get_channel_messages(&channel_id, params.limit, params.offset)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;

    let result: Vec<ChannelMessageResponse> = messages
        .into_iter()
        .map(|m| ChannelMessageResponse {
            message_id: hex::encode(m.message_id),
            channel_id: hex::encode(m.channel_id),
            source: hex::encode(m.source.as_bytes()),
            data: String::from_utf8_lossy(&m.data).to_string(),
            content_type: m.content_type,
            timestamp: m.timestamp,
        })
        .collect();

    Ok(Json(result))
}

/// POST /v1/channels/:channel_id/messages — Post a message to a channel
pub async fn post_message(
    State(state): State<AppState>,
    Path(channel_id_hex): Path<String>,
    Json(req): Json<PostChannelMessageRequest>,
) -> Result<(StatusCode, Json<SendMessageResponse>), (StatusCode, Json<ApiError>)> {
    let channel_id = parse_channel_id(&channel_id_hex)?;
    ensure_channel_exists(&state, &channel_id)?;

    let message_id = MessageId::random();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Store locally
    state
        .node
        .db
        .store_channel_message(
            message_id.as_bytes(),
            &channel_id,
            &state.node.node_id,
            req.data.as_bytes(),
            req.content_type,
            timestamp,
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;

    // Broadcast the channel message to all connected peers via wire protocol
    let payload = mycelium_protocol::wire::serialize_channel_message(
        &channel_id,
        req.content_type,
        req.data.as_bytes(),
    );
    let envelope = mycelium_protocol::codec::Envelope {
        source: state.node.node_id,
        destination: mycelium_protocol::types::NodeId::ZERO, // broadcast
        message_id,
        ttl: 10,
        hop_count: 0,
        flags: mycelium_protocol::types::MessageFlags::NONE,
        lamport_clock: 0,
        device_timestamp: timestamp,
        protocol_version: mycelium_protocol::types::ProtocolVersion::CURRENT,
        payload,
    };
    let data = envelope.serialize();
    let peers = state.node.transport_manager.known_peers().await;
    for p in peers {
        let _ = state.node.transport_manager.send(&p, &data).await;
    }

    // Notify WebSocket clients
    state.broadcast(crate::types::WsServerMessage::ChannelMessage {
        channel_id: hex::encode(channel_id),
        source: hex::encode(state.node.node_id.as_bytes()),
        message_id: hex::encode(message_id.as_bytes()),
        data: req.data,
        content_type: req.content_type,
        timestamp,
    });

    Ok((
        StatusCode::CREATED,
        Json(SendMessageResponse {
            message_id: hex::encode(message_id.as_bytes()),
        }),
    ))
}
