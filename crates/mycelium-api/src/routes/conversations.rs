//! Conversation listing endpoints.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use crate::state::AppState;
use crate::types::{ApiError, ConversationSummary, UnreadCountResponse};

/// GET /v1/conversations — List all conversations
pub async fn list_conversations(
    State(state): State<AppState>,
) -> Result<Json<Vec<ConversationSummary>>, (StatusCode, Json<ApiError>)> {
    let local_id = state.node.node_id;

    let records = state.node.db.list_conversations(&local_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;

    let summaries: Vec<ConversationSummary> = records
        .into_iter()
        .map(|r| {
            let display_name = state
                .node
                .db
                .get_contact(&r.peer_id)
                .ok()
                .map(|c| c.display_name);

            ConversationSummary {
                peer_id: hex::encode(r.peer_id.as_bytes()),
                display_name,
                last_message_time: r.last_message_time,
                message_count: r.message_count,
                has_unread: r.has_unread,
            }
        })
        .collect();

    Ok(Json(summaries))
}

/// GET /v1/conversations/unread — Total unread count
pub async fn unread_count(
    State(state): State<AppState>,
) -> Result<Json<UnreadCountResponse>, (StatusCode, Json<ApiError>)> {
    let local_id = state.node.node_id;

    let count = state.node.db.total_unread_count(&local_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;

    Ok(Json(UnreadCountResponse {
        total_unread: count,
    }))
}
