//! Node status and identity endpoints.

use axum::extract::State;
use axum::Json;

use crate::state::AppState;
use crate::types::{NodeIdentityResponse, NodeStatusResponse};

/// GET /v1/node/status
pub async fn get_status(
    State(state): State<AppState>,
) -> Json<NodeStatusResponse> {
    let uptime = state.started_at.elapsed().as_secs();
    let node_id = hex::encode(state.node.node_id.as_bytes());
    let display_name = state.node.config.display_name.clone();

    let session_count = state.node.session_manager.read().await.all_sessions().count();
    let group_count = state.node.groups.read().await.len();
    let prekey_remaining = state.node.prekey_state.read().await.one_time_prekeys.len();

    Json(NodeStatusResponse {
        node_id,
        display_name,
        uptime_secs: uptime,
        version: env!("CARGO_PKG_VERSION").to_string(),
        session_count,
        group_count,
        prekey_remaining,
    })
}

/// GET /v1/node/identity
pub async fn get_identity(
    State(state): State<AppState>,
) -> Json<NodeIdentityResponse> {
    let node_id = hex::encode(state.node.node_id.as_bytes());
    let public_key = hex::encode(state.node.identity.public_key_bytes());

    Json(NodeIdentityResponse {
        node_id,
        public_key,
    })
}
