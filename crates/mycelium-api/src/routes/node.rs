//! Node status and identity endpoints.

use axum::extract::State;
use axum::Json;

use crate::state::AppState;
use crate::types::{NodeIdentityResponse, NodeStatusResponse, TrustStatsResponse};

/// GET /v1/node/status
pub async fn get_status(State(state): State<AppState>) -> Json<NodeStatusResponse> {
    let uptime = state.started_at.elapsed().as_secs();
    let node_id = hex::encode(state.node.node_id.as_bytes());
    let display_name = state.node.config.display_name.clone();

    let session_count = state
        .node
        .session_manager
        .read()
        .await
        .all_sessions()
        .count();
    let group_count = state.node.groups.read().await.len();
    let prekey_remaining = state.node.prekey_state.read().await.one_time_prekeys.len();

    let (battery_level, power_mode, is_charging) = {
        let bm = state.node.battery.read().await;
        (
            bm.battery_level(),
            format!("{:?}", bm.power_mode()),
            bm.is_charging(),
        )
    };

    Json(NodeStatusResponse {
        node_id,
        display_name,
        uptime_secs: uptime,
        version: env!("CARGO_PKG_VERSION").to_string(),
        session_count,
        group_count,
        prekey_remaining,
        battery_level,
        power_mode,
        is_charging,
    })
}

/// GET /v1/node/trust — Trust graph stats
pub async fn get_trust_stats(State(state): State<AppState>) -> Json<TrustStatsResponse> {
    let total_contacts = state.node.db.list_contacts().map(|c| c.len()).unwrap_or(0);

    let trust_graph = state.node.trust_graph.read().await;
    let self_id = state.node.node_id;
    let total_vouches = trust_graph.vouched_by_node(&self_id).len();

    let session_mgr = state.node.session_manager.read().await;
    let verified_sessions = session_mgr
        .all_sessions()
        .filter(|(_, s)| s.is_verified)
        .count();

    Json(TrustStatsResponse {
        total_contacts,
        total_vouches,
        verified_sessions,
    })
}

/// GET /v1/node/identity
pub async fn get_identity(State(state): State<AppState>) -> Json<NodeIdentityResponse> {
    let node_id = hex::encode(state.node.node_id.as_bytes());
    let public_key = hex::encode(state.node.identity.public_key_bytes());

    Json(NodeIdentityResponse {
        node_id,
        public_key,
    })
}
