//! Prekey bundle cache endpoints (for supernode relay).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use crate::state::AppState;
use crate::types::{ApiError, PrekeyBundleResponse};
use crate::util::parse_node_id;

/// GET /v1/prekeys/{node_id} — Retrieve cached prekey bundle for a peer.
pub async fn get_cached_bundle(
    State(state): State<AppState>,
    Path(node_id_hex): Path<String>,
) -> Result<Json<PrekeyBundleResponse>, (StatusCode, Json<ApiError>)> {
    let node_id = parse_node_id(&node_id_hex)?;

    // Check in-memory cache first
    {
        let cache = state.node.prekey_cache.read().await;
        if let Some((bundle, _)) = cache.get(&node_id) {
            return Ok(Json(PrekeyBundleResponse {
                node_id: node_id_hex,
                identity_key: hex::encode(bundle.identity_key),
                signed_prekey: hex::encode(bundle.signed_prekey),
                signed_prekey_signature: hex::encode(&bundle.signed_prekey_signature),
                signed_prekey_id: bundle.signed_prekey_id,
                one_time_prekey: bundle.one_time_prekey.map(hex::encode),
                one_time_prekey_id: bundle.one_time_prekey_id,
            }));
        }
    }

    // Fall back to database
    match state.node.db.get_cached_prekey_bundle(node_id.as_bytes()) {
        Ok(bundle_data) => {
            use mycelium_protocol::wire::PrekeyBundlePayload;
            match PrekeyBundlePayload::deserialize_body(&bundle_data) {
                Ok(bp) => Ok(Json(PrekeyBundleResponse {
                    node_id: node_id_hex,
                    identity_key: hex::encode(bp.identity_key),
                    signed_prekey: hex::encode(bp.signed_prekey),
                    signed_prekey_signature: hex::encode(&bp.signed_prekey_signature),
                    signed_prekey_id: bp.signed_prekey_id,
                    one_time_prekey: bp.one_time_prekey.map(hex::encode),
                    one_time_prekey_id: bp.one_time_prekey_id,
                })),
                Err(_) => Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiError {
                        error: "Corrupted cached bundle".to_string(),
                        code: 500,
                    }),
                )),
            }
        }
        Err(_) => Err((
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: format!("No cached prekey bundle for {}", node_id_hex),
                code: 404,
            }),
        )),
    }
}
