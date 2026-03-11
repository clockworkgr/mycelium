//! Contact management endpoints.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use mycelium_storage::contacts::ContactRecord;

use crate::state::AppState;
use crate::types::{AddContactRequest, ApiError, ContactResponse};
use crate::util::parse_node_id;

/// GET /v1/contacts — List all contacts
pub async fn list_contacts(
    State(state): State<AppState>,
) -> Result<Json<Vec<ContactResponse>>, (StatusCode, Json<ApiError>)> {
    let contacts = state.node.db.list_contacts().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;

    let result: Vec<ContactResponse> = contacts
        .into_iter()
        .map(|c| ContactResponse {
            node_id: hex::encode(c.node_id.as_bytes()),
            display_name: c.display_name,
            trust_score: c.trust_score,
            is_verified: c.is_verified,
            last_seen: c.last_seen,
        })
        .collect();

    Ok(Json(result))
}

/// POST /v1/contacts — Add or update a contact
pub async fn add_contact(
    State(state): State<AppState>,
    Json(req): Json<AddContactRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let node_id = parse_node_id(&req.node_id)?;

    let contact = ContactRecord {
        node_id,
        display_name: req.display_name,
        public_key: Vec::new(),
        trust_score: 0.0,
        is_verified: false,
        last_seen: None,
    };

    state.node.db.save_contact(&contact).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;

    Ok(StatusCode::CREATED)
}

/// DELETE /v1/contacts/:node_id — Remove a contact
pub async fn delete_contact(
    State(state): State<AppState>,
    Path(node_id_hex): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let node_id = parse_node_id(&node_id_hex)?;

    state.node.db.delete_contact(&node_id).map_err(|e| {
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

/// GET /v1/contacts/:node_id/trust — Get trust score
pub async fn get_trust(
    State(state): State<AppState>,
    Path(node_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let node_id = parse_node_id(&node_id_hex)?;
    let tg = state.node.trust_graph.read().await;
    let score = tg.trust_score(&state.node.node_id, &node_id);
    Ok(Json(serde_json::json!({
        "trust_score": score.value,
        "hops": score.hops,
    })))
}

/// POST /v1/contacts/:node_id/vouch — Add trust vouch
pub async fn add_vouch(
    State(state): State<AppState>,
    Path(node_id_hex): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let vouchee = parse_node_id(&node_id_hex)?;
    let voucher = state.node.node_id;

    {
        let mut tg = state.node.trust_graph.write().await;
        tg.add_vouch(voucher, vouchee);
    }

    use mycelium_storage::vouches::VouchRecord;
    let record = VouchRecord {
        voucher_id: voucher,
        vouchee_id: vouchee,
        voucher_public_key: state.node.identity.public_key_bytes().to_vec(),
        display_name: String::new(),
        signature: Vec::new(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    state.node.db.save_vouch(&record).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;

    Ok(StatusCode::CREATED)
}

/// POST /v1/contacts/:node_id/verify — Verify session (safety number confirmed)
pub async fn verify_session(
    State(state): State<AppState>,
    Path(node_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let peer = parse_node_id(&node_id_hex)?;

    let verified = {
        let mut sm = state.node.session_manager.write().await;
        sm.verify_session(&peer)
    };

    if verified {
        Ok(Json(serde_json::json!({ "verified": true })))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "No session found for peer".to_string(),
                code: 404,
            }),
        ))
    }
}

/// GET /v1/contacts/:node_id/safety-number — Get safety number string
pub async fn get_safety_number(
    State(state): State<AppState>,
    Path(node_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let peer = parse_node_id(&node_id_hex)?;

    let sm = state.node.session_manager.read().await;
    match sm.safety_number(&peer) {
        Some(sn) => Ok(Json(serde_json::json!({
            "safety_number": sn.to_string(),
            "peer_id": node_id_hex,
        }))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "No session found for peer".to_string(),
                code: 404,
            }),
        )),
    }
}
