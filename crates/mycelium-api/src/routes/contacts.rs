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
