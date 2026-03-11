//! Group management and messaging endpoints.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use mycelium_crypto::group::{SenderKey, SenderKeyGroup};
use mycelium_protocol::types::ContentType;

use crate::state::AppState;
use crate::types::{
    AddGroupMemberRequest, ApiError, CreateGroupResponse, GroupSummary, SendGroupMessageRequest,
    SendMessageResponse,
};
use crate::util::parse_node_id;

/// Helper: parse a hex-encoded 32-byte group ID.
fn parse_group_id(hex_str: &str) -> Result<[u8; 32], (StatusCode, Json<ApiError>)> {
    let bytes = hex::decode(hex_str).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: format!("Invalid hex group ID: {}", hex_str),
                code: 400,
            }),
        )
    })?;

    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: format!(
                    "Group ID must be 32 bytes (64 hex chars), got {}",
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

/// Helper: map a content_type byte to ContentType enum.
fn byte_to_content_type(b: u8) -> ContentType {
    match b {
        1 => ContentType::Image,
        2 => ContentType::File,
        3 => ContentType::GpsPin,
        4 => ContentType::VoiceNote,
        5 => ContentType::Receipt,
        6 => ContentType::System,
        _ => ContentType::Text,
    }
}

/// POST /v1/groups -- Create a new group
pub async fn create_group(
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<CreateGroupResponse>), (StatusCode, Json<ApiError>)> {
    // Generate random 32-byte group_id
    let mut group_id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut group_id);

    let group = SenderKeyGroup::new(group_id);

    // Persist to DB
    state
        .node
        .db
        .save_group_blob(&group_id, &group.to_bytes())
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;

    // Store in node.groups HashMap
    {
        let mut groups = state.node.groups.write().await;
        groups.insert(group_id, group);
    }

    Ok((
        StatusCode::CREATED,
        Json(CreateGroupResponse {
            group_id: hex::encode(group_id),
        }),
    ))
}

/// GET /v1/groups -- List all groups
pub async fn list_groups(
    State(state): State<AppState>,
) -> Result<Json<Vec<GroupSummary>>, (StatusCode, Json<ApiError>)> {
    let groups = state.node.groups.read().await;

    let result: Vec<GroupSummary> = groups
        .iter()
        .map(|(id, group)| GroupSummary {
            group_id: hex::encode(id),
            member_count: group.member_count(),
        })
        .collect();

    Ok(Json(result))
}

/// GET /v1/groups/:group_id/members -- List members of a group
pub async fn list_members(
    State(state): State<AppState>,
    Path(group_id_hex): Path<String>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<ApiError>)> {
    let group_id = parse_group_id(&group_id_hex)?;

    let groups = state.node.groups.read().await;
    let group = groups.get(&group_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "Group not found".to_string(),
                code: 404,
            }),
        )
    })?;

    let members: Vec<String> = group
        .members
        .iter()
        .map(|m| hex::encode(m.as_bytes()))
        .collect();

    Ok(Json(members))
}

/// POST /v1/groups/:group_id/members -- Add a member to a group
pub async fn add_member(
    State(state): State<AppState>,
    Path(group_id_hex): Path<String>,
    Json(req): Json<AddGroupMemberRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let group_id = parse_group_id(&group_id_hex)?;
    let member_node_id = parse_node_id(&req.node_id)?;

    let mut groups = state.node.groups.write().await;
    let group = groups.get_mut(&group_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "Group not found".to_string(),
                code: 404,
            }),
        )
    })?;

    // Generate a sender key for the new member
    let sender_key = SenderKey::generate();
    group.add_member(member_node_id, sender_key);

    // Persist updated group state to DB
    state
        .node
        .db
        .save_group_blob(&group_id, &group.to_bytes())
        .map_err(|e| {
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

/// DELETE /v1/groups/:group_id/members/:member_id -- Remove a member from a group
pub async fn remove_member(
    State(state): State<AppState>,
    Path((group_id_hex, member_id_hex)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let group_id = parse_group_id(&group_id_hex)?;
    let member_node_id = parse_node_id(&member_id_hex)?;

    let mut groups = state.node.groups.write().await;
    let group = groups.get_mut(&group_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "Group not found".to_string(),
                code: 404,
            }),
        )
    })?;

    group.remove_member(&member_node_id);

    // Persist updated group state to DB
    state
        .node
        .db
        .save_group_blob(&group_id, &group.to_bytes())
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

/// POST /v1/groups/:group_id/messages -- Send a group message
pub async fn send_group_message(
    State(state): State<AppState>,
    Path(group_id_hex): Path<String>,
    Json(req): Json<SendGroupMessageRequest>,
) -> Result<(StatusCode, Json<SendMessageResponse>), (StatusCode, Json<ApiError>)> {
    let group_id = parse_group_id(&group_id_hex)?;

    let content_type = byte_to_content_type(req.content_type.unwrap_or(0));

    let message_id = state
        .node
        .send_group_message(group_id, req.data.as_bytes(), content_type)
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
