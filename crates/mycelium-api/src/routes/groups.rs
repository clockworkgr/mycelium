//! Group management and messaging endpoints.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

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
    let group_id = state.node.create_group().await.map_err(|e| {
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

    // The node adds the member and distributes sender keys over the
    // pairwise sessions (establishing them if needed).
    state
        .node
        .add_group_member(group_id, member_node_id)
        .await
        .map_err(group_error)?;

    Ok(StatusCode::CREATED)
}

/// DELETE /v1/groups/:group_id/members/:member_id -- Remove a member from a group
pub async fn remove_member(
    State(state): State<AppState>,
    Path((group_id_hex, member_id_hex)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let group_id = parse_group_id(&group_id_hex)?;
    let member_node_id = parse_node_id(&member_id_hex)?;

    // Rotates our sender key and redistributes it with the new roster.
    state
        .node
        .remove_group_member(group_id, member_node_id)
        .await
        .map_err(group_error)?;

    Ok(StatusCode::NO_CONTENT)
}

fn group_error(e: mycelium_node::node::NodeError) -> (StatusCode, Json<ApiError>) {
    let (status, code) = match e {
        mycelium_node::node::NodeError::GroupNotFound => (StatusCode::NOT_FOUND, 404),
        mycelium_node::node::NodeError::SendToSelf => (StatusCode::BAD_REQUEST, 400),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, 500),
    };
    (
        status,
        Json(ApiError {
            error: e.to_string(),
            code,
        }),
    )
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
