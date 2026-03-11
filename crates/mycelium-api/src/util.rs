//! Shared utilities for the API.

use axum::http::StatusCode;
use axum::Json;

use mycelium_protocol::types::NodeId;

use crate::types::ApiError;

/// Parse a hex-encoded 32-byte NodeId from a string.
pub fn parse_node_id(hex_str: &str) -> Result<NodeId, (StatusCode, Json<ApiError>)> {
    let bytes = hex::decode(hex_str).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: format!("Invalid hex node ID: {}", hex_str),
                code: 400,
            }),
        )
    })?;

    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: format!("Node ID must be 32 bytes (64 hex chars), got {}", bytes.len()),
                code: 400,
            }),
        ));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(NodeId::from_bytes(arr))
}
