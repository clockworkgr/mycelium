//! Bearer-token authentication and browser-origin checks for the local API.
//!
//! The API exposes decrypted message history and can send messages, so it
//! must not be reachable by any process or web page that happens to find the
//! port. Every node generates a random token on first start and stores it at
//! `<data_dir>/api.token` (owner-readable only); clients present it as
//! `Authorization: Bearer <token>` (REST and WebSocket) or `?token=<token>`
//! (WebSocket, for clients that cannot set headers).

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use tracing::debug;

use crate::state::AppState;
use crate::types::ApiError;

/// File name of the token inside the node's data directory.
pub const TOKEN_FILE_NAME: &str = "api.token";

/// Load the API token from `<data_dir>/api.token`, creating a fresh random
/// one (32 bytes, hex) if the file is missing or empty.
pub fn load_or_create_api_token(data_dir: &str) -> std::io::Result<String> {
    let path = std::path::Path::new(data_dir).join(TOKEN_FILE_NAME);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let token = hex::encode(rand::random::<[u8; 32]>());
    write_private_file(&path, token.as_bytes())?;
    Ok(token)
}

/// Write a file readable only by its owner (0600 on Unix).
pub fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

/// Constant-time byte comparison so a token cannot be guessed byte by byte
/// from response timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether an `Origin` header value names this machine (a browser page
/// served from localhost). Native clients send no Origin at all.
pub fn is_loopback_origin(origin: &str) -> bool {
    let rest = match origin.split_once("://") {
        Some((_, rest)) => rest,
        None => return origin == "null",
    };
    let host_port = rest.split('/').next().unwrap_or("");
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn token_from_query(query: Option<&str>) -> Option<String> {
    query?
        .split('&')
        .find_map(|kv| kv.strip_prefix("token=").map(|v| v.to_string()))
}

fn unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))],
        Json(ApiError {
            error: msg.to_string(),
            code: 401,
        }),
    )
        .into_response()
}

/// axum middleware: require the configured bearer token (when one is set)
/// and, for WebSocket upgrades, refuse browser origins other than loopback.
pub async fn require_auth(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let is_ws = req.uri().path() == "/v1/ws";

    // WebSockets are exempt from CORS in browsers, so a foreign page could
    // otherwise open a live event stream. Origin is only sent by browsers.
    if is_ws {
        if let Some(origin) = req.headers().get(header::ORIGIN) {
            let origin = origin.to_str().unwrap_or("");
            if !is_loopback_origin(origin) {
                debug!("Rejecting WebSocket upgrade from origin {}", origin);
                return (
                    StatusCode::FORBIDDEN,
                    Json(ApiError {
                        error: "websocket connections are only accepted from loopback origins"
                            .to_string(),
                        code: 403,
                    }),
                )
                    .into_response();
            }
        }
    }

    let Some(expected) = state.auth_token.as_deref() else {
        return next.run(req).await;
    };

    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string())
        .or_else(|| {
            if is_ws {
                token_from_query(req.uri().query())
            } else {
                None
            }
        });

    match presented {
        Some(token) if constant_time_eq(token.as_bytes(), expected.as_bytes()) => {
            next.run(req).await
        }
        Some(_) => unauthorized("invalid bearer token"),
        None => unauthorized("missing bearer token (Authorization: Bearer <token>)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_origins() {
        assert!(is_loopback_origin("http://localhost:3000"));
        assert!(is_loopback_origin("http://127.0.0.1"));
        assert!(is_loopback_origin("http://[::1]:8080/path"));
        assert!(is_loopback_origin("null"));
        assert!(!is_loopback_origin("https://evil.example"));
        assert!(!is_loopback_origin("http://127.0.0.1.evil.example"));
        assert!(!is_loopback_origin("http://localhost.evil.example"));
    }

    #[test]
    fn token_query_parsing() {
        assert_eq!(token_from_query(Some("token=abc")), Some("abc".to_string()));
        assert_eq!(
            token_from_query(Some("x=1&token=abc&y=2")),
            Some("abc".to_string())
        );
        assert_eq!(token_from_query(Some("x=1")), None);
        assert_eq!(token_from_query(None), None);
    }

    #[test]
    fn token_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "mycelium-token-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.to_string_lossy().into_owned();
        let t1 = load_or_create_api_token(&d).unwrap();
        let t2 = load_or_create_api_token(&d).unwrap();
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 64);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
