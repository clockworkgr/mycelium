//! Integration tests for the mycelium-api crate.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use mycelium_api::{build_router, AppState};
use mycelium_crypto::identity::Identity;
use mycelium_node::config::NodeConfig;
use mycelium_node::node::Node;
use mycelium_storage::db::Database;

fn create_test_node() -> Arc<Node> {
    let db = Database::open_in_memory().unwrap();
    let identity = Identity::generate();
    let config = NodeConfig::default();
    Arc::new(Node::new(config, db, identity))
}

#[tokio::test]
async fn test_node_status() {
    let node = create_test_node();
    let state = AppState::new(node);
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/node/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["node_id"].is_string());
    assert!(json["display_name"].is_string());
    assert!(json["uptime_secs"].is_number());
    assert!(json["version"].is_string());
}

#[tokio::test]
async fn test_node_identity() {
    let node = create_test_node();
    let state = AppState::new(node);
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/node/identity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Node ID is 32 bytes = 64 hex chars
    assert_eq!(json["node_id"].as_str().unwrap().len(), 64);
    // Public key is 32 bytes = 64 hex chars
    assert_eq!(json["public_key"].as_str().unwrap().len(), 64);
}

#[tokio::test]
async fn test_list_contacts_empty() {
    let node = create_test_node();
    let state = AppState::new(node);
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/contacts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_list_conversations_empty() {
    let node = create_test_node();
    let state = AppState::new(node);
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/conversations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_unread_count_zero() {
    let node = create_test_node();
    let state = AppState::new(node);
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/conversations/unread")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["total_unread"], 0);
}

#[tokio::test]
async fn test_network_status() {
    let node = create_test_node();
    let state = AppState::new(node);
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/network/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["neighbor_count"], 0);
    assert_eq!(json["is_connected"], false);
    assert_eq!(json["dtn_queue_size"], 0);
}

#[tokio::test]
async fn test_routing_table_empty() {
    let node = create_test_node();
    let state = AppState::new(node);
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/network/routes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_dtn_bundles_empty() {
    let node = create_test_node();
    let state = AppState::new(node);
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/network/dtn")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_send_message_bad_node_id() {
    let node = create_test_node();
    let state = AppState::new(node);
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/messages")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"destination":"not-valid-hex","data":"hello"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_add_and_list_contact() {
    let node = create_test_node();
    let state = AppState::new(node);
    let app = build_router(state.clone());

    // Add a contact
    let add_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/contacts")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"node_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","display_name":"Alice"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(add_response.status(), StatusCode::CREATED);

    // List contacts
    let app = build_router(state);
    let list_response = app
        .oneshot(
            Request::builder()
                .uri("/v1/contacts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(list_response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(list_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let contacts = json.as_array().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0]["display_name"], "Alice");
}

#[tokio::test]
async fn test_404_unknown_route() {
    let node = create_test_node();
    let state = AppState::new(node);
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Renaming a contact over REST must keep the fields that were learned from
/// the mesh (public key, verification, trust, last seen).
#[tokio::test]
async fn test_add_contact_preserves_existing_fields() {
    use mycelium_protocol::types::NodeId;
    use mycelium_storage::contacts::ContactRecord;

    let node = create_test_node();
    let peer = NodeId([0xab; 32]);
    node.db
        .save_contact(&ContactRecord {
            node_id: peer,
            display_name: "Old".to_string(),
            public_key: vec![7u8; 32],
            trust_score: 0.5,
            is_verified: true,
            last_seen: Some(1234),
        })
        .unwrap();

    let state = AppState::new(node.clone());
    let app = build_router(state);
    let body = format!(
        r#"{{"node_id":"{}","display_name":"New"}}"#,
        hex::encode(peer.as_bytes())
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/contacts")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let saved = node.db.get_contact(&peer).unwrap();
    assert_eq!(saved.display_name, "New");
    assert_eq!(saved.public_key, vec![7u8; 32]);
    assert!(saved.is_verified);
    assert_eq!(saved.trust_score, 0.5);
    assert_eq!(saved.last_seen, Some(1234));
}

#[tokio::test]
async fn test_subscribe_unknown_channel_404() {
    let node = create_test_node();
    let state = AppState::new(node);
    let app = build_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/channels/{}/subscribe", "cd".repeat(32)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// With a token configured, every request needs the bearer header.
#[tokio::test]
async fn test_bearer_token_required() {
    let node = create_test_node();
    let state = AppState::new(node).with_auth_token(Some("s3cret".to_string()));

    // No header → 401 with a WWW-Authenticate challenge
    let response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/v1/node/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get("www-authenticate").unwrap(),
        "Bearer"
    );

    // Wrong token → 401
    let response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/v1/node/status")
                .header("authorization", "Bearer nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Right token → 200
    let response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/v1/node/status")
                .header("authorization", "Bearer s3cret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // A token in the query string is only honoured for the WebSocket path
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .uri("/v1/node/status?token=s3cret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A browser page on another origin must not be able to open the event stream.
#[tokio::test]
async fn test_websocket_rejects_foreign_origin() {
    let node = create_test_node();
    let state = AppState::new(node).with_auth_token(Some("s3cret".to_string()));
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .uri("/v1/ws?token=s3cret")
                .header("origin", "https://evil.example")
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// CORS preflight from a loopback page succeeds without a token; a foreign
/// origin gets no allow-origin header.
#[tokio::test]
async fn test_cors_loopback_only() {
    let node = create_test_node();
    let state = AppState::new(node).with_auth_token(Some("s3cret".to_string()));
    let response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/v1/node/status")
                .header("origin", "http://localhost:3000")
                .header("access-control-request-method", "GET")
                .header("access-control-request-headers", "authorization")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "http://localhost:3000"
    );

    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/v1/node/status")
                .header("origin", "https://evil.example")
                .header("access-control-request-method", "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
}
