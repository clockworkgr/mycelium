//! API server setup and startup.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{delete, get, post};
use axum::Router;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::info;

use mycelium_node::config::ApiConfig;
use mycelium_node::node::Node;

use crate::routes::{contacts, conversations, groups, messages, network, node};
use crate::state::AppState;
use crate::ws;

/// Build the axum Router with all API routes.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        // Node
        .route("/v1/node/status", get(node::get_status))
        .route("/v1/node/identity", get(node::get_identity))
        // Messages
        .route("/v1/messages", post(messages::send_message))
        .route("/v1/messages/{peer_id}", get(messages::get_messages))
        .route("/v1/messages/{peer_id}", delete(messages::delete_conversation))
        .route("/v1/messages/{peer_id}/read", post(messages::mark_read))
        // Conversations
        .route("/v1/conversations", get(conversations::list_conversations))
        .route("/v1/conversations/unread", get(conversations::unread_count))
        // Contacts
        .route("/v1/contacts", get(contacts::list_contacts))
        .route("/v1/contacts", post(contacts::add_contact))
        .route("/v1/contacts/{node_id}", delete(contacts::delete_contact))
        // Groups
        .route("/v1/groups", get(groups::list_groups).post(groups::create_group))
        .route("/v1/groups/{group_id}/members", get(groups::list_members).post(groups::add_member))
        .route("/v1/groups/{group_id}/members/{member_id}", delete(groups::remove_member))
        .route("/v1/groups/{group_id}/messages", post(groups::send_group_message))
        // Network diagnostics
        .route("/v1/network/status", get(network::get_status))
        .route("/v1/network/routes", get(network::get_routes))
        .route("/v1/network/dtn", get(network::get_dtn_bundles))
        // WebSocket
        .route("/v1/ws", get(ws::ws_upgrade))
        // Middleware
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Start the API server. Returns a JoinHandle that can be awaited or aborted.
pub async fn start_server(
    node: Arc<Node>,
    config: &ApiConfig,
) -> Result<tokio::task::JoinHandle<()>, std::io::Error> {
    let state = AppState::new(node);
    let app = build_router(state);

    let addr: SocketAddr = format!("{}:{}", config.bind_address, config.port)
        .parse()
        .expect("invalid API bind address");

    let listener = TcpListener::bind(addr).await?;
    info!("API server listening on {}", addr);

    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("API server error: {}", e);
        }
    });

    Ok(handle)
}
