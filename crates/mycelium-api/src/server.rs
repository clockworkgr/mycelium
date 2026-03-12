//! API server setup and startup.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::routing::{delete, get, post};
use axum::Router;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{debug, info, warn};

use mycelium_node::config::ApiConfig;
use mycelium_node::events::NodeEvent;
use mycelium_node::node::Node;

use crate::routes::{contacts, conversations, groups, messages, network, node};
use crate::state::AppState;
use crate::types::WsServerMessage;
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
        .route("/v1/contacts/{node_id}/trust", get(contacts::get_trust))
        .route("/v1/contacts/{node_id}/vouch", post(contacts::add_vouch))
        .route("/v1/contacts/{node_id}/verify", post(contacts::verify_session))
        .route("/v1/contacts/{node_id}/safety-number", get(contacts::get_safety_number))
        // Groups
        .route("/v1/groups", get(groups::list_groups).post(groups::create_group))
        .route("/v1/groups/{group_id}/members", get(groups::list_members).post(groups::add_member))
        .route("/v1/groups/{group_id}/members/{member_id}", delete(groups::remove_member))
        .route("/v1/groups/{group_id}/messages", post(groups::send_group_message))
        // Network diagnostics
        .route("/v1/network/status", get(network::get_status))
        .route("/v1/network/routes", get(network::get_routes))
        .route("/v1/network/dtn", get(network::get_dtn_bundles))
        .route("/v1/network/transports", get(network::get_transports))
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
    let state = AppState::new(node.clone());

    // Spawn bridge task: NodeEvent → WsServerMessage
    let ws_tx = state.event_tx.clone();
    let mut node_rx = node.event_tx.subscribe();
    tokio::spawn(async move {
        loop {
            match node_rx.recv().await {
                Ok(event) => {
                    if let Some(ws_msg) = convert_node_event(event) {
                        let _ = ws_tx.send(ws_msg);
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!("Event bridge lagged, dropped {} events", n);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    debug!("Node event channel closed, stopping bridge");
                    break;
                }
            }
        }
    });

    // Spawn periodic NetworkEvent broadcast (every 5 seconds)
    let net_tx = state.event_tx.clone();
    let net_node = node.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            let routing = net_node.routing.read().await;
            let now = Instant::now();
            let neighbor_count = routing
                .aodv()
                .routes()
                .values()
                .filter(|r| r.is_valid && r.hop_count == 1 && r.lifetime > now)
                .count();
            let dtn_queue_size = routing.dtn().bundle_count();
            drop(routing);
            let _ = net_tx.send(WsServerMessage::NetworkEvent {
                neighbor_count,
                is_connected: neighbor_count > 0,
                dtn_queue_size,
            });
        }
    });

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

/// Convert a NodeEvent into a WsServerMessage for WebSocket broadcast.
fn convert_node_event(event: NodeEvent) -> Option<WsServerMessage> {
    match event {
        NodeEvent::MessageReceived {
            source,
            message_id,
            data,
            content_type,
            timestamp,
        } => {
            let ct_str = match content_type {
                0 => "text",
                1 => "image",
                2 => "file",
                3 => "gps_pin",
                4 => "voice_note",
                _ => "unknown",
            };
            Some(WsServerMessage::IncomingMessage {
                source: hex::encode(source.as_bytes()),
                message_id: message_id.to_string(),
                data: String::from_utf8_lossy(&data).to_string(),
                protocol_id: "mycelium.chat.v1".to_string(),
                content_type: ct_str.to_string(),
                timestamp,
            })
        }
        NodeEvent::ReceiptUpdated { message_id, status } => {
            Some(WsServerMessage::DeliveryReceipt {
                message_id: message_id.to_string(),
                status,
            })
        }
        NodeEvent::PeerDiscovered { peer_id, transport } => {
            Some(WsServerMessage::PeerEvent {
                event: "discovered".to_string(),
                peer_id: hex::encode(peer_id.as_bytes()),
                transport,
            })
        }
        NodeEvent::PeerLost { peer_id, transport } => {
            Some(WsServerMessage::PeerEvent {
                event: "lost".to_string(),
                peer_id: hex::encode(peer_id.as_bytes()),
                transport,
            })
        }
    }
}
