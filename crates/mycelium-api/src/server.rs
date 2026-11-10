//! API server setup and startup.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::HeaderValue;
use axum::routing::{delete, get, post};
use axum::{middleware, Router};
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tracing::{debug, info, warn};

/// Bind a TCP listener with SO_REUSEADDR to allow quick rebinding.
async fn bind_reuseaddr(addr: SocketAddr) -> Result<TcpListener, std::io::Error> {
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(128)
}

/// Handle to a running API server. Dropping it does not stop the server;
/// call [`shutdown`](Self::shutdown).
pub struct ApiServerHandle {
    task: tokio::task::JoinHandle<()>,
    shutdown: tokio_util::sync::CancellationToken,
}

impl ApiServerHandle {
    /// Stop the listener, the event bridge, the status broadcaster and every
    /// WebSocket session. Returns once the cancellation has been signalled;
    /// the serve task is aborted so no lingering connection can keep it alive.
    pub fn shutdown(self) {
        self.shutdown.cancel();
        self.task.abort();
    }

    /// Whether the serve task has exited.
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

use mycelium_node::config::ApiConfig;
use mycelium_node::events::NodeEvent;
use mycelium_node::node::Node;

use crate::auth;
use crate::routes::{
    channels, contacts, conversations, emergency, groups, messages, network, node, prekeys,
};
use crate::state::AppState;
use crate::types::WsServerMessage;
use crate::ws;

/// Build the axum Router with all API routes.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        // Node
        .route("/v1/node/status", get(node::get_status))
        .route("/v1/node/identity", get(node::get_identity))
        .route("/v1/node/trust", get(node::get_trust_stats))
        // Messages
        .route("/v1/messages", post(messages::send_message))
        .route("/v1/messages/{peer_id}", get(messages::get_messages))
        .route(
            "/v1/messages/{peer_id}",
            delete(messages::delete_conversation),
        )
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
        .route(
            "/v1/contacts/{node_id}/verify",
            post(contacts::verify_session),
        )
        .route(
            "/v1/contacts/{node_id}/safety-number",
            get(contacts::get_safety_number),
        )
        // Groups
        .route(
            "/v1/groups",
            get(groups::list_groups).post(groups::create_group),
        )
        .route(
            "/v1/groups/{group_id}/members",
            get(groups::list_members).post(groups::add_member),
        )
        .route(
            "/v1/groups/{group_id}/members/{member_id}",
            delete(groups::remove_member),
        )
        .route(
            "/v1/groups/{group_id}/messages",
            post(groups::send_group_message),
        )
        // Channels
        .route(
            "/v1/channels",
            get(channels::list_channels).post(channels::create_channel),
        )
        .route(
            "/v1/channels/{channel_id}/subscribe",
            post(channels::subscribe).delete(channels::unsubscribe),
        )
        .route(
            "/v1/channels/{channel_id}/messages",
            get(channels::get_messages).post(channels::post_message),
        )
        // Prekeys
        .route("/v1/prekeys/{node_id}", get(prekeys::get_cached_bundle))
        // Emergency
        .route("/v1/emergency/broadcast", post(emergency::broadcast))
        .route("/v1/emergency/history", get(emergency::history))
        // Network diagnostics
        .route("/v1/network/status", get(network::get_status))
        .route("/v1/network/routes", get(network::get_routes))
        .route("/v1/network/dtn", get(network::get_dtn_bundles))
        .route("/v1/network/transports", get(network::get_transports))
        .route("/v1/network/peers", get(network::get_peers))
        .route("/v1/network/pending", get(network::get_pending))
        .route("/v1/network/events", get(network::get_events))
        // WebSocket
        .route("/v1/ws", get(ws::ws_upgrade))
        // Middleware: bearer token + WebSocket origin check (inner), then
        // CORS restricted to loopback browser origins (outer, so preflight
        // requests are answered without a token).
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ))
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _| {
                    auth::is_loopback_origin(origin.to_str().unwrap_or(""))
                }))
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state)
}

/// Start the API server. Returns a handle used to stop it again.
pub async fn start_server(
    node: Arc<Node>,
    config: &ApiConfig,
) -> Result<ApiServerHandle, std::io::Error> {
    let state = AppState::new(node.clone()).with_auth_token(config.auth_token.clone());
    if config.auth_token.is_none() {
        warn!("API server starting WITHOUT authentication");
    }
    let shutdown = state.shutdown.clone();

    // Spawn bridge task: NodeEvent → WsServerMessage
    let ws_tx = state.event_tx.clone();
    let bridge_log = state.event_log.clone();
    let bridge_start = state.started_at;
    let bridge_cancel = shutdown.clone();
    let mut node_rx = node.event_tx.subscribe();
    tokio::spawn(async move {
        loop {
            let received = tokio::select! {
                _ = bridge_cancel.cancelled() => break,
                r = node_rx.recv() => r,
            };
            match received {
                Ok(event) => {
                    let (evt_type, detail) = event_summary(&event);
                    if let Ok(mut log) = bridge_log.lock() {
                        if log.len() >= 50 {
                            log.pop_front();
                        }
                        log.push_back(crate::types::EventEntry {
                            uptime_secs: bridge_start.elapsed().as_secs(),
                            event_type: evt_type,
                            detail,
                        });
                    }
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
    let net_cancel = shutdown.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = net_cancel.cancelled() => break,
                _ = interval.tick() => {}
            }
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

    let addr: SocketAddr = format!("{}:{}", config.bind_address, config.port)
        .parse()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "invalid API bind address {}:{}: {}",
                    config.bind_address, config.port, e
                ),
            )
        })?;

    let listener = bind_reuseaddr(addr).await?;
    info!("API server listening on {}", addr);

    let serve_cancel = shutdown.clone();
    let task = tokio::spawn(async move {
        let app = build_router(state);
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(async move { serve_cancel.cancelled().await })
            .await;
        match result {
            Ok(()) => debug!("API server on {} stopped", addr),
            Err(e) => tracing::error!("API server error: {}", e),
        }
    });

    Ok(ApiServerHandle { task, shutdown })
}

/// Produce a short (event_type, detail) pair for the event log ring buffer.
fn event_summary(event: &NodeEvent) -> (String, String) {
    match event {
        NodeEvent::MessageReceived { source, .. } => (
            "message_received".to_string(),
            format!("from {}", &hex::encode(source.as_bytes())[..16]),
        ),
        NodeEvent::ReceiptUpdated {
            message_id, status, ..
        } => (
            "receipt".to_string(),
            format!("{} {}", status, &message_id.to_string()[..8]),
        ),
        NodeEvent::PeerDiscovered {
            peer_id, transport, ..
        } => (
            "peer_discovered".to_string(),
            format!(
                "{} via {}",
                &hex::encode(peer_id.as_bytes())[..16],
                transport
            ),
        ),
        NodeEvent::PeerLost {
            peer_id, transport, ..
        } => (
            "peer_lost".to_string(),
            format!(
                "{} via {}",
                &hex::encode(peer_id.as_bytes())[..16],
                transport
            ),
        ),
        NodeEvent::EmergencyBroadcast { source, level, .. } => (
            "emergency".to_string(),
            format!(
                "level {} from {}",
                level,
                &hex::encode(source.as_bytes())[..16]
            ),
        ),
    }
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
        NodeEvent::PeerDiscovered { peer_id, transport } => Some(WsServerMessage::PeerEvent {
            event: "discovered".to_string(),
            peer_id: hex::encode(peer_id.as_bytes()),
            transport,
        }),
        NodeEvent::PeerLost { peer_id, transport } => Some(WsServerMessage::PeerEvent {
            event: "lost".to_string(),
            peer_id: hex::encode(peer_id.as_bytes()),
            transport,
        }),
        NodeEvent::EmergencyBroadcast {
            source,
            level,
            message,
        } => Some(WsServerMessage::EmergencyBroadcast {
            source: hex::encode(source.as_bytes()),
            level,
            message,
        }),
    }
}
