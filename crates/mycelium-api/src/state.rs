//! Shared application state for the API server.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::broadcast;

use mycelium_node::node::Node;

use crate::types::WsServerMessage;

/// Shared state passed to all axum handlers via State extractor.
#[derive(Clone)]
pub struct AppState {
    pub node: Arc<Node>,
    pub started_at: Instant,
    /// Broadcast channel for pushing events to WebSocket clients.
    pub event_tx: broadcast::Sender<WsServerMessage>,
}

impl AppState {
    pub fn new(node: Arc<Node>) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            node,
            started_at: Instant::now(),
            event_tx,
        }
    }

    /// Broadcast an event to all connected WebSocket clients.
    pub fn broadcast(&self, msg: WsServerMessage) {
        // Ignore send errors (no subscribers is fine)
        let _ = self.event_tx.send(msg);
    }
}
