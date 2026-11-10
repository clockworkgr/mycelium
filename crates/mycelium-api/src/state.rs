//! Shared application state for the API server.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use mycelium_node::node::Node;

use crate::types::{EventEntry, WsServerMessage};

const MAX_EVENT_LOG: usize = 50;

/// Shared state passed to all axum handlers via State extractor.
#[derive(Clone)]
pub struct AppState {
    pub node: Arc<Node>,
    pub started_at: Instant,
    /// Broadcast channel for pushing events to WebSocket clients.
    pub event_tx: broadcast::Sender<WsServerMessage>,
    /// Recent events ring buffer.
    pub event_log: Arc<Mutex<VecDeque<EventEntry>>>,
    /// Cancelled when the API server shuts down; every long-lived task
    /// (event bridge, status broadcaster, WebSocket sessions) exits on it so
    /// nothing keeps the `Node` alive after stop.
    pub shutdown: CancellationToken,
    /// Bearer token required on every request; `None` disables auth (tests).
    pub auth_token: Option<String>,
}

impl AppState {
    pub fn new(node: Arc<Node>) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            node,
            started_at: Instant::now(),
            event_tx,
            event_log: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_EVENT_LOG))),
            shutdown: CancellationToken::new(),
            auth_token: None,
        }
    }

    /// Require this bearer token on every request.
    pub fn with_auth_token(mut self, token: Option<String>) -> Self {
        self.auth_token = token;
        self
    }

    /// Broadcast an event to all connected WebSocket clients.
    pub fn broadcast(&self, msg: WsServerMessage) {
        // Ignore send errors (no subscribers is fine)
        let _ = self.event_tx.send(msg);
    }

    /// Record an event in the ring buffer.
    pub fn record_event(&self, event_type: String, detail: String) {
        if let Ok(mut log) = self.event_log.lock() {
            let ts = self.started_at.elapsed().as_secs();
            if log.len() >= MAX_EVENT_LOG {
                log.pop_front();
            }
            log.push_back(EventEntry {
                uptime_secs: ts,
                event_type,
                detail,
            });
        }
    }
}
