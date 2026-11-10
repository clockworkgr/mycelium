//! WebSocket handler for real-time event streaming.

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::state::AppState;
use crate::types::{WsClientMessage, WsServerMessage};
use crate::util::{parse_content_type, parse_node_id};

/// GET /v1/ws — WebSocket upgrade handler
pub async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: AppState) {
    debug!("WebSocket client connected");

    let mut event_rx = state.event_tx.subscribe();
    let mut subscribed_protocols: Vec<String> = Vec::new();

    loop {
        tokio::select! {
            // Server shutting down: close the session so it does not outlive
            // the node.
            _ = state.shutdown.cancelled() => {
                let _ = socket.send(Message::Close(None)).await;
                return;
            }

            // Receive messages from the client
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<WsClientMessage>(&text) {
                            Ok(WsClientMessage::Subscribe { protocol_ids }) => {
                                debug!("Client subscribed to protocols: {:?}", protocol_ids);
                                subscribed_protocols = protocol_ids;
                            }
                            Ok(WsClientMessage::SendData {
                                destination,
                                data,
                                protocol_id: _,
                                content_type,
                            }) => {
                                // Tell this client what happened to its send:
                                // the message id on success, the error otherwise.
                                let result = match parse_node_id(&destination) {
                                    Ok(dest) => state
                                        .node
                                        .send_message(dest, data.as_bytes(), parse_content_type(&content_type))
                                        .await
                                        .map(|id| hex::encode(id.as_bytes()))
                                        .map_err(|e| e.to_string()),
                                    Err((_, err)) => Err(err.error.clone()),
                                };
                                if let Err(e) = &result {
                                    warn!("WebSocket send_message failed: {}", e);
                                }
                                let frame = WsServerMessage::SendResult {
                                    destination,
                                    message_id: result.as_ref().ok().cloned(),
                                    error: result.err(),
                                };
                                if let Ok(json) = serde_json::to_string(&frame) {
                                    if socket.send(Message::Text(json.into())).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("WebSocket: invalid JSON message: {}", e);
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        debug!("WebSocket client disconnected");
                        return;
                    }
                    Some(Ok(_)) => {
                        // Ignore binary, ping, pong
                    }
                    Some(Err(e)) => {
                        warn!("WebSocket error: {}", e);
                        return;
                    }
                }
            }

            // Forward broadcast events to this client
            event = event_rx.recv() => {
                match event {
                    Ok(msg) => {
                        // Filter by subscribed protocols if any are set
                        if should_send(&msg, &subscribed_protocols) {
                            if let Ok(json) = serde_json::to_string(&msg) {
                                if socket.send(Message::Text(json.into())).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("WebSocket client lagged, dropped {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return;
                    }
                }
            }
        }
    }
}

/// Check if a server message should be sent to a client based on protocol filter.
fn should_send(msg: &WsServerMessage, subscribed: &[String]) -> bool {
    if subscribed.is_empty() {
        return true; // No filter = receive everything
    }

    match msg {
        WsServerMessage::IncomingMessage { protocol_id, .. } => {
            subscribed.iter().any(|p| p == protocol_id)
        }
        // Non-message events are always sent
        _ => true,
    }
}
