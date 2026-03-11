use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, warn};

use mycelium_protocol::types::{LinkQuality, NodeId};

use super::{Transport, TransportError, TransportEvent, TransportType};

/// Per-peer transport scoring info.
#[derive(Debug, Clone)]
struct PeerTransportInfo {
    transport_type: TransportType,
    quality: LinkQuality,
}

/// Manages multiple transports, selects the best one per peer, provides unified send.
pub struct TransportManager {
    transports: RwLock<Vec<Arc<dyn Transport>>>,
    /// Best known transport per peer
    peer_transports: Arc<RwLock<HashMap<NodeId, Vec<PeerTransportInfo>>>>,
    /// Unified event channel
    event_tx: broadcast::Sender<TransportEvent>,
    /// Whether start() has been called (late-added transports need event forwarding)
    started: RwLock<bool>,
}

impl TransportManager {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1024);
        Self {
            transports: RwLock::new(Vec::new()),
            peer_transports: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            started: RwLock::new(false),
        }
    }

    /// Register a transport. If start() was already called, starts the transport
    /// and spawns an event forwarder immediately so late-added transports (like BLE) work.
    pub async fn add_transport(&self, transport: Arc<dyn Transport>) {
        let already_started = *self.started.read().await;
        if already_started {
            if let Err(e) = transport.start().await {
                warn!("Failed to start late-added transport: {}", e);
            }
            self.spawn_event_forwarder(&transport);
        }
        let mut transports = self.transports.write().await;
        transports.push(transport);
    }

    /// Start all transports and begin forwarding events.
    pub async fn start(&self) -> Result<(), TransportError> {
        let transports = self.transports.read().await;
        for t in transports.iter() {
            t.start().await?;
        }
        // Spawn event forwarders for each transport
        for t in transports.iter() {
            self.spawn_event_forwarder(t);
        }
        *self.started.write().await = true;
        Ok(())
    }

    /// Spawn a task that forwards events from a transport into the unified
    /// event channel and updates per-peer transport tracking.
    fn spawn_event_forwarder(&self, transport: &Arc<dyn Transport>) {
        let mut rx = transport.events();
        let event_tx = self.event_tx.clone();
        let peer_transports = self.peer_transports.clone();
        let transport_type = transport.transport_type();

        tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                match &event {
                    TransportEvent::NeighborDiscovered { peer, .. } => {
                        let mut pt = peer_transports.write().await;
                        let info = PeerTransportInfo {
                            transport_type,
                            quality: LinkQuality {
                                rssi: None,
                                throughput_bps: 1_000_000,
                                packet_loss: 0.0,
                                latency_ms: 50,
                            },
                        };
                        pt.entry(*peer).or_default().push(info);
                    }
                    TransportEvent::NeighborLost { peer, transport } => {
                        let mut pt = peer_transports.write().await;
                        if let Some(infos) = pt.get_mut(peer) {
                            infos.retain(|i| i.transport_type != *transport);
                        }
                    }
                    TransportEvent::LinkQualityChanged {
                        peer,
                        quality,
                        transport,
                    } => {
                        let mut pt = peer_transports.write().await;
                        if let Some(infos) = pt.get_mut(peer) {
                            for info in infos.iter_mut() {
                                if info.transport_type == *transport {
                                    info.quality = *quality;
                                }
                            }
                        }
                    }
                    _ => {}
                }
                let _ = event_tx.send(event);
            }
        });
    }

    /// Stop all transports.
    pub async fn stop(&self) -> Result<(), TransportError> {
        let transports = self.transports.read().await;
        for t in transports.iter() {
            t.stop().await?;
        }
        Ok(())
    }

    /// Send data to a peer, selecting the best available transport.
    pub async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError> {
        let best = self.select_transport(peer).await;

        if let Some(transport_type) = best {
            let transports = self.transports.read().await;
            for t in transports.iter() {
                if t.transport_type() == transport_type {
                    match t.send(peer, data).await {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            warn!("Transport {} failed for {}: {}", transport_type, peer, e);
                        }
                    }
                }
            }
        }

        // Fallback: try all transports
        let transports = self.transports.read().await;
        for t in transports.iter() {
            match t.send(peer, data).await {
                Ok(()) => {
                    debug!("Fallback send via {} to {}", t.transport_type(), peer);
                    return Ok(());
                }
                Err(_) => continue,
            }
        }

        Err(TransportError::PeerNotConnected(*peer))
    }

    /// Subscribe to unified transport events.
    pub fn events(&self) -> broadcast::Receiver<TransportEvent> {
        self.event_tx.subscribe()
    }

    /// Select the best transport for a peer based on link quality scores.
    async fn select_transport(&self, peer: &NodeId) -> Option<TransportType> {
        let pt = self.peer_transports.read().await;
        pt.get(peer)
            .and_then(|infos| {
                infos
                    .iter()
                    .max_by(|a, b| {
                        a.quality
                            .score()
                            .partial_cmp(&b.quality.score())
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|info| info.transport_type)
            })
    }

    /// Get all known peers across all transports.
    pub async fn known_peers(&self) -> Vec<NodeId> {
        let pt = self.peer_transports.read().await;
        pt.keys().copied().collect()
    }
}

impl Default for TransportManager {
    fn default() -> Self {
        Self::new()
    }
}
