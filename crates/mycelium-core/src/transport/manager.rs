use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio_util::sync::CancellationToken;
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
    /// Cancels the event-forwarder tasks spawned since the last start().
    forwarder_cancel: RwLock<CancellationToken>,
}

/// Static preference used to break ties between transports whose measured
/// link quality is equal (which is the common case, since few transports
/// report quality changes). Higher is better.
fn static_priority(t: TransportType) -> u8 {
    match t {
        TransportType::WifiDirect => 6,
        TransportType::WifiAware => 5,
        TransportType::BtClassic => 4,
        TransportType::InternetTunnel => 3,
        TransportType::Ble => 2,
        // Foreign-protocol bridges rank with the radio they ride on: both are
        // low-bandwidth LoRa-class links, and a message that can go over a
        // native transport should.
        TransportType::Reticulum => 2,
        TransportType::Lora => 1,
        TransportType::Meshtastic => 1,
        TransportType::Mock => 0,
    }
}

impl TransportManager {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1024);
        Self {
            transports: RwLock::new(Vec::new()),
            peer_transports: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            started: RwLock::new(false),
            forwarder_cancel: RwLock::new(CancellationToken::new()),
        }
    }

    /// Register a transport. If start() was already called, starts the transport
    /// and spawns an event forwarder immediately so late-added transports (like BLE) work.
    pub async fn add_transport(&self, transport: Arc<dyn Transport>) {
        let already_started = *self.started.read().await;
        if already_started {
            match transport.start().await {
                Ok(()) | Err(TransportError::AlreadyStarted) => {}
                Err(e) => warn!("Failed to start late-added transport: {}", e),
            }
            let cancel = self.forwarder_cancel.read().await.clone();
            self.spawn_event_forwarder(&transport, cancel);
        }
        let mut transports = self.transports.write().await;
        transports.push(transport);
    }

    /// Replace any existing transport of the same type (removing stale entries),
    /// then register the new one. Used when the app restarts and needs a fresh
    /// BLE transport while the old one's outbox is orphaned.
    pub async fn replace_transport(&self, transport: Arc<dyn Transport>) {
        let transport_type = transport.transport_type();

        // Remove old transports of the same type
        {
            let mut transports = self.transports.write().await;
            transports.retain(|t| t.transport_type() != transport_type);
        }

        // Clear stale peer entries for this transport type
        {
            let mut pt = self.peer_transports.write().await;
            for infos in pt.values_mut() {
                infos.retain(|i| i.transport_type != transport_type);
            }
            pt.retain(|_, infos| !infos.is_empty());
        }

        self.add_transport(transport).await;
    }

    /// Start all transports and begin forwarding events.
    ///
    /// Idempotent: a second call is a no-op, and transports that are already
    /// running are left alone. Forwarders spawned here (and by later
    /// `add_transport` calls) live until `stop()`.
    pub async fn start(&self) -> Result<(), TransportError> {
        if *self.started.read().await {
            return Ok(());
        }
        let cancel = CancellationToken::new();
        *self.forwarder_cancel.write().await = cancel.clone();

        let transports = self.transports.read().await;
        for t in transports.iter() {
            match t.start().await {
                Ok(()) | Err(TransportError::AlreadyStarted) => {}
                Err(e) => return Err(e),
            }
        }
        // Spawn event forwarders for each transport
        for t in transports.iter() {
            self.spawn_event_forwarder(t, cancel.clone());
        }
        *self.started.write().await = true;
        Ok(())
    }

    /// Spawn a task that forwards events from a transport into the unified
    /// event channel and updates per-peer transport tracking.
    fn spawn_event_forwarder(&self, transport: &Arc<dyn Transport>, cancel: CancellationToken) {
        let mut rx = transport.events();
        let event_tx = self.event_tx.clone();
        let peer_transports = self.peer_transports.clone();
        let transport_type = transport.transport_type();
        let transport = transport.clone();

        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = cancel.cancelled() => break,
                    r = rx.recv() => match r {
                        Ok(event) => event,
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            // Never exit on lag: the transport would go
                            // permanently deaf. Peers dropped here are
                            // re-learned from later events.
                            warn!("{} event forwarder lagged, dropped {} events", transport_type, n);
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                };
                match &event {
                    TransportEvent::NeighborDiscovered { peer, .. } => {
                        let mut pt = peer_transports.write().await;
                        let infos = pt.entry(*peer).or_default();
                        if !infos.iter().any(|i| i.transport_type == transport_type) {
                            // Seed from the transport's own measurement when it
                            // has one, so selection is not purely by arrival order.
                            let quality = transport.link_quality(peer).unwrap_or(LinkQuality {
                                rssi: None,
                                throughput_bps: 1_000_000,
                                packet_loss: 0.0,
                                latency_ms: 50,
                            });
                            infos.push(PeerTransportInfo {
                                transport_type,
                                quality,
                            });
                        }
                    }
                    TransportEvent::NeighborLost { peer, transport } => {
                        let mut pt = peer_transports.write().await;
                        if let Some(infos) = pt.get_mut(peer) {
                            infos.retain(|i| i.transport_type != *transport);
                            if infos.is_empty() {
                                pt.remove(peer);
                            }
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

    /// Stop all transports and their event forwarders.
    ///
    /// Every transport is asked to stop even if an earlier one fails; the
    /// first real error is returned. `NotStarted` is not an error here.
    pub async fn stop(&self) -> Result<(), TransportError> {
        self.forwarder_cancel.read().await.cancel();
        let mut first_err = None;
        let transports = self.transports.read().await;
        for t in transports.iter() {
            match t.stop().await {
                Ok(()) | Err(TransportError::NotStarted) => {}
                Err(e) => {
                    warn!("Failed to stop {} transport: {}", t.transport_type(), e);
                    first_err.get_or_insert(e);
                }
            }
        }
        *self.started.write().await = false;
        self.peer_transports.write().await.clear();
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
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

    /// Broadcast on every transport that supports it (see
    /// [`Transport::supports_broadcast`]). Returns how many transports
    /// accepted the data. Failures are logged, not returned: a broadcast is
    /// best effort by nature.
    pub async fn broadcast(&self, data: &[u8]) -> usize {
        let transports = self.transports.read().await;
        let mut accepted = 0;
        for t in transports.iter().filter(|t| t.supports_broadcast()) {
            match t.send(&NodeId::ZERO, data).await {
                Ok(()) => accepted += 1,
                Err(e) => debug!("Broadcast via {} failed: {}", t.transport_type(), e),
            }
        }
        accepted
    }

    /// Subscribe to unified transport events.
    pub fn events(&self) -> broadcast::Receiver<TransportEvent> {
        self.event_tx.subscribe()
    }

    /// Select the best transport for a peer based on link quality scores.
    async fn select_transport(&self, peer: &NodeId) -> Option<TransportType> {
        let pt = self.peer_transports.read().await;
        pt.get(peer).and_then(|infos| {
            infos
                .iter()
                .max_by(|a, b| {
                    a.quality
                        .score()
                        .partial_cmp(&b.quality.score())
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| {
                            static_priority(a.transport_type)
                                .cmp(&static_priority(b.transport_type))
                        })
                })
                .map(|info| info.transport_type)
        })
    }

    /// Get all known peers across all transports.
    pub async fn known_peers(&self) -> Vec<NodeId> {
        let pt = self.peer_transports.read().await;
        pt.keys().copied().collect()
    }

    /// The smallest MTU among the registered transports, or `None` when none
    /// are registered.
    ///
    /// What a *flooded* message must fit: it goes to every peer, so the
    /// narrowest link decides. A sender that ignores this floods the subset of
    /// the mesh whose links are wide enough and stops silently at the rest —
    /// on BLE, which refuses an oversized message outright, that means every
    /// phone (ROADMAP T-39).
    pub async fn min_mtu(&self) -> Option<usize> {
        let transports = self.transports.read().await;
        transports.iter().map(|t| t.mtu()).min()
    }
}

impl Default for TransportManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    /// A flooded message must fit the narrowest link, so the manager reports
    /// that rather than the widest or the preferred one. BLE's 512 bytes is
    /// what an emergency alert is measured against on a phone (ROADMAP T-39).
    #[tokio::test]
    async fn test_min_mtu_is_the_narrowest_registered_transport() {
        use super::*;
        use crate::transport::ble::BleTransport;
        use crate::transport::mock::{MockNetwork, MockTransport};

        let local = NodeId([1u8; 32]);
        let manager = TransportManager::new();
        assert_eq!(manager.min_mtu().await, None, "no transports, no limit");

        let mock = Arc::new(MockTransport::new(local, MockNetwork::new()).await);
        let mock_mtu = mock.mtu();
        manager.add_transport(mock).await;
        assert_eq!(manager.min_mtu().await, Some(mock_mtu));

        let ble = Arc::new(BleTransport::new(local));
        let ble_mtu = ble.mtu();
        manager.add_transport(ble).await;
        assert!(ble_mtu < mock_mtu, "BLE is the narrow one here");
        assert_eq!(
            manager.min_mtu().await,
            Some(ble_mtu),
            "the narrowest transport decides what a flood may be"
        );
    }

    use super::*;
    use crate::transport::mock::{MockLinkConfig, MockNetwork, MockTransport};

    async fn wait_until(manager: &TransportManager, predicate: impl Fn(&[NodeId]) -> bool) {
        for _ in 0..100 {
            if predicate(&manager.known_peers().await) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("condition not met in time");
    }

    #[tokio::test]
    async fn test_known_peers_forget_lost_peers() {
        let a = NodeId([1u8; 32]);
        let b = NodeId([2u8; 32]);
        let network = MockNetwork::new();
        let ta = Arc::new(MockTransport::new(a, network.clone()).await);
        let _tb = Arc::new(MockTransport::new(b, network.clone()).await);

        let manager = TransportManager::new();
        manager.add_transport(ta.clone()).await;
        manager.start().await.unwrap();
        // Idempotent restart must not fail or duplicate anything.
        manager.start().await.unwrap();

        network.add_link(a, b, MockLinkConfig::default()).await;
        wait_until(&manager, |peers| peers.contains(&b)).await;
        // Re-discovery must not duplicate the peer entry.
        network.add_link(a, b, MockLinkConfig::default()).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(manager.known_peers().await.len(), 1);

        network.remove_link(&a, &b).await;
        wait_until(&manager, |peers| peers.is_empty()).await;

        // stop() then start() must not leave a stale forwarder or started flag.
        manager.stop().await.unwrap();
        manager.stop().await.unwrap();
        manager.start().await.unwrap();
        manager.stop().await.unwrap();
    }
}
