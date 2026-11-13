//! Bluetooth Classic SPP (Serial Port Profile) transport.
//!
//! BT Classic provides higher throughput than BLE (~2 Mbps) via RFCOMM
//! sockets. No fragmentation needed due to large MTU.

use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

/// Maximum packets queued while the platform is not polling the outbox.
const MAX_OUTBOX: usize = 512;

use mycelium_protocol::types::{LinkQuality, NodeId};

use super::{
    PriorityOutbox, SendPriority, Transport, TransportError, TransportEvent, TransportType,
};

/// Bluetooth Classic SPP transport.
///
/// Characteristics:
/// - Range: ~10-100m
/// - MTU: 16384 bytes (RFCOMM frame, no fragmentation needed)
/// - Power: Medium (higher than BLE)
/// - Use: Bulk data transfer, file sharing, voice notes
pub struct BtClassicTransport {
    tx: broadcast::Sender<TransportEvent>,
    connected_peers: Arc<RwLock<Vec<NodeId>>>,
    started: Arc<RwLock<bool>>,
    #[allow(clippy::type_complexity)]
    outbox: Arc<Mutex<PriorityOutbox>>,
}

impl Default for BtClassicTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl BtClassicTransport {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(128);
        Self {
            tx,
            connected_peers: Arc::new(RwLock::new(Vec::new())),
            started: Arc::new(RwLock::new(false)),
            outbox: Arc::new(Mutex::new(PriorityOutbox::new(MAX_OUTBOX))),
        }
    }

    /// Number of packets waiting in the outbox.
    pub fn outbox_len(&self) -> usize {
        self.outbox.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// Dequeue a pending send from the outbox.
    pub fn dequeue_send(&self) -> Option<(NodeId, Vec<u8>)> {
        self.outbox.lock().ok()?.pop()
    }

    /// Called when a BT Classic peer connects via SPP.
    pub async fn on_peer_connected(&self, peer: NodeId) {
        let mut peers = self.connected_peers.write().await;
        if !peers.contains(&peer) {
            info!("BT Classic peer connected: {}", peer);
            peers.push(peer);
            let _ = self.tx.send(TransportEvent::NeighborDiscovered {
                peer,
                transport: TransportType::BtClassic,
            });
        }
    }

    /// Called when a BT Classic peer disconnects.
    pub async fn on_peer_disconnected(&self, peer: NodeId) {
        let mut peers = self.connected_peers.write().await;
        peers.retain(|p| *p != peer);
        let _ = self.tx.send(TransportEvent::NeighborLost {
            peer,
            transport: TransportType::BtClassic,
        });
    }

    /// Called when data arrives from a BT Classic peer.
    pub async fn on_data_received(&self, peer: NodeId, data: Vec<u8>) {
        debug!(
            "BT Classic data received: {} bytes from {}",
            data.len(),
            peer
        );
        let _ = self.tx.send(TransportEvent::DataReceived {
            peer,
            data,
            transport: TransportType::BtClassic,
        });
    }
}

#[async_trait::async_trait]
impl Transport for BtClassicTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::BtClassic
    }

    async fn start(&self) -> Result<(), TransportError> {
        let mut started = self.started.write().await;
        if *started {
            return Err(TransportError::AlreadyStarted);
        }
        *started = true;
        info!("BT Classic transport started");
        Ok(())
    }

    async fn stop(&self) -> Result<(), TransportError> {
        let mut started = self.started.write().await;
        if !*started {
            return Err(TransportError::NotStarted);
        }
        *started = false;
        let mut peers = self.connected_peers.write().await;
        peers.clear();
        Ok(())
    }

    async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError> {
        self.send_with_priority(peer, data, SendPriority::Normal)
            .await
    }

    /// An `Alert` frame is queued ahead of ordinary traffic, and kept in
    /// preference to it when the outbox is full (spec §9.5, ADR-014).
    async fn send_with_priority(
        &self,
        peer: &NodeId,
        data: &[u8],
        priority: SendPriority,
    ) -> Result<(), TransportError> {
        let started = self.started.read().await;
        if !*started {
            return Err(TransportError::NotStarted);
        }

        let peers = self.connected_peers.read().await;
        if !peers.contains(peer) {
            return Err(TransportError::PeerNotConnected(*peer));
        }

        if data.len() > self.mtu() {
            return Err(TransportError::ExceedsMtu {
                size: data.len(),
                mtu: self.mtu(),
            });
        }

        debug!("BT Classic send: {} bytes to {}", data.len(), peer);

        if let Ok(mut outbox) = self.outbox.lock() {
            if outbox.push(*peer, data.to_vec(), priority).is_err() {
                warn!(
                    "BT Classic outbox full ({}) of alerts, dropping ordinary traffic",
                    MAX_OUTBOX
                );
                return Err(TransportError::SendFailed(
                    "outbox is full of emergency traffic".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn events(&self) -> broadcast::Receiver<TransportEvent> {
        self.tx.subscribe()
    }

    fn link_quality(&self, peer: &NodeId) -> Option<LinkQuality> {
        let peers = self.connected_peers.try_read().ok()?;
        if peers.contains(peer) {
            Some(LinkQuality {
                rssi: Some(-50),
                packet_loss: 0.01,
                latency_ms: 20,
                throughput_bps: 2_000_000, // ~2 Mbps SPP
            })
        } else {
            None
        }
    }

    fn connected_peers(&self) -> Vec<NodeId> {
        self.connected_peers
            .try_read()
            .map(|p| p.clone())
            .unwrap_or_default()
    }

    fn mtu(&self) -> usize {
        16384 // Large RFCOMM frames, no fragmentation needed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bt_classic_lifecycle() {
        let transport = BtClassicTransport::new();
        assert_eq!(transport.transport_type(), TransportType::BtClassic);
        assert_eq!(transport.mtu(), 16384);

        transport.start().await.unwrap();

        let peer = NodeId([0xAA; 32]);
        transport.on_peer_connected(peer).await;
        assert_eq!(transport.connected_peers(), vec![peer]);

        // Send should succeed
        let result = transport.send(&peer, &[1, 2, 3]).await;
        assert!(result.is_ok());
        assert_eq!(transport.outbox_len(), 1);

        // Dequeue
        let (dest, data) = transport.dequeue_send().unwrap();
        assert_eq!(dest, peer);
        assert_eq!(data, vec![1, 2, 3]);

        transport.on_peer_disconnected(peer).await;
        assert!(transport.connected_peers().is_empty());

        transport.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_bt_classic_not_started() {
        let transport = BtClassicTransport::new();
        let result = transport.send(&NodeId([0xBB; 32]), &[1]).await;
        assert!(matches!(result.unwrap_err(), TransportError::NotStarted));
    }
}
