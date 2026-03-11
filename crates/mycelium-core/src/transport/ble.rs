//! BLE (Bluetooth Low Energy) transport stub.
//!
//! On Android/iOS, the real implementation will use platform BLE APIs
//! via FFI callbacks. This stub provides the trait implementation structure.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info};

use mycelium_protocol::types::{LinkQuality, NodeId};

use super::{Transport, TransportError, TransportEvent, TransportType};

/// FFI send callback type for BLE transport.
/// Parameters: peer_id (32 bytes), data pointer, data length.
/// Returns 0 on success, non-zero on failure.
pub type BleSendCallback = extern "C" fn(*const [u8; 32], *const u8, u32) -> i32;

/// BLE transport for short-range mesh communication.
///
/// Characteristics:
/// - Range: ~10-100m depending on environment
/// - MTU: 512 bytes (negotiated, may be smaller on older devices)
/// - Power: Low (designed for battery-constrained devices)
/// - Use: Discovery beacons, small control messages, session init
pub struct BleTransport {
    local_id: NodeId,
    tx: broadcast::Sender<TransportEvent>,
    connected_peers: Arc<RwLock<Vec<NodeId>>>,
    started: Arc<RwLock<bool>>,
    send_callback: Arc<RwLock<Option<BleSendCallback>>>,
    /// Outbox queue for outgoing data. Dart polls this via FFI since it cannot
    /// provide a synchronous C callback across threads.
    outbox: Arc<Mutex<VecDeque<(NodeId, Vec<u8>)>>>,
}

impl BleTransport {
    pub fn new(local_id: NodeId) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            local_id,
            tx,
            connected_peers: Arc::new(RwLock::new(Vec::new())),
            started: Arc::new(RwLock::new(false)),
            send_callback: Arc::new(RwLock::new(None)),
            outbox: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Dequeue a pending send from the outbox.
    /// Returns `Some((peer, data))` if there was a packet waiting, `None` otherwise.
    pub fn dequeue_send(&self) -> Option<(NodeId, Vec<u8>)> {
        let result = self.outbox.lock().ok()?.pop_front();
        if let Some((ref peer, ref data)) = result {
            debug!("BLE outbox dequeue: {} bytes for {}", data.len(), peer);
        }
        result
    }

    /// Register a platform send callback. When the Rust layer calls `send()`,
    /// this callback is invoked to deliver the data via the platform BLE API.
    pub async fn set_send_callback(&self, callback: BleSendCallback) {
        *self.send_callback.write().await = Some(callback);
    }

    /// Called by platform-specific code when a BLE peripheral is discovered.
    pub async fn on_peer_discovered(&self, peer: NodeId) {
        let mut peers = self.connected_peers.write().await;
        if !peers.contains(&peer) {
            info!("BLE peer discovered: {}", peer);
            peers.push(peer);
            let _ = self.tx.send(TransportEvent::NeighborDiscovered {
                peer,
                transport: TransportType::Ble,
            });
        }
    }

    /// Called by platform-specific code when a BLE peripheral disconnects.
    pub async fn on_peer_lost(&self, peer: NodeId) {
        let mut peers = self.connected_peers.write().await;
        peers.retain(|p| *p != peer);
        let _ = self.tx.send(TransportEvent::NeighborLost {
            peer,
            transport: TransportType::Ble,
        });
    }

    /// Called by platform-specific code when data arrives from a BLE peer.
    pub async fn on_data_received(&self, peer: NodeId, data: Vec<u8>) {
        debug!("BLE data received: {} bytes from {}", data.len(), peer);
        let _ = self.tx.send(TransportEvent::DataReceived {
            peer,
            data,
            transport: TransportType::Ble,
        });
    }
}

#[async_trait::async_trait]
impl Transport for BleTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Ble
    }

    async fn start(&self) -> Result<(), TransportError> {
        let mut started = self.started.write().await;
        if *started {
            return Err(TransportError::AlreadyStarted);
        }
        *started = true;
        info!("BLE transport started");
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

        debug!("BLE send: {} bytes to {}", data.len(), peer);

        // Use platform send callback if registered, otherwise queue for Dart polling
        let cb = self.send_callback.read().await;
        if let Some(callback) = *cb {
            let peer_bytes = peer.as_bytes();
            let result = callback(peer_bytes as *const [u8; 32], data.as_ptr(), data.len() as u32);
            if result != 0 {
                return Err(TransportError::SendFailed(format!("BLE send callback returned {}", result)));
            }
        } else {
            // Push to outbox for Dart to poll via mycelium_ble_dequeue_send
            if let Ok(mut outbox) = self.outbox.lock() {
                outbox.push_back((*peer, data.to_vec()));
                debug!("BLE outbox: queued, depth now {}", outbox.len());
            }
        }
        Ok(())
    }

    fn events(&self) -> broadcast::Receiver<TransportEvent> {
        self.tx.subscribe()
    }

    fn link_quality(&self, peer: &NodeId) -> Option<LinkQuality> {
        // Would read RSSI from platform BLE layer
        let peers = self.connected_peers.try_read().ok()?;
        if peers.contains(peer) {
            Some(LinkQuality {
                rssi: Some(-60),
                packet_loss: 0.0,
                latency_ms: 50,
                throughput_bps: 125_000, // ~1 Mbps BLE 5
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
        512
    }
}
