//! Wi-Fi Direct transport.
//!
//! On Android, the real implementation uses the WifiP2pManager API
//! via FFI callbacks. Dart polls the outbox for outgoing data at 50ms.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, warn};

use mycelium_protocol::types::{LinkQuality, NodeId};

use super::{Transport, TransportError, TransportEvent, TransportType};

/// FFI send callback type for Wi-Fi Direct transport.
/// Parameters: peer_id (32 bytes), data pointer, data length.
/// Returns 0 on success, non-zero on failure.
pub type WifiSendCallback = extern "C" fn(*const [u8; 32], *const u8, u32) -> i32;

/// Wi-Fi Direct transport for high-bandwidth mesh communication.
///
/// Characteristics:
/// - Range: ~50-200m depending on environment
/// - MTU: 65535 bytes (TCP-like, large payloads)
/// - Power: Medium-High (Wi-Fi radio)
/// - Use: Bulk data transfer, large messages, file sharing
pub struct WifiDirectTransport {
    local_id: NodeId,
    tx: broadcast::Sender<TransportEvent>,
    connected_peers: Arc<RwLock<Vec<NodeId>>>,
    started: Arc<RwLock<bool>>,
    send_callback: Arc<RwLock<Option<WifiSendCallback>>>,
    /// Outbox queue for outgoing data. Dart polls this via FFI since it cannot
    /// provide a synchronous C callback across threads.
    outbox: Arc<Mutex<VecDeque<(NodeId, Vec<u8>)>>>,
}

impl WifiDirectTransport {
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
            debug!("WiFi Direct outbox dequeue: {} bytes for {}", data.len(), peer);
        }
        result
    }

    /// Register a platform send callback. When the Rust layer calls `send()`,
    /// this callback is invoked to deliver the data via the platform Wi-Fi Direct API.
    pub async fn set_send_callback(&self, callback: WifiSendCallback) {
        *self.send_callback.write().await = Some(callback);
    }

    /// Called by platform-specific code when a Wi-Fi Direct peer connects.
    pub async fn on_peer_connected(&self, peer: NodeId) {
        let mut peers = self.connected_peers.write().await;
        if !peers.contains(&peer) {
            peers.push(peer);
            let _ = self.tx.send(TransportEvent::NeighborDiscovered {
                peer,
                transport: TransportType::WifiDirect,
            });
        }
    }

    /// Called by platform-specific code when a Wi-Fi Direct peer disconnects.
    pub async fn on_peer_disconnected(&self, peer: NodeId) {
        let mut peers = self.connected_peers.write().await;
        peers.retain(|p| *p != peer);
        let _ = self.tx.send(TransportEvent::NeighborLost {
            peer,
            transport: TransportType::WifiDirect,
        });
    }

    /// Called by platform-specific code when data arrives from a Wi-Fi Direct peer.
    pub async fn on_data_received(&self, peer: NodeId, data: Vec<u8>) {
        let _ = self.tx.send(TransportEvent::DataReceived {
            peer,
            data,
            transport: TransportType::WifiDirect,
        });
    }
}

#[async_trait::async_trait]
impl Transport for WifiDirectTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::WifiDirect
    }

    async fn start(&self) -> Result<(), TransportError> {
        let mut started = self.started.write().await;
        if *started {
            return Err(TransportError::AlreadyStarted);
        }
        *started = true;
        // Platform-specific Wi-Fi Direct group creation/discovery would start here
        warn!("Wi-Fi Direct transport started (stub — no platform implementation)");
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

        debug!("WiFi Direct send: {} bytes to {}", data.len(), peer);

        // Use platform send callback if registered, otherwise queue for Dart polling
        let cb = self.send_callback.read().await;
        if let Some(callback) = *cb {
            let peer_bytes = peer.as_bytes();
            let result = callback(peer_bytes as *const [u8; 32], data.as_ptr(), data.len() as u32);
            if result != 0 {
                return Err(TransportError::SendFailed(format!("WiFi Direct send callback returned {}", result)));
            }
        } else {
            // Push to outbox for Dart to poll via mycelium_wifi_dequeue_send
            if let Ok(mut outbox) = self.outbox.lock() {
                outbox.push_back((*peer, data.to_vec()));
                debug!("WiFi Direct outbox: queued, depth now {}", outbox.len());
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
                rssi: Some(-40),
                packet_loss: 0.0,
                latency_ms: 10,
                throughput_bps: 6_250_000, // ~50 Mbps Wi-Fi Direct
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
        65535
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[tokio::test]
    async fn test_outbox_send_and_dequeue() {
        let transport = WifiDirectTransport::new(test_node_id(1));
        transport.start().await.unwrap();
        let peer = test_node_id(2);
        transport.on_peer_connected(peer).await;

        // Send should queue to outbox (no callback registered)
        transport.send(&peer, b"hello wifi").await.unwrap();

        let (dequeued_peer, dequeued_data) = transport.dequeue_send().unwrap();
        assert_eq!(dequeued_peer, peer);
        assert_eq!(dequeued_data, b"hello wifi");

        // Outbox should be empty now
        assert!(transport.dequeue_send().is_none());
    }

    #[tokio::test]
    async fn test_outbox_multiple_sends() {
        let transport = WifiDirectTransport::new(test_node_id(1));
        transport.start().await.unwrap();
        let peer = test_node_id(2);
        transport.on_peer_connected(peer).await;

        transport.send(&peer, b"msg1").await.unwrap();
        transport.send(&peer, b"msg2").await.unwrap();
        transport.send(&peer, b"msg3").await.unwrap();

        let (_, d1) = transport.dequeue_send().unwrap();
        let (_, d2) = transport.dequeue_send().unwrap();
        let (_, d3) = transport.dequeue_send().unwrap();
        assert_eq!(d1, b"msg1");
        assert_eq!(d2, b"msg2");
        assert_eq!(d3, b"msg3");
        assert!(transport.dequeue_send().is_none());
    }

    #[tokio::test]
    async fn test_send_not_started() {
        let transport = WifiDirectTransport::new(test_node_id(1));
        let peer = test_node_id(2);
        let result = transport.send(&peer, b"data").await;
        assert!(matches!(result, Err(TransportError::NotStarted)));
    }

    #[tokio::test]
    async fn test_send_peer_not_connected() {
        let transport = WifiDirectTransport::new(test_node_id(1));
        transport.start().await.unwrap();
        let peer = test_node_id(2);
        let result = transport.send(&peer, b"data").await;
        assert!(matches!(result, Err(TransportError::PeerNotConnected(_))));
    }
}
