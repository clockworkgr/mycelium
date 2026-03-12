use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, RwLock};

use mycelium_protocol::types::{LinkQuality, NodeId};

use super::{Transport, TransportError, TransportEvent, TransportType};

/// Configuration for a mock link between two nodes.
#[derive(Debug, Clone)]
pub struct MockLinkConfig {
    pub latency_ms: u32,
    pub packet_loss: f32,
    pub bandwidth_bps: u32,
    pub enabled: bool,
}

impl Default for MockLinkConfig {
    fn default() -> Self {
        Self {
            latency_ms: 10,
            packet_loss: 0.0,
            bandwidth_bps: 1_000_000,
            enabled: true,
        }
    }
}

/// Simulates a mesh network for testing. Manages links between MockTransport instances.
pub struct MockNetwork {
    /// Map from (src, dst) -> link config
    links: RwLock<HashMap<(NodeId, NodeId), MockLinkConfig>>,
    /// Map from node_id -> sender channel for delivering data
    nodes: RwLock<HashMap<NodeId, broadcast::Sender<TransportEvent>>>,
}

impl MockNetwork {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            links: RwLock::new(HashMap::new()),
            nodes: RwLock::new(HashMap::new()),
        })
    }

    /// Create a bidirectional link between two nodes.
    pub async fn add_link(&self, a: NodeId, b: NodeId, config: MockLinkConfig) {
        let mut links = self.links.write().await;
        links.insert((a, b), config.clone());
        links.insert((b, a), config);

        // Notify both sides of neighbor discovery
        let nodes = self.nodes.read().await;
        if let Some(tx) = nodes.get(&a) {
            let _ = tx.send(TransportEvent::NeighborDiscovered {
                peer: b,
                transport: TransportType::Mock,
            });
        }
        if let Some(tx) = nodes.get(&b) {
            let _ = tx.send(TransportEvent::NeighborDiscovered {
                peer: a,
                transport: TransportType::Mock,
            });
        }
    }

    /// Remove the link between two nodes (simulate partition).
    pub async fn remove_link(&self, a: &NodeId, b: &NodeId) {
        let mut links = self.links.write().await;
        links.remove(&(*a, *b));
        links.remove(&(*b, *a));

        let nodes = self.nodes.read().await;
        if let Some(tx) = nodes.get(a) {
            let _ = tx.send(TransportEvent::NeighborLost {
                peer: *b,
                transport: TransportType::Mock,
            });
        }
        if let Some(tx) = nodes.get(b) {
            let _ = tx.send(TransportEvent::NeighborLost {
                peer: *a,
                transport: TransportType::Mock,
            });
        }
    }

    /// Register a node's event sender.
    pub async fn register_node(&self, node_id: NodeId, tx: broadcast::Sender<TransportEvent>) {
        self.nodes.write().await.insert(node_id, tx);
    }

    /// Deliver data from src to dst, respecting link config.
    pub async fn deliver(
        &self,
        src: NodeId,
        dst: NodeId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        let links = self.links.read().await;
        let config = links
            .get(&(src, dst))
            .ok_or(TransportError::PeerNotConnected(dst))?;

        if !config.enabled {
            return Err(TransportError::PeerNotConnected(dst));
        }

        // Simulate packet loss
        if config.packet_loss > 0.0 {
            let r: f32 = rand::random();
            if r < config.packet_loss {
                return Ok(()); // Silently dropped
            }
        }

        let latency = config.latency_ms;
        drop(links);

        // Simulate latency
        if latency > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(latency as u64)).await;
        }

        // Deliver to destination
        let nodes = self.nodes.read().await;
        if let Some(tx) = nodes.get(&dst) {
            let _ = tx.send(TransportEvent::DataReceived {
                peer: src,
                data,
                transport: TransportType::Mock,
            });
            Ok(())
        } else {
            Err(TransportError::PeerNotConnected(dst))
        }
    }

    /// Get neighbors of a node (nodes with active links).
    pub async fn neighbors(&self, node: &NodeId) -> Vec<NodeId> {
        let links = self.links.read().await;
        links
            .keys()
            .filter(|(src, _)| src == node)
            .map(|(_, dst)| *dst)
            .collect()
    }
}

impl MockNetwork {
    /// Alias for `new()` for convenience.
    pub fn default_arc() -> Arc<Self> {
        Self::new()
    }
}

/// A mock transport implementation for testing.
pub struct MockTransport {
    node_id: NodeId,
    network: Arc<MockNetwork>,
    tx: broadcast::Sender<TransportEvent>,
    started: Mutex<bool>,
}

impl MockTransport {
    pub async fn new(node_id: NodeId, network: Arc<MockNetwork>) -> Self {
        let (tx, _) = broadcast::channel(256);
        network.register_node(node_id, tx.clone()).await;
        Self {
            node_id,
            network,
            tx,
            started: Mutex::new(false),
        }
    }
}

#[async_trait::async_trait]
impl Transport for MockTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Mock
    }

    async fn start(&self) -> Result<(), TransportError> {
        let mut started = self.started.lock().await;
        if *started {
            return Err(TransportError::AlreadyStarted);
        }
        *started = true;
        Ok(())
    }

    async fn stop(&self) -> Result<(), TransportError> {
        let mut started = self.started.lock().await;
        if !*started {
            return Err(TransportError::NotStarted);
        }
        *started = false;
        Ok(())
    }

    async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError> {
        let started = self.started.lock().await;
        if !*started {
            return Err(TransportError::NotStarted);
        }
        drop(started);

        self.network
            .deliver(self.node_id, *peer, data.to_vec())
            .await
    }

    fn events(&self) -> broadcast::Receiver<TransportEvent> {
        self.tx.subscribe()
    }

    fn link_quality(&self, _peer: &NodeId) -> Option<LinkQuality> {
        Some(LinkQuality {
            rssi: Some(-50),
            throughput_bps: 1_000_000,
            packet_loss: 0.0,
            latency_ms: 10,
        })
    }

    fn connected_peers(&self) -> Vec<NodeId> {
        // Use try_read to avoid blocking in sync context
        match self.network.links.try_read() {
            Ok(links) => links
                .keys()
                .filter(|(src, _)| *src == self.node_id)
                .map(|(_, dst)| *dst)
                .collect(),
            Err(_) => vec![],
        }
    }

    fn mtu(&self) -> usize {
        65535
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_network_delivery() {
        let network = MockNetwork::new();
        let a = NodeId([1u8; 32]);
        let b = NodeId([2u8; 32]);

        let transport_a = MockTransport::new(a, network.clone()).await;
        let transport_b = MockTransport::new(b, network.clone()).await;
        let mut rx_b = transport_b.events();

        transport_a.start().await.unwrap();
        transport_b.start().await.unwrap();

        network.add_link(a, b, MockLinkConfig::default()).await;

        transport_a.send(&b, b"hello mesh").await.unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx_b.recv())
            .await
            .expect("timeout")
            .expect("recv error");

        match event {
            TransportEvent::DataReceived { peer, data, .. } => {
                assert_eq!(peer, a);
                assert_eq!(data, b"hello mesh");
            }
            TransportEvent::NeighborDiscovered { .. } => {
                // We may get the discovery event first, try again
                let event = rx_b.recv().await.unwrap();
                if let TransportEvent::DataReceived { peer, data, .. } = event {
                    assert_eq!(peer, a);
                    assert_eq!(data, b"hello mesh");
                }
            }
            _ => panic!("unexpected event: {:?}", event),
        }
    }

    #[tokio::test]
    async fn test_mock_partition() {
        let network = MockNetwork::new();
        let a = NodeId([1u8; 32]);
        let b = NodeId([2u8; 32]);

        let transport_a = MockTransport::new(a, network.clone()).await;
        let _transport_b = MockTransport::new(b, network.clone()).await;

        transport_a.start().await.unwrap();

        // No link => should fail
        let result = transport_a.send(&b, b"hello").await;
        assert!(result.is_err());
    }
}
