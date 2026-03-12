//! Kademlia-style Distributed Hash Table for internet peer discovery.
//!
//! Nodes use their 256-bit `NodeId` (Ed25519 public key hash) as their DHT key.
//! The DHT enables internet-connected nodes to discover each other and relay
//! mesh messages over TCP.

pub mod routing_table;
pub mod rpc;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;

use mycelium_protocol::types::NodeId;

use routing_table::RoutingTable;
use rpc::{DhtMessage, DhtResponse};

/// Configuration for the DHT.
#[derive(Debug, Clone)]
pub struct DhtConfig {
    /// K parameter — bucket size and replication factor.
    pub k: usize,
    /// Alpha parameter — concurrency for iterative lookups.
    pub alpha: usize,
    /// How often to refresh buckets (seconds).
    pub refresh_interval_secs: u64,
    /// Bootstrap nodes to connect to initially.
    pub bootstrap_nodes: Vec<SocketAddr>,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            k: 20,
            alpha: 3,
            refresh_interval_secs: 3600,
            bootstrap_nodes: Vec::new(),
        }
    }
}

/// A peer's contact information in the DHT.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub last_seen: Instant,
}

/// The Kademlia DHT engine.
pub struct DhtEngine {
    local_id: NodeId,
    config: DhtConfig,
    routing_table: Arc<RwLock<RoutingTable>>,
    /// Stored values (NodeId → endpoint mapping).
    store: Arc<RwLock<HashMap<NodeId, SocketAddr>>>,
}

impl DhtEngine {
    pub fn new(local_id: NodeId, config: DhtConfig) -> Self {
        let routing_table = RoutingTable::new(local_id, config.k);
        Self {
            local_id,
            config,
            routing_table: Arc::new(RwLock::new(routing_table)),
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the local node ID.
    pub fn local_id(&self) -> NodeId {
        self.local_id
    }

    /// Add a known peer to the routing table.
    pub async fn add_peer(&self, peer: PeerInfo) {
        let mut rt = self.routing_table.write().await;
        rt.insert(peer);
    }

    /// Remove a peer from the routing table.
    pub async fn remove_peer(&self, node_id: &NodeId) {
        let mut rt = self.routing_table.write().await;
        rt.remove(node_id);
    }

    /// Find the K closest nodes to a target in our routing table.
    pub async fn find_closest(&self, target: &NodeId) -> Vec<PeerInfo> {
        let rt = self.routing_table.read().await;
        rt.closest_peers(target, self.config.k)
    }

    /// Store our own address in the DHT (publish to closest nodes).
    pub async fn store_self(&self, addr: SocketAddr) {
        let mut store = self.store.write().await;
        store.insert(self.local_id, addr);
    }

    /// Look up a node's address.
    pub async fn lookup(&self, target: &NodeId) -> Option<SocketAddr> {
        let store = self.store.read().await;
        store.get(target).copied()
    }

    /// Store a value (peer's address) in our local store.
    pub async fn store_value(&self, node_id: NodeId, addr: SocketAddr) {
        let mut store = self.store.write().await;
        store.insert(node_id, addr);
    }

    /// Handle an incoming DHT message and produce a response.
    pub async fn handle_message(&self, msg: DhtMessage) -> Option<DhtResponse> {
        match msg {
            DhtMessage::Ping {
                sender_id,
                sender_addr,
            } => {
                self.add_peer(PeerInfo {
                    node_id: sender_id,
                    addr: sender_addr,
                    last_seen: Instant::now(),
                })
                .await;
                Some(DhtResponse::Pong {
                    responder_id: self.local_id,
                })
            }
            DhtMessage::FindNode {
                sender_id,
                sender_addr,
                target,
            } => {
                self.add_peer(PeerInfo {
                    node_id: sender_id,
                    addr: sender_addr,
                    last_seen: Instant::now(),
                })
                .await;
                let closest = self.find_closest(&target).await;
                let nodes: Vec<(NodeId, SocketAddr)> =
                    closest.into_iter().map(|p| (p.node_id, p.addr)).collect();
                Some(DhtResponse::FoundNodes {
                    responder_id: self.local_id,
                    nodes,
                })
            }
            DhtMessage::Store {
                sender_id,
                sender_addr,
                key,
                value,
            } => {
                self.add_peer(PeerInfo {
                    node_id: sender_id,
                    addr: sender_addr,
                    last_seen: Instant::now(),
                })
                .await;
                self.store_value(key, value).await;
                Some(DhtResponse::Stored {
                    responder_id: self.local_id,
                })
            }
            DhtMessage::FindValue {
                sender_id,
                sender_addr,
                key,
            } => {
                self.add_peer(PeerInfo {
                    node_id: sender_id,
                    addr: sender_addr,
                    last_seen: Instant::now(),
                })
                .await;
                let store = self.store.read().await;
                if let Some(&addr) = store.get(&key) {
                    Some(DhtResponse::FoundValue {
                        responder_id: self.local_id,
                        value: addr,
                    })
                } else {
                    drop(store);
                    let closest = self.find_closest(&key).await;
                    let nodes: Vec<(NodeId, SocketAddr)> =
                        closest.into_iter().map(|p| (p.node_id, p.addr)).collect();
                    Some(DhtResponse::FoundNodes {
                        responder_id: self.local_id,
                        nodes,
                    })
                }
            }
        }
    }

    /// Get all known peers from the routing table.
    pub async fn all_peers(&self) -> Vec<PeerInfo> {
        let rt = self.routing_table.read().await;
        rt.all_peers()
    }

    /// Get the bootstrap addresses.
    pub fn bootstrap_addrs(&self) -> &[SocketAddr] {
        &self.config.bootstrap_nodes
    }

    /// Get count of peers in the routing table.
    pub async fn peer_count(&self) -> usize {
        let rt = self.routing_table.read().await;
        rt.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn random_node_id() -> NodeId {
        use rand::Rng;
        NodeId::from_bytes(rand::thread_rng().gen())
    }

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    #[tokio::test]
    async fn test_dht_ping_response() {
        let local_id = random_node_id();
        let engine = DhtEngine::new(local_id, DhtConfig::default());

        let sender_id = random_node_id();
        let resp = engine
            .handle_message(DhtMessage::Ping {
                sender_id,
                sender_addr: make_addr(5000),
            })
            .await;

        assert!(matches!(resp, Some(DhtResponse::Pong { .. })));
        assert_eq!(engine.peer_count().await, 1);
    }

    #[tokio::test]
    async fn test_dht_find_node() {
        let local_id = random_node_id();
        let engine = DhtEngine::new(local_id, DhtConfig::default());

        // Add some peers
        for i in 0..5 {
            engine
                .add_peer(PeerInfo {
                    node_id: random_node_id(),
                    addr: make_addr(5000 + i),
                    last_seen: Instant::now(),
                })
                .await;
        }

        let target = random_node_id();
        let resp = engine
            .handle_message(DhtMessage::FindNode {
                sender_id: random_node_id(),
                sender_addr: make_addr(6000),
                target,
            })
            .await;

        match resp {
            Some(DhtResponse::FoundNodes { nodes, .. }) => {
                assert!(!nodes.is_empty());
            }
            _ => panic!("Expected FoundNodes response"),
        }
    }

    #[tokio::test]
    async fn test_dht_store_and_find_value() {
        let local_id = random_node_id();
        let engine = DhtEngine::new(local_id, DhtConfig::default());

        let key = random_node_id();
        let addr = make_addr(7000);

        // Store
        let resp = engine
            .handle_message(DhtMessage::Store {
                sender_id: random_node_id(),
                sender_addr: make_addr(6000),
                key,
                value: addr,
            })
            .await;
        assert!(matches!(resp, Some(DhtResponse::Stored { .. })));

        // Find value
        let resp = engine
            .handle_message(DhtMessage::FindValue {
                sender_id: random_node_id(),
                sender_addr: make_addr(6001),
                key,
            })
            .await;

        match resp {
            Some(DhtResponse::FoundValue { value, .. }) => {
                assert_eq!(value, addr);
            }
            _ => panic!("Expected FoundValue response"),
        }
    }

    #[tokio::test]
    async fn test_dht_find_value_returns_closest_when_not_found() {
        let local_id = random_node_id();
        let engine = DhtEngine::new(local_id, DhtConfig::default());

        // Add a peer
        engine
            .add_peer(PeerInfo {
                node_id: random_node_id(),
                addr: make_addr(5000),
                last_seen: Instant::now(),
            })
            .await;

        let resp = engine
            .handle_message(DhtMessage::FindValue {
                sender_id: random_node_id(),
                sender_addr: make_addr(6000),
                key: random_node_id(),
            })
            .await;

        assert!(matches!(resp, Some(DhtResponse::FoundNodes { .. })));
    }
}
