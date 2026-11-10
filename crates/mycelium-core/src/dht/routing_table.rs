//! Kademlia k-bucket routing table.
//!
//! Organizes known peers into 256 buckets based on XOR distance from our node ID.
//! Each bucket holds up to K entries for peers at that distance.

use mycelium_protocol::types::NodeId;

use super::PeerInfo;

/// XOR distance between two node IDs, returned as an array for comparison.
/// Big-endian byte order, so the arrays compare in distance order directly.
pub fn xor_distance(a: &NodeId, b: &NodeId) -> [u8; 32] {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a_bytes[i] ^ b_bytes[i];
    }
    result
}

/// Get the bucket index (0-255) for a given distance.
/// This is the position of the highest set bit in the XOR distance.
/// Returns None if distance is zero (same node).
fn bucket_index(distance: &[u8; 32]) -> Option<usize> {
    for (byte_idx, &byte) in distance.iter().enumerate() {
        if byte != 0 {
            let bit_pos = 7 - byte.leading_zeros() as usize;
            return Some((31 - byte_idx) * 8 + bit_pos);
        }
    }
    None // Distance is zero
}

/// A single k-bucket holding up to K peers.
#[derive(Debug)]
struct KBucket {
    entries: Vec<PeerInfo>,
    k: usize,
}

impl KBucket {
    fn new(k: usize) -> Self {
        Self {
            entries: Vec::with_capacity(k),
            k,
        }
    }

    /// Insert a peer. If the bucket is full and the peer is new, it's dropped.
    /// If the peer already exists, update its last_seen.
    fn insert(&mut self, peer: PeerInfo) -> bool {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.node_id == peer.node_id) {
            existing.last_seen = peer.last_seen;
            existing.addr = peer.addr;
            return true;
        }

        if self.entries.len() < self.k {
            self.entries.push(peer);
            true
        } else {
            false // Bucket full
        }
    }

    fn remove(&mut self, node_id: &NodeId) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.node_id != *node_id);
        self.entries.len() != before
    }

    #[allow(dead_code)]
    fn contains(&self, node_id: &NodeId) -> bool {
        self.entries.iter().any(|e| e.node_id == *node_id)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn peers(&self) -> &[PeerInfo] {
        &self.entries
    }
}

/// Kademlia routing table with 256 k-buckets.
pub struct RoutingTable {
    local_id: NodeId,
    buckets: Vec<KBucket>,
    _k: usize,
}

impl RoutingTable {
    /// Create a new routing table for the given local node ID.
    pub fn new(local_id: NodeId, k: usize) -> Self {
        let buckets = (0..256).map(|_| KBucket::new(k)).collect();
        Self {
            local_id,
            buckets,
            _k: k,
        }
    }

    /// Insert a peer into the appropriate bucket.
    pub fn insert(&mut self, peer: PeerInfo) -> bool {
        if peer.node_id == self.local_id {
            return false; // Don't add self
        }

        let dist = xor_distance(&self.local_id, &peer.node_id);
        if let Some(idx) = bucket_index(&dist) {
            self.buckets[idx].insert(peer)
        } else {
            false
        }
    }

    /// Remove a peer from the routing table.
    pub fn remove(&mut self, node_id: &NodeId) -> bool {
        let dist = xor_distance(&self.local_id, node_id);
        if let Some(idx) = bucket_index(&dist) {
            self.buckets[idx].remove(node_id)
        } else {
            false
        }
    }

    /// Find the K closest peers to a target.
    pub fn closest_peers(&self, target: &NodeId, count: usize) -> Vec<PeerInfo> {
        let mut all: Vec<(PeerInfo, [u8; 32])> = Vec::new();

        for bucket in &self.buckets {
            for peer in bucket.peers() {
                let dist = xor_distance(&peer.node_id, target);
                all.push((peer.clone(), dist));
            }
        }

        all.sort_by(|a, b| a.1.cmp(&b.1));
        all.into_iter().take(count).map(|(p, _)| p).collect()
    }

    /// Get all peers in the routing table.
    pub fn all_peers(&self) -> Vec<PeerInfo> {
        let mut result = Vec::new();
        for bucket in &self.buckets {
            result.extend(bucket.peers().iter().cloned());
        }
        result
    }

    /// Total number of peers in the routing table.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    /// Whether the routing table is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Instant;

    fn random_node_id() -> NodeId {
        use rand::Rng;
        NodeId::from_bytes(rand::thread_rng().gen())
    }

    fn make_peer(port: u16) -> PeerInfo {
        PeerInfo {
            node_id: random_node_id(),
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            last_seen: Instant::now(),
        }
    }

    #[test]
    fn test_xor_distance_identity() {
        let id = random_node_id();
        let dist = xor_distance(&id, &id);
        assert_eq!(dist, [0u8; 32]);
    }

    #[test]
    fn test_xor_distance_symmetric() {
        let a = random_node_id();
        let b = random_node_id();
        assert_eq!(xor_distance(&a, &b), xor_distance(&b, &a));
    }

    #[test]
    fn test_bucket_index_zero_distance() {
        let dist = [0u8; 32];
        assert_eq!(bucket_index(&dist), None);
    }

    #[test]
    fn test_bucket_index_max_distance() {
        let dist = [0xFFu8; 32];
        assert_eq!(bucket_index(&dist), Some(255));
    }

    #[test]
    fn test_bucket_index_min_nonzero() {
        let mut dist = [0u8; 32];
        dist[31] = 1; // Least significant bit set
        assert_eq!(bucket_index(&dist), Some(0));
    }

    #[test]
    fn test_routing_table_insert_and_find() {
        let local = random_node_id();
        let mut rt = RoutingTable::new(local, 20);

        let peer = make_peer(5000);
        let peer_id = peer.node_id;
        assert!(rt.insert(peer));
        assert_eq!(rt.len(), 1);

        let closest = rt.closest_peers(&peer_id, 5);
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].node_id, peer_id);
    }

    #[test]
    fn test_routing_table_no_self_insert() {
        let local = random_node_id();
        let mut rt = RoutingTable::new(local, 20);

        let peer = PeerInfo {
            node_id: local,
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5000)),
            last_seen: Instant::now(),
        };
        assert!(!rt.insert(peer));
        assert_eq!(rt.len(), 0);
    }

    #[test]
    fn test_routing_table_remove() {
        let local = random_node_id();
        let mut rt = RoutingTable::new(local, 20);

        let peer = make_peer(5000);
        let peer_id = peer.node_id;
        rt.insert(peer);
        assert_eq!(rt.len(), 1);

        assert!(rt.remove(&peer_id));
        assert_eq!(rt.len(), 0);
    }

    #[test]
    fn test_closest_peers_ordering() {
        let local = random_node_id();
        let mut rt = RoutingTable::new(local, 20);

        let target = random_node_id();
        let mut peers = Vec::new();
        for i in 0..10 {
            let p = make_peer(5000 + i);
            peers.push(p.clone());
            rt.insert(p);
        }

        let closest = rt.closest_peers(&target, 5);
        assert_eq!(closest.len(), 5);

        // Verify they're sorted by distance
        for i in 1..closest.len() {
            let d_prev = xor_distance(&closest[i - 1].node_id, &target);
            let d_curr = xor_distance(&closest[i].node_id, &target);
            assert!(d_prev <= d_curr);
        }
    }

    #[test]
    fn test_bucket_capacity() {
        let local = random_node_id();
        let mut rt = RoutingTable::new(local, 2); // K=2

        // Insert 10 peers — some buckets will be full
        for i in 0..10 {
            rt.insert(make_peer(5000 + i));
        }

        // Should have at most 2 per bucket, but total depends on distribution
        assert!(rt.len() <= 10);
        assert!(rt.len() >= 2); // At least some should fit
    }
}
