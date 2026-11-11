//! Kademlia k-bucket routing table.
//!
//! Organizes known peers into 256 buckets based on XOR distance from our node ID.
//! Each bucket holds up to K entries for peers at that distance.

use mycelium_protocol::types::NodeId;

use super::{AddrSource, PeerInfo};

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
    /// If the peer already exists, its liveness is refreshed and its address
    /// replaced only by better or fresher evidence.
    fn insert(&mut self, peer: PeerInfo) -> bool {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.node_id == peer.node_id) {
            existing.last_seen = peer.last_seen;
            if Self::addr_wins(&peer, existing) {
                existing.addr = peer.addr;
                existing.addr_source = peer.addr_source;
                existing.addr_proved_at = peer.addr_proved_at;
            }
            return true;
        }

        if self.entries.len() < self.k {
            self.entries.push(peer);
            true
        } else {
            false // Bucket full
        }
    }

    /// Whether `incoming`'s address should replace `held`'s.
    ///
    /// A dial beats a claim: a claim that displaced an address we reached
    /// would make a peer behind a port forward undialable — its signed
    /// `public:9736` is not where we found it at `public:443`. Within a
    /// level the fresher evidence wins, which is why the comparison is
    /// `addr_proved_at` and not `last_seen`: a live channel refreshes its
    /// contact on every DHT request it answers, and dating those refreshes
    /// `now` let an old channel keep reinstating its own endpoint over one a
    /// later dial had proved. A claim replacing an older claim is how a peer
    /// that moved is re-learned; an address we dialled that has gone stale is
    /// for bucket liveness to remove (ROADMAP T-32), not for a claim to
    /// overwrite.
    fn addr_wins(incoming: &PeerInfo, held: &PeerInfo) -> bool {
        match (incoming.addr_source, held.addr_source) {
            (AddrSource::Dialled, AddrSource::Claimed) => true,
            (AddrSource::Claimed, AddrSource::Dialled) => false,
            _ => incoming.addr_proved_at >= held.addr_proved_at,
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
    use std::time::{Duration, Instant};

    fn random_node_id() -> NodeId {
        use rand::Rng;
        NodeId::from_bytes(rand::thread_rng().gen())
    }

    fn make_peer(port: u16) -> PeerInfo {
        make_peer_from(port, AddrSource::Dialled)
    }

    fn make_peer_from(port: u16, addr_source: AddrSource) -> PeerInfo {
        PeerInfo {
            node_id: random_node_id(),
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            last_seen: Instant::now(),
            addr_source,
            addr_proved_at: Instant::now(),
        }
    }

    /// The address a peer holds in a bucket, for the provenance tests.
    fn held(table: &RoutingTable, peer: &PeerInfo) -> Option<PeerInfo> {
        table.closest_peers(&peer.node_id, 1).into_iter().next()
    }

    #[test]
    fn test_a_claimed_address_does_not_displace_one_we_dialled() {
        let mut table = RoutingTable::new(random_node_id(), 20);
        let dialled = make_peer_from(443, AddrSource::Dialled);
        assert!(table.insert(dialled.clone()));

        // The same peer, now claiming the port it listens on inside its own
        // network — what an inbound connection or a referral yields.
        let mut claimed = dialled.clone();
        claimed.addr = "127.0.0.1:9736".parse().unwrap();
        claimed.addr_source = AddrSource::Claimed;
        claimed.last_seen = Instant::now();
        assert!(table.insert(claimed.clone()));

        let entry = held(&table, &dialled).expect("the peer must still be there");
        assert_eq!(
            entry.addr, dialled.addr,
            "a claim must not replace an address we dialled"
        );
        assert_eq!(entry.addr_source, AddrSource::Dialled);
        assert!(
            entry.last_seen >= claimed.last_seen,
            "liveness must still be refreshed"
        );
    }

    #[test]
    fn test_a_claim_replaces_an_earlier_claim_so_a_peer_can_move() {
        let mut table = RoutingTable::new(random_node_id(), 20);
        let first = make_peer_from(9736, AddrSource::Claimed);
        assert!(table.insert(first.clone()));

        let mut moved = first.clone();
        moved.addr = "127.0.0.1:9737".parse().unwrap();
        assert!(table.insert(moved.clone()));
        assert_eq!(
            held(&table, &first).map(|p| p.addr),
            Some(moved.addr),
            "nothing we hold is better evidence than the newer claim"
        );

        // And a dial supersedes any claim.
        let mut proven = first.clone();
        proven.addr = "127.0.0.1:443".parse().unwrap();
        proven.addr_source = AddrSource::Dialled;
        assert!(table.insert(proven.clone()));
        let entry = held(&table, &first).expect("still there");
        assert_eq!(entry.addr, proven.addr);
        assert_eq!(entry.addr_source, AddrSource::Dialled);
    }

    #[test]
    fn test_a_refresh_does_not_restore_an_endpoint_a_newer_dial_superseded() {
        let mut table = RoutingTable::new(random_node_id(), 20);
        let first = make_peer_from(443, AddrSource::Dialled);
        let mut second = first.clone();
        second.addr = "127.0.0.1:444".parse().unwrap();
        second.addr_proved_at = first.addr_proved_at + Duration::from_secs(1);
        second.last_seen = second.addr_proved_at;

        assert!(table.insert(first.clone()));
        assert!(table.insert(second.clone()));
        assert_eq!(held(&table, &first).map(|p| p.addr), Some(second.addr));

        // The first connection is still alive and answers a DHT request,
        // which refreshes the contact. Its evidence is older than the second
        // dial's, so it must not put its own endpoint back.
        let mut refresh = first.clone();
        refresh.last_seen = Instant::now();
        assert!(table.insert(refresh.clone()));

        let entry = held(&table, &first).expect("the peer must still be there");
        assert_eq!(
            entry.addr, second.addr,
            "a liveness refresh must not restore the older endpoint"
        );
        assert!(
            entry.last_seen >= refresh.last_seen,
            "liveness must still be refreshed"
        );
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
            addr_source: AddrSource::Dialled,
            addr_proved_at: Instant::now(),
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
