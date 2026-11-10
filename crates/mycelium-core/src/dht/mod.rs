//! Kademlia-style Distributed Hash Table for internet peer discovery.
//!
//! Nodes use their 256-bit `NodeId` (Ed25519 public key hash) as their DHT key.
//! The DHT lets internet-connected nodes find each other's addresses.
//!
//! Three properties are load-bearing and are enforced here rather than left to
//! callers (ROADMAP T-09):
//!
//! - **Every stored record is signed by the node it describes** ([`record`]),
//!   so a peer cannot publish someone else's address and hijack their traffic.
//! - **Records expire and the store is capped**, so a peer cannot grow our
//!   memory without bound or park an address that outlives the truth.
//! - **Lookups terminate deterministically**, bounded by a visited set, a
//!   round limit, a per-request timeout and an overall deadline.

pub mod record;
pub mod routing_table;
pub mod rpc;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tracing::debug;

use mycelium_crypto::identity::Identity;
use mycelium_protocol::types::NodeId;

use record::{unix_now, DhtRecord, RecordRejection, MAX_CLOCK_SKEW_SECS, RECORD_TTL_SECS};
use routing_table::{xor_distance, RoutingTable};
use rpc::{DhtReply, DhtReplyBody, DhtRequest, DhtRequestBody, MAX_FOUND_NODES};

/// How long one request may take before the lookup gives up on that peer.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Wall-clock bound on a whole iterative lookup.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Backstop on lookup rounds. Convergence normally ends a lookup sooner, when
/// every one of the k closest known nodes has been queried; this only bounds
/// the case where each round keeps turning up closer nodes.
pub const MAX_LOOKUP_ROUNDS: usize = 16;

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
    /// Hard cap on stored records.
    pub max_records: usize,
    /// How long a record stays valid after it was published.
    pub record_ttl_secs: u64,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            k: 20,
            alpha: 3,
            refresh_interval_secs: 3600,
            bootstrap_nodes: Vec::new(),
            max_records: 4096,
            record_ttl_secs: RECORD_TTL_SECS,
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

/// Sends a DHT request to one peer and waits for its reply.
///
/// Implemented by the transport, so the engine can drive an iterative lookup
/// without knowing how peers are reached.
#[async_trait::async_trait]
pub trait DhtRpc: Send + Sync + 'static {
    /// Returns `None` if the peer could not be reached or did not answer.
    async fn request(&self, peer: PeerInfo, request: DhtRequest) -> Option<DhtReply>;
}

/// The Kademlia DHT engine.
pub struct DhtEngine {
    identity: Arc<Identity>,
    local_id: NodeId,
    config: DhtConfig,
    routing_table: Arc<RwLock<RoutingTable>>,
    /// Signed records, keyed by the NodeId each one describes.
    store: Arc<RwLock<HashMap<NodeId, DhtRecord>>>,
    next_request_id: AtomicU64,
}

impl DhtEngine {
    pub fn new(identity: Arc<Identity>, config: DhtConfig) -> Self {
        let local_id = identity.node_id();
        let routing_table = RoutingTable::new(local_id, config.k);
        Self {
            identity,
            local_id,
            config,
            routing_table: Arc::new(RwLock::new(routing_table)),
            store: Arc::new(RwLock::new(HashMap::new())),
            next_request_id: AtomicU64::new(1),
        }
    }

    /// Get the local node ID.
    pub fn local_id(&self) -> NodeId {
        self.local_id
    }

    /// A fresh request id, unique within this process.
    pub fn next_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Add a known peer to the routing table.
    pub async fn add_peer(&self, peer: PeerInfo) {
        if peer.node_id == self.local_id {
            return;
        }
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

    /// The closest nodes to a target, as wire entries for a `FoundNodes` reply.
    async fn closest_entries(&self, target: &NodeId) -> Vec<(NodeId, SocketAddr)> {
        self.find_closest(target)
            .await
            .into_iter()
            .take(MAX_FOUND_NODES)
            .map(|p| (p.node_id, p.addr))
            .collect()
    }

    /// Build a signed record for our own address.
    pub fn self_record(&self, addr: SocketAddr) -> DhtRecord {
        DhtRecord::new_signed(&self.identity, addr, unix_now())
    }

    /// Publish our own address into the local store.
    ///
    /// Propagation to other nodes is the transport's job: it sends this record
    /// to every peer it authenticates.
    pub async fn store_self(&self, addr: SocketAddr) {
        let record = self.self_record(addr);
        if let Err(e) = self.store_record(record).await {
            debug!("DHT: could not store our own record: {}", e);
        }
    }

    /// Validate and store a record.
    ///
    /// Rejects, in this order: a bad signature or a key that does not hash to
    /// the record's NodeId; a timestamp beyond the tolerated clock skew; an
    /// already-expired record; a record no newer than one we hold (so a
    /// replayed old address cannot displace the current one); and finally a
    /// full store.
    pub async fn store_record(&self, record: DhtRecord) -> Result<NodeId, RecordRejection> {
        let node_id = record.verify()?;
        let now = unix_now();
        if record.published_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(RecordRejection::FromFuture);
        }
        if record.is_expired(now, self.config.record_ttl_secs) {
            return Err(RecordRejection::Expired);
        }

        let mut store = self.store.write().await;
        store.retain(|_, r| !r.is_expired(now, self.config.record_ttl_secs));

        if let Some(existing) = store.get(&node_id) {
            if existing.published_at >= record.published_at {
                return Err(RecordRejection::Stale);
            }
        } else if store.len() >= self.config.max_records {
            // At capacity: make room by dropping whatever is closest to
            // expiring. Refusing instead would let whoever fills the store
            // first lock everyone else out of it.
            let evict = store
                .iter()
                .min_by_key(|(_, r)| r.published_at)
                .map(|(id, _)| *id);
            match evict {
                Some(id) => {
                    store.remove(&id);
                }
                None => return Err(RecordRejection::StoreFull),
            }
        }

        store.insert(node_id, record);
        Ok(node_id)
    }

    /// Look up a record in the local store, ignoring expired entries.
    pub async fn lookup_record(&self, target: &NodeId) -> Option<DhtRecord> {
        let now = unix_now();
        let store = self.store.read().await;
        store
            .get(target)
            .filter(|r| !r.is_expired(now, self.config.record_ttl_secs))
            .cloned()
    }

    /// Look up a node's address in the local store.
    pub async fn lookup(&self, target: &NodeId) -> Option<SocketAddr> {
        self.lookup_record(target).await.map(|r| r.addr)
    }

    /// Resolve a node's address, asking the network when we do not hold it.
    ///
    /// Terminates on the first of: the record found, every one of the k closest
    /// known nodes queried with nothing closer turning up, `MAX_LOOKUP_ROUNDS`
    /// rounds, or `LOOKUP_TIMEOUT` elapsed. A peer's reply can only ever add
    /// candidates or supply a record that verifies as the target's — it cannot
    /// extend the search past these bounds.
    pub async fn iterative_find_value(
        &self,
        rpc: Arc<dyn DhtRpc>,
        target: &NodeId,
    ) -> Option<DhtRecord> {
        if let Some(record) = self.lookup_record(target).await {
            return Some(record);
        }

        // tokio's clock, not std's: the deadline is what a paused-clock test
        // advances, and it is the bound that actually binds in the field.
        let deadline = tokio::time::Instant::now() + LOOKUP_TIMEOUT;
        let mut candidates = self.find_closest(target).await;
        let mut queried: HashSet<NodeId> = HashSet::new();
        let alpha = self.config.alpha.max(1);

        for _ in 0..MAX_LOOKUP_ROUNDS {
            if tokio::time::Instant::now() >= deadline {
                break;
            }

            let batch: Vec<PeerInfo> = candidates
                .iter()
                .filter(|p| !queried.contains(&p.node_id))
                .take(alpha)
                .cloned()
                .collect();
            if batch.is_empty() {
                break;
            }

            // No request may outlive the lookup's own deadline, so a round
            // started just before it cannot run on for another REQUEST_TIMEOUT.
            let request_deadline = deadline.min(tokio::time::Instant::now() + REQUEST_TIMEOUT);
            let mut tasks = JoinSet::new();
            for peer in batch {
                queried.insert(peer.node_id);
                let rpc = rpc.clone();
                let request = DhtRequest {
                    request_id: self.next_request_id(),
                    body: DhtRequestBody::FindValue { key: *target },
                };
                tasks.spawn(async move {
                    tokio::time::timeout_at(request_deadline, rpc.request(peer, request))
                        .await
                        .ok()
                        .flatten()
                });
            }

            let mut discovered: Vec<PeerInfo> = Vec::new();
            while let Ok(Some(joined)) = tokio::time::timeout_at(deadline, tasks.join_next()).await
            {
                let Ok(Some(reply)) = joined else { continue };
                match reply.body {
                    DhtReplyBody::FoundValue { record } => {
                        // A peer may answer with any record it likes. It counts
                        // only if it belongs to the target *and* passes the
                        // same checks a `Store` would — signature, clock skew,
                        // TTL and no rollback. Returning a record the store
                        // refused would hand the caller an address the node
                        // itself considers invalid.
                        if record.node_id() != *target {
                            debug!("DHT: answer for {} was a record for another node", target);
                            continue;
                        }
                        match self.store_record(record.clone()).await {
                            Ok(_) => return Some(record),
                            Err(RecordRejection::Stale) => {
                                // Another lookup for the same node cached an
                                // at-least-as-new record while this one was in
                                // flight. That answer is just as good as ours,
                                // and reporting "not found" because of it
                                // would make concurrent lookups fail at random.
                                if let Some(current) = self.lookup_record(target).await {
                                    return Some(current);
                                }
                            }
                            Err(e) => {
                                debug!("DHT: discarding an unacceptable record: {}", e);
                            }
                        }
                    }
                    DhtReplyBody::FoundNodes { nodes } => {
                        for (node_id, addr) in nodes {
                            if node_id == self.local_id || queried.contains(&node_id) {
                                continue;
                            }
                            discovered.push(PeerInfo {
                                node_id,
                                addr,
                                last_seen: Instant::now(),
                            });
                        }
                    }
                    _ => {}
                }
            }

            for peer in discovered {
                if !candidates.iter().any(|c| c.node_id == peer.node_id) {
                    candidates.push(peer);
                }
            }
            candidates.sort_by_key(|p| xor_distance(&p.node_id, target));
            candidates.truncate(self.config.k);
        }

        None
    }

    /// Handle an incoming DHT request from an authenticated peer.
    ///
    /// `peer` comes from the transport's completed handshake, never from the
    /// message body: a self-asserted sender would just be a way to poison the
    /// routing table with addresses the sender does not own.
    pub async fn handle_request(&self, peer: PeerInfo, request: DhtRequest) -> DhtReply {
        self.add_peer(peer).await;
        let body = match request.body {
            DhtRequestBody::Ping => DhtReplyBody::Pong,
            DhtRequestBody::FindNode { target } => DhtReplyBody::FoundNodes {
                nodes: self.closest_entries(&target).await,
            },
            DhtRequestBody::FindValue { key } => match self.lookup_record(&key).await {
                Some(record) => DhtReplyBody::FoundValue { record },
                None => DhtReplyBody::FoundNodes {
                    nodes: self.closest_entries(&key).await,
                },
            },
            DhtRequestBody::Store { record } => match self.store_record(record).await {
                Ok(_) => DhtReplyBody::Stored,
                Err(e) => {
                    debug!("DHT: refused a record: {}", e);
                    DhtReplyBody::Rejected
                }
            },
        };
        DhtReply {
            request_id: request.request_id,
            body,
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

    /// Number of unexpired records held.
    pub async fn record_count(&self) -> usize {
        let now = unix_now();
        let store = self.store.read().await;
        store
            .values()
            .filter(|r| !r.is_expired(now, self.config.record_ttl_secs))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Mutex;

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    fn engine() -> DhtEngine {
        DhtEngine::new(Arc::new(Identity::generate()), DhtConfig::default())
    }

    fn peer_info(node_id: NodeId, port: u16) -> PeerInfo {
        PeerInfo {
            node_id,
            addr: make_addr(port),
            last_seen: Instant::now(),
        }
    }

    fn request(body: DhtRequestBody) -> DhtRequest {
        DhtRequest {
            request_id: 7,
            body,
        }
    }

    #[tokio::test]
    async fn test_ping_is_answered_and_the_peer_is_learned() {
        let engine = engine();
        let sender = Identity::generate().node_id();
        let reply = engine
            .handle_request(peer_info(sender, 5000), request(DhtRequestBody::Ping))
            .await;
        assert_eq!(reply.request_id, 7);
        assert!(matches!(reply.body, DhtReplyBody::Pong));
        assert_eq!(engine.peer_count().await, 1);
    }

    #[tokio::test]
    async fn test_find_node_returns_known_peers() {
        let engine = engine();
        for i in 0..5 {
            engine
                .add_peer(peer_info(Identity::generate().node_id(), 5000 + i))
                .await;
        }
        let reply = engine
            .handle_request(
                peer_info(Identity::generate().node_id(), 6000),
                request(DhtRequestBody::FindNode {
                    target: Identity::generate().node_id(),
                }),
            )
            .await;
        match reply.body {
            DhtReplyBody::FoundNodes { nodes } => assert!(!nodes.is_empty()),
            other => panic!("unexpected {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_store_then_find_value_returns_the_record() {
        let engine = engine();
        let publisher = Identity::generate();
        let record = DhtRecord::new_signed(&publisher, make_addr(7000), unix_now());

        let reply = engine
            .handle_request(
                peer_info(Identity::generate().node_id(), 6000),
                request(DhtRequestBody::Store {
                    record: record.clone(),
                }),
            )
            .await;
        assert!(matches!(reply.body, DhtReplyBody::Stored));

        let reply = engine
            .handle_request(
                peer_info(Identity::generate().node_id(), 6001),
                request(DhtRequestBody::FindValue {
                    key: publisher.node_id(),
                }),
            )
            .await;
        match reply.body {
            DhtReplyBody::FoundValue { record: got } => assert_eq!(got, record),
            other => panic!("unexpected {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_find_value_falls_back_to_closest_nodes() {
        let engine = engine();
        engine
            .add_peer(peer_info(Identity::generate().node_id(), 5000))
            .await;
        let reply = engine
            .handle_request(
                peer_info(Identity::generate().node_id(), 6000),
                request(DhtRequestBody::FindValue {
                    key: Identity::generate().node_id(),
                }),
            )
            .await;
        assert!(matches!(reply.body, DhtReplyBody::FoundNodes { .. }));
    }

    #[tokio::test]
    async fn test_a_store_request_with_a_forged_record_is_rejected() {
        let engine = engine();
        let victim = Identity::generate();
        let mut record = DhtRecord::new_signed(&victim, make_addr(7000), unix_now());
        // The attacker rewrites the victim's address to point at itself.
        record.addr = make_addr(31337);

        let reply = engine
            .handle_request(
                peer_info(Identity::generate().node_id(), 6000),
                request(DhtRequestBody::Store {
                    record: record.clone(),
                }),
            )
            .await;
        assert!(
            matches!(reply.body, DhtReplyBody::Rejected),
            "an unsigned address claim must not be stored"
        );
        assert_eq!(engine.record_count().await, 0);
        assert_eq!(
            engine.store_record(record).await,
            Err(RecordRejection::BadSignature)
        );
    }

    #[tokio::test]
    async fn test_an_expired_record_is_refused_and_never_returned() {
        let engine = engine();
        let publisher = Identity::generate();
        let stale = DhtRecord::new_signed(
            &publisher,
            make_addr(7000),
            unix_now() - RECORD_TTL_SECS - 1,
        );
        assert_eq!(
            engine.store_record(stale).await,
            Err(RecordRejection::Expired)
        );
        assert!(engine.lookup_record(&publisher.node_id()).await.is_none());
    }

    #[tokio::test]
    async fn test_a_future_dated_record_is_refused() {
        let engine = engine();
        let publisher = Identity::generate();
        let record = DhtRecord::new_signed(
            &publisher,
            make_addr(7000),
            unix_now() + MAX_CLOCK_SKEW_SECS + 60,
        );
        assert_eq!(
            engine.store_record(record).await,
            Err(RecordRejection::FromFuture)
        );
    }

    #[tokio::test]
    async fn test_a_replayed_older_record_cannot_displace_the_current_one() {
        let engine = engine();
        let publisher = Identity::generate();
        let now = unix_now();
        let old = DhtRecord::new_signed(&publisher, make_addr(7000), now - 100);
        let new = DhtRecord::new_signed(&publisher, make_addr(7001), now);

        engine.store_record(new).await.unwrap();
        assert_eq!(
            engine.store_record(old).await,
            Err(RecordRejection::Stale),
            "replaying a captured older record must not roll the address back"
        );
        assert_eq!(
            engine.lookup(&publisher.node_id()).await,
            Some(make_addr(7001))
        );
    }

    #[tokio::test]
    async fn test_the_record_store_is_capped() {
        let engine = DhtEngine::new(
            Arc::new(Identity::generate()),
            DhtConfig {
                max_records: 4,
                ..DhtConfig::default()
            },
        );
        let now = unix_now();
        for i in 0..20u16 {
            let publisher = Identity::generate();
            // Ascending timestamps, so the oldest is always the eviction target.
            let record =
                DhtRecord::new_signed(&publisher, make_addr(7000 + i), now - 100 + i as u64);
            engine.store_record(record).await.unwrap();
        }
        assert_eq!(engine.record_count().await, 4);
    }

    /// A fake network of real engines. Peers in `black_holes` never answer.
    struct FakeNetwork {
        /// Who the requests come from, so the engines being queried learn the
        /// caller rather than a fresh stranger on every call.
        caller: NodeId,
        engines: HashMap<NodeId, Arc<DhtEngine>>,
        black_holes: HashSet<NodeId>,
        requests: Mutex<usize>,
    }

    impl FakeNetwork {
        fn new(
            caller: NodeId,
            engines: HashMap<NodeId, Arc<DhtEngine>>,
            black_holes: HashSet<NodeId>,
        ) -> Self {
            Self {
                caller,
                engines,
                black_holes,
                requests: Mutex::new(0),
            }
        }

        fn request_count(&self) -> usize {
            *self.requests.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl DhtRpc for FakeNetwork {
        async fn request(&self, peer: PeerInfo, request: DhtRequest) -> Option<DhtReply> {
            *self.requests.lock().unwrap() += 1;
            if self.black_holes.contains(&peer.node_id) {
                // Outlives the per-request timeout without ever answering.
                tokio::time::sleep(Duration::from_secs(3600)).await;
                return None;
            }
            let engine = self.engines.get(&peer.node_id)?;
            Some(
                engine
                    .handle_request(peer_info(self.caller, 1), request)
                    .await,
            )
        }
    }

    /// A peer that answers every lookup with a valid record for the wrong node.
    struct LyingPeer {
        record: DhtRecord,
    }

    #[async_trait::async_trait]
    impl DhtRpc for LyingPeer {
        async fn request(&self, _peer: PeerInfo, request: DhtRequest) -> Option<DhtReply> {
            Some(DhtReply {
                request_id: request.request_id,
                body: DhtReplyBody::FoundValue {
                    record: self.record.clone(),
                },
            })
        }
    }

    #[tokio::test]
    async fn test_iterative_lookup_finds_a_record_two_hops_away() {
        let local = engine();

        let publisher = Identity::generate();
        let record = DhtRecord::new_signed(&publisher, make_addr(9000), unix_now());

        // The record lives on `far`, which only `near` knows about.
        let far_identity = Arc::new(Identity::generate());
        let far = Arc::new(DhtEngine::new(far_identity.clone(), DhtConfig::default()));
        far.store_record(record.clone()).await.unwrap();

        let near_identity = Arc::new(Identity::generate());
        let near = Arc::new(DhtEngine::new(near_identity.clone(), DhtConfig::default()));
        near.add_peer(peer_info(far_identity.node_id(), 2)).await;

        local.add_peer(peer_info(near_identity.node_id(), 1)).await;

        let mut engines = HashMap::new();
        engines.insert(near_identity.node_id(), near);
        engines.insert(far_identity.node_id(), far);
        let net = Arc::new(FakeNetwork::new(local.local_id(), engines, HashSet::new()));

        let found = local
            .iterative_find_value(net, &publisher.node_id())
            .await
            .expect("the record should be reachable through one referral");
        assert_eq!(found, record);
        // The result is cached, so a second lookup is answered locally.
        assert_eq!(
            local.lookup(&publisher.node_id()).await,
            Some(make_addr(9000))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_lookup_against_unresponsive_peers_stops_at_its_deadline() {
        let local = engine();
        let mut black_holes = HashSet::new();
        // More peers than the deadline allows rounds for: 20 candidates at
        // alpha 3 would need 7 rounds of 2 s, and the deadline is 10 s.
        for i in 0..24u16 {
            let id = Identity::generate().node_id();
            local.add_peer(peer_info(id, 3000 + i)).await;
            black_holes.insert(id);
        }
        let net = Arc::new(FakeNetwork::new(
            local.local_id(),
            HashMap::new(),
            black_holes,
        ));

        let started = tokio::time::Instant::now();
        let found = local
            .iterative_find_value(net.clone(), &Identity::generate().node_id())
            .await;
        assert!(found.is_none());
        let elapsed = tokio::time::Instant::now() - started;
        assert!(
            elapsed <= LOOKUP_TIMEOUT,
            "the deadline must bound the requests in flight, not just the gap \
             between rounds; took {:?}",
            elapsed
        );
        assert!(
            net.request_count() < 20,
            "the deadline, not running out of peers, must be what ended it ({} requests)",
            net.request_count()
        );
    }

    #[tokio::test]
    async fn test_a_lookup_over_a_referral_cycle_terminates() {
        // Two engines that only ever refer the caller to each other.
        let a_identity = Arc::new(Identity::generate());
        let b_identity = Arc::new(Identity::generate());
        let a = Arc::new(DhtEngine::new(a_identity.clone(), DhtConfig::default()));
        let b = Arc::new(DhtEngine::new(b_identity.clone(), DhtConfig::default()));
        a.add_peer(peer_info(b_identity.node_id(), 2)).await;
        b.add_peer(peer_info(a_identity.node_id(), 1)).await;

        let local = engine();
        local.add_peer(peer_info(a_identity.node_id(), 1)).await;

        let mut engines = HashMap::new();
        engines.insert(a_identity.node_id(), a);
        engines.insert(b_identity.node_id(), b);
        let net = Arc::new(FakeNetwork::new(local.local_id(), engines, HashSet::new()));

        let found = local
            .iterative_find_value(net.clone(), &Identity::generate().node_id())
            .await;
        assert!(found.is_none());
        // Each peer is asked exactly once: the visited set, not luck, ends it.
        assert_eq!(net.request_count(), 2);
    }

    #[tokio::test]
    async fn test_an_expired_record_from_the_network_is_not_accepted() {
        let local = engine();
        local
            .add_peer(peer_info(Identity::generate().node_id(), 1))
            .await;

        // Correctly signed, for the right node, and past its TTL. A network
        // answer has to pass the same checks a `Store` would.
        let publisher = Identity::generate();
        let net = Arc::new(LyingPeer {
            record: DhtRecord::new_signed(
                &publisher,
                make_addr(9000),
                unix_now() - RECORD_TTL_SECS - 1,
            ),
        });

        let target = publisher.node_id();
        assert!(
            local.iterative_find_value(net, &target).await.is_none(),
            "an expired record must not answer a lookup"
        );
        assert!(local.lookup(&target).await.is_none());
    }

    #[tokio::test]
    async fn test_a_future_dated_record_from_the_network_is_not_accepted() {
        let local = engine();
        local
            .add_peer(peer_info(Identity::generate().node_id(), 1))
            .await;

        let publisher = Identity::generate();
        let net = Arc::new(LyingPeer {
            record: DhtRecord::new_signed(
                &publisher,
                make_addr(9000),
                unix_now() + MAX_CLOCK_SKEW_SECS + 600,
            ),
        });

        let target = publisher.node_id();
        assert!(
            local.iterative_find_value(net, &target).await.is_none(),
            "a record dated past the clock-skew tolerance must not answer a lookup"
        );
        assert!(local.lookup(&target).await.is_none());
    }

    #[tokio::test]
    async fn test_a_fresh_record_from_the_network_is_accepted() {
        // The control for the two tests above: the same path, with a record
        // that is actually valid, must succeed.
        let local = engine();
        local
            .add_peer(peer_info(Identity::generate().node_id(), 1))
            .await;

        let publisher = Identity::generate();
        let record = DhtRecord::new_signed(&publisher, make_addr(9000), unix_now());
        let net = Arc::new(LyingPeer {
            record: record.clone(),
        });

        assert_eq!(
            local
                .iterative_find_value(net, &publisher.node_id())
                .await
                .as_ref(),
            Some(&record)
        );
    }

    /// Answers a lookup after first caching the record in the engine itself,
    /// which is what a second concurrent lookup for the same node looks like.
    struct ConcurrentPeer {
        engine: Arc<DhtEngine>,
        record: DhtRecord,
    }

    #[async_trait::async_trait]
    impl DhtRpc for ConcurrentPeer {
        async fn request(&self, _peer: PeerInfo, request: DhtRequest) -> Option<DhtReply> {
            self.engine.store_record(self.record.clone()).await.ok();
            Some(DhtReply {
                request_id: request.request_id,
                body: DhtReplyBody::FoundValue {
                    record: self.record.clone(),
                },
            })
        }
    }

    #[tokio::test]
    async fn test_a_lookup_raced_by_another_returns_the_cached_record() {
        let local = Arc::new(engine());
        local
            .add_peer(peer_info(Identity::generate().node_id(), 1))
            .await;

        let publisher = Identity::generate();
        let record = DhtRecord::new_signed(&publisher, make_addr(9000), unix_now());
        let net = Arc::new(ConcurrentPeer {
            engine: local.clone(),
            record: record.clone(),
        });

        // Our own store already holds the answer by the time we try to store
        // it, so `store_record` says `Stale`. Returning None there would make
        // two concurrent lookups for the same node fail at random.
        assert_eq!(
            local
                .iterative_find_value(net, &publisher.node_id())
                .await
                .as_ref(),
            Some(&record)
        );
    }

    #[tokio::test]
    async fn test_a_record_for_another_node_is_not_accepted_as_the_answer() {
        let local = engine();
        let liar_id = Identity::generate().node_id();
        local.add_peer(peer_info(liar_id, 1)).await;

        // Perfectly valid record — for the liar's own address, not the target's.
        let liar_identity = Identity::generate();
        let net = Arc::new(LyingPeer {
            record: DhtRecord::new_signed(&liar_identity, make_addr(31337), unix_now()),
        });

        let target = Identity::generate().node_id();
        assert!(
            local.iterative_find_value(net, &target).await.is_none(),
            "a signed record belonging to someone else must not answer the lookup"
        );
        assert!(
            local.lookup(&target).await.is_none(),
            "and it must never be cached under the target's id"
        );
    }
}
