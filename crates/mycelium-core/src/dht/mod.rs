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

pub mod marks;
pub mod record;
pub mod routing_table;
pub mod rpc;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, Mutex, OnceCell, RwLock};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use mycelium_crypto::identity::Identity;
use mycelium_protocol::types::NodeId;

use marks::{Admitted, Mark, MarkStore, MarkStoreError, MarkTable, MemoryMarkStore};
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
    /// Hard cap on high-water marks. Twice `max_records`, so a full store's
    /// worth of records can rotate once inside the replay window without
    /// pressure. A mark has to outlive the record it guards, so this can never
    /// sensibly be smaller than the record store.
    pub mark_capacity: usize,
    /// How many marks may be held by publishers still on probation. A
    /// first-seen publisher is always admitted and takes its room from this
    /// slice, never from an established mark — see [`marks::MarkTable`].
    /// A sixteenth of the table: a mesh admitting more than this many
    /// genuinely new publishers inside one retention period is past anything
    /// the testbed has modelled (ROADMAP T-19 measures it).
    pub mark_first_seen_reserve: usize,
    /// How long a mark is kept past the signed expiry of the newest record it
    /// has seen. Sized for the largest backward wall-clock correction a device
    /// plausibly makes — an NTP step after a flat battery.
    pub mark_retention_grace_secs: u64,
    /// How many durable mark writes may be queued before they are dropped.
    ///
    /// Dropping one costs durability, not protection: the mark is in memory
    /// and still refuses a rollback for as long as the process runs. Blocking
    /// instead would hand an attacker a way to stall admission by filling the
    /// queue. Configurable mainly so the saturation behaviour can be tested
    /// without queueing a thousand records.
    pub mark_write_queue: usize,
    /// How much of the record store one delivering peer may occupy.
    ///
    /// A sixteenth of `max_records`, so sixteen peers must cooperate to fill
    /// it. Too low throttles a supernode publishing for many peers, too high
    /// and the bound is decorative; ROADMAP T-19 measures it against the
    /// testbed.
    pub max_records_per_peer: usize,
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
            mark_capacity: 8192,
            mark_first_seen_reserve: 512,
            mark_retention_grace_secs: 86_400,
            mark_write_queue: 1024,
            max_records_per_peer: 256,
        }
    }
}

/// Where a contact's address came from.
///
/// The distinction is load-bearing: an address we dialled is reachable from
/// here, while one the peer asserts may not be. A peer behind a port forward
/// signs the port it listens on inside its own network, so letting its claim
/// replace a proven `public:443` records an unreachable `public:9736`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrSource {
    /// We dialled this address and the handshake completed.
    Dialled,
    /// The peer's own claim: an inbound socket's IP with the listen port it
    /// signed, or a referral from a third node.
    Claimed,
}

/// A peer's contact information in the DHT.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub last_seen: Instant,
    /// How `addr` was learned. See [`AddrSource`].
    pub addr_source: AddrSource,
    /// When `addr` was learned — *not* when the peer was last heard from.
    ///
    /// A live connection refreshes its contact on every DHT request it
    /// answers, and each of those refreshes carries the address that
    /// connection was made to. Dated `now`, an old channel's refresh would
    /// keep reinstating its own endpoint over a newer one.
    pub addr_proved_at: Instant,
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
    store: Arc<RwLock<HashMap<NodeId, StoredRecord>>>,
    /// The newest `published_at` ever admitted per publisher. Outlives the
    /// record it guards, which is what makes ADR-011's rollback rule true
    /// even after capacity eviction (ADR-016, T-38).
    marks: Arc<RwLock<MarkTable>>,
    /// Where the marks are persisted. In-memory unless the embedder supplies
    /// one, so a node without a database still gets rollback protection for
    /// as long as it runs.
    mark_store: Arc<dyn MarkStore>,
    /// Durable mark writes, queued rather than awaited.
    ///
    /// Admission must not await storage. It holds the mark lock, and a caller
    /// can be cancelled — a lookup has a deadline, a `Store` RPC is dropped
    /// when the transport stops — so awaiting a write there meant three
    /// different failures: a cancelled admission could skip the `put` for a
    /// record it had already installed, with no second chance because the
    /// republish then answers `Stale`; a write handed to a thread could land
    /// out of order; and a stalled backend held the lock, and with it every
    /// `Store` RPC, indefinitely.
    ///
    /// Queueing fixes all three at once. `try_send` never awaits and never
    /// cancels, the queue preserves the order the writes were issued in
    /// because every send happens under the mark lock, and a slow or stuck
    /// backend can no longer block admission.
    mark_writes: mpsc::Sender<MarkWrite>,
    /// The receiving half, taken by the first admission that spawns the
    /// writer. `DhtEngine::new` is synchronous and may be called with no
    /// runtime, so the task cannot be spawned there.
    mark_writes_rx: Mutex<Option<mpsc::Receiver<MarkWrite>>>,
    mark_writer: OnceCell<()>,
    /// Whether the persisted marks have been read, once and successfully.
    ///
    /// Admission is gated on it, so the gate has to be here rather than left
    /// to the embedder calling `restore_marks` at the right moment: dialling
    /// does not require `start()`, and a dialled peer's `Store` requests
    /// would otherwise be admitted against an empty table.
    marks_restored: OnceCell<()>,
    /// Deletions that could not be queued, or that the backend refused,
    /// folded into the next attempt.
    ///
    /// A dropped `Drop` is worse than a dropped `Put`. A lost `Put` is
    /// rewritten by the publisher's next record, but a lost delete leaves a
    /// durable row that nothing in memory points at any more — so no later
    /// sweep can target it, and repeated overflow would grow the store past
    /// `mark_capacity` within a single run. Startup reconciliation alone meant
    /// that growth persisted until the next restart.
    ///
    /// Shared with the writer task, because the two ways a deletion can be
    /// lost are the same loss: a full queue never carried it, and a backend
    /// error never applied it. Logging the second and discarding it left
    /// exactly the orphan rows this list exists to collect.
    ///
    /// Bounded, because the point is to retry cleanup rather than to become a
    /// second unbounded queue. When it is full the oldest entries go, and
    /// those are precisely the ones startup reconciliation will catch anyway.
    pending_drops: Arc<std::sync::Mutex<Vec<(NodeId, u64)>>>,
    next_request_id: AtomicU64,
}

/// Who delivered a record to us.
///
/// `store_record` is reached three ways and they are not equivalent. Our own
/// record is ours; a `Store` request carries the peer the transport
/// authenticated; a lookup answer belongs to the peer that answered it. The
/// per-peer admission bound needs that distinction, and ADR-016's note was
/// right that `store_record` itself had no way to know — the authenticated
/// identity exists one layer out and simply was not passed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordSource {
    /// Our own record. Exempt from the bound: refusing to publish ourselves
    /// because peers have filled the store would be self-defeating.
    Local,
    /// Delivered by this authenticated peer.
    Peer(NodeId),
}

impl RecordSource {
    fn peer(&self) -> Option<NodeId> {
        match self {
            RecordSource::Local => None,
            RecordSource::Peer(id) => Some(*id),
        }
    }
}

/// A record and who handed it to us.
#[derive(Debug, Clone)]
pub struct StoredRecord {
    pub record: DhtRecord,
    /// `None` for our own. Kept so the per-peer bound can be counted by
    /// scanning, rather than by maintaining counters that replacement and
    /// eviction can drift out of step — a hazard ADR-016's note calls out
    /// explicitly. The store holds at most `max_records` entries, so the scan
    /// is cheap and cannot be wrong.
    pub from: Option<NodeId>,
}

/// A durable mark write, queued for the writer task.
#[derive(Debug)]
enum MarkWrite {
    /// Write this mark. See [`MarkStore::put`] — the whole mark, conditional on
    /// the stored one not being newer, so a replay is harmless and a lost write
    /// is repaired by the next one.
    Put(NodeId, Mark),
    /// Drop these ids, each conditional on its mark not having moved.
    Drop(Vec<(NodeId, u64)>),
    /// Answer once every write queued before this one has been applied.
    ///
    /// The queue is FIFO, so this is an exact barrier rather than a guess at
    /// when the writer has caught up.
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// How long [`DhtEngine::flush_marks`] waits for the writer to drain.
const MARK_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// How many deferred mark deletions are remembered for retry.
const MAX_PENDING_DROPS: usize = 4096;

/// Remember deletions that could not be applied, within the bound.
///
/// One function for both callers, because a deletion lost to a full queue and
/// one lost to a backend error are the same loss, and the bound has to be
/// enforced in one place or not at all.
fn defer_mark_drops(pending: &std::sync::Mutex<Vec<(NodeId, u64)>>, ids: Vec<(NodeId, u64)>) {
    if ids.is_empty() {
        return;
    }
    if let Ok(mut pending) = pending.lock() {
        pending.extend(ids);
        let overflow = pending.len().saturating_sub(MAX_PENDING_DROPS);
        if overflow > 0 {
            pending.drain(..overflow);
        }
    }
}

/// Apply one queued batch of mark deletions.
///
/// **A deletion never erases a mark the table holds.** The in-memory table is
/// the authority on what is live, and it is consulted *here*, where the delete
/// is applied, rather than where it was queued — because those are different
/// moments and every way an id can re-enter the table has to be covered:
///
/// * Admission queues an eviction's `Drop` before the re-admission's `Put`,
///   so queue order alone covers that case.
/// * A deletion that could not be queued waits in `pending_drops` and is
///   re-sent later, by which time the id may have been re-admitted.
/// * **Restoration adopts marks without queueing a `Put` at all**, so a
///   `Drop` already in flight for an adopted id applies afterwards with
///   nothing left to repair it. An equal `published_at` makes the conditional
///   delete unable to tell the restored row from the one it meant to remove,
///   so the mark is erased and rollback protection is lost at the next
///   restart.
///
/// Deciding at the point of application covers all three with one rule. The
/// alternative — cancelling pending deletions at each point an id can arrive —
/// is what left the third uncovered, because restoration arrives without
/// writing anything.
async fn apply_mark_drop(
    store: &Arc<dyn MarkStore>,
    marks: &Arc<RwLock<MarkTable>>,
    pending: &std::sync::Mutex<Vec<(NodeId, u64)>>,
    ids: Vec<(NodeId, u64)>,
) -> Result<(), MarkStoreError> {
    let doomed: Vec<(NodeId, u64)> = {
        // Only ever a read, and the two places that take the write lock hold
        // it across no awaits at all, so the writer cannot be what blocks
        // admission.
        let held = marks.read().await;
        ids.into_iter()
            .filter(|(id, _)| held.get(id).is_none())
            .collect()
    };
    if doomed.is_empty() {
        return Ok(());
    }
    let outcome = store.remove_not_newer(&doomed).await;
    if outcome.is_err() {
        // The rows are still there with nothing in memory pointing at them,
        // which is precisely the orphan this list exists to collect. Logging
        // the error and discarding the ids left them unreachable by any later
        // sweep.
        defer_mark_drops(pending, doomed);
    }
    outcome
}

impl DhtEngine {
    /// Build an engine whose marks live only in memory.
    ///
    /// Rollback protection then lasts as long as the process does. A node with
    /// a database should use [`DhtEngine::with_mark_store`]: on a phone the
    /// daemon is stopped whenever the OS decides, so in-memory marks would
    /// rarely be more than a few hours old (ADR-016).
    pub fn new(identity: Arc<Identity>, config: DhtConfig) -> Self {
        Self::with_mark_store(identity, config, Arc::new(MemoryMarkStore::default()))
    }

    /// Build an engine that persists its marks through `mark_store`.
    ///
    /// The marks already in that store are adopted by
    /// [`DhtEngine::restore_marks`], which the embedder calls once the runtime
    /// is up — loading is async and this is not.
    pub fn with_mark_store(
        identity: Arc<Identity>,
        config: DhtConfig,
        mark_store: Arc<dyn MarkStore>,
    ) -> Self {
        let local_id = identity.node_id();
        let routing_table = RoutingTable::new(local_id, config.k);
        // Graduation age is derived inside the table as the full replay
        // window, so there is no separate figure to configure or get wrong.
        let marks = MarkTable::new(
            config.mark_capacity,
            config.mark_first_seen_reserve,
            config.mark_retention_grace_secs,
            config.record_ttl_secs,
            Vec::new(),
        );
        let (mark_writes, mark_writes_rx) = mpsc::channel(config.mark_write_queue.max(1));
        Self {
            identity,
            local_id,
            config,
            routing_table: Arc::new(RwLock::new(routing_table)),
            store: Arc::new(RwLock::new(HashMap::new())),
            marks: Arc::new(RwLock::new(marks)),
            mark_store,
            mark_writes,
            mark_writes_rx: Mutex::new(Some(mark_writes_rx)),
            mark_writer: OnceCell::new(),
            marks_restored: OnceCell::new(),
            pending_drops: Arc::new(std::sync::Mutex::new(Vec::new())),
            next_request_id: AtomicU64::new(1),
        }
    }

    /// Start the durable mark writer, once.
    ///
    /// Spawned here rather than in the constructor because that is synchronous
    /// and may run with no reactor — the FFI builds a transport before the
    /// runtime in one path. Called before anything is queued, and before the
    /// mark lock is taken, so a cancellation here cannot interrupt a write.
    async fn ensure_mark_writer(&self) {
        self.mark_writer
            .get_or_init(|| async {
                let Some(rx) = self.mark_writes_rx.lock().await.take() else {
                    return;
                };
                let store = self.mark_store.clone();
                let marks = self.marks.clone();
                let pending = self.pending_drops.clone();
                tokio::spawn(async move {
                    let mut rx = rx;
                    // Ends when the engine is dropped and the sender with it.
                    while let Some(write) = rx.recv().await {
                        let outcome = match write {
                            MarkWrite::Put(id, mark) => store.put(id, mark).await,
                            MarkWrite::Drop(ids) => {
                                apply_mark_drop(&store, &marks, &pending, ids).await
                            }
                            MarkWrite::Flush(reply) => {
                                // Everything queued earlier has been applied.
                                let _ = reply.send(());
                                Ok(())
                            }
                        };
                        if let Err(e) = outcome {
                            warn!("DHT: a high-water mark write failed: {}", e);
                        }
                    }
                });
            })
            .await;
    }

    /// Queue a durable mark write.
    ///
    /// Never awaits, so it cannot be a cancellation point, and never blocks on
    /// a slow backend. A full queue drops the write and says so: the mark is
    /// still in memory, so protection holds for this run and only durability
    /// across a restart is lost.
    fn queue_mark_write(&self, write: MarkWrite) {
        if let Err(e) = self.mark_writes.try_send(write) {
            warn!("DHT: a high-water mark is not durable: {}", e);
        }
    }

    /// Whether any deletion is waiting to be retried.
    fn has_pending_drops(&self) -> bool {
        self.pending_drops
            .lock()
            .map(|pending| !pending.is_empty())
            .unwrap_or(false)
    }

    /// Queue a batch of mark deletions, carrying forward any that an earlier
    /// attempt could not queue or apply.
    ///
    /// Deletions are retried where `Put`s are not, because a lost delete has
    /// nothing left in memory to re-issue it: see `pending_drops`.
    ///
    /// Nothing here checks whether an id has since been re-admitted. That
    /// decision belongs to [`apply_mark_drop`], which makes it when the delete
    /// actually runs — the later and therefore the only reliable moment.
    fn queue_mark_drop(&self, mut ids: Vec<(NodeId, u64)>) {
        if let Ok(mut pending) = self.pending_drops.lock() {
            ids.append(&mut pending);
        }
        if ids.is_empty() {
            return;
        }
        let count = ids.len();
        if let Err(e) = self.mark_writes.try_send(MarkWrite::Drop(ids)) {
            // Recover the ids out of the rejected message rather than cloning
            // the batch on the path that normally succeeds.
            let returned = match e {
                mpsc::error::TrySendError::Full(MarkWrite::Drop(ids))
                | mpsc::error::TrySendError::Closed(MarkWrite::Drop(ids)) => ids,
                _ => Vec::new(),
            };
            defer_mark_drops(&self.pending_drops, returned);
            debug!("DHT: deferred {} mark deletion(s) for retry", count);
        }
    }

    /// Wait until every mark write queued so far has been applied.
    ///
    /// The writer is a detached task, so an orderly shutdown that simply drops
    /// the runtime discards whatever it had not reached — losing marks with no
    /// storage error to show for it, and reopening rollback at the next start.
    /// Call this before teardown. Bounded, so a stuck backend delays shutdown
    /// by at most `MARK_FLUSH_TIMEOUT` rather than hanging it.
    /// Returns whether the writer caught up.
    ///
    /// A caller that is about to replace this engine with another over the
    /// same backend needs the answer: two engines have two independent writers
    /// and no ordering between them, so one engine's pending eviction can land
    /// after the other's restoration and erase a mark it had adopted. A
    /// confirmed drain is what establishes that order.
    pub async fn flush_marks(&self) -> bool {
        let drained = self.drain_marks().await;
        if !drained {
            warn!("DHT: the mark writer did not drain in time");
        }
        drained
    }

    /// Wait for the writer, reporting whether it caught up.
    ///
    /// Restoration needs the answer rather than a log line: it reads the store
    /// and has to know that what it reads is the result of every write already
    /// issued.
    async fn drain_marks(&self) -> bool {
        if self.mark_writer.get().is_none() {
            // Nothing was ever queued, so there is nothing to wait for.
            return true;
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        // `send`, not `try_send`: a full queue is exactly when there is most
        // to lose, and returning straight away there discarded writes the
        // backend could have drained well inside the timeout. Waiting for
        // space and for the acknowledgement share one bound, so a stuck
        // backend still cannot hang teardown.
        let drained = tokio::time::timeout(MARK_FLUSH_TIMEOUT, async {
            self.mark_writes.send(MarkWrite::Flush(tx)).await.ok()?;
            rx.await.ok()
        })
        .await;
        matches!(drained, Ok(Some(())))
    }

    /// Adopt the persisted marks, eagerly.
    ///
    /// Called by the embedder at startup, which is where it belongs: the load
    /// is then paid once, before anything is served. It is not the only route,
    /// because it cannot be — see [`DhtEngine::ensure_marks_restored`].
    ///
    /// Marks already in memory win: this only ever adds what the store knows
    /// and we do not, so calling it late cannot lower a high-water mark.
    pub async fn restore_marks(&self) {
        if let Err(e) = self.ensure_marks_restored().await {
            warn!("DHT: high-water marks could not be restored: {}", e);
        }
    }

    /// Restore once, and refuse to pretend it happened if it failed.
    ///
    /// **Admission is gated on this**, not on the embedder having called
    /// [`DhtEngine::restore_marks`] first. The transport restores in `start()`,
    /// but dialling does not require `start()` — `connect_to` installs a read
    /// loop that serves `Store` requests — so records could be admitted and
    /// served against an empty table, which is the defect the table exists to
    /// remove. Gating here covers every route in.
    ///
    /// `get_or_try_init` rather than `get_or_init`: a failed load must not be
    /// recorded as a restoration, or one unreadable moment would disable the
    /// protection for the life of the process. The next admission retries, and
    /// refuses until one succeeds.
    async fn ensure_marks_restored(&self) -> Result<(), MarkStoreError> {
        self.marks_restored
            .get_or_try_init(|| self.restore_marks_once())
            .await
            .map(|_| ())
    }

    async fn restore_marks_once(&self) -> Result<(), MarkStoreError> {
        self.ensure_mark_writer().await;

        // Drain the writer before reading the store, and **refuse to restore
        // if it does not drain**.
        //
        // `apply_mark_drop` reads the mark table and then awaits the backend,
        // so a delete already past that check can be executing while this
        // function loads and adopts — erasing a row the table now holds, with
        // adoption writing nothing of its own to repair it. Draining first
        // removes the possibility rather than repairing the consequence: once
        // the writer has caught up, nothing is queued and nothing is in
        // flight, and no new write can appear, because the only thing that
        // issues one is admission and admission is gated on *this* call. The
        // `OnceCell` serialises the waiters, so there is no second restoration
        // either.
        //
        // If it does not drain, this is an error rather than a warning. The
        // alternative — restore anyway and write the adopted marks back as a
        // repair — makes the repair load-bearing on the one path where the
        // queue is most likely to be full and the write most likely to be
        // dropped. Refusing is the direction ADR-016 chooses, and it is
        // retried by the next admission.
        //
        // In practice this cannot trigger at startup: nothing has been queued
        // yet, so the drain is one round-trip through an idle writer.
        if !self.drain_marks().await {
            return Err(MarkStoreError(
                "the mark writer did not drain before restoration".to_string(),
            ));
        }

        // Bounded, for the same reason the drain is. This is awaited from
        // `start()`, which holds the transport's `started` lock, and from a
        // `Store` request, whose connection holds a socket and a slot permit
        // that `stop()` waits on — so an unbounded load could outlast a
        // shutdown. A load that does not answer is treated as one that failed:
        // admission is refused and the next attempt retries.
        let loaded = match tokio::time::timeout(MARK_FLUSH_TIMEOUT, self.mark_store.load()).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(MarkStoreError(
                    "the mark store did not answer in time".to_string(),
                ))
            }
        };
        if loaded.is_empty() {
            return Ok(());
        }
        let count = loaded.len();
        // Kept before `adopt` takes ownership, so the rows that were *not*
        // adopted can be identified afterwards.
        let offered: Vec<(NodeId, u64)> = loaded
            .iter()
            .map(|(id, m)| (*id, m.newest_published_at))
            .collect();

        // Both locks before anything is mutated. Adopting first and *then*
        // awaiting the store lock left a window: a cancellation there — this
        // runs from the transport's startup, which can be dropped — adopted
        // the marks while leaving the records they supersede resident and
        // servable, which is the state this function exists to prevent.
        // Nothing between here and the end of the function awaits.
        let mut marks = self.marks.write().await;
        let mut store = self.store.write().await;

        // Expired marks are filtered *before* capacity is applied. Adoption
        // takes established marks first, so a table-full of expired
        // established rows — after a capacity reduction, or orphans that
        // accumulated — could crowd out a live probationary mark, which the
        // reconciliation below would then delete for good. Order matters:
        // capacity should choose among marks that are still inside their
        // replay window, not among all the rows that happen to exist.
        let now = unix_now();
        let (live, expired): (Vec<_>, Vec<_>) = loaded
            .into_iter()
            .partition(|(_, mark)| marks.retains(mark, now));
        if !expired.is_empty() {
            debug!("DHT: {} restored marks had already expired", expired.len());
        }
        marks.adopt(live);

        // Rows the table did not take are orphans: nothing in memory points
        // at them any more, so no later sweep will ever revisit them. They
        // accumulate — a mark beyond capacity, or one whose `Drop` was lost to
        // a full queue — and would grow the store past `mark_capacity` without
        // bound. Startup is where both sides are in hand, so it reconciles.
        // Everything offered that the table does not now hold: expired marks,
        // rows beyond capacity, and rows whose deletion was lost earlier.
        let orphans: Vec<(NodeId, u64)> = offered
            .into_iter()
            .filter(|(id, _)| marks.get(id).is_none())
            .collect();
        if !orphans.is_empty() {
            debug!("DHT: dropping {} orphaned high-water marks", orphans.len());
            self.queue_mark_drop(orphans);
        }

        // A resident record below its restored mark is one we *know* has been
        // superseded. It was admitted before the marks were read, so it never
        // faced the rollback check — and leaving it would mean `lookup_record`
        // and `FindValue` keep answering with an address ADR-011 says is
        // stale, which is the whole outcome this protection exists to prevent.
        let superseded: Vec<NodeId> = store
            .iter()
            .filter(|(id, held)| {
                marks
                    .newest_for(id)
                    .is_some_and(|newest| held.record.published_at < newest)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &superseded {
            store.remove(id);
        }
        if !superseded.is_empty() {
            debug!(
                "DHT: dropped {} resident record(s) a restored mark supersedes",
                superseded.len()
            );
        }
        debug!("DHT: restored {} high-water marks", count);
        Ok(())
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

    /// Test hook: hold the record store's write lock, so a caller that needs
    /// it parks. Used to stop `start()` inside the window between its bind
    /// and the registration of its background tasks.
    #[cfg(test)]
    pub(crate) async fn hold_store_for_test(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, HashMap<NodeId, StoredRecord>> {
        self.store.write().await
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
        if let Err(e) = self.store_record(record, RecordSource::Local).await {
            debug!("DHT: could not store our own record: {}", e);
        }
    }

    /// Validate and store a record.
    ///
    /// Rejects, in this order: a bad signature or a key that does not hash to
    /// the record's NodeId; a timestamp beyond the tolerated clock skew; an
    /// already-expired record; a wildcard address, which nothing can dial; a
    /// record no newer than one we hold (so a replayed old address cannot
    /// displace the current one); and finally a full store.
    ///
    /// The order is fixed and each refusal has its own reason, so a record
    /// failing two checks always reports the earlier one (ADR-016).
    pub async fn store_record(
        &self,
        record: DhtRecord,
        from: RecordSource,
    ) -> Result<NodeId, RecordRejection> {
        let node_id = record.verify()?;
        let now = unix_now();
        if record.published_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(RecordRejection::FromFuture);
        }
        if record.is_expired(now, self.config.record_ttl_secs) {
            return Err(RecordRejection::Expired);
        }
        // Checked here and not only where we publish: the transport's refusal
        // to sign one covers our own record, while a peer's correctly signed
        // wildcard record is valid and was admitted — occupying a slot and
        // answering a `FindValue` with an address nothing can dial
        // (ADR-011's note, ADR-016).
        if record.is_wildcard_addr() {
            return Err(RecordRejection::WildcardAddress);
        }

        // One critical section, holding the mark lock across the whole
        // admission.
        //
        // Deciding under the mark lock and acting under the store lock was
        // wrong: between the two, another task could admit a newer record for
        // this id and a third could evict it at capacity, leaving a decision
        // of "not a rollback" that was true when taken and false when used —
        // and nothing resident for the `Stale` check to catch. The older
        // record went in and lookups answered with it, which is the very thing
        // ADR-016 exists to stop.
        //
        // A precondition, not a step in ADR-016's admission order: until the
        // persisted marks have been read, this node does not know what it has
        // held, so admitting anything risks accepting the replay the marks
        // would have refused. Refusing is the direction ADR-016 chooses
        // explicitly — a denial beats a silent rollback — and it is retried on
        // every admission, so a transient backend failure costs availability
        // for as long as it lasts and no longer.
        //
        // Before the mark lock, like `ensure_mark_writer`: this awaits
        // storage, and awaiting it under the lock is what rounds 1 and 2 of
        // this task removed.
        // Bounded per caller, not just per load. `get_or_try_init` serialises
        // its waiters, and a failing load takes the full bound each time — so
        // N concurrent `Store` requests could queue N bounds' worth of waiting,
        // each holding a socket and a slot permit that `stop()` waits on. The
        // outer bound is what keeps one caller's wait from being the sum of
        // everyone else's.
        match tokio::time::timeout(MARK_FLUSH_TIMEOUT, self.ensure_marks_restored()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return Err(RecordRejection::MarksUnavailable),
        }

        // Lock order is always marks → store, and nothing takes them the
        // other way round.
        //
        // Durable writes are *queued*, never awaited, so nothing inside this
        // section can be interrupted part-way: the only await left is taking
        // the store lock, and that happens before any mutation. Queueing under
        // this lock also makes the queue order the lock order, so an eviction's
        // delete can never be applied after a re-admission's put for the same
        // id — which a conditional delete alone could not distinguish when the
        // two carried the same timestamp.
        self.ensure_mark_writer().await;
        let mut marks = self.marks.write().await;
        let mut store = self.store.write().await;

        // Both locks first, and only then the clock — because everything
        // between the first reading and this point can wait: the restoration
        // gate above may have loaded the whole mark table, and either lock can
        // be contended. A record that was inside its TTL when it arrived can
        // be outside it by now, and admitting it would put an expired record
        // in the store and hand it straight back out of
        // `iterative_find_value`. Reading the clock after the *marks* lock but
        // before the store lock left the second wait uncovered.
        //
        // Both time-dependent checks are redone, not just expiry. The earlier
        // version of this reasoned that "a record acceptably dated cannot
        // become unacceptable as time moves forward" — true, and the clock can
        // move *backward*. A correction during the waits can push an incoming
        // record past the permitted future skew, and admitting it then would
        // store and serve a record this node considers future-dated.
        let now = unix_now();
        if record.published_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(RecordRejection::FromFuture);
        }
        if record.is_expired(now, self.config.record_ttl_secs) {
            return Err(RecordRejection::Expired);
        }

        // Swept here rather than on a timer, like the record expiry sweep
        // below — a node that never admits a record has no table to drain, and
        // a timer would need a task per engine.
        // Retried on this path too, not only when the sweep found something:
        // a deletion deferred earlier has nothing else to re-issue it.
        let dead = marks.sweep(now);
        if !dead.is_empty() || self.has_pending_drops() {
            self.queue_mark_drop(dead);
        }

        store.retain(|_, held| !held.record.is_expired(now, self.config.record_ttl_secs));

        // Two refusals, kept distinct because they tell the caller different
        // things. `Stale` means we hold something at least as new, so there is
        // nothing to learn. `RolledBack` means we hold nothing — the record was
        // evicted or expired out of the store — but we *remember* having held
        // something newer, which is the replay capacity eviction used to let
        // through (ADR-016).
        if let Some(existing) = store.get(&node_id) {
            if existing.record.published_at >= record.published_at {
                return Err(RecordRejection::Stale);
            }
        }
        // Checked on both paths, not only when nothing is resident: restored
        // marks can sit above a record admitted before the store was read, and
        // then a record newer than the resident one is still a rollback.
        if marks.is_rollback(&node_id, record.published_at) {
            return Err(RecordRejection::RolledBack);
        }
        // Fairness, not the rollback defence — identities are free, so a
        // bound per publisher cannot stop rotation, as ADR-016 concluded. What
        // it does stop is one delivering peer crowding out the records of
        // peers this node actually talks to.
        //
        // Counted against the authenticated peer that *delivered* the record,
        // because a bound per signer would be vacuous: the store already holds
        // at most one record per signing id. A replacement from the same peer
        // does not grow that peer's share, so it is exempt; one from a
        // different peer does, and is not.
        if let Some(deliverer) = from.peer() {
            let replacing_own = store
                .get(&node_id)
                .is_some_and(|held| held.from == Some(deliverer));
            if !replacing_own {
                let held = store
                    .values()
                    .filter(|held| held.from == Some(deliverer))
                    .count();
                if held >= self.config.max_records_per_peer {
                    return Err(RecordRejection::PublisherQuota);
                }
            }
        }
        if !store.contains_key(&node_id) && store.len() >= self.config.max_records {
            // At capacity: make room by dropping whatever is closest to
            // expiring. Refusing instead would let whoever fills the store
            // first lock everyone else out of it — and the mark above is what
            // stops that eviction being a way to roll an address back.
            let evict = store
                .iter()
                .min_by_key(|(_, held)| held.record.published_at)
                .map(|(id, _)| *id);
            match evict {
                Some(id) => {
                    store.remove(&id);
                }
                None => return Err(RecordRejection::StoreFull),
            }
        }

        let published_at = record.published_at;
        store.insert(
            node_id,
            StoredRecord {
                record,
                from: from.peer(),
            },
        );
        drop(store);

        // The mark is raised only once the record is really admitted, so a
        // record refused above cannot leave a high-water mark behind that
        // would refuse the publisher's own next attempt.
        let evicted = match marks.admit(node_id, published_at, now) {
            Admitted::FirstSeen { evicted } => evicted,
            Admitted::Refreshed => None,
        };
        // Queued in this order, and applied in it: the evicted mark's row
        // goes before the incoming mark's, so re-admitting the very id that
        // was just evicted cannot have its new row deleted by the old delete.
        if let Some(gone) = evicted {
            self.queue_mark_drop(vec![gone]);
        }
        // The table's whole mark, whether this was a first sighting or a
        // refresh. One operation rather than two: the table is the authority
        // on the publisher's current lifetime, so writing what it holds is
        // always right, and a write that is lost is repaired by the next
        // record rather than leaving a merged half-truth behind.
        if let Some(mark) = marks.get(&node_id).copied() {
            self.queue_mark_write(MarkWrite::Put(node_id, mark));
        }
        Ok(node_id)
    }

    /// The newest `published_at` we have ever admitted for this publisher,
    /// whether or not we still hold that record.
    ///
    /// The invariant worth checking against it: a resident record is never
    /// older than its own mark.
    pub async fn newest_mark_for(&self, id: &NodeId) -> Option<u64> {
        self.marks.read().await.newest_for(id)
    }

    /// Look up a record in the local store, ignoring expired entries.
    pub async fn lookup_record(&self, target: &NodeId) -> Option<DhtRecord> {
        let now = unix_now();
        let store = self.store.read().await;
        store
            .get(target)
            .filter(|held| !held.record.is_expired(now, self.config.record_ttl_secs))
            .map(|held| held.record.clone())
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
                // The answering peer travels with its answer: a record learned
                // from a lookup is attributed to whoever served it, and it was
                // simply dropped here before.
                let answered_by = peer.node_id;
                tasks.spawn(async move {
                    let reply =
                        tokio::time::timeout_at(request_deadline, rpc.request(peer, request))
                            .await
                            .ok()
                            .flatten();
                    reply.map(|reply| (answered_by, reply))
                });
            }

            let mut discovered: Vec<PeerInfo> = Vec::new();
            while let Ok(Some(joined)) = tokio::time::timeout_at(deadline, tasks.join_next()).await
            {
                let Ok(Some((answered_by, reply))) = joined else {
                    continue;
                };
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
                        // Bounded by the lookup's own deadline. Admission
                        // now awaits durable mark writes, and a stalled disk
                        // would otherwise hold a lookup open past the limit
                        // ADR-011 gives it. Cancelling here is safe because
                        // every `MarkStore` write is monotonic: a write already
                        // in flight cannot land out of order and undo one.
                        let admitted = tokio::time::timeout_at(
                            deadline,
                            self.store_record(record.clone(), RecordSource::Peer(answered_by)),
                        )
                        .await;
                        let Ok(admitted) = admitted else {
                            debug!("DHT: ran out of time admitting the answer for {}", target);
                            continue;
                        };
                        match admitted {
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
                                // A referral is another node's claim, and we
                                // learn it now.
                                addr_source: AddrSource::Claimed,
                                addr_proved_at: Instant::now(),
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
        // Taken before the peer is consumed: this is the authenticated
        // identity a delivered record is attributed to.
        let deliverer = peer.node_id;
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
            DhtRequestBody::Store { record } => match self
                .store_record(record, RecordSource::Peer(deliverer))
                .await
            {
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
            .filter(|held| !held.record.is_expired(now, self.config.record_ttl_secs))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};
    use std::sync::Mutex;

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    /// One fixed delivering peer.
    ///
    /// The tests that are not about the bound still go through the peer path
    /// rather than `Local`, so the attribution and the quota scan are
    /// exercised everywhere; the default bound is far above anything they
    /// store.
    fn from_a_peer() -> RecordSource {
        RecordSource::Peer(NodeId([0xAB; 32]))
    }

    fn engine() -> DhtEngine {
        DhtEngine::new(Arc::new(Identity::generate()), DhtConfig::default())
    }

    fn peer_info(node_id: NodeId, port: u16) -> PeerInfo {
        PeerInfo {
            node_id,
            addr: make_addr(port),
            last_seen: Instant::now(),
            addr_source: AddrSource::Dialled,
            addr_proved_at: Instant::now(),
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
            engine.store_record(record, from_a_peer()).await,
            Err(RecordRejection::BadSignature)
        );
    }

    /// The internet transport declines to *sign* a wildcard record, which
    /// protects only our own. A peer's correctly signed one was admitted,
    /// taking a slot and answering `FindValue` with an address nothing can
    /// dial (ADR-011's note, ADR-016).
    #[tokio::test]
    async fn test_a_wildcard_record_is_refused_on_admission() {
        let engine = engine();
        for addr in [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7100),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 7100),
        ] {
            let publisher = Identity::generate();
            let record = DhtRecord::new_signed(&publisher, addr, unix_now());
            // It really is a valid record otherwise: only the address is wrong.
            assert!(record.verify().is_ok());
            assert_eq!(
                engine.store_record(record, from_a_peer()).await,
                Err(RecordRejection::WildcardAddress),
                "a signed record for {} must not be admitted",
                addr
            );
            assert!(engine.lookup_record(&publisher.node_id()).await.is_none());
        }
        assert_eq!(engine.record_count().await, 0);
    }

    /// Admission order is fixed, so a record failing two checks reports the
    /// earlier one (ADR-016).
    #[tokio::test]
    async fn test_an_expired_wildcard_record_reports_expiry_not_the_address() {
        let engine = engine();
        let publisher = Identity::generate();
        let record = DhtRecord::new_signed(
            &publisher,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7101),
            unix_now() - RECORD_TTL_SECS - 1,
        );
        assert_eq!(
            engine.store_record(record, from_a_peer()).await,
            Err(RecordRejection::Expired),
            "freshness is checked before the address"
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
            engine.store_record(stale, from_a_peer()).await,
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
            engine.store_record(record, from_a_peer()).await,
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

        engine.store_record(new, from_a_peer()).await.unwrap();
        assert_eq!(
            engine.store_record(old, from_a_peer()).await,
            Err(RecordRejection::Stale),
            "replaying a captured older record must not roll the address back"
        );
        assert_eq!(
            engine.lookup(&publisher.node_id()).await,
            Some(make_addr(7001))
        );
    }

    /// T-38, end to end. A record is self-signed and identities are free, so a
    /// peer can fill the store with records for identities it generates, evict
    /// the victim's current record, and then replay the victim's older,
    /// still-fresh one. With nothing left to compare against it was admitted,
    /// and lookups answered with an address the attacker chose — exactly what
    /// ADR-011 exists to prevent (ADR-016).
    #[tokio::test]
    async fn test_a_replay_cannot_roll_back_a_record_that_was_evicted() {
        let engine = DhtEngine::new(
            Arc::new(Identity::generate()),
            DhtConfig {
                max_records: 4,
                ..DhtConfig::default()
            },
        );
        let victim = Identity::generate();
        let now = unix_now();
        // All three well inside the TTL, so nothing here turns on expiry.
        let captured = DhtRecord::new_signed(&victim, make_addr(7000), now - 200);
        let current = DhtRecord::new_signed(&victim, make_addr(7001), now - 100);

        engine.store_record(current, from_a_peer()).await.unwrap();
        assert_eq!(
            engine.lookup(&victim.node_id()).await,
            Some(make_addr(7001))
        );

        // Eviction drops whatever is closest to expiring, so records dated
        // `now` push the victim's out first.
        for i in 0..8u16 {
            let filler = Identity::generate();
            let record = DhtRecord::new_signed(&filler, make_addr(8000 + i), now);
            engine.store_record(record, from_a_peer()).await.unwrap();
        }
        assert!(
            engine.lookup(&victim.node_id()).await.is_none(),
            "the victim's record should have been evicted — otherwise this \
             proves nothing"
        );

        // The replay: correctly signed, inside its TTL, and the store holds
        // nothing for this id.
        assert_eq!(
            engine.store_record(captured, from_a_peer()).await,
            Err(RecordRejection::RolledBack),
            "a record older than one we have held must be refused even once \
             that record is gone"
        );
        assert!(
            engine.lookup(&victim.node_id()).await.is_none(),
            "and the stale address must never be served"
        );
    }

    /// **The documented exposure, pinned as a test.**
    ///
    /// ADR-011 and ADR-016 both say a mark is never evicted inside the replay
    /// window. That is true of the *established* region only. A publisher that
    /// has not yet graduated holds a probationary slot, and the reserve that
    /// guarantees a first-seen publisher is always admitted is the same
    /// reserve its own mark lives in — so enough new publishers evict it, and
    /// with the record already gone the replay lands. The attacker still pays
    /// for it: the churn has to happen inside one publisher's graduation
    /// window, and it buys a rollback only for publishers seen recently and
    /// briefly.
    ///
    /// This test asserts the gap rather than the guarantee, so a later change
    /// that claims to close it has something to flip, and so the ADR notes
    /// cannot drift back to the unqualified claim.
    /// `test_an_established_mark_survives_an_attacker_rotating_identities`
    /// covers the region that is genuinely protected.
    #[tokio::test]
    async fn test_a_probationary_mark_evicted_in_its_window_loses_its_protection() {
        let engine = DhtEngine::new(
            Arc::new(Identity::generate()),
            DhtConfig {
                // A one-mark table, so the victim is the only candidate and
                // the eviction is deterministic.
                //
                // This test used to hold two marks and admit three fillers,
                // relying on the victim being the least recently refreshed.
                // Everything here happens inside one second, so the refresh
                // times *tie* and the tie-break is the NodeId — which is
                // freshly generated, so which mark went was random. It failed
                // roughly two runs in five, and the Codex review caught it by
                // running the suite twelve times rather than once.
                mark_capacity: 1,
                mark_first_seen_reserve: 1,
                max_records: 1,
                ..DhtConfig::default()
            },
        );
        let victim = Identity::generate();
        let now = unix_now();
        let captured = DhtRecord::new_signed(&victim, make_addr(7000), now - 200);
        let current = DhtRecord::new_signed(&victim, make_addr(7001), now - 100);

        engine.store_record(current, from_a_peer()).await.unwrap();
        assert_eq!(
            engine.newest_mark_for(&victim.node_id()).await,
            Some(now - 100)
        );

        // One first-seen publisher against a table of one: the victim's mark
        // is the only thing that can make room, and it is still well inside
        // the replay window.
        let filler = Identity::generate();
        engine
            .store_record(
                DhtRecord::new_signed(&filler, make_addr(8000), now),
                from_a_peer(),
            )
            .await
            .unwrap();
        assert_eq!(
            engine.newest_mark_for(&victim.node_id()).await,
            None,
            "the probationary mark should have been evicted — otherwise this \
             test is not measuring the exposure it claims to"
        );
        assert!(engine.lookup(&victim.node_id()).await.is_none());

        // And so the replay succeeds. This is the residual, not the intent.
        engine.store_record(captured, from_a_peer()).await.expect(
            "the documented exposure: with the mark evicted there is \
                     nothing left to compare against",
        );
        assert_eq!(
            engine.lookup(&victim.node_id()).await,
            Some(make_addr(7000)),
            "and the stale address is served, which is what ADR-011 exists to \
             prevent — for a publisher the table never got to establish"
        );
    }

    /// The mark has to survive the eviction of the record it guards, which is
    /// the whole difference from ADR-011's original rule.
    #[tokio::test]
    async fn test_the_victims_own_newer_record_is_still_accepted_after_eviction() {
        let engine = DhtEngine::new(
            Arc::new(Identity::generate()),
            DhtConfig {
                max_records: 4,
                ..DhtConfig::default()
            },
        );
        let victim = Identity::generate();
        let now = unix_now();
        engine
            .store_record(
                DhtRecord::new_signed(&victim, make_addr(7001), now - 100),
                from_a_peer(),
            )
            .await
            .unwrap();
        for i in 0..8u16 {
            let filler = Identity::generate();
            engine
                .store_record(
                    DhtRecord::new_signed(&filler, make_addr(8000 + i), now),
                    from_a_peer(),
                )
                .await
                .unwrap();
        }

        // Republishing is how a node stays reachable. A mark must not turn
        // into a lockout for the publisher it protects.
        let republished = DhtRecord::new_signed(&victim, make_addr(7002), now);
        assert!(engine
            .store_record(republished, from_a_peer())
            .await
            .is_ok());
        assert_eq!(
            engine.lookup(&victim.node_id()).await,
            Some(make_addr(7002))
        );
    }

    /// A `MarkStore` that suspends on every operation.
    ///
    /// Without this the memory store never yields, so admissions run to
    /// completion one after another on any runtime and a split critical
    /// section is invisible. A real store awaits I/O, which is where the
    /// interleaving comes from.
    struct YieldingMarkStore(Arc<marks::MemoryMarkStore>);

    #[async_trait::async_trait]
    impl MarkStore for YieldingMarkStore {
        async fn load(&self) -> Result<Vec<(NodeId, marks::Mark)>, marks::MarkStoreError> {
            tokio::task::yield_now().await;
            self.0.load().await
        }
        async fn put(&self, id: NodeId, mark: marks::Mark) -> Result<(), marks::MarkStoreError> {
            tokio::task::yield_now().await;
            let r = self.0.put(id, mark).await;
            tokio::task::yield_now().await;
            r
        }
        async fn remove_not_newer(
            &self,
            ids: &[(NodeId, u64)],
        ) -> Result<(), marks::MarkStoreError> {
            tokio::task::yield_now().await;
            self.0.remove_not_newer(ids).await
        }
    }

    /// Admission used to decide under the mark lock and act under the store
    /// lock. In between, another task could admit a newer record for the same
    /// id and a third could evict it at capacity, so the decision was true
    /// when taken and false when used — and with nothing resident, the `Stale`
    /// check could not catch it either.
    ///
    /// Driven on a multi-threaded runtime through a store that suspends on
    /// every write, so admissions really do interleave. The invariant: a
    /// resident record is never older than its own mark.
    ///
    /// **This does not reproduce the race, and it was checked.** Reinstating
    /// the split critical section leaves it passing — the interleaving needs a
    /// newer record admitted *and* evicted inside one task's window between
    /// deciding and acting, which yield points do not reliably produce.
    /// Forcing it would mean test hooks in the admission path. It is kept as a
    /// cheap invariant guard, and
    /// `test_a_mark_above_the_resident_record_still_refuses_a_rollback`
    /// covers the same disagreement deterministically.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_admissions_never_leave_a_record_older_than_its_mark() {
        for round in 0..24u64 {
            let engine = Arc::new(DhtEngine::with_mark_store(
                Arc::new(Identity::generate()),
                DhtConfig {
                    max_records: 4,
                    ..DhtConfig::default()
                },
                Arc::new(YieldingMarkStore(Arc::new(
                    marks::MemoryMarkStore::default(),
                ))),
            ));
            let victim = Arc::new(Identity::generate());
            let victim_id = victim.node_id();
            let now = unix_now();

            let mut tasks = JoinSet::new();
            // Competing admissions for the one id, interleaved with pressure
            // that evicts — which is what turned a stale decision into an
            // admitted rollback.
            for i in 0..8u64 {
                let engine = engine.clone();
                let victim = victim.clone();
                let published = now - (i * 10) - round;
                tasks.spawn(async move {
                    let record =
                        DhtRecord::new_signed(&victim, make_addr(7000 + i as u16), published);
                    let _ = engine.store_record(record, from_a_peer()).await;
                });
            }
            for i in 0..8u16 {
                let engine = engine.clone();
                tasks.spawn(async move {
                    let filler = Identity::generate();
                    let record = DhtRecord::new_signed(&filler, make_addr(9000 + i), now);
                    let _ = engine.store_record(record, from_a_peer()).await;
                });
            }
            while tasks.join_next().await.is_some() {}

            let mark = engine.newest_mark_for(&victim_id).await;
            if let Some(resident) = engine.lookup_record(&victim_id).await {
                assert_eq!(
                    Some(resident.published_at),
                    mark,
                    "round {}: a resident record must be the one the mark remembers",
                    round
                );
            }
        }
    }

    /// The mark and the record store can disagree, with the mark ahead: a
    /// restored mark sits above a record admitted before the store was read,
    /// and the stale-decision race had the same shape. A record newer than
    /// what is resident is then *still* a rollback, which is why the check
    /// runs on both branches rather than only when nothing is resident.
    #[tokio::test]
    async fn test_a_mark_above_the_resident_record_still_refuses_a_rollback() {
        let publisher = Identity::generate();
        let now = unix_now();
        let store = Arc::new(marks::MemoryMarkStore::default());
        // What the durable store remembers: something newer than anything this
        // engine has admitted this run.
        store
            .put(
                publisher.node_id(),
                marks::Mark {
                    newest_published_at: now - 50,
                    first_seen: now - 1_000,
                    last_refreshed: now - 50,
                    established: false,
                },
            )
            .await
            .unwrap();

        let engine =
            DhtEngine::with_mark_store(Arc::new(Identity::generate()), DhtConfig::default(), store);

        // The record is made resident *directly*, because admission can no
        // longer produce this state: `store_record` restores the marks before
        // it admits anything, so a record can never get in ahead of the mark
        // that supersedes it. This test used to reach the state by admitting
        // first and restoring second, which is exactly the ordering the gate
        // removed. The retirement path below is therefore defence in depth
        // now rather than the only thing standing between a restored mark and
        // a stale address — and it is kept, and kept tested, for that reason.
        {
            let mut held = engine.hold_store_for_test().await;
            held.insert(
                publisher.node_id(),
                StoredRecord {
                    record: DhtRecord::new_signed(&publisher, make_addr(7000), now - 200),
                    from: Some(NodeId([0xAB; 32])),
                },
            );
        }
        engine.restore_marks().await;
        assert_eq!(
            engine.newest_mark_for(&publisher.node_id()).await,
            Some(now - 50)
        );

        // Newer than the resident record, so `Stale` does not catch it, and
        // older than the mark, so it is a rollback.
        assert_eq!(
            engine
                .store_record(
                    DhtRecord::new_signed(&publisher, make_addr(7001), now - 100),
                    from_a_peer()
                )
                .await,
            Err(RecordRejection::RolledBack),
            "a record newer than what is resident can still be a rollback"
        );
        // And the superseded record is no longer served. It was admitted
        // before the marks were read, so it never faced the rollback check;
        // leaving it resident would answer lookups with an address the
        // restored mark says is stale, which is the outcome this protection
        // exists to prevent.
        assert!(
            engine.lookup(&publisher.node_id()).await.is_none(),
            "restoration must retire a resident record below its own mark"
        );
    }

    /// Rows the table cannot hold are orphans: nothing in memory points at
    /// them, so no sweep will ever revisit them. A lost `Drop` — a full queue,
    /// a stalled backend — leaves one behind, and repeated overflow would grow
    /// the store past `mark_capacity` without bound. Startup reconciles.
    /// Capacity must choose among marks that are still inside their replay
    /// window. Adoption takes established marks first, so a table-full of
    /// *expired* established rows would crowd out a live probationary mark —
    /// and reconciliation would then delete that live mark for good.
    #[tokio::test]
    async fn test_restoration_prefers_a_live_mark_over_expired_established_ones() {
        let store = Arc::new(marks::MemoryMarkStore::default());
        let now = unix_now();
        let horizon =
            DhtConfig::default().record_ttl_secs + DhtConfig::default().mark_retention_grace_secs;

        // Two established marks, both long past their replay window.
        for i in 0..2u8 {
            store
                .put(
                    NodeId([i; 32]),
                    Mark {
                        newest_published_at: now - horizon - 10,
                        first_seen: now - horizon - 1_000,
                        last_refreshed: now - horizon - 10,
                        established: true,
                    },
                )
                .await
                .unwrap();
        }
        // And one live probationary mark.
        let live = NodeId([9u8; 32]);
        store
            .put(
                live,
                Mark {
                    newest_published_at: now,
                    first_seen: now,
                    last_refreshed: now,
                    established: false,
                },
            )
            .await
            .unwrap();

        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig {
                mark_capacity: 2,
                mark_first_seen_reserve: 1,
                ..DhtConfig::default()
            },
            store.clone(),
        );
        engine.restore_marks().await;

        assert_eq!(
            engine.newest_mark_for(&live).await,
            Some(now),
            "a live mark must not be crowded out by expired established ones"
        );
        engine.flush_marks().await;
        let held = store.load().await.expect("load");
        assert!(
            held.iter().any(|(id, _)| *id == live),
            "and it must not be reconciled away"
        );
    }

    #[tokio::test]
    async fn test_restoration_prunes_marks_the_table_cannot_hold() {
        let store = Arc::new(marks::MemoryMarkStore::default());
        let now = unix_now();
        for i in 0..6u32 {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&i.to_be_bytes());
            store
                .put(
                    NodeId(bytes),
                    Mark {
                        newest_published_at: now - i as u64,
                        first_seen: now - 1_000,
                        last_refreshed: now,
                        established: false,
                    },
                )
                .await
                .unwrap();
        }
        assert_eq!(store.load().await.expect("load").len(), 6);

        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig {
                mark_capacity: 2,
                mark_first_seen_reserve: 1,
                ..DhtConfig::default()
            },
            store.clone(),
        );
        engine.restore_marks().await;
        engine.flush_marks().await;

        assert_eq!(
            store.load().await.expect("load").len(),
            2,
            "the store must be pruned to what the table can hold"
        );
    }

    /// A `MarkStore` whose writes take real time, so the queue can actually
    /// fill.
    struct SlowMarkStore(Arc<marks::MemoryMarkStore>, Duration);

    #[async_trait::async_trait]
    impl MarkStore for SlowMarkStore {
        async fn load(&self) -> Result<Vec<(NodeId, marks::Mark)>, marks::MarkStoreError> {
            self.0.load().await
        }
        async fn put(&self, id: NodeId, mark: marks::Mark) -> Result<(), marks::MarkStoreError> {
            tokio::time::sleep(self.1).await;
            self.0.put(id, mark).await
        }
        async fn remove_not_newer(
            &self,
            ids: &[(NodeId, u64)],
        ) -> Result<(), marks::MarkStoreError> {
            tokio::time::sleep(self.1).await;
            self.0.remove_not_newer(ids).await
        }
    }

    /// A full queue is the one moment flush has most to lose, so it must wait
    /// for space rather than give up.
    ///
    /// The queue is two deep and each write takes 50 ms, so it is certainly
    /// still full when flush is called. With `try_send` the sentinel never got
    /// in and flush returned while the writes were still pending.
    #[tokio::test]
    async fn test_flush_waits_for_a_full_queue_rather_than_giving_up() {
        let store = Arc::new(marks::MemoryMarkStore::default());
        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig {
                mark_write_queue: 2,
                ..DhtConfig::default()
            },
            Arc::new(SlowMarkStore(store.clone(), Duration::from_millis(50))),
        );
        let now = unix_now();
        for i in 0..2u16 {
            let publisher = Identity::generate();
            engine
                .store_record(
                    DhtRecord::new_signed(&publisher, make_addr(7000 + i), now),
                    from_a_peer(),
                )
                .await
                .unwrap();
        }
        // Both writes are queued and the writer is still on the first one.
        assert!(
            store.load().await.expect("load").len() < 2,
            "the writer should still be behind — otherwise this proves nothing"
        );

        engine.flush_marks().await;
        assert_eq!(
            store.load().await.expect("load").len(),
            2,
            "flush must wait for queue space and for the writer to catch up"
        );
    }

    /// A lost `Drop` has nothing left in memory to re-issue it, so without a
    /// retry the row survives until the next restart — and repeated overflow
    /// grows the store past `mark_capacity` inside one run.
    #[tokio::test]
    async fn test_a_deletion_that_could_not_be_queued_is_retried() {
        let store = Arc::new(marks::MemoryMarkStore::default());
        let doomed = NodeId([9u8; 32]);
        let at = unix_now();
        store
            .put(
                doomed,
                Mark {
                    newest_published_at: at,
                    first_seen: at,
                    last_refreshed: at,
                    established: false,
                },
            )
            .await
            .unwrap();

        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig {
                mark_write_queue: 2,
                ..DhtConfig::default()
            },
            Arc::new(SlowMarkStore(store.clone(), Duration::from_millis(50))),
        );
        engine.ensure_mark_writer().await;

        // Fill the queue: two sends with no await between them, so the writer
        // has had no chance to take either.
        let filler = Mark {
            newest_published_at: at,
            first_seen: at,
            last_refreshed: at,
            established: false,
        };
        engine.queue_mark_write(MarkWrite::Put(NodeId([1u8; 32]), filler));
        engine.queue_mark_write(MarkWrite::Put(NodeId([2u8; 32]), filler));

        // The deletion cannot be queued, so it is deferred rather than lost.
        engine.queue_mark_drop(vec![(doomed, at)]);
        assert!(
            engine.has_pending_drops(),
            "a deletion that could not be queued must be remembered"
        );

        engine.flush_marks().await;
        assert!(
            store
                .load()
                .await
                .expect("load")
                .iter()
                .any(|(id, _)| *id == doomed),
            "it should still be there — the delete never reached the store"
        );

        // The next attempt carries it, as the sweep in any later admission
        // would.
        engine.queue_mark_drop(Vec::new());
        assert!(!engine.has_pending_drops());
        engine.flush_marks().await;
        assert!(
            !store
                .load()
                .await
                .expect("load")
                .iter()
                .any(|(id, _)| *id == doomed),
            "the deferred deletion must be applied on the next attempt"
        );
    }

    /// The retry list reopened what queue ordering had closed: a deferred
    /// delete applied *after* a re-admission's put erases a live mark, and an
    /// equal timestamp makes the two indistinguishable.
    ///
    /// **This passes with or without the fix, and that was checked.** Admission
    /// begins by retrying deferred deletions, so in a single-threaded run the
    /// delete is re-sent *before* the put and order is preserved anyway. What
    /// `apply_mark_drop` covers is the case that retry itself fails while the
    /// later put succeeds — space freed by the writer in between — which needs
    /// an interleaving the harness cannot force without hooks in the admission
    /// path. Kept as an invariant check on the outcome that matters: the live
    /// mark reaches the store. `test_a_queued_deletion_cannot_erase_a_restored_mark`
    /// is the deterministic test of the same rule.
    ///
    /// It does *not* assert that nothing is left pending afterwards. That was
    /// never an invariant and is now visibly not one: a deletion that cannot
    /// be queued stays pending for as long as the queue is full, and
    /// `apply_mark_drop` is what makes that safe rather than the list being
    /// empty.
    #[tokio::test]
    async fn test_a_deferred_deletion_cannot_erase_a_re_admitted_mark() {
        let store = Arc::new(marks::MemoryMarkStore::default());
        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig {
                mark_write_queue: 2,
                mark_capacity: 2,
                mark_first_seen_reserve: 1,
                max_records: 1,
                ..DhtConfig::default()
            },
            Arc::new(SlowMarkStore(store.clone(), Duration::from_millis(50))),
        );
        // Restoration up front, with the queue still empty: `store_record`
        // restores on its first call, and paying for that against a two-deep
        // queue would just be the test fighting its own fixture.
        engine.restore_marks().await;
        let now = unix_now();
        let publisher = Identity::generate();
        let id = publisher.node_id();

        // Fill the queue so the next deletion cannot be sent.
        let filler = Mark {
            newest_published_at: now,
            first_seen: now,
            last_refreshed: now,
            established: false,
        };
        engine.queue_mark_write(MarkWrite::Put(NodeId([1u8; 32]), filler));
        engine.queue_mark_write(MarkWrite::Put(NodeId([2u8; 32]), filler));

        // A deletion for this publisher is deferred.
        engine.queue_mark_drop(vec![(id, now)]);
        assert!(engine.has_pending_drops());

        // Then the very same publisher is admitted again, at the same
        // timestamp. The deferred deletion is now obsolete.
        engine.flush_marks().await;
        engine
            .store_record(
                DhtRecord::new_signed(&publisher, make_addr(7000), now),
                from_a_peer(),
            )
            .await
            .unwrap();
        engine.flush_marks().await;
        assert!(
            store
                .load()
                .await
                .expect("load")
                .iter()
                .any(|(held, _)| *held == id),
            "the live mark must survive — the retried delete would have erased it"
        );
    }

    /// Restoration adopts marks and queues no `Put` for them, so a deletion
    /// already in the queue for an adopted id applies afterwards with nothing
    /// left to repair it. The watermarks are equal — it is the same row — so
    /// the conditional delete cannot tell the restored mark from the one the
    /// delete meant to remove. The mark is erased, the in-memory table still
    /// believes it is durable, and rollback protection is gone at the next
    /// restart.
    ///
    /// Queue ordering was what covered this on the admission path, and
    /// restoration writes nothing to order against. `apply_mark_drop` decides
    /// at the point of application instead, where "does the table hold this
    /// id" is answerable however the id got there.
    ///
    /// The deletion is issued after restoration rather than before it, because
    /// in the fixed code *when* it was queued makes no difference and the
    /// ordering the finding describes cannot be forced without a hook in the
    /// writer. The invariant is the same either way: a queued deletion never
    /// erases a mark the table holds. Removing the fix fails this test.
    #[tokio::test]
    async fn test_a_queued_deletion_cannot_erase_a_restored_mark() {
        let store = Arc::new(marks::MemoryMarkStore::default());
        let restored = NodeId([0x5Au8; 32]);
        let at = unix_now();
        store
            .put(
                restored,
                Mark {
                    newest_published_at: at,
                    first_seen: at,
                    last_refreshed: at,
                    established: false,
                },
            )
            .await
            .unwrap();

        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig::default(),
            store.clone(),
        );
        engine.restore_marks().await;
        assert_eq!(
            engine.newest_mark_for(&restored).await,
            Some(at),
            "the mark should have been adopted"
        );

        // A deletion for an id the table holds. Nothing cancelled it, and
        // nothing can: it is already a message in the queue.
        engine.queue_mark_drop(vec![(restored, at)]);
        engine.flush_marks().await;

        assert!(
            store
                .load()
                .await
                .expect("load")
                .iter()
                .any(|(id, _)| *id == restored),
            "a queued deletion erased a mark the table holds — rollback \
             protection would be gone after the next restart"
        );
        assert_eq!(
            engine.newest_mark_for(&restored).await,
            Some(at),
            "the in-memory mark must be unchanged too"
        );
    }

    /// A store whose deletion announces itself and then waits to be released,
    /// so a delete can be held *inside* the backend with no timing assumptions.
    struct GatedDeleteMarkStore {
        inner: Arc<marks::MemoryMarkStore>,
        entered: Arc<tokio::sync::Semaphore>,
        release: Arc<tokio::sync::Semaphore>,
    }

    #[async_trait::async_trait]
    impl MarkStore for GatedDeleteMarkStore {
        async fn load(&self) -> Result<Vec<(NodeId, marks::Mark)>, marks::MarkStoreError> {
            self.inner.load().await
        }
        async fn put(&self, id: NodeId, mark: marks::Mark) -> Result<(), marks::MarkStoreError> {
            self.inner.put(id, mark).await
        }
        async fn remove_not_newer(
            &self,
            ids: &[(NodeId, u64)],
        ) -> Result<(), marks::MarkStoreError> {
            self.entered.add_permits(1);
            let _permit = self.release.acquire().await.ok();
            self.inner.remove_not_newer(ids).await
        }
    }

    /// `apply_mark_drop` checks the table and *then* awaits the backend, so a
    /// delete already past that check could be in flight while restoration
    /// loads and adopts — erasing a row the table now holds, which adoption
    /// writes nothing of its own to repair.
    ///
    /// Restoration therefore drains the writer first and **refuses to restore
    /// if it cannot**, rather than restoring and repairing afterwards. This
    /// test holds a delete inside the backend forever, so the drain cannot
    /// succeed, and checks that admission is refused rather than proceeding
    /// against a table it has no reason to trust.
    ///
    /// The paused clock is what makes it instant: the drain's bound is five
    /// seconds of virtual time, and with every task idle the runtime advances
    /// straight to it. No sleeps, no interleaving to orchestrate.
    #[tokio::test(start_paused = true)]
    async fn test_restoration_refuses_rather_than_race_a_delete_it_cannot_drain() {
        let inner = Arc::new(marks::MemoryMarkStore::default());
        let caught = NodeId([0x7Eu8; 32]);
        let at = unix_now();
        inner
            .put(
                caught,
                Mark {
                    newest_published_at: at,
                    first_seen: at,
                    last_refreshed: at,
                    established: false,
                },
            )
            .await
            .unwrap();

        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        // Never released: the writer stays inside the delete for good.
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig::default(),
            Arc::new(GatedDeleteMarkStore {
                inner: inner.clone(),
                entered: entered.clone(),
                release: release.clone(),
            }),
        );
        engine.ensure_mark_writer().await;

        // The table is empty, so this delete passes the held-ids check and
        // reaches the backend, where it stops.
        engine.queue_mark_drop(vec![(caught, at)]);
        let _in_flight = entered.acquire().await.expect("the delete should start");

        // Restoration cannot drain the writer, so it does not restore.
        engine.restore_marks().await;
        assert_eq!(
            engine.newest_mark_for(&caught).await,
            None,
            "restoring against an undrained writer is what this refuses to do"
        );

        // And admission is refused rather than run against a table that has
        // never been read.
        let publisher = Identity::generate();
        assert_eq!(
            engine
                .store_record(
                    DhtRecord::new_signed(&publisher, make_addr(7001), at),
                    from_a_peer()
                )
                .await,
            Err(RecordRejection::MarksUnavailable),
            "admission must not proceed on an unrestored table"
        );
    }

    /// A publisher whose mark expired and then came back must come back
    /// probationary, in the store as well as in the table.
    ///
    /// The sweep's deletion for the ended lifetime is not applied — the table
    /// holds the id again by the time the writer gets to it, and the
    /// conditional delete would spare the refreshed row anyway — so the old
    /// row is still there when the new mark is written. A merge then takes
    /// `MIN(first_seen)` and `MAX(established)` across the lifetime boundary,
    /// and the next restart restores an established publisher where the table
    /// holds a probationary one: establishment banked, not re-earned. An
    /// identity could fall silent past the whole replay window, republish, and
    /// come back protected.
    ///
    /// A first sighting therefore replaces rather than merges.
    #[tokio::test]
    async fn test_a_publisher_that_expired_and_returned_comes_back_probationary() {
        let store = Arc::new(marks::MemoryMarkStore::default());
        let publisher = Identity::generate();
        let id = publisher.node_id();
        let now = unix_now();

        // What the store holds from a lifetime that retention has ended: a
        // mark old enough that `retains` is false for it.
        let ancient = now - (RECORD_TTL_SECS + 86_400 + 600);
        store
            .put(
                id,
                Mark {
                    newest_published_at: ancient,
                    first_seen: ancient,
                    last_refreshed: ancient,
                    established: true,
                },
            )
            .await
            .unwrap();

        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig::default(),
            store.clone(),
        );
        // Restoration discards it as expired and reconciles the row away; the
        // publisher then republishes, which is a first sighting.
        engine.restore_marks().await;
        engine
            .store_record(
                DhtRecord::new_signed(&publisher, make_addr(7000), now),
                from_a_peer(),
            )
            .await
            .expect("the republished record is admitted");
        engine.flush_marks().await;

        let held = store.load().await.expect("load");
        let mark = held
            .iter()
            .find(|(held_id, _)| *held_id == id)
            .map(|(_, mark)| *mark)
            .expect("the new mark must be persisted");
        assert!(
            !mark.established,
            "establishment survived a lifetime the replay window had already \
             ended — it would be restored without being re-earned"
        );
        assert_eq!(
            mark.first_seen, now,
            "first_seen came from the ended lifetime, so graduation would be \
             measured from the wrong moment"
        );
        assert_eq!(mark.newest_published_at, now);
    }

    /// A store whose load never answers.
    struct BlockedLoadMarkStore(Arc<tokio::sync::Semaphore>);

    #[async_trait::async_trait]
    impl MarkStore for BlockedLoadMarkStore {
        async fn load(&self) -> Result<Vec<(NodeId, marks::Mark)>, marks::MarkStoreError> {
            let _permit = self.0.acquire().await.ok();
            Ok(Vec::new())
        }
        async fn put(&self, _id: NodeId, _mark: marks::Mark) -> Result<(), marks::MarkStoreError> {
            Ok(())
        }
        async fn remove_not_newer(
            &self,
            _ids: &[(NodeId, u64)],
        ) -> Result<(), marks::MarkStoreError> {
            Ok(())
        }
    }

    /// A load with no bound can outlast a shutdown.
    ///
    /// Restoration is awaited from `start()`, which holds the transport's
    /// `started` lock, and from a `Store` request, whose connection holds a
    /// socket and a slot permit that `stop()` waits on. An unbounded load
    /// there would pin both for as long as the backend stays silent. A load
    /// that does not answer is treated as one that failed — refused, and
    /// retried by the next admission.
    #[tokio::test(start_paused = true)]
    async fn test_a_mark_load_that_never_answers_is_bounded() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig::default(),
            Arc::new(BlockedLoadMarkStore(gate)),
        );
        let publisher = Identity::generate();
        let now = unix_now();
        assert_eq!(
            engine
                .store_record(
                    DhtRecord::new_signed(&publisher, make_addr(7000), now),
                    from_a_peer()
                )
                .await,
            Err(RecordRejection::MarksUnavailable),
            "a silent mark store must bound the wait and refuse"
        );
    }

    /// A store whose load takes long enough for a record to expire during it.
    struct SlowLoadMarkStore(Duration);

    #[async_trait::async_trait]
    impl MarkStore for SlowLoadMarkStore {
        async fn load(&self) -> Result<Vec<(NodeId, marks::Mark)>, marks::MarkStoreError> {
            tokio::time::sleep(self.0).await;
            Ok(Vec::new())
        }
        async fn put(&self, _id: NodeId, _mark: marks::Mark) -> Result<(), marks::MarkStoreError> {
            Ok(())
        }
        async fn remove_not_newer(
            &self,
            _ids: &[(NodeId, u64)],
        ) -> Result<(), marks::MarkStoreError> {
            Ok(())
        }
    }

    /// Freshness is re-checked once the locks are held.
    ///
    /// The clock is read when the record arrives, and everything between there
    /// and the insert can wait: the restoration gate may load the whole mark
    /// table, and both locks can be contended. A record that was inside its
    /// TTL on arrival would otherwise be stored expired and handed back out of
    /// `iterative_find_value`.
    ///
    /// This runs on the real clock, deliberately: `unix_now` reads
    /// `SystemTime`, which the test runtime's paused clock does not move, so
    /// the only way to make a record age is to let it. Two seconds against a
    /// one-second TTL — `unix_now` truncates to whole seconds, so sleeping two
    /// guarantees the reading advances by exactly two.
    #[tokio::test]
    async fn test_a_record_that_expires_while_admission_waits_is_refused() {
        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig {
                record_ttl_secs: 1,
                ..DhtConfig::default()
            },
            Arc::new(SlowLoadMarkStore(Duration::from_secs(2))),
        );
        let publisher = Identity::generate();
        let now = unix_now();
        // Fresh on arrival: `now > now + 1` is false.
        assert_eq!(
            engine
                .store_record(
                    DhtRecord::new_signed(&publisher, make_addr(7000), now),
                    from_a_peer()
                )
                .await,
            Err(RecordRejection::Expired),
            "a record that aged past its TTL while admission waited must be \
             refused rather than stored and served"
        );
        assert!(engine.lookup(&publisher.node_id()).await.is_none());
    }

    /// A store whose first load fails and whose later ones succeed.
    struct FlakyLoadMarkStore(Arc<marks::MemoryMarkStore>, std::sync::atomic::AtomicBool);

    #[async_trait::async_trait]
    impl MarkStore for FlakyLoadMarkStore {
        async fn load(&self) -> Result<Vec<(NodeId, marks::Mark)>, marks::MarkStoreError> {
            if self.1.swap(false, Ordering::SeqCst) {
                return Err(marks::MarkStoreError("database is locked".to_string()));
            }
            self.0.load().await
        }
        async fn put(&self, id: NodeId, mark: marks::Mark) -> Result<(), marks::MarkStoreError> {
            self.0.put(id, mark).await
        }
        async fn remove_not_newer(
            &self,
            ids: &[(NodeId, u64)],
        ) -> Result<(), marks::MarkStoreError> {
            self.0.remove_not_newer(ids).await
        }
    }

    /// A load failure is not an empty table.
    ///
    /// Flattening the two meant a node whose database could not be read
    /// accepted every replay it had a persisted mark for, silently, with a log
    /// line as the only trace — the exact defect T-38 exists to remove, now
    /// reachable through a transient storage error instead of through capacity
    /// eviction. Admission is refused while the marks are unreadable, and the
    /// refusal is retried: the second attempt restores and the replay is
    /// caught.
    #[tokio::test]
    async fn test_an_unreadable_mark_store_refuses_admission_and_then_recovers() {
        let inner = Arc::new(marks::MemoryMarkStore::default());
        let victim = Identity::generate();
        let now = unix_now();
        inner
            .put(
                victim.node_id(),
                Mark {
                    newest_published_at: now - 50,
                    first_seen: now - 1_000,
                    last_refreshed: now - 50,
                    established: false,
                },
            )
            .await
            .unwrap();

        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig::default(),
            Arc::new(FlakyLoadMarkStore(
                inner.clone(),
                std::sync::atomic::AtomicBool::new(true),
            )),
        );

        let replay = DhtRecord::new_signed(&victim, make_addr(7000), now - 200);
        assert_eq!(
            engine.store_record(replay.clone(), from_a_peer()).await,
            Err(RecordRejection::MarksUnavailable),
            "an unreadable mark store must refuse, not admit"
        );

        // The failure was not recorded as a restoration, so this retries the
        // load — which now works, and the mark it reads refuses the replay.
        assert_eq!(
            engine.store_record(replay, from_a_peer()).await,
            Err(RecordRejection::RolledBack),
            "the retry must restore and then catch the replay"
        );
    }

    /// Restoration happens in `start()`, but dialling does not require
    /// `start()`: `connect_to` installs a read loop that serves `Store`
    /// requests. A record admitted that way faced an empty mark table, so a
    /// replay was accepted and served — persisted protection that the engine
    /// simply had not looked at yet.
    ///
    /// The gate is in `store_record`, so it covers every route in rather than
    /// the one the transport happens to take. Here there is no `restore_marks`
    /// call at all, which is the pre-start state.
    #[tokio::test]
    async fn test_a_replay_is_refused_before_anyone_restores_the_marks() {
        let inner = Arc::new(marks::MemoryMarkStore::default());
        let victim = Identity::generate();
        let now = unix_now();
        inner
            .put(
                victim.node_id(),
                Mark {
                    newest_published_at: now - 50,
                    first_seen: now - 1_000,
                    last_refreshed: now - 50,
                    established: false,
                },
            )
            .await
            .unwrap();

        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig::default(),
            inner.clone(),
        );

        assert_eq!(
            engine
                .store_record(
                    DhtRecord::new_signed(&victim, make_addr(7000), now - 200),
                    from_a_peer()
                )
                .await,
            Err(RecordRejection::RolledBack),
            "admission must read the marks itself rather than trust the \
             embedder to have done it"
        );
        assert!(engine.lookup(&victim.node_id()).await.is_none());
    }

    /// A store whose first deletion fails and whose later ones succeed.
    ///
    /// The failure is the backend's, not the queue's, which is the difference
    /// that mattered: a deletion that never reached the queue was remembered,
    /// while one the backend refused was logged and discarded.
    struct FlakyDeleteMarkStore(Arc<marks::MemoryMarkStore>, std::sync::atomic::AtomicBool);

    #[async_trait::async_trait]
    impl MarkStore for FlakyDeleteMarkStore {
        async fn load(&self) -> Result<Vec<(NodeId, marks::Mark)>, marks::MarkStoreError> {
            self.0.load().await
        }
        async fn put(&self, id: NodeId, mark: marks::Mark) -> Result<(), marks::MarkStoreError> {
            self.0.put(id, mark).await
        }
        async fn remove_not_newer(
            &self,
            ids: &[(NodeId, u64)],
        ) -> Result<(), marks::MarkStoreError> {
            if self.1.swap(false, Ordering::SeqCst) {
                return Err(marks::MarkStoreError("disk full".to_string()));
            }
            self.0.remove_not_newer(ids).await
        }
    }

    /// A deletion the backend refuses leaves a durable row that nothing in
    /// memory points at, so no later sweep can target it — the same orphan a
    /// deletion lost to a full queue leaves, one layer further down. Logging
    /// the error and discarding the ids let those rows accumulate for the whole
    /// run, past `mark_capacity` under repeated failure, until a restart
    /// reconciled them.
    ///
    /// The table is deliberately *not* restored here: these marks are orphans,
    /// so the table must not hold them, or `apply_mark_drop` would rightly
    /// refuse to delete them and the test would prove nothing.
    #[tokio::test]
    async fn test_a_deletion_the_backend_refused_is_retried() {
        let inner = Arc::new(marks::MemoryMarkStore::default());
        let orphan = NodeId([0x3Cu8; 32]);
        let at = unix_now();
        inner
            .put(
                orphan,
                Mark {
                    newest_published_at: at,
                    first_seen: at,
                    last_refreshed: at,
                    established: false,
                },
            )
            .await
            .unwrap();

        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig::default(),
            Arc::new(FlakyDeleteMarkStore(
                inner.clone(),
                std::sync::atomic::AtomicBool::new(true),
            )),
        );
        engine.ensure_mark_writer().await;

        engine.queue_mark_drop(vec![(orphan, at)]);
        engine.flush_marks().await;
        assert!(
            inner
                .load()
                .await
                .expect("load")
                .iter()
                .any(|(id, _)| *id == orphan),
            "the backend refused, so the row should still be there"
        );
        assert!(
            engine.has_pending_drops(),
            "a deletion the backend refused must be remembered, not logged away"
        );

        // The next attempt carries it, as the sweep in any later admission
        // would.
        engine.queue_mark_drop(Vec::new());
        engine.flush_marks().await;
        assert!(
            !inner
                .load()
                .await
                .expect("load")
                .iter()
                .any(|(id, _)| *id == orphan),
            "the refused deletion must be retried"
        );
    }

    #[tokio::test]
    async fn test_an_admitted_mark_is_written_through_to_the_store() {
        let store = Arc::new(marks::MemoryMarkStore::default());
        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig::default(),
            store.clone(),
        );
        let publisher = Identity::generate();
        let now = unix_now();
        engine
            .store_record(
                DhtRecord::new_signed(&publisher, make_addr(7000), now),
                from_a_peer(),
            )
            .await
            .unwrap();

        engine.flush_marks().await;
        let held = store.load().await.expect("load");
        assert_eq!(held.len(), 1, "the mark must reach the durable store");
        assert_eq!(held[0].0, publisher.node_id());
        assert_eq!(held[0].1.newest_published_at, now);
    }

    /// The hazard a conditional delete alone cannot cover: an id is evicted
    /// from the probationary region and then re-admitted at the *same*
    /// timestamp. The delete and the put are indistinguishable by timestamp,
    /// so the queue applying them in the order they were issued is what keeps
    /// the live mark (ADR-016).
    #[tokio::test]
    async fn test_re_admitting_an_evicted_id_at_the_same_timestamp_keeps_its_mark() {
        let store = Arc::new(marks::MemoryMarkStore::default());
        let engine = DhtEngine::with_mark_store(
            Arc::new(Identity::generate()),
            DhtConfig {
                // A one-mark table, so every first-seen publisher displaces
                // the previous one — eviction happens when the table is full,
                // which here is at one. The record store is one slot too: the
                // mark has to be gone *and* the record evicted for a republish
                // of the same record to be admitted rather than refused as
                // `Stale`, which is the only way the equal-timestamp case is
                // reachable at all.
                mark_capacity: 1,
                mark_first_seen_reserve: 1,
                max_records: 1,
                ..DhtConfig::default()
            },
            store.clone(),
        );
        let first = Identity::generate();
        let second = Identity::generate();
        let now = unix_now();

        engine
            .store_record(
                DhtRecord::new_signed(&first, make_addr(7000), now),
                from_a_peer(),
            )
            .await
            .unwrap();
        // Evicts the first publisher's mark.
        engine
            .store_record(
                DhtRecord::new_signed(&second, make_addr(7001), now),
                from_a_peer(),
            )
            .await
            .unwrap();
        assert_eq!(engine.newest_mark_for(&first.node_id()).await, None);

        // The same publisher republishing the same record: first-seen again,
        // same timestamp, and it evicts the second publisher in turn.
        engine
            .store_record(
                DhtRecord::new_signed(&first, make_addr(7000), now),
                from_a_peer(),
            )
            .await
            .unwrap();
        assert_eq!(engine.newest_mark_for(&first.node_id()).await, Some(now));

        engine.flush_marks().await;
        let held = store.load().await.expect("load");
        assert_eq!(
            held.len(),
            1,
            "exactly the re-admitted mark should be durable, got {:?}",
            held
        );
        assert_eq!(
            held[0].0,
            first.node_id(),
            "the re-admitted mark must survive the earlier eviction's delete"
        );
    }

    /// Fairness, not a rollback defence: one delivering peer must not crowd
    /// out the records of peers this node actually talks to (ADR-016).
    #[tokio::test]
    async fn test_one_delivering_peer_cannot_fill_the_store() {
        let engine = DhtEngine::new(
            Arc::new(Identity::generate()),
            DhtConfig {
                max_records_per_peer: 3,
                ..DhtConfig::default()
            },
        );
        let hog = RecordSource::Peer(NodeId([1u8; 32]));
        let other = RecordSource::Peer(NodeId([2u8; 32]));
        let now = unix_now();

        for i in 0..3u16 {
            let publisher = Identity::generate();
            engine
                .store_record(
                    DhtRecord::new_signed(&publisher, make_addr(7000 + i), now),
                    hog,
                )
                .await
                .unwrap();
        }
        let blocked = Identity::generate();
        assert_eq!(
            engine
                .store_record(DhtRecord::new_signed(&blocked, make_addr(7100), now), hog,)
                .await,
            Err(RecordRejection::PublisherQuota),
            "a peer past its share must be refused"
        );

        // Another peer is unaffected: the store is nowhere near full, and that
        // is the whole point of the bound.
        let welcome = Identity::generate();
        assert!(
            engine
                .store_record(DhtRecord::new_signed(&welcome, make_addr(7101), now), other,)
                .await
                .is_ok(),
            "the bound is per delivering peer, not a global cap"
        );
        // And our own record is exempt.
        assert!(engine
            .store_record(
                DhtRecord::new_signed(&Identity::generate(), make_addr(7102), now),
                RecordSource::Local,
            )
            .await
            .is_ok());
    }

    /// A peer refreshing a record it already delivered does not grow its
    /// share, so it must not be refused once at the bound — otherwise the
    /// bound would stop peers republishing and the records would simply
    /// expire.
    #[tokio::test]
    async fn test_a_peer_at_its_share_can_still_refresh_what_it_delivered() {
        let engine = DhtEngine::new(
            Arc::new(Identity::generate()),
            DhtConfig {
                max_records_per_peer: 2,
                ..DhtConfig::default()
            },
        );
        let deliverer = RecordSource::Peer(NodeId([1u8; 32]));
        let now = unix_now();
        let a = Identity::generate();
        let b = Identity::generate();
        engine
            .store_record(
                DhtRecord::new_signed(&a, make_addr(7000), now - 100),
                deliverer,
            )
            .await
            .unwrap();
        engine
            .store_record(
                DhtRecord::new_signed(&b, make_addr(7001), now - 100),
                deliverer,
            )
            .await
            .unwrap();

        // At the bound, and a newer record for one it already holds.
        assert!(
            engine
                .store_record(DhtRecord::new_signed(&a, make_addr(7002), now), deliverer)
                .await
                .is_ok(),
            "a refresh of its own record does not grow its share"
        );
        assert_eq!(engine.lookup(&a.node_id()).await, Some(make_addr(7002)));
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
            engine.store_record(record, from_a_peer()).await.unwrap();
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
        far.store_record(record.clone(), from_a_peer())
            .await
            .unwrap();

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
            self.engine
                .store_record(self.record.clone(), from_a_peer())
                .await
                .ok();
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
