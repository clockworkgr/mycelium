//! High-water marks for DHT record freshness.
//!
//! ADR-011 states that a replayed older record cannot roll an address back,
//! because `store_record` refuses a record no newer than the one it holds.
//! That rule depends on *holding* the newer record, and capacity eviction
//! throws it away — so a peer that fills the store with records for identities
//! it generates can evict a victim's current record and then replay the
//! victim's older, still-fresh one. A mark outlives the record it guards, which
//! is what makes the claim true unconditionally (ADR-016, ROADMAP T-38).
//!
//! # Why the table does not simply evict
//!
//! A bounded cache that evicts like any other inherits the attack it was meant
//! to stop: an identity is free, so an attacker mints keypairs until the
//! eviction policy discards the mark it wants gone. ADR-016's decision is that
//! **a mark inside the replay window is never evicted**, and ADR-016's own note
//! records the price: "refuse the unseen" lets an attacker who already holds
//! admitted identities refresh them forever, so the table never drains and a
//! legitimate new peer is denied for as long as that continues.
//!
//! The table therefore has two regions:
//!
//! * **Established** marks — publishers seen continuously for at least
//!   `graduation_age` — are never evicted inside the replay window. They are
//!   dropped only by the retention sweep, once the record they guard can no
//!   longer be fresh.
//! * **Probationary** marks — everything newer — are evicted
//!   least-recently-refreshed first. `first_seen_reserve` is a **floor** on how
//!   many of them a full table holds, not a ceiling: establishment is capped at
//!   `capacity - first_seen_reserve`, so a full table always contains at least
//!   that many probationary marks for a newcomer to evict. There is no upper
//!   bound — before anything has graduated, or after restoration, every mark in
//!   the table can be probationary, which only makes first-seen admission
//!   easier.
//!
//! A first-seen publisher is therefore **always admitted**: the probationary
//! region makes room from its own entries and never touches an established
//! mark. An attacker minting identities churns only that slice.
//!
//! **The residual, stated rather than hidden:** an attacker that *maintains*
//! identities across a full `graduation_age` graduates them and can fill the
//! established region. New publishers are still admitted after that — they are
//! never refused — but they can no longer graduate, so their rollback
//! protection lasts only as long as they hold a probationary slot. That is a
//! far higher bar than churning a cache, and it is bounded, but it is not
//! closed.

use std::collections::HashMap;

use async_trait::async_trait;
use mycelium_protocol::types::NodeId;

/// What we remember about one publisher, independently of its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark {
    /// The newest `published_at` ever admitted for this id. A record older
    /// than this is a rollback attempt whether or not we still hold one.
    pub newest_published_at: u64,
    /// Unix seconds when this id was first admitted. Drives graduation.
    pub first_seen: u64,
    /// Unix seconds when this id was last admitted. Orders eviction inside
    /// the probationary region.
    pub last_refreshed: u64,
    /// Whether this mark has graduated out of the probationary region and is
    /// no longer evictable inside the replay window.
    pub established: bool,
}

/// Durable storage for the marks.
///
/// A narrow trait rather than a `Database` handle, so `mycelium-core` stays
/// storage-agnostic and the tests here can exercise the capacity rules against
/// an in-memory implementation. The engine is async and SQLCipher is
/// synchronous, which the implementation deals with, not this crate.
///
/// # Every write states the whole truth, conditionally
///
/// Admission holds a lock across these calls, but a caller can be cancelled —
/// a lookup has a deadline, and a dropped future releases the guard wherever it
/// happened to be. An implementation that hands the work to a thread or a task
/// can then have a write outlive the caller that asked for it.
///
/// **An implementation need not order calls against each other, and the engine
/// does.** Every write reaches a store through one writer task that awaits
/// each call before taking the next, so calls arrive in the order they were
/// issued, and some invariants need that:
///
/// * Two writes carrying the **same** watermark both apply, so the later one
///   wins. A demotion and an older establishment at one watermark are
///   distinguishable only by which was issued second.
/// * A deletion is not applied to an id the table holds again, which the
///   engine decides when the delete runs rather than when it was queued.
///
/// So the division is: an implementation may hand work to a thread and need
/// not serialise anything itself, because only one call is ever outstanding;
/// what it must not do is make the *result* depend on a comparison it performs
/// non-atomically. Each operation below is a single statement for that reason,
/// and each is conditional on the stored row rather than a delta:
///
/// * [`MarkStore::put`] writes the caller's whole mark, unless the stored
///   `newest_published_at` is **newer** than the one being written. A stale
///   write that arrives late is a no-op; a current one is complete.
/// * [`MarkStore::remove_not_newer`] deletes an id only while the stored mark
///   is no newer than the one the caller saw. A sweep whose write lands after
///   a refresh therefore cannot delete a live mark — which would have reopened
///   rollback at the next restart.
///
/// **A merge would be wrong, and was.** Combining the incoming mark with the
/// stored one field by field — greater watermark, earlier `first_seen`, never
/// un-establishing — survives reordering just as well, and makes every write a
/// delta that cannot correct anything. Two consequences, both of which were
/// real:
///
/// * Retention ends a publisher's lifetime. If it republishes, merging carries
///   the old lifetime's `first_seen` and `established` into the new one, so a
///   restart restores an established publisher where the table holds a
///   probationary one — establishment it never re-earned. An identity could
///   bank it, fall silent past the whole replay window, republish, and come
///   back protected.
/// * Restoration demotes established marks beyond the protected region, and a
///   merge can never persist that: `established` only ever moved upward, so
///   the demoted publisher was promoted again at the next start.
///
/// Writing the whole mark makes every write idempotent and self-correcting: one
/// that is lost costs nothing the publisher's next record does not restore.
///
/// An implementation that writes or deletes *unconditionally* is still wrong,
/// and will pass the simple tests.
#[async_trait]
pub trait MarkStore: Send + Sync {
    /// Every mark we have persisted.
    ///
    /// **An error is not an empty table.** Returning `Ok(vec![])` for a
    /// backend that could not be read would make a node accept every replay
    /// it has a persisted mark for, silently, which is the whole defect this
    /// table exists to remove. The engine refuses admission instead, and
    /// retries this call: ADR-016's own framing is that a denial of new
    /// entries is a far better failure than a silent rollback of an existing
    /// one.
    ///
    /// # One engine per store
    ///
    /// An implementation is used by a single `DhtEngine`. Two engines over one
    /// backend have two independent writer tasks and no ordering between them,
    /// so one engine's eviction can land after the other's restoration and
    /// erase a mark it had adopted.
    async fn load(&self) -> Result<Vec<(NodeId, Mark)>, MarkStoreError>;

    /// Write one mark, unless the stored one is newer. See the trait docs.
    ///
    /// The whole mark, not a merge: the caller's table is the authority on the
    /// publisher's current lifetime, and a write that only ever moved fields
    /// in one direction could not express a lifetime that restarted or an
    /// establishment that was withdrawn.
    ///
    /// An **equal** watermark writes. A mark can be evicted and the very same
    /// record re-admitted — neither stale nor a rollback, because the mark and
    /// the record went together — and that is a new lifetime at an unchanged
    /// timestamp.
    async fn put(&self, id: NodeId, mark: Mark) -> Result<(), MarkStoreError>;

    /// Forget each id whose stored mark is no newer than the paired
    /// `newest_published_at`. See the trait docs.
    async fn remove_not_newer(&self, ids: &[(NodeId, u64)]) -> Result<(), MarkStoreError>;
}

/// A mark could not be persisted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("mark store write failed: {0}")]
pub struct MarkStoreError(pub String);

/// A `MarkStore` that keeps everything in memory. For tests, and for a node
/// running without a database.
#[derive(Debug, Default)]
pub struct MemoryMarkStore {
    marks: std::sync::Mutex<HashMap<NodeId, Mark>>,
}

#[async_trait]
impl MarkStore for MemoryMarkStore {
    async fn load(&self) -> Result<Vec<(NodeId, Mark)>, MarkStoreError> {
        self.marks
            .lock()
            .map(|m| m.iter().map(|(id, mark)| (*id, *mark)).collect())
            .map_err(|_| MarkStoreError("mark mutex poisoned".to_string()))
    }

    async fn put(&self, id: NodeId, mark: Mark) -> Result<(), MarkStoreError> {
        if let Ok(mut m) = self.marks.lock() {
            let not_older = m
                .get(&id)
                .is_none_or(|held| mark.newest_published_at >= held.newest_published_at);
            if not_older {
                m.insert(id, mark);
            }
        }
        Ok(())
    }

    async fn remove_not_newer(&self, ids: &[(NodeId, u64)]) -> Result<(), MarkStoreError> {
        if let Ok(mut m) = self.marks.lock() {
            for (id, newest) in ids {
                let safe = m
                    .get(id)
                    .is_some_and(|held| held.newest_published_at <= *newest);
                if safe {
                    m.remove(id);
                }
            }
        }
        Ok(())
    }
}

/// What admitting a record did to the table, so the caller knows what to
/// persist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    /// A mark for an id we had not seen. `evicted` names the probationary
    /// mark that made room, if one had to, with the high-water mark it held —
    /// the durable delete is conditional on it, so a mark refreshed in the
    /// meantime is not dropped.
    FirstSeen { evicted: Option<(NodeId, u64)> },
    /// An existing mark moved forward.
    Refreshed,
}

/// The in-memory mark table and its admission rules.
///
/// Pure and synchronous on purpose: every rule here is testable without a
/// database or an executor. Persistence is the caller's job, driven by what
/// [`MarkTable::admit`] reports.
#[derive(Debug)]
pub struct MarkTable {
    marks: HashMap<NodeId, Mark>,
    capacity: usize,
    first_seen_reserve: usize,
    /// How long a publisher must have been continuously known before its mark
    /// stops being evictable. Derived as the full replay window
    /// (`record_ttl + retention_grace`) rather than configured: it is the
    /// attacker's cost to establish one identity, and tying it to the window a
    /// mark is kept for means there is no separate figure to get wrong. One
    /// record lifetime was too cheap — an attacker needed only an hour per
    /// identity.
    graduation_age: u64,
    /// How long a mark is kept past the expiry of the newest record it has
    /// seen. Measured against the record's *signed* expiry, never a wall-clock
    /// interval from when the mark was written: after a mark is swept, a
    /// backward clock correction would otherwise make an older signed record
    /// fresh again (ADR-013's lesson, ADR-016).
    retention_grace: u64,
    record_ttl: u64,
}

impl MarkTable {
    /// Build a table, adopting already-persisted marks.
    ///
    /// `first_seen_reserve` is clamped below `capacity`: a reserve as large as
    /// the table would leave no protected region at all, which is the policy
    /// this type exists to implement.
    pub fn new(
        capacity: usize,
        first_seen_reserve: usize,
        retention_grace: u64,
        record_ttl: u64,
        loaded: Vec<(NodeId, Mark)>,
    ) -> Self {
        let capacity = capacity.max(1);
        let mut table = Self {
            marks: HashMap::new(),
            capacity,
            first_seen_reserve: first_seen_reserve.min(capacity.saturating_sub(1)).max(1),
            graduation_age: record_ttl.saturating_add(retention_grace),
            retention_grace,
            record_ttl,
        };
        // Through `adopt`, so loaded marks are subject to the same region
        // bounds as admitted ones. Collecting them straight into the map
        // skipped that and could seat more established marks than the reserve
        // leaves.
        table.adopt(loaded);
        table
    }

    /// How long a publisher must be continuously known before it graduates.
    pub fn graduation_age(&self) -> u64 {
        self.graduation_age
    }

    /// The newest `published_at` we have ever admitted for this id.
    pub fn newest_for(&self, id: &NodeId) -> Option<u64> {
        self.marks.get(id).map(|m| m.newest_published_at)
    }

    /// Whether `published_at` would roll this id's address back.
    ///
    /// Strictly older only: re-admitting the very record the mark was set from
    /// is not a rollback, and refusing it would break a node re-learning its
    /// own peer's current address after a capacity eviction.
    pub fn is_rollback(&self, id: &NodeId, published_at: u64) -> bool {
        self.marks
            .get(id)
            .is_some_and(|m| published_at < m.newest_published_at)
    }

    pub fn len(&self) -> usize {
        self.marks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.marks.is_empty()
    }

    pub fn get(&self, id: &NodeId) -> Option<&Mark> {
        self.marks.get(id)
    }

    /// How many marks may be established at once.
    ///
    /// The reserve is what is left over, and the invariant it buys is load
    /// bearing: while `established_count() <= protected_capacity()`, a full
    /// table always contains at least one probationary mark, so
    /// [`MarkTable::evict_one_probationary`] can always make room and a
    /// first-seen publisher is never refused. Both `adopt` and the graduation
    /// path check it.
    fn protected_capacity(&self) -> usize {
        self.capacity - self.first_seen_reserve
    }

    fn established_count(&self) -> usize {
        self.marks.values().filter(|m| m.established).count()
    }

    /// The region the reserve puts a floor under.
    ///
    /// Test-only, and that is the point: admission no longer consults it.
    /// Eviction is driven by capacity alone, and the floor is a *consequence*
    /// of capping establishment at `protected_capacity` rather than a rule
    /// anything enforces directly. Counting it in `admit` was the bug — it
    /// made the reserve a ceiling and discarded a live mark for every
    /// first-seen publisher past the 512th.
    #[cfg(test)]
    fn probationary_count(&self) -> usize {
        self.marks.len() - self.established_count()
    }

    /// Record that a record for `id`, published at `published_at`, was
    /// admitted.
    ///
    /// The caller has already refused a rollback via [`MarkTable::is_rollback`],
    /// so this only moves the table forward.
    pub fn admit(&mut self, id: NodeId, published_at: u64, now: u64) -> Admitted {
        if let Some(mark) = self.marks.get_mut(&id) {
            mark.newest_published_at = mark.newest_published_at.max(published_at);
            mark.last_refreshed = now;
            let old_enough = now.saturating_sub(mark.first_seen) >= self.graduation_age;
            let graduating = !mark.established && old_enough;
            if graduating {
                // Checked against the protected region's own bound, so new
                // arrivals cannot grow it past what the reserve leaves.
                if self.established_count() < self.protected_capacity() {
                    if let Some(m) = self.marks.get_mut(&id) {
                        m.established = true;
                    }
                }
            }
            return Admitted::Refreshed;
        }

        // A publisher we have never seen. It is always admitted: room comes
        // from the probationary region's own entries, never from an
        // established mark.
        //
        // Evicted only when the table is genuinely full. `first_seen_reserve`
        // is a floor on the probationary region, not a ceiling — it exists to
        // cap *establishment* at `protected_capacity`, which is what
        // guarantees a full table always contains a probationary mark to take.
        // Treating it as a ceiling here discarded a live mark for every
        // first-seen publisher past the 512th while thousands of slots sat
        // empty, which is the rollback exposure this table exists to shrink,
        // widened for no reason.
        let evicted = if self.marks.len() >= self.capacity {
            self.evict_one_probationary()
        } else {
            None
        };
        self.marks.insert(
            id,
            Mark {
                newest_published_at: published_at,
                first_seen: now,
                last_refreshed: now,
                established: false,
            },
        );
        Admitted::FirstSeen { evicted }
    }

    /// Adopt persisted marks.
    ///
    /// Anything already in memory wins where the two disagree, so this can
    /// only ever raise a high-water mark, never lower one — which matters
    /// because records may already have been admitted before the store was
    /// read.
    ///
    /// Bounded by capacity, and established marks are taken first: the
    /// configured capacity can shrink between runs, and in that case the marks
    /// worth keeping are the ones that are no longer evictable.
    pub fn adopt(&mut self, mut loaded: Vec<(NodeId, Mark)>) {
        loaded.sort_by_key(|(id, m)| {
            (
                !m.established,
                std::cmp::Reverse(m.newest_published_at),
                *id.as_bytes(),
            )
        });
        for (id, mut mark) in loaded {
            match self.marks.get(&id).copied() {
                Some(existing) => {
                    let mut merged = Mark {
                        newest_published_at: existing
                            .newest_published_at
                            .max(mark.newest_published_at),
                        first_seen: existing.first_seen.min(mark.first_seen),
                        last_refreshed: existing.last_refreshed.max(mark.last_refreshed),
                        established: existing.established || mark.established,
                    };
                    // Promoting an existing mark counts against the protected
                    // region just as seating a new one does.
                    if merged.established
                        && !existing.established
                        && self.established_count() >= self.protected_capacity()
                    {
                        merged.established = false;
                    }
                    self.marks.insert(id, merged);
                }
                None => {
                    if self.marks.len() >= self.capacity {
                        continue;
                    }
                    // A restored mark may not push the protected region past
                    // its bound. The configured capacity or reserve can change
                    // between runs, and a table filled entirely with
                    // established marks has no probationary victim to evict —
                    // the next first-seen publisher would then be inserted
                    // over capacity. Demoted rather than dropped: the
                    // high-water mark is the protection, and keeping it while
                    // making it evictable loses far less than forgetting it.
                    if mark.established && self.established_count() >= self.protected_capacity() {
                        mark.established = false;
                    }
                    self.marks.insert(id, mark);
                }
            }
        }
        debug_assert!(
            self.established_count() <= self.protected_capacity(),
            "adopting marks must leave the reserve intact"
        );
    }

    /// Drop the least-recently-refreshed probationary mark, if there is one.
    fn evict_one_probationary(&mut self) -> Option<(NodeId, u64)> {
        let victim = self
            .marks
            .iter()
            .filter(|(_, m)| !m.established)
            .min_by_key(|(id, m)| (m.last_refreshed, *id.as_bytes()))
            .map(|(id, m)| (*id, m.newest_published_at))?;
        self.marks.remove(&victim.0);
        Some(victim)
    }

    /// Whether a mark is still inside its replay window.
    ///
    /// The one place the retention horizon is computed, so the sweep and
    /// restoration cannot disagree about it.
    pub fn retains(&self, mark: &Mark, now: u64) -> bool {
        let horizon = self.record_ttl.saturating_add(self.retention_grace);
        mark.newest_published_at.saturating_add(horizon) > now
    }

    /// Forget marks whose newest record can no longer be fresh.
    ///
    /// Measured against the record's signed expiry plus a grace, so a backward
    /// clock correction cannot revive a record whose mark has been swept.
    /// Returns the ids dropped, for the caller to remove durably.
    pub fn sweep(&mut self, now: u64) -> Vec<(NodeId, u64)> {
        let dead: Vec<(NodeId, u64)> = self
            .marks
            .iter()
            .filter(|(_, m)| !self.retains(m, now))
            .map(|(id, m)| (*id, m.newest_published_at))
            .collect();
        for (id, _) in &dead {
            self.marks.remove(id);
        }
        dead
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: u64 = 3600;
    const GRACE: u64 = 86_400;
    /// Derived inside the table as the full replay window.
    const GRADUATE: u64 = TTL + GRACE;

    fn id(n: u32) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&n.to_be_bytes());
        NodeId(bytes)
    }

    fn table(capacity: usize, reserve: usize) -> MarkTable {
        MarkTable::new(capacity, reserve, GRACE, TTL, Vec::new())
    }

    /// Fill every protected slot with a publisher that has been refreshing
    /// long enough to have graduated.
    fn with_established(capacity: usize, reserve: usize, now: u64) -> MarkTable {
        let mut t = table(capacity, reserve);
        let protected = capacity - reserve;
        for i in 0..protected {
            let who = id(i as u32);
            t.admit(who, now - GRADUATE - 1, now - GRADUATE - 1);
            // A second admission once it is old enough is what graduates it.
            t.admit(who, now, now);
            assert!(
                t.get(&who).unwrap().established,
                "publisher {} should be established",
                i
            );
        }
        t
    }

    #[test]
    fn test_a_strictly_older_record_is_a_rollback_and_an_equal_one_is_not() {
        let mut t = table(16, 4);
        let who = id(1);
        t.admit(who, 1_000, 1_000);
        assert!(
            t.is_rollback(&who, 999),
            "an older record rolls the address back"
        );
        assert!(
            !t.is_rollback(&who, 1_000),
            "re-admitting the very record the mark came from is not a rollback"
        );
        assert!(!t.is_rollback(&who, 1_001));
        assert!(
            !t.is_rollback(&id(2), 1),
            "an unknown publisher cannot roll back"
        );
    }

    #[test]
    fn test_a_mark_moves_forward_and_never_backward() {
        let mut t = table(16, 4);
        let who = id(1);
        t.admit(who, 1_000, 1_000);
        t.admit(who, 900, 1_100);
        assert_eq!(
            t.newest_for(&who),
            Some(1_000),
            "a lower published_at must not lower the high-water mark"
        );
    }

    /// ADR-016's acceptance names this one explicitly: a quota per publisher
    /// does not survive identity rotation, so the table must not either.
    #[test]
    fn test_an_established_mark_survives_an_attacker_rotating_identities() {
        let now = 1_000_000;
        let mut t = with_established(32, 8, now);
        let victim = id(0);
        let victim_mark = *t.get(&victim).unwrap();

        // Ten times the table's capacity in fresh identities, each publishing
        // once. Every one is admitted — they are never refused — and not one
        // may displace an established mark.
        for i in 0..320u32 {
            t.admit(id(10_000 + i), now, now);
        }

        assert_eq!(
            t.get(&victim),
            Some(&victim_mark),
            "rotating identities must not evict an established mark"
        );
        for i in 0..(32 - 8) {
            assert!(
                t.get(&id(i as u32)).is_some(),
                "established mark {} was evicted",
                i
            );
        }
        assert!(
            t.len() <= 32,
            "the table stayed within capacity: {}",
            t.len()
        );
    }

    #[test]
    fn test_a_first_seen_publisher_is_always_admitted() {
        let now = 1_000_000;
        let mut t = with_established(16, 4, now);
        // Fill the probationary region too, so the table is completely full.
        for i in 0..4u32 {
            t.admit(id(2_000 + i), now, now);
        }
        assert_eq!(t.len(), 16);

        let newcomer = id(9_999);
        let outcome = t.admit(newcomer, now, now + 1);
        assert!(
            matches!(outcome, Admitted::FirstSeen { evicted: Some(_) }),
            "a full table makes room from its own probationary entries"
        );
        assert!(
            t.get(&newcomer).is_some(),
            "a first-seen publisher is never refused"
        );
        assert_eq!(t.len(), 16, "and capacity still holds");
    }

    #[test]
    fn test_the_probationary_region_churns_least_recently_refreshed() {
        let now = 1_000_000;
        // The table must be **full** for anything to be evicted. It used to
        // evict as soon as the probationary count reached the reserve, which
        // threw a live mark away with most of the table empty; the reserve is
        // a floor on that region, not a ceiling.
        let mut t = table(3, 1);
        let oldest = id(1);
        let middle = id(2);
        let newest = id(3);
        t.admit(oldest, now, now);
        t.admit(middle, now, now + 10);
        t.admit(newest, now, now + 20);

        let outcome = t.admit(id(4), now, now + 30);
        assert_eq!(
            outcome,
            Admitted::FirstSeen {
                evicted: Some((oldest, now))
            },
            "the least recently refreshed probationary mark goes first"
        );
        assert!(t.get(&middle).is_some());
        assert!(t.get(&newest).is_some());
    }

    #[test]
    fn test_nothing_is_evicted_while_the_table_has_room() {
        let now = 1_000_000;
        // Capacity 8, reserve 2: the third first-seen publisher used to evict
        // the first, because the reserve was treated as a cap on the
        // probationary region. Six slots were empty at the time, and the
        // discarded mark was live — every rollback it would have refused
        // became admissible for no reason at all.
        let mut t = table(8, 2);
        for i in 0..8u32 {
            assert_eq!(
                t.admit(id(i + 1), now, now + i as u64),
                Admitted::FirstSeen { evicted: None },
                "nothing may be evicted while slots remain"
            );
        }
        assert_eq!(t.len(), 8);
        // And the floor still holds where it matters: a full table keeps at
        // least `first_seen_reserve` probationary marks, because establishment
        // is capped at what is left, so there is always one to give and the
        // ninth publisher is still admitted.
        assert!(t.probationary_count() >= 2);
        assert!(matches!(
            t.admit(id(9), now, now + 9),
            Admitted::FirstSeen { evicted: Some(_) }
        ));
    }

    #[test]
    fn test_a_publisher_graduates_only_after_the_graduation_age() {
        let mut t = table(16, 4);
        let who = id(1);
        t.admit(who, 1_000, 1_000);
        assert!(
            !t.get(&who).unwrap().established,
            "new publishers start on probation"
        );

        t.admit(who, 1_500, 1_000 + GRADUATE - 1);
        assert!(
            !t.get(&who).unwrap().established,
            "one second short of the age is still probationary"
        );

        t.admit(who, 2_000, 1_000 + GRADUATE);
        assert!(
            t.get(&who).unwrap().established,
            "continuous presence for the graduation age establishes the mark"
        );
    }

    #[test]
    fn test_graduation_cannot_grow_past_what_the_reserve_leaves() {
        let now = 1_000_000;
        // Every protected slot is already taken.
        let mut t = with_established(8, 2, now);
        let latecomer = id(5_000);
        t.admit(latecomer, now - GRADUATE - 1, now - GRADUATE - 1);
        t.admit(latecomer, now, now);
        assert!(
            !t.get(&latecomer).unwrap().established,
            "a mark old enough to graduate still may not displace the reserve's bound"
        );
    }

    /// ADR-016's note asks for this specifically: not a single burst, but
    /// renewals kept up past a whole retention period, which is what makes
    /// "the table drains by itself" false.
    #[test]
    fn test_sustained_renewals_never_lock_out_a_new_publisher() {
        let mut now = 1_000_000;
        let mut t = with_established(16, 4, now);
        let horizon = TTL + GRACE;

        // The attacker holds every protected slot and keeps refreshing it,
        // well past one retention period, so nothing is ever swept.
        for round in 0..5 {
            now += horizon / 2;
            for i in 0..(16 - 4) {
                t.admit(id(i as u32), now, now);
            }
            // A mark that is being refreshed never expires. Earlier rounds'
            // newcomers do, which is the table draining as designed.
            let swept = t.sweep(now);
            for i in 0..(16 - 4) {
                assert!(
                    !swept.iter().any(|(gone, _)| *gone == id(i as u32)),
                    "round {}: a refreshed mark must not be swept",
                    round
                );
                assert!(t.get(&id(i as u32)).is_some());
            }

            let newcomer = id(40_000 + round);
            t.admit(newcomer, now, now);
            assert!(
                t.get(&newcomer).is_some(),
                "round {}: a new publisher must still be admitted under sustained renewal",
                round
            );
        }
    }

    #[test]
    fn test_a_mark_outlives_the_record_it_guards() {
        let mut t = table(16, 4);
        let who = id(1);
        let published = 1_000_000;
        t.admit(who, published, published);

        // The record itself is expired by now, and would have been swept from
        // the record store — but the mark is still here, which is the point.
        let after_record_expiry = published + TTL + 1;
        assert!(t.sweep(after_record_expiry).is_empty());
        assert!(
            t.is_rollback(&who, published - 1),
            "an older record is still refused after its successor expired"
        );
    }

    #[test]
    fn test_retention_is_measured_against_the_records_signed_expiry() {
        let mut t = table(16, 4);
        let who = id(1);
        let published = 1_000_000;
        t.admit(who, published, published);

        // One second before the signed expiry plus the grace: still held, even
        // though the mark was written long ago in wall-clock terms.
        let dropped = t.sweep(published + TTL + GRACE - 1);
        assert!(dropped.is_empty(), "the grace has not elapsed yet");

        let dropped = t.sweep(published + TTL + GRACE);
        assert_eq!(
            dropped,
            vec![(who, published)],
            "the sweep reports it with the watermark the durable delete is \
             conditional on"
        );
        assert!(t.get(&who).is_none());
        assert!(
            !t.is_rollback(&who, published - 1),
            "once swept there is nothing left to compare against — the stated residual"
        );
    }

    #[test]
    fn test_the_reserve_is_clamped_below_capacity() {
        // A reserve as large as the table would leave nothing protected, which
        // is the whole policy.
        let now = 1_000_000;
        let mut t = MarkTable::new(4, 99, GRACE, TTL, Vec::new());
        for i in 0..4u32 {
            t.admit(id(i), now - GRADUATE - 1, now - GRADUATE - 1);
            t.admit(id(i), now, now);
        }
        assert!(
            t.marks.values().any(|m| m.established),
            "at least one slot must be protected however the reserve is configured"
        );
    }

    /// The capacity or the reserve can change between runs, and a table
    /// restored entirely from established marks has no probationary victim —
    /// the next first-seen publisher would then be inserted over capacity.
    #[test]
    fn test_adopting_more_established_marks_than_the_reserve_leaves_demotes_them() {
        let now = 1_000_000;
        // Four established marks, but only three protected slots.
        let loaded: Vec<(NodeId, Mark)> = (0..4u32)
            .map(|i| {
                (
                    id(i),
                    Mark {
                        newest_published_at: now,
                        first_seen: now - GRADUATE - 1,
                        last_refreshed: now,
                        established: true,
                    },
                )
            })
            .collect();
        let mut t = MarkTable::new(4, 1, GRACE, TTL, loaded);

        assert_eq!(t.len(), 4, "every mark is kept");
        assert_eq!(
            t.established_count(),
            3,
            "the protected region is not pushed past what the reserve leaves"
        );
        // Demoted, not dropped: the high-water mark is the protection.
        for i in 0..4u32 {
            assert!(t.is_rollback(&id(i), now - 1), "mark {} lost its value", i);
        }

        let newcomer = id(500);
        t.admit(newcomer, now, now);
        assert!(
            t.get(&newcomer).is_some(),
            "a first-seen publisher is still admitted"
        );
        assert!(t.len() <= 4, "and capacity is not exceeded: {}", t.len());
    }

    #[test]
    fn test_the_graduation_age_is_the_whole_replay_window() {
        let t = table(16, 4);
        assert_eq!(
            t.graduation_age(),
            TTL + GRACE,
            "one record lifetime was too cheap — an attacker needed an hour per identity"
        );
    }

    #[tokio::test]
    async fn test_marks_round_trip_through_a_store() {
        let store = MemoryMarkStore::default();
        let who = id(7);
        let mark = Mark {
            newest_published_at: 1_234,
            first_seen: 1_000,
            last_refreshed: 1_234,
            established: true,
        };
        store.put(who, mark).await.unwrap();

        let t = MarkTable::new(16, 4, GRACE, TTL, store.load().await.expect("load"));
        assert_eq!(
            t.get(&who),
            Some(&mark),
            "an established mark stays established"
        );
        assert!(
            t.is_rollback(&who, 1_233),
            "a reloaded mark still refuses a rollback"
        );

        // The delete is conditional, so a watermark older than the stored
        // one leaves the mark alone — this is what stops a sweep's write
        // landing after a refresh and reopening rollback.
        store.remove_not_newer(&[(who, 1_233)]).await.unwrap();
        assert_eq!(
            store.load().await.expect("load").len(),
            1,
            "a stale delete must not drop a mark that has moved on"
        );

        store.remove_not_newer(&[(who, 1_234)]).await.unwrap();
        assert!(store.load().await.expect("load").is_empty());
    }

    /// Why the write queue has to preserve order, stated as a test.
    ///
    /// A conditional delete cannot tell "the mark I decided to evict" from "a
    /// new mark for the same id that happens to carry the same timestamp" —
    /// both satisfy `stored <= seen`. So a delayed eviction delete would erase
    /// a live mark. Ordering is what rules that out, not the condition.
    #[tokio::test]
    async fn test_a_conditional_delete_cannot_see_an_equal_timestamp_re_admission() {
        let store = MemoryMarkStore::default();
        let who = id(7);
        let at = 1_234;
        let mark = Mark {
            newest_published_at: at,
            first_seen: at,
            last_refreshed: at,
            established: false,
        };

        // The mark was evicted, and the same id was then re-admitted at the
        // same timestamp — a republish of the very same record.
        store.put(who, mark).await.unwrap();
        // The eviction's delete, arriving late.
        store.remove_not_newer(&[(who, at)]).await.unwrap();
        assert!(
            store.load().await.expect("load").is_empty(),
            "the condition cannot distinguish them — which is exactly why the \
             write queue must apply the delete before the put, and does"
        );
    }

    /// A late `put` must merge, not replace: admission can be cancelled and an
    /// implementation may let a write outlive its caller, so two writes can
    /// land in the opposite order to the one they were issued in.
    #[tokio::test]
    async fn test_a_late_put_cannot_lower_a_stored_mark() {
        let store = MemoryMarkStore::default();
        let who = id(7);
        store
            .put(
                who,
                Mark {
                    newest_published_at: 2_000,
                    first_seen: 1_000,
                    last_refreshed: 2_000,
                    established: true,
                },
            )
            .await
            .unwrap();
        // The write that was issued first, arriving second.
        store
            .put(
                who,
                Mark {
                    newest_published_at: 1_500,
                    first_seen: 1_000,
                    last_refreshed: 1_500,
                    established: false,
                },
            )
            .await
            .unwrap();

        let held = store.load().await.expect("load");
        assert_eq!(held.len(), 1);
        let (_, mark) = held[0];
        assert_eq!(
            mark.newest_published_at, 2_000,
            "the mark may not go backwards"
        );
        assert_eq!(mark.last_refreshed, 2_000);
        assert!(mark.established, "nor may it be un-established");
    }
}
