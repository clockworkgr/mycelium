//! Time-keyed duplicate suppression for flooded messages.
//!
//! A flood terminates because every node remembers what it has already
//! forwarded. The previous implementation was a `HashSet<MessageId>` that was
//! **cleared wholesale** at 10 000 entries and never expired anything, which
//! made two attacks possible (ROADMAP T-36, T-14):
//!
//! - forcing the clear by flooding distinct ids, after which a captured
//!   message could be replayed under its original id and accepted again;
//! - unbounded retention in the meantime, on a supernode that never restarts.
//!
//! This module replaces it with age-based eviction: an entry lives for `ttl`,
//! the map is swept on a timer, and at capacity the oldest eighth is dropped
//! rather than the whole set. Retention is chosen so that an entry outlives
//! the window in which its message could still be accepted — see
//! `EMERGENCY_DEDUP_TTL` in `node.rs` — which is what makes eviction safe
//! rather than a replay window.
//!
//! An entry is forgotten only when **both** clocks agree it is spent: `ttl`
//! has elapsed on the monotonic clock, and the wall clock is past the entry's
//! `keep_until` by `CLOCK_REGRESSION_GRACE_SECS`. Each covers the other's
//! failure mode. Retention has to be monotonic, because a flood's age is
//! measured from when it arrived; freshness has to be wall-clock, because it
//! is measured against a time the originator wrote. Expiring on the monotonic
//! clock alone means a backward clock correction can retire an entry while
//! the message it covers is still acceptable, which is a replay; expiring on
//! the wall clock alone means a forward jump can retire one early. The grace
//! covers the remaining case — a step backwards *after* an entry was swept,
//! which no live entry can protect against — and the capacity cap is what
//! keeps the map bounded if a wall clock sits far in the past.
//!
//! An entry also records the furthest **reach** — remaining TTL — seen for
//! that key. The TTL is cleartext and cannot be part of the key, since every
//! hop decrements it, so without this a relay could deliver a captured
//! message with `ttl = 0` first: the receiver would accept it, forward
//! nothing, and then drop the genuine higher-TTL copy as a duplicate. A copy
//! that reaches further is worth forwarding again; one that does not is not.
//!
//! Entries are keyed on a caller-supplied 32-byte digest, not on the
//! envelope's `message_id`. A `message_id` is cleartext and unauthenticated,
//! so keying on it alone let any relay suppress a message by sending a bogus
//! copy carrying the same id. The caller keys on what identifies its flood:
//! `mycelium_crypto::emergency::broadcast_digest` for an emergency broadcast,
//! `channel_flood_key` below for a channel message.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mycelium_protocol::types::{MessageId, NodeId};
use mycelium_protocol::wire::EmergencyLevel;
use sha2::{Digest, Sha256};

/// How many distinct *authenticated* approval lists one flood may be
/// forwarded with: the first, plus two improvements.
///
/// A relay can strip approvals, and the originator's signature is what lets a
/// receiver tell a genuine improvement from an invented one (ADR-014). But the
/// originator holds that signing key: it can pad the list with junk and
/// re-sign as often as it likes, so "forward again when the approvals change"
/// needs a ceiling or it is an amplifier. Two improvements is enough for the
/// case this exists for — a stripped copy arriving before the full one — and
/// bounded enough that padding buys almost nothing.
const MAX_APPROVAL_LISTS: usize = 3;

/// How often the map is swept for expired entries while it has room.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// How far past a message's validity window an entry is kept, to absorb a
/// wall clock that steps backwards.
///
/// Sweeping is irreversible: an entry dropped the moment its window closed is
/// gone if the clock then steps back and reopens it, which would let the
/// message be accepted a second time. Keeping it a little longer costs one
/// map entry and nothing else, since a message past its window is refused on
/// freshness anyway.
///
/// Same figure as the clock skew the freshness check already tolerates. A
/// correction larger than this, landing in the moments after an entry was
/// swept, can still reopen a replay; the alternative — tracking a
/// non-regressing clock of our own — risks a worse failure, since a clock
/// briefly set far in the future would make a node refuse *every* alert
/// until it restarted (ADR-013).
const CLOCK_REGRESSION_GRACE_SECS: u64 = 300;

/// Domain separation for the channel-flood dedup key.
const CHANNEL_FLOOD_CONTEXT: &[u8] = b"mycelium-channel-flood-v1:";

/// Seconds since the Unix epoch, saturating at 0 for a clock before 1970.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What identifies one channel-message flood.
///
/// Covers everything the receiver acts on, so a copy that differs in any of
/// it is a different message rather than a duplicate of this one, and a copy
/// that differs in none of it is this message.
pub fn channel_flood_key(
    message_id: &MessageId,
    source: &NodeId,
    channel_id: &[u8; 32],
    content_type: u8,
    data: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHANNEL_FLOOD_CONTEXT);
    hasher.update(message_id.as_bytes());
    hasher.update(source.as_bytes());
    hasher.update(channel_id);
    hasher.update([content_type]);
    hasher.update((data.len() as u32).to_le_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

/// What one copy of a flood is worth, against what we have already kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloodCopy {
    /// Nothing is remembered for this key.
    New,
    /// Remembered, but this copy can travel further than the one we kept.
    Further,
    /// Remembered, and this copy adds nothing.
    Duplicate,
}

/// One accepted copy of a flood, as the dedup set records it.
#[derive(Debug, Clone, Copy)]
pub struct FloodMark {
    /// What identifies the message.
    pub key: [u8; 32],
    /// Remaining TTL this copy carries.
    pub reach: u8,
    /// Wall-clock second up to which this key must be kept whatever the
    /// monotonic clock says — for a message with a signed validity window,
    /// the end of that window. `0` means the message carries no window of its
    /// own and retention is the monotonic TTL alone, which is what a channel
    /// message gets.
    pub keep_until: u64,
    /// Digest of everything this copy carries *about* the message that is not
    /// part of its identity — for an emergency broadcast, the originator's
    /// signature over the approval list (ADR-014). A copy whose value differs
    /// from the one already forwarded is worth forwarding again, up to
    /// `MAX_APPROVAL_REVISIONS` times. `[0; 32]` for a message with no such
    /// payload, which is what a channel message gets.
    pub origin: [u8; 32],
}

/// One approval list this flood has been forwarded with, and how far.
struct ForwardedList {
    origin: [u8; 32],
    /// Furthest remaining TTL forwarded for *this* list.
    reach: u8,
}

struct Entry {
    seen: Instant,
    /// See `FloodMark::keep_until`.
    keep_until: u64,
    /// Reach already forwarded, per approval list, bounded by
    /// `MAX_APPROVAL_LISTS`.
    ///
    /// Reach has to be tracked per list rather than per entry. A single pair
    /// cannot say both "this list has travelled 20 hops" and "that list has
    /// travelled none": a relay delivering a new list with its TTL spent
    /// would otherwise either pin the old list's reach, stopping the new one,
    /// or let any copy with a higher TTL past the ceiling by claiming a new
    /// list.
    forwarded: Vec<ForwardedList>,
}

/// Bounded, age-expiring record of floods already seen.
pub struct FloodDedup {
    entries: HashMap<[u8; 32], Entry>,
    ttl: Duration,
    capacity: usize,
    last_sweep: Instant,
}

impl FloodDedup {
    /// `ttl` is how long an entry is remembered; `capacity` bounds the map.
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
            // A zero capacity would remember nothing and break flood
            // termination, so it is clamped rather than trusted.
            capacity: capacity.max(1),
            last_sweep: Instant::now(),
        }
    }

    /// What this copy is worth, without remembering anything.
    ///
    /// Read-only on purpose. Reading the set before checking a message is
    /// safe — an entry exists only because this node already accepted that
    /// exact message, so a hit is proof the work has been done — but a copy
    /// that claims more reach must not have that claim recorded until it has
    /// been checked, or a bogus copy could pin a reach the genuine one then
    /// fails to beat.
    pub fn probe(&self, mark: &FloodMark) -> FloodCopy {
        self.probe_at(mark, Instant::now(), unix_now())
    }

    /// `probe` with explicit clocks, for tests.
    pub fn probe_at(&self, mark: &FloodMark, now: Instant, now_secs: u64) -> FloodCopy {
        match self.entries.get(&mark.key) {
            Some(entry) if !Self::spent(entry, self.ttl, now, now_secs) => {
                if Self::carries_more(entry, mark) {
                    FloodCopy::Further
                } else {
                    FloodCopy::Duplicate
                }
            }
            _ => FloodCopy::New,
        }
    }

    /// Whether this copy brings something the kept ones do not: more reach for
    /// a list already forwarded, or a list not forwarded yet with room left
    /// for it.
    fn carries_more(entry: &Entry, mark: &FloodMark) -> bool {
        match entry.forwarded.iter().find(|f| f.origin == mark.origin) {
            Some(forwarded) => mark.reach > forwarded.reach,
            None => entry.forwarded.len() < MAX_APPROVAL_LISTS,
        }
    }

    /// Remember a copy the caller has accepted, and say what it was worth.
    pub fn accept(&mut self, mark: FloodMark) -> FloodCopy {
        self.accept_at(mark, Instant::now(), unix_now())
    }

    /// `accept` with explicit clocks, for tests.
    pub fn accept_at(&mut self, mark: FloodMark, now: Instant, now_secs: u64) -> FloodCopy {
        if now.saturating_duration_since(self.last_sweep) >= SWEEP_INTERVAL {
            self.sweep(now, now_secs);
        }

        let ttl = self.ttl;
        if let Some(entry) = self.entries.get_mut(&mark.key) {
            if !Self::spent(entry, ttl, now, now_secs) {
                // Keep the longer window: a copy must not be able to shorten
                // how long its own message is remembered.
                entry.keep_until = entry.keep_until.max(mark.keep_until);
                match entry.forwarded.iter_mut().find(|f| f.origin == mark.origin) {
                    // A list we have carried before: worth carrying again only
                    // if this copy reaches further than it got last time.
                    Some(forwarded) => {
                        if mark.reach > forwarded.reach {
                            forwarded.reach = mark.reach;
                            return FloodCopy::Further;
                        }
                        return FloodCopy::Duplicate;
                    }
                    // A list we have not carried, if there is room for it. The
                    // ceiling is on *lists*, not on sends, so bumping the TTL
                    // cannot buy another one.
                    None => {
                        if entry.forwarded.len() < MAX_APPROVAL_LISTS {
                            entry.forwarded.push(ForwardedList {
                                origin: mark.origin,
                                reach: mark.reach,
                            });
                            return FloodCopy::Further;
                        }
                        return FloodCopy::Duplicate;
                    }
                }
            }
            // Known but spent: overwritten below as if absent.
        } else if self.entries.len() >= self.capacity {
            self.sweep(now, now_secs);
            if self.entries.len() >= self.capacity {
                self.evict_oldest();
            }
        }

        self.entries.insert(
            mark.key,
            Entry {
                seen: now,
                keep_until: mark.keep_until,
                forwarded: vec![ForwardedList {
                    origin: mark.origin,
                    reach: mark.reach,
                }],
            },
        );
        FloodCopy::New
    }

    /// Number of entries currently remembered, expired ones included until
    /// the next sweep.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// An entry is spent only when both clocks say so. See the module docs.
    fn spent(entry: &Entry, ttl: Duration, now: Instant, now_secs: u64) -> bool {
        let aged_out = now.saturating_duration_since(entry.seen) >= ttl;
        let past_window = entry.keep_until == 0
            || now_secs > entry.keep_until.saturating_add(CLOCK_REGRESSION_GRACE_SECS);
        aged_out && past_window
    }

    fn sweep(&mut self, now: Instant, now_secs: u64) {
        let ttl = self.ttl;
        self.entries
            .retain(|_, entry| !Self::spent(entry, ttl, now, now_secs));
        self.last_sweep = now;
    }

    /// Drop the oldest eighth of the map.
    ///
    /// Clearing the whole set was the defect: it discarded entries that were
    /// still inside their validity window, which is what let a captured
    /// message be replayed. Dropping the oldest keeps the newest — the ones a
    /// replay or a loop is most likely to be about — and amortises the sort
    /// over the next eighth of the capacity.
    fn evict_oldest(&mut self) {
        let drop_count = (self.capacity / 8).max(1);
        let mut by_age: Vec<([u8; 32], Instant)> = self
            .entries
            .iter()
            .map(|(k, entry)| (*k, entry.seen))
            .collect();
        by_age.sort_unstable_by_key(|(_, seen)| *seen);
        for (key, _) in by_age.into_iter().take(drop_count) {
            self.entries.remove(&key);
        }
    }
}

/// Flood dedup for emergency broadcasts, kept **per level**.
///
/// One set shared across levels is flushed by whichever level is cheapest to
/// get accepted, and the entry pushed out need not be of that level. Level 1
/// needs only a trust score over `envelope.source`, which nothing
/// authenticates (ROADMAP T-37); a peer already 1 hop away — vouched by hand,
/// or auto-vouched because its beacon carried a group-discovery hash matching
/// ours — clears every threshold and is in the tier the rate limiter does not
/// bound at all. Ten thousand junk level-1 alerts would then evict the entry
/// holding a captured level-3 alert shut, and the capture could be flooded
/// again inside its validity window.
///
/// Per level, evicting a level-3 entry costs ten thousand *accepted* level-3
/// broadcasts — three verifying co-signatures each, over a digest that covers
/// the id, originator, level, date and message, so one capture yields exactly
/// one of them. An attacker who can pay that can already flood the mesh
/// without a replay.
pub struct EmergencyDedup {
    priority: FloodDedup,
    urgent: FloodDedup,
    critical: FloodDedup,
}

impl EmergencyDedup {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            priority: FloodDedup::new(ttl, capacity),
            urgent: FloodDedup::new(ttl, capacity),
            critical: FloodDedup::new(ttl, capacity),
        }
    }

    /// What this copy is worth at `level`, without remembering anything.
    pub fn probe(&self, level: EmergencyLevel, mark: &FloodMark) -> FloodCopy {
        self.level(level).probe(mark)
    }

    /// Remember an accepted copy at `level`, and say what it was worth.
    pub fn accept(&mut self, level: EmergencyLevel, mark: FloodMark) -> FloodCopy {
        self.set(level).accept(mark)
    }

    /// `accept` with explicit clocks, for tests.
    pub fn accept_at(
        &mut self,
        level: EmergencyLevel,
        mark: FloodMark,
        now: Instant,
        now_secs: u64,
    ) -> FloodCopy {
        self.set(level).accept_at(mark, now, now_secs)
    }

    fn level(&self, level: EmergencyLevel) -> &FloodDedup {
        match level {
            EmergencyLevel::Priority => &self.priority,
            EmergencyLevel::Urgent => &self.urgent,
            EmergencyLevel::Critical => &self.critical,
        }
    }

    fn set(&mut self, level: EmergencyLevel) -> &mut FloodDedup {
        match level {
            EmergencyLevel::Priority => &mut self.priority,
            EmergencyLevel::Urgent => &mut self.urgent,
            EmergencyLevel::Critical => &mut self.critical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// Full reach, so most of these tests are about identity, not TTL.
    const FAR: u8 = 20;

    /// A mark with no wall-clock window of its own — what a channel message
    /// gets, so retention is the monotonic TTL alone.
    fn mark(n: u8) -> FloodMark {
        FloodMark {
            key: key(n),
            reach: FAR,
            keep_until: 0,
            origin: [0u8; 32],
        }
    }

    fn mark_with(n: u8, reach: u8, keep_until: u64) -> FloodMark {
        FloodMark {
            key: key(n),
            reach,
            keep_until,
            origin: [0u8; 32],
        }
    }

    /// A mark for the same message carrying a different approval list.
    fn mark_revised(n: u8, reach: u8, origin: u8) -> FloodMark {
        FloodMark {
            key: key(n),
            reach,
            keep_until: 0,
            origin: [origin; 32],
        }
    }

    #[test]
    fn test_a_repeat_inside_the_ttl_is_refused() {
        let mut dedup = FloodDedup::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();
        assert_eq!(dedup.accept_at(mark(1), t0, 1000), FloodCopy::New);
        assert_eq!(
            dedup.accept_at(mark(1), t0 + Duration::from_secs(59), 1059),
            FloodCopy::Duplicate,
            "a flood seen inside the TTL must be recognised as a duplicate"
        );
        assert_eq!(
            dedup.accept_at(mark(2), t0, 1000),
            FloodCopy::New,
            "a different key is not a duplicate"
        );
    }

    #[test]
    fn test_an_entry_older_than_the_ttl_is_forgotten() {
        let mut dedup = FloodDedup::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();
        assert_eq!(dedup.accept_at(mark(1), t0, 1000), FloodCopy::New);
        assert_eq!(
            dedup.accept_at(mark(1), t0 + Duration::from_secs(61), 1061),
            FloodCopy::New,
            "past the TTL the entry must be gone, so the key counts as new"
        );
        assert_eq!(
            dedup.len(),
            1,
            "the expired entry must not be kept alongside its replacement"
        );
    }

    /// Retention is monotonic and freshness is wall-clock, so a backward
    /// clock correction could retire an entry while the message it covers is
    /// still inside its signed validity window — which is a replay. An entry
    /// is spent only when both clocks say so.
    #[test]
    fn test_a_clock_rollback_does_not_retire_an_entry_early() {
        let mut dedup = FloodDedup::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();
        // Acceptable until wall-clock second 1100.
        assert_eq!(
            dedup.accept_at(mark_with(1, FAR, 1100), t0, 1000),
            FloodCopy::New
        );

        // The TTL has elapsed but the clock stepped back, so the message is
        // still acceptable and the entry must still be here.
        let aged = t0 + Duration::from_secs(61);
        assert_eq!(
            dedup.probe_at(&mark_with(1, FAR, 1100), aged, 1090),
            FloodCopy::Duplicate,
            "an entry whose message is still fresh must not be forgotten"
        );
        assert_eq!(
            dedup.accept_at(mark_with(1, FAR, 1100), aged, 1090),
            FloodCopy::Duplicate
        );

        // A correction inside the grace must not retire it either, because
        // sweeping cannot be undone: an entry dropped the instant its window
        // closed is gone if the clock then steps back and reopens it.
        assert_eq!(
            dedup.probe_at(&mark_with(1, FAR, 0), aged, 1101),
            FloodCopy::Duplicate,
            "an entry must outlive its window by the grace, not expire at it"
        );

        // Past the window and the grace, it goes.
        assert_eq!(
            dedup.probe_at(
                &mark_with(1, FAR, 0),
                aged,
                1101 + CLOCK_REGRESSION_GRACE_SECS
            ),
            FloodCopy::New,
            "past both clocks and the grace the entry is spent"
        );
    }

    /// A forward jump must not retire an entry either: the monotonic TTL
    /// still has to elapse.
    #[test]
    fn test_a_clock_jump_forward_does_not_retire_an_entry_early() {
        let mut dedup = FloodDedup::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();
        dedup.accept_at(mark_with(1, FAR, 1100), t0, 1000);
        assert_eq!(
            dedup.probe_at(
                &mark_with(1, FAR, 0),
                t0 + Duration::from_secs(1),
                9_999_999
            ),
            FloodCopy::Duplicate,
            "the TTL has not elapsed, whatever the wall clock says"
        );
    }

    /// A copy must not be able to shorten how long its message is kept.
    #[test]
    fn test_a_copy_cannot_shorten_the_window() {
        let mut dedup = FloodDedup::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();
        dedup.accept_at(mark_with(1, 0, 1100), t0, 1000);
        dedup.accept_at(mark_with(1, 1, 1000), t0, 1000);
        let aged = t0 + Duration::from_secs(61);
        assert_eq!(
            dedup.probe_at(
                &mark_with(1, 1, 0),
                aged,
                1100 + CLOCK_REGRESSION_GRACE_SECS
            ),
            FloodCopy::Duplicate,
            "the longer window must survive a copy claiming a shorter one"
        );
    }

    /// A relay can deliver a captured message with its TTL spent, which the
    /// receiver accepts and cannot forward. The genuine copy behind it must
    /// still travel, or the flood stops there.
    #[test]
    fn test_a_copy_that_reaches_further_is_worth_forwarding_again() {
        let mut dedup = FloodDedup::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();

        assert_eq!(
            dedup.accept_at(mark_with(1, 0, 0), t0, 1000),
            FloodCopy::New
        );
        assert_eq!(
            dedup.probe_at(&mark_with(1, 20, 0), t0, 1000),
            FloodCopy::Further,
            "a copy with reach left must not be dismissed as a duplicate"
        );
        assert_eq!(
            dedup.accept_at(mark_with(1, 20, 0), t0, 1000),
            FloodCopy::Further
        );
        assert_eq!(
            dedup.accept_at(mark_with(1, 20, 0), t0, 1000),
            FloodCopy::Duplicate,
            "once that reach is recorded, the same reach adds nothing"
        );
        assert_eq!(
            dedup.accept_at(mark_with(1, 19, 0), t0, 1000),
            FloodCopy::Duplicate,
            "and neither does less"
        );
    }

    /// `probe` must not record the reach it was asked about: the copy
    /// claiming it has not been checked yet, and a bogus one must not be able
    /// to pin a reach the genuine copy then fails to beat.
    #[test]
    fn test_probing_records_nothing() {
        let mut dedup = FloodDedup::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();

        assert_eq!(
            dedup.probe_at(&mark_with(1, 20, 0), t0, 1000),
            FloodCopy::New
        );
        assert_eq!(
            dedup.len(),
            0,
            "probing an unknown key must not remember it"
        );

        dedup.accept_at(mark_with(1, 5, 0), t0, 1000);
        assert_eq!(
            dedup.probe_at(&mark_with(1, 20, 0), t0, 1000),
            FloodCopy::Further
        );
        assert_eq!(
            dedup.probe_at(&mark_with(1, 20, 0), t0, 1000),
            FloodCopy::Further,
            "a probe must stay answerable the same way until a copy is accepted"
        );
    }

    /// The old set cleared itself at capacity, dropping entries that were
    /// still inside their validity window. Eviction must take the oldest and
    /// leave the newest.
    #[test]
    fn test_at_capacity_the_oldest_go_and_the_newest_survive() {
        let capacity = 16;
        let mut dedup = FloodDedup::new(Duration::from_secs(3600), capacity);
        let t0 = Instant::now();

        for n in 0..capacity {
            // One second apart, so insertion order is age order.
            dedup.accept_at(
                mark(n as u8),
                t0 + Duration::from_secs(n as u64),
                1000 + n as u64,
            );
        }
        assert_eq!(dedup.len(), capacity);

        // One more entry forces an eviction of the oldest eighth (2 of 16).
        let later = t0 + Duration::from_secs(capacity as u64);
        let later_secs = 1000 + capacity as u64;
        assert_eq!(dedup.accept_at(mark(99), later, later_secs), FloodCopy::New);
        assert!(
            dedup.len() <= capacity,
            "the map must stay bounded, got {}",
            dedup.len()
        );

        assert_eq!(
            dedup.probe_at(&mark_with(0, FAR, 0), later, later_secs),
            FloodCopy::New,
            "the oldest entry should have been evicted"
        );
        assert_eq!(
            dedup.probe_at(&mark_with(15, FAR, 0), later, later_secs),
            FloodCopy::Duplicate,
            "the newest entries must survive eviction"
        );
        assert_eq!(
            dedup.probe_at(&mark_with(99, FAR, 0), later, later_secs),
            FloodCopy::Duplicate,
            "the entry that caused the eviction must itself be remembered"
        );
    }

    /// Capacity pressure must not cost more than the oldest eighth: a set
    /// that cleared itself would forget key 15 here too.
    #[test]
    fn test_eviction_keeps_most_of_the_set() {
        let capacity = 16;
        let mut dedup = FloodDedup::new(Duration::from_secs(3600), capacity);
        let t0 = Instant::now();
        for n in 0..capacity {
            dedup.accept_at(
                mark(n as u8),
                t0 + Duration::from_secs(n as u64),
                1000 + n as u64,
            );
        }
        let later = t0 + Duration::from_secs(capacity as u64);
        let later_secs = 1000 + capacity as u64;
        dedup.accept_at(mark(99), later, later_secs);

        let still_known = (0..capacity)
            .filter(|n| {
                dedup.probe_at(&mark_with(*n as u8, FAR, 0), later, later_secs)
                    == FloodCopy::Duplicate
            })
            .count();
        assert!(
            still_known >= capacity - capacity / 8 - 1,
            "eviction dropped {} of {} entries, expected about an eighth",
            capacity - still_known,
            capacity
        );
    }

    /// Within one level, pressure still evicts the oldest — and a replay of
    /// an evicted entry is only stopped by the freshness check, which is why
    /// `test_emergency_dedup_outlives_the_freshness_window` exists.
    #[test]
    fn test_pressure_within_a_level_evicts_the_oldest() {
        let capacity = 16;
        let mut dedup = FloodDedup::new(Duration::from_secs(3900), capacity);
        let t0 = Instant::now();
        for n in 0..=capacity {
            dedup.accept_at(
                mark(n as u8),
                t0 + Duration::from_secs(n as u64),
                1000 + n as u64,
            );
        }
        let now = t0 + Duration::from_secs(capacity as u64);
        let now_secs = 1000 + capacity as u64;
        assert_eq!(
            dedup.probe_at(&mark_with(0, FAR, 0), now, now_secs),
            FloodCopy::New,
            "the oldest is gone"
        );
        assert_eq!(
            dedup.probe_at(&mark_with(capacity as u8, FAR, 0), now, now_secs),
            FloodCopy::Duplicate,
            "the newest is kept"
        );
    }

    /// The levels must not share a budget: a cheap level-1 flood evicting a
    /// co-signed level-3 entry is a replay window on the only broadcast that
    /// floods the whole mesh.
    #[test]
    fn test_a_level_one_flood_does_not_evict_a_level_three_entry() {
        let capacity = 16;
        let mut dedup = EmergencyDedup::new(Duration::from_secs(3900), capacity);
        let t0 = Instant::now();

        let alert = FloodMark {
            key: key(200),
            reach: FAR,
            keep_until: 0,
            origin: [0u8; 32],
        };
        assert_eq!(
            dedup.accept_at(EmergencyLevel::Critical, alert, t0, 1000),
            FloodCopy::New
        );

        // Four times the capacity in level-1 traffic, all accepted.
        for n in 0..(capacity * 4) {
            let mut junk = [0u8; 32];
            junk[..8].copy_from_slice(&(n as u64).to_le_bytes());
            dedup.accept_at(
                EmergencyLevel::Priority,
                FloodMark {
                    key: junk,
                    reach: FAR,
                    keep_until: 0,
                    origin: [0u8; 32],
                },
                t0 + Duration::from_millis(n as u64),
                1000,
            );
        }

        assert_eq!(
            dedup.probe(EmergencyLevel::Critical, &alert),
            FloodCopy::Duplicate,
            "the level-3 entry must survive any amount of level-1 traffic"
        );
    }

    /// A copy carrying a different authenticated approval list is worth
    /// forwarding again — a relay may have stripped the first one — but the
    /// originator holds the signing key, so the ceiling is what stops it
    /// minting improvements forever (ADR-014).
    #[test]
    fn test_only_a_bounded_number_of_approval_lists_is_carried() {
        let mut dedup = FloodDedup::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();

        assert_eq!(
            dedup.accept_at(mark_revised(1, FAR, 1), t0, 1000),
            FloodCopy::New
        );
        for list in 2..=MAX_APPROVAL_LISTS as u8 {
            assert_eq!(
                dedup.accept_at(mark_revised(1, FAR, list), t0, 1000),
                FloodCopy::Further,
                "list {list} is within the ceiling"
            );
        }
        assert_eq!(
            dedup.accept_at(mark_revised(1, FAR, 99), t0, 1000),
            FloodCopy::Duplicate,
            "past the ceiling another approval list buys nothing"
        );
        assert_eq!(
            dedup.probe_at(&mark_revised(1, FAR, 100), t0, 1000),
            FloodCopy::Duplicate,
            "and a probe agrees, so no verification is spent on it"
        );
    }

    /// The ceiling is on approval *lists*, not on sends: a copy claiming a new
    /// list must not get past it by carrying a higher TTL.
    #[test]
    fn test_a_higher_ttl_does_not_buy_another_approval_list() {
        let mut dedup = FloodDedup::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();

        // Fill the ceiling with spent copies, so every later copy has more
        // reach than anything recorded.
        dedup.accept_at(mark_revised(1, 0, 1), t0, 1000);
        for list in 2..=MAX_APPROVAL_LISTS as u8 {
            assert_eq!(
                dedup.accept_at(mark_revised(1, 0, list), t0, 1000),
                FloodCopy::Further
            );
        }
        for (reach, list) in [(1u8, 90u8), (2, 91), (20, 92)] {
            assert_eq!(
                dedup.accept_at(mark_revised(1, reach, list), t0, 1000),
                FloodCopy::Duplicate,
                "reach {reach} must not buy a slot for list {list}"
            );
        }
    }

    /// Replaying an earlier list must not consume the room a later one needs.
    /// A(20) → B(0) → A(20) → B(20): the last copy is the only one that can
    /// carry B anywhere, so it has to be worth forwarding.
    #[test]
    fn test_replaying_a_list_does_not_crowd_out_the_one_behind_it() {
        let mut dedup = FloodDedup::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();
        let a = |reach| mark_revised(1, reach, 1);
        let b = |reach| mark_revised(1, reach, 2);

        assert_eq!(dedup.accept_at(a(20), t0, 1000), FloodCopy::New);
        assert_eq!(
            dedup.accept_at(b(0), t0, 1000),
            FloodCopy::Further,
            "the new list is recorded, though its TTL leaves nothing to send"
        );
        assert_eq!(
            dedup.accept_at(a(20), t0, 1000),
            FloodCopy::Duplicate,
            "replaying the first list at the reach it already had buys nothing"
        );
        assert_eq!(
            dedup.probe_at(&b(20), t0, 1000),
            FloodCopy::Further,
            "and the second list can still travel"
        );
        assert_eq!(dedup.accept_at(b(20), t0, 1000), FloodCopy::Further);
    }

    /// A new approval list delivered with its TTL spent must not pin the old
    /// list's reach: the copy that can actually carry it comes next, and it
    /// would otherwise look like a duplicate.
    #[test]
    fn test_a_new_approval_list_does_not_inherit_the_old_reach() {
        let mut dedup = FloodDedup::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();

        assert_eq!(
            dedup.accept_at(mark_revised(1, 20, 1), t0, 1000),
            FloodCopy::New
        );
        // The new list arrives spent: recorded, but nothing to forward.
        assert_eq!(
            dedup.accept_at(mark_revised(1, 0, 2), t0, 1000),
            FloodCopy::Further
        );
        // The copy that can carry it must still be worth forwarding.
        assert_eq!(
            dedup.probe_at(&mark_revised(1, 20, 2), t0, 1000),
            FloodCopy::Further,
            "the spent copy must not have pinned the previous list's reach"
        );
        assert_eq!(
            dedup.accept_at(mark_revised(1, 20, 2), t0, 1000),
            FloodCopy::Further
        );
        assert_eq!(
            dedup.accept_at(mark_revised(1, 20, 2), t0, 1000),
            FloodCopy::Duplicate,
            "and once carried, it is a duplicate like any other"
        );
    }

    #[test]
    fn test_the_channel_key_covers_every_field_it_claims_to() {
        let id = MessageId::random();
        let source = NodeId([1u8; 32]);
        let channel = [2u8; 32];
        let base = channel_flood_key(&id, &source, &channel, 0, b"hello");

        assert_ne!(
            base,
            channel_flood_key(&MessageId::random(), &source, &channel, 0, b"hello")
        );
        assert_ne!(
            base,
            channel_flood_key(&id, &NodeId([9u8; 32]), &channel, 0, b"hello")
        );
        assert_ne!(
            base,
            channel_flood_key(&id, &source, &[3u8; 32], 0, b"hello")
        );
        assert_ne!(base, channel_flood_key(&id, &source, &channel, 1, b"hello"));
        assert_ne!(
            base,
            channel_flood_key(&id, &source, &channel, 0, b"goodbye")
        );
        assert_eq!(base, channel_flood_key(&id, &source, &channel, 0, b"hello"));
    }
}
