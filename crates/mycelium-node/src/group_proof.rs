//! Challenges a node is waiting on answers to (ADR-019).
//!
//! A beacon's group hint is public, so a match is only a hint: the verifier
//! sends a fresh nonce and vouches for the peer that returns
//! `HMAC(proof_key, nonce ‖ verifier ‖ responder)`. This is the verifier's
//! side of that wait — one outstanding nonce per peer, aged out, bounded, and
//! spendable once.
//!
//! Three rules the table exists to enforce, none of which the MAC can:
//!
//! - **One guess per nonce.** An answer, right or wrong, spends the nonce.
//!   Without it a wrong answer would simply be followed by another, and the
//!   peer could keep asking until it got lucky.
//! - **A cooldown, not a retry per beacon.** Beacons arrive every 10–30 s, so
//!   challenging an unvouched peer on each one would make us the flooder:
//!   twice a minute, for as long as it stays in range, for each of however
//!   many identities it cares to beacon under. One attempt per peer per
//!   [`PROOF_RETRY_AFTER`] instead, which costs a real member one further
//!   wait when a challenge is lost on a flaky link.
//! - **A ceiling on the wait.** At [`MAX_PENDING_PROOFS`] the table refuses to
//!   open another challenge rather than evicting one. Eviction would be the
//!   wrong way round: a node that beacons under many identities would displace
//!   the nonce a genuine member still owes an answer to. Refusing costs that
//!   member a later attempt; evicting costs it the vouch it had already
//!   earned.
//!
//! Nothing here is persisted. A restart forgets every outstanding nonce, which
//! is correct — the answer to a nonce nobody is waiting on is worthless — and
//! the next beacon starts the exchange again.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use mycelium_protocol::types::NodeId;

/// How long an answer is accepted after the challenge went out.
///
/// One beacon interval on a phone: long enough for a round trip over a radio
/// that fragments, short enough that a captured answer is stale before it can
/// be carried anywhere.
pub const PROOF_TTL: Duration = Duration::from_secs(30);

/// How long before the same peer may be challenged again.
///
/// Measured from the attempt, not from its outcome, so a peer that stays
/// silent and one that answers wrongly wait the same: both cost us a nonce,
/// and neither should be able to ask for the next one sooner.
pub const PROOF_RETRY_AFTER: Duration = Duration::from_secs(120);

/// How many peers may owe an answer at once.
pub const MAX_PENDING_PROOFS: usize = 256;

/// Per-peer budget for the exchange, in messages an hour.
///
/// Answering a challenge is work a stranger can ask for, so it is bounded —
/// but by a figure of its own, not by the trust tiers, which give an unknown
/// peer five messages an hour. This path exists to run *before* any trust
/// exists: on the tier a real member would spend its whole allowance inside
/// the first minutes of being in range and then have nothing left to answer
/// with (ADR-019).
pub const PROOF_MESSAGES_PER_HOUR: u32 = 30;

/// A challenge sent, and whether its one answer has been spent.
#[derive(Debug, Clone)]
struct Attempt {
    nonce: [u8; 32],
    sent_at: Instant,
    answered: bool,
}

/// The nonces this node is waiting on, one per peer.
#[derive(Debug)]
pub struct PendingProofs {
    attempts: HashMap<NodeId, Attempt>,
    capacity: usize,
}

/// Through `new`, not derived: a derived `Default` would give a table of
/// capacity zero, which refuses every challenge and so turns the exchange off
/// without saying so.
impl Default for PendingProofs {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingProofs {
    pub fn new() -> Self {
        Self::with_capacity(MAX_PENDING_PROOFS)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            attempts: HashMap::new(),
            capacity,
        }
    }

    /// Record a challenge about to be sent to `peer`.
    ///
    /// `false` means do not send one: an attempt is still outstanding or
    /// cooling down, or the table is full. The caller generates the nonce and
    /// sends it only on `true`, so a refusal leaves nothing half-recorded.
    pub fn open(&mut self, peer: NodeId, nonce: [u8; 32]) -> bool {
        self.open_at(peer, nonce, Instant::now())
    }

    /// `open` against a supplied clock.
    pub fn open_at(&mut self, peer: NodeId, nonce: [u8; 32], now: Instant) -> bool {
        if let Some(attempt) = self.attempts.get(&peer) {
            if now.saturating_duration_since(attempt.sent_at) < PROOF_RETRY_AFTER {
                return false;
            }
        } else if self.attempts.len() >= self.capacity {
            self.sweep(now);
            if self.attempts.len() >= self.capacity {
                return false;
            }
        }

        self.attempts.insert(
            peer,
            Attempt {
                nonce,
                sent_at: now,
                answered: false,
            },
        );
        true
    }

    /// The nonce `peer` owes an answer to, spending the one guess it gets.
    ///
    /// `None` when there is no outstanding challenge, when it has already been
    /// answered, or when it has aged out. The attempt is kept either way, so
    /// answering does not shorten the cooldown.
    pub fn answer(&mut self, peer: &NodeId) -> Option<[u8; 32]> {
        self.answer_at(peer, Instant::now())
    }

    /// `answer` against a supplied clock.
    pub fn answer_at(&mut self, peer: &NodeId, now: Instant) -> Option<[u8; 32]> {
        let attempt = self.attempts.get_mut(peer)?;
        if attempt.answered || now.saturating_duration_since(attempt.sent_at) > PROOF_TTL {
            return None;
        }
        attempt.answered = true;
        Some(attempt.nonce)
    }

    /// Drop attempts that can neither be answered nor block a new challenge.
    pub fn sweep_now(&mut self) {
        self.sweep(Instant::now());
    }

    fn sweep(&mut self, now: Instant) {
        self.attempts
            .retain(|_, a| now.saturating_duration_since(a.sent_at) < PROOF_RETRY_AFTER);
    }

    pub fn len(&self) -> usize {
        self.attempts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attempts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> NodeId {
        NodeId::from_bytes([n; 32])
    }

    #[test]
    fn test_an_answer_within_the_ttl_returns_the_nonce() {
        let mut pending = PendingProofs::new();
        let t0 = Instant::now();
        assert!(pending.open_at(peer(1), [9u8; 32], t0));
        assert_eq!(
            pending.answer_at(&peer(1), t0 + Duration::from_secs(5)),
            Some([9u8; 32])
        );
    }

    #[test]
    fn test_a_peer_that_was_never_challenged_owes_nothing() {
        let mut pending = PendingProofs::new();
        assert_eq!(pending.answer(&peer(1)), None);
    }

    /// The nonce buys one attempt. A second answer — a second guess at the
    /// MAC — has nothing to check against.
    #[test]
    fn test_a_nonce_is_spent_by_the_first_answer() {
        let mut pending = PendingProofs::new();
        let t0 = Instant::now();
        assert!(pending.open_at(peer(1), [9u8; 32], t0));
        assert!(pending.answer_at(&peer(1), t0).is_some());
        assert_eq!(pending.answer_at(&peer(1), t0), None);
    }

    #[test]
    fn test_an_answer_after_the_ttl_is_too_late() {
        let mut pending = PendingProofs::new();
        let t0 = Instant::now();
        assert!(pending.open_at(peer(1), [9u8; 32], t0));
        assert_eq!(pending.answer_at(&peer(1), t0 + PROOF_TTL * 2), None);
    }

    /// A beacon every 30 s must not mean a challenge every 30 s.
    #[test]
    fn test_a_second_challenge_waits_for_the_cooldown() {
        let mut pending = PendingProofs::new();
        let t0 = Instant::now();
        assert!(pending.open_at(peer(1), [1u8; 32], t0));
        assert!(!pending.open_at(peer(1), [2u8; 32], t0 + Duration::from_secs(30)));
        assert!(!pending.open_at(
            peer(1),
            [2u8; 32],
            t0 + PROOF_RETRY_AFTER - Duration::from_secs(1)
        ));
        assert!(pending.open_at(peer(1), [2u8; 32], t0 + PROOF_RETRY_AFTER));
        // And the new nonce is the one an answer is checked against.
        assert_eq!(
            pending.answer_at(&peer(1), t0 + PROOF_RETRY_AFTER),
            Some([2u8; 32])
        );
    }

    /// Answering wrongly must not buy a fresh nonce: the cooldown runs from
    /// the attempt, not from its outcome.
    #[test]
    fn test_a_wrong_answer_does_not_shorten_the_cooldown() {
        let mut pending = PendingProofs::new();
        let t0 = Instant::now();
        assert!(pending.open_at(peer(1), [1u8; 32], t0));
        // The handler took the nonce, found the MAC wrong, and vouched for
        // nobody. The next beacon arrives seconds later.
        assert!(pending.answer_at(&peer(1), t0).is_some());
        assert!(!pending.open_at(peer(1), [2u8; 32], t0 + Duration::from_secs(1)));
    }

    #[test]
    fn test_the_table_refuses_rather_than_evicting_a_live_challenge() {
        let mut pending = PendingProofs::with_capacity(2);
        let t0 = Instant::now();
        assert!(pending.open_at(peer(1), [1u8; 32], t0));
        assert!(pending.open_at(peer(2), [2u8; 32], t0));
        assert!(!pending.open_at(peer(3), [3u8; 32], t0));
        // The one that was already waiting still is.
        assert_eq!(pending.answer_at(&peer(1), t0), Some([1u8; 32]));
    }

    #[test]
    fn test_room_comes_back_when_attempts_age_out() {
        let mut pending = PendingProofs::with_capacity(1);
        let t0 = Instant::now();
        assert!(pending.open_at(peer(1), [1u8; 32], t0));
        assert!(!pending.open_at(peer(2), [2u8; 32], t0));
        assert!(pending.open_at(peer(2), [2u8; 32], t0 + PROOF_RETRY_AFTER));
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_the_default_table_accepts_a_challenge() {
        let mut pending = PendingProofs::default();
        assert!(pending.open(peer(1), [1u8; 32]));
        assert_eq!(pending.answer(&peer(1)), Some([1u8; 32]));
    }

    #[test]
    fn test_sweeping_keeps_a_challenge_that_can_still_be_answered() {
        let mut pending = PendingProofs::new();
        let t0 = Instant::now();
        assert!(pending.open_at(peer(1), [1u8; 32], t0));
        pending.sweep(t0 + PROOF_TTL / 2);
        assert_eq!(pending.len(), 1);
        pending.sweep(t0 + PROOF_RETRY_AFTER);
        assert!(pending.is_empty());
    }
}
