//! Message fragmentation and reassembly for transports with a frame cap.
//!
//! A Mycelium envelope is 106 bytes before its payload, and some links carry
//! far less in one frame: LoRa manages 51 bytes at SF12, and BLE refuses a
//! message over 512. Both need a message split across frames and put back
//! together on the far side, and both need the same safety rules, so they
//! share one implementation rather than two that drift (ROADMAP T-39, T-40).
//!
//! The header on every frame is sender tag (u16 LE), fragment id (u16 LE),
//! index (u8) and count (u8). The sender tag is random per transport
//! instance, so two senders' fragment ids cannot collide into one
//! reassembly — the ids themselves are only unique per sender.
//!
//! Where the link knows who sent a frame, that peer is part of the key too. A
//! 16-bit tag collides by accident often enough on a busy mesh, and a peer
//! that wants to can simply copy another's; either way two senders' fragments
//! would combine into one message, attributed to whoever completed it. LoRa
//! has no link-layer address and passes `NodeId::ZERO`, which is one scope for
//! every sender — there the tag is all that separates them, which is why it
//! exists.
//!
//! What the reassembler refuses, because none of it can be assumed of a
//! stranger's frames: more than `max_message` bytes in total, more
//! concurrent reassemblies than its cap, and anything still incomplete after
//! its TTL.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::debug;

use mycelium_protocol::types::NodeId;

use super::TransportError;

/// Sender tag (2) + fragment id (2) + index (1) + count (1).
pub const FRAG_HEADER: usize = 6;

/// Concurrent reassemblies one transport keeps, and how long an incomplete
/// message waits for its missing fragments.
const MAX_REASSEMBLIES: usize = 64;
const REASSEMBLY_TTL: Duration = Duration::from_secs(120);

/// Split `data` into frames of at most `frame_mtu` bytes, each prefixed with
/// the fragment header.
pub fn fragment(
    data: &[u8],
    frame_mtu: usize,
    sender_tag: u16,
    id: u16,
) -> Result<Vec<Vec<u8>>, TransportError> {
    if frame_mtu <= FRAG_HEADER {
        return Err(TransportError::ExceedsMtu {
            size: data.len(),
            mtu: 0,
        });
    }
    let chunk = frame_mtu - FRAG_HEADER;
    let count = data.len().div_ceil(chunk).max(1);
    if count > u8::MAX as usize {
        return Err(TransportError::ExceedsMtu {
            size: data.len(),
            mtu: chunk * u8::MAX as usize,
        });
    }
    let mut frames = Vec::with_capacity(count);
    for (index, piece) in data.chunks(chunk).enumerate() {
        frames.push(frame_for(sender_tag, id, index as u8, count as u8, piece));
    }
    if frames.is_empty() {
        // An empty message still needs one frame, or the peer never sees it.
        frames.push(frame_for(sender_tag, id, 0, 1, &[]));
    }
    Ok(frames)
}

fn frame_for(sender_tag: u16, id: u16, index: u8, count: u8, piece: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAG_HEADER + piece.len());
    frame.extend_from_slice(&sender_tag.to_le_bytes());
    frame.extend_from_slice(&id.to_le_bytes());
    frame.push(index);
    frame.push(count);
    frame.extend_from_slice(piece);
    frame
}

/// Parse a fragment header. Returns (sender_tag, id, index, count, payload).
fn parse_fragment(frame: &[u8]) -> Option<(u16, u16, u8, u8, &[u8])> {
    if frame.len() < FRAG_HEADER {
        return None;
    }
    let tag = u16::from_le_bytes([frame[0], frame[1]]);
    let id = u16::from_le_bytes([frame[2], frame[3]]);
    let index = frame[4];
    let count = frame[5];
    if count == 0 || index >= count {
        return None;
    }
    Some((tag, id, index, count, &frame[FRAG_HEADER..]))
}

/// Fragments of one message received so far.
struct Reassembly {
    parts: Vec<Option<Vec<u8>>>,
    received: usize,
    bytes: usize,
    started: Instant,
    /// Set once this message was refused for size. The entry stays — holding
    /// nothing — so later fragments of the same message are dropped instead
    /// of starting a fresh accumulation, which is how a refused message
    /// otherwise walks straight back in.
    refused: bool,
}

/// Collects fragments into whole messages, bounded in every direction.
pub struct Reassembler {
    pending: HashMap<(NodeId, u16, u16), Reassembly>,
    max_message: usize,
    label: &'static str,
}

impl Reassembler {
    /// `max_message` is the largest reassembled message accepted; `label`
    /// names the transport in log lines.
    pub fn new(max_message: usize, label: &'static str) -> Self {
        Self {
            pending: HashMap::new(),
            max_message,
            label,
        }
    }

    /// Incomplete messages currently held.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Feed one received frame in, from `peer` where the link knows who sent
    /// it (`NodeId::ZERO` where it does not). Returns the message once every
    /// fragment has arrived.
    pub fn push(&mut self, peer: NodeId, frame: &[u8]) -> Option<Vec<u8>> {
        self.push_at(peer, frame, Instant::now())
    }

    /// `push` with an explicit clock, for tests.
    pub fn push_at(&mut self, peer: NodeId, frame: &[u8], now: Instant) -> Option<Vec<u8>> {
        let (tag, id, index, count, payload) = match parse_fragment(frame) {
            Some(f) => f,
            None => {
                debug!("{}: dropping malformed frame", self.label);
                return None;
            }
        };
        if payload.len() > self.max_message {
            debug!(
                "{}: dropping a {}-byte fragment, over the {}-byte message limit",
                self.label,
                payload.len(),
                self.max_message
            );
            return None;
        }

        self.pending
            .retain(|_, r| now.saturating_duration_since(r.started) < REASSEMBLY_TTL);
        let key = (peer, tag, id);

        // Before the single-fragment path, not after: a refused message must
        // not walk back in as a `count = 1` frame claiming the same key.
        if self.pending.get(&key).is_some_and(|r| r.refused) {
            return None;
        }
        if count == 1 {
            return Some(payload.to_vec());
        }

        if !self.pending.contains_key(&key) && self.pending.len() >= MAX_REASSEMBLIES {
            // Evict the oldest incomplete message rather than grow
            // unbounded, preferring one that is still collecting: a refusal
            // marker holds nothing and exists to outlive the fragments it
            // refused.
            //
            // When every entry is a marker, one is evicted anyway. A marker
            // saves repeated accumulation work; it is not what enforces the
            // size limit, which the restarted message meets again at the same
            // fragment. Refusing new reassemblies instead would let an
            // attacker block legitimate large messages for the whole TTL by
            // filling the table with refusals, which is the worse trade.
            let victim = self
                .pending
                .iter()
                .filter(|(_, r)| !r.refused)
                .min_by_key(|(_, r)| r.started)
                .map(|(k, _)| *k)
                .or_else(|| {
                    self.pending
                        .iter()
                        .min_by_key(|(_, r)| r.started)
                        .map(|(k, _)| *k)
                });
            if let Some(victim) = victim {
                self.pending.remove(&victim);
            }
        }
        let max_message = self.max_message;
        let label = self.label;
        let entry = self.pending.entry(key).or_insert_with(|| Reassembly {
            parts: vec![None; count as usize],
            received: 0,
            bytes: 0,
            started: now,
            refused: false,
        });
        if entry.refused {
            return None;
        }
        if entry.parts.len() != count as usize {
            // Fragment id reused with a different count: start over.
            entry.parts = vec![None; count as usize];
            entry.received = 0;
            entry.bytes = 0;
            entry.started = now;
        }

        // A fragment already held adds nothing, and must not be counted: the
        // same fragment twice would otherwise push the total past the limit
        // and refuse a message that fits.
        if entry.parts[index as usize].is_some() {
            return None;
        }

        // The cap is checked against the bytes accumulated so far, not against
        // one fragment: enough valid fragments otherwise add up past a limit
        // each of them respects, which is how a documented bound goes
        // unenforced (ROADMAP T-40).
        if entry.bytes + payload.len() > max_message {
            debug!(
                "{}: refusing a reassembly past the {}-byte limit",
                label, max_message
            );
            entry.refused = true;
            entry.parts = Vec::new();
            entry.received = 0;
            entry.bytes = 0;
            return None;
        }

        entry.bytes += payload.len();
        entry.parts[index as usize] = Some(payload.to_vec());
        entry.received += 1;
        if entry.received < count as usize {
            return None;
        }
        let done = self.pending.remove(&key)?;
        let mut out = Vec::with_capacity(done.bytes);
        for part in done.parts.into_iter().flatten() {
            out.extend_from_slice(&part);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One scope for most tests; the cross-peer test uses two.
    const PEER: NodeId = NodeId([1u8; 32]);

    /// Moved from the LoRa transport when this became shared: the frame
    /// bounds are the fragmenter's, not one radio's.
    #[test]
    fn test_fragment_bounds() {
        let frames = fragment(&[0u8; 45], 51, 3, 1).unwrap();
        assert_eq!(frames.len(), 1);
        let frames = fragment(&[0u8; 46], 51, 3, 1).unwrap();
        assert_eq!(frames.len(), 2);
        assert!(
            fragment(&[0u8; 45 * 256], 51, 3, 1).is_err(),
            "more fragments than the count byte can express"
        );
        assert!(
            fragment(&[0u8; 10], 6, 3, 1).is_err(),
            "a frame with no room for payload"
        );
        let empty = fragment(&[], 51, 3, 9).unwrap();
        assert_eq!(empty.len(), 1, "an empty message still goes out");
        let (tag, id, index, count, payload) = parse_fragment(&empty[0]).unwrap();
        assert_eq!((tag, id, index, count, payload.len()), (3, 9, 0, 1, 0));
    }

    #[test]
    fn test_a_message_survives_a_round_trip() {
        let data: Vec<u8> = (0..250u8).collect();
        let frames = fragment(&data, 64, 7, 1).expect("fragments");
        assert!(frames.len() > 1, "250 bytes does not fit one 64-byte frame");

        let mut reassembler = Reassembler::new(2048, "test");
        let mut out = None;
        for frame in &frames {
            out = reassembler.push(PEER, frame);
        }
        assert_eq!(out, Some(data), "and comes back whole");
        assert_eq!(reassembler.pending(), 0, "with nothing left over");
    }

    #[test]
    fn test_fragments_may_arrive_in_any_order() {
        let data: Vec<u8> = (0..200u8).collect();
        let mut frames = fragment(&data, 64, 7, 1).expect("fragments");
        frames.reverse();

        let mut reassembler = Reassembler::new(2048, "test");
        let mut out = None;
        for frame in &frames {
            out = reassembler.push(PEER, frame);
        }
        assert_eq!(out, Some(data));
    }

    /// The limit is on the *message*, so it has to be checked against the
    /// bytes accumulated: fragments that each respect it can add up past it,
    /// which is how ADR-008's 2048-byte bound went unenforced.
    #[test]
    fn test_fragments_cannot_add_up_past_the_message_limit() {
        let data: Vec<u8> = (0..200u8).collect();
        let frames = fragment(&data, 64, 7, 1).expect("fragments");

        let mut reassembler = Reassembler::new(100, "test");
        let mut out = None;
        for frame in &frames {
            out = reassembler.push(PEER, frame);
        }
        assert_eq!(out, None, "a 200-byte message is refused at a 100-byte cap");

        // And it stays refused: dropping the partial reassembly instead would
        // let the remaining fragments start a fresh one, so the message walks
        // back in a few frames later.
        for frame in &frames {
            assert_eq!(reassembler.push(PEER, frame), None, "still refused");
        }
    }

    #[test]
    fn test_an_incomplete_reassembly_expires() {
        let data: Vec<u8> = (0..200u8).collect();
        let frames = fragment(&data, 64, 7, 1).expect("fragments");
        let t0 = Instant::now();

        let mut reassembler = Reassembler::new(2048, "test");
        assert_eq!(reassembler.push_at(PEER, &frames[0], t0), None);
        assert_eq!(reassembler.pending(), 1);

        // A later frame of a different message sweeps the expired one.
        let other = fragment(&data, 64, 7, 2).expect("fragments");
        reassembler.push_at(
            PEER,
            &other[0],
            t0 + REASSEMBLY_TTL + Duration::from_secs(1),
        );
        assert_eq!(
            reassembler.pending(),
            1,
            "the abandoned reassembly is gone, the new one is held"
        );
    }

    /// Where the link knows who sent a frame, that peer is part of the key.
    /// Two peers using the same tag and id — by accident on a 16-bit tag, or
    /// because one copied the other — must not combine into one message
    /// attributed to whoever completed it.
    #[test]
    fn test_two_peers_sharing_a_tag_do_not_mix_fragments() {
        const OTHER: NodeId = NodeId([2u8; 32]);
        let mine: Vec<u8> = vec![1u8; 100];
        let theirs: Vec<u8> = vec![2u8; 100];
        // Identical tag and id, different senders.
        let frames_mine = fragment(&mine, 64, 5, 5).expect("fragments");
        let frames_theirs = fragment(&theirs, 64, 5, 5).expect("fragments");

        let mut reassembler = Reassembler::new(2048, "test");
        assert_eq!(reassembler.push(PEER, &frames_mine[0]), None);
        assert_eq!(reassembler.push(OTHER, &frames_theirs[0]), None);
        assert_eq!(reassembler.pending(), 2, "kept apart by peer");
        assert_eq!(reassembler.push(PEER, &frames_mine[1]), Some(mine));
        assert_eq!(reassembler.push(OTHER, &frames_theirs[1]), Some(theirs));
    }

    /// A fragment already held adds nothing. Counting it towards the total
    /// would push a message that fits past the limit — and the refusal is
    /// sticky, so the message would never arrive.
    #[test]
    fn test_a_duplicate_fragment_does_not_refuse_a_message_that_fits() {
        let data: Vec<u8> = (0..100u8).collect();
        let frames = fragment(&data, 64, 7, 1).expect("fragments");
        assert_eq!(frames.len(), 2);

        let mut reassembler = Reassembler::new(100, "test");
        assert_eq!(reassembler.push(PEER, &frames[0]), None);
        assert_eq!(
            reassembler.push(PEER, &frames[0]),
            None,
            "the same fragment twice is simply ignored"
        );
        assert_eq!(
            reassembler.push(PEER, &frames[1]),
            Some(data),
            "and the message still completes at exactly the limit"
        );
    }

    /// A refused message must not return as a single-fragment frame claiming
    /// the same key: the refusal is checked before that path.
    #[test]
    fn test_a_refused_message_cannot_return_as_one_fragment() {
        let data: Vec<u8> = (0..200u8).collect();
        let frames = fragment(&data, 64, 7, 1).expect("fragments");

        let mut reassembler = Reassembler::new(100, "test");
        for frame in &frames {
            reassembler.push(PEER, frame);
        }

        // Same tag and id, one fragment, small enough on its own.
        let sneaky = fragment(&[9u8; 50], 64, 7, 1).expect("fragments");
        assert_eq!(sneaky.len(), 1);
        assert_eq!(
            reassembler.push(PEER, &sneaky[0]),
            None,
            "the key is refused, whatever the frame claims"
        );
    }

    /// With every slot holding a refusal marker, a new reassembly still gets
    /// in: a marker saves repeated accumulation work rather than enforcing
    /// the limit, and the restarted message meets the same check at the same
    /// fragment. Blocking legitimate large messages for a whole TTL would be
    /// the worse failure (ADR-022).
    #[test]
    fn test_a_table_full_of_refusals_still_admits_a_new_message() {
        let oversized: Vec<u8> = (0..200u8).collect();
        let mut reassembler = Reassembler::new(100, "test");

        // Saturate the table with refused messages, each from its own peer.
        for n in 0..MAX_REASSEMBLIES {
            let peer = NodeId([n as u8; 32]);
            let frames = fragment(&oversized, 64, 7, 1).expect("fragments");
            for frame in &frames {
                reassembler.push(peer, frame);
            }
        }
        assert_eq!(reassembler.pending(), MAX_REASSEMBLIES);

        // A message that fits, from a peer the table has never seen.
        let fits: Vec<u8> = (0..100u8).collect();
        let frames = fragment(&fits, 64, 1, 1).expect("fragments");
        let newcomer = NodeId([200u8; 32]);
        assert_eq!(reassembler.push(newcomer, &frames[0]), None);
        assert_eq!(
            reassembler.push(newcomer, &frames[1]),
            Some(fits),
            "a legitimate message is not blocked by a table of refusals"
        );

        // And an oversized message is still refused, restarted or not.
        let frames = fragment(&oversized, 64, 9, 9).expect("fragments");
        let mut out = None;
        for frame in &frames {
            out = reassembler.push(newcomer, frame);
        }
        assert_eq!(out, None, "the size limit does not depend on the marker");
    }

    #[test]
    fn test_a_malformed_frame_is_dropped() {
        let mut reassembler = Reassembler::new(2048, "test");
        assert_eq!(
            reassembler.push(PEER, &[1, 2]),
            None,
            "shorter than the header"
        );
        // count = 0 is impossible; index past count is a lie about position.
        assert_eq!(reassembler.push(PEER, &[0, 0, 0, 0, 0, 0]), None);
        assert_eq!(reassembler.push(PEER, &[0, 0, 0, 0, 3, 2]), None);
        assert_eq!(reassembler.pending(), 0);
    }

    /// Two senders' fragment ids are independent, so the tag has to be part of
    /// the key or their fragments would combine into one corrupted message.
    #[test]
    fn test_two_senders_do_not_share_a_reassembly() {
        let a: Vec<u8> = vec![1u8; 100];
        let b: Vec<u8> = vec![2u8; 100];
        let frames_a = fragment(&a, 64, 1, 5).expect("fragments");
        let frames_b = fragment(&b, 64, 2, 5).expect("fragments");

        let mut reassembler = Reassembler::new(2048, "test");
        assert_eq!(reassembler.push(PEER, &frames_a[0]), None);
        assert_eq!(reassembler.push(PEER, &frames_b[0]), None);
        assert_eq!(reassembler.pending(), 2, "kept apart by sender tag");
        assert_eq!(reassembler.push(PEER, &frames_a[1]), Some(a));
        assert_eq!(reassembler.push(PEER, &frames_b[1]), Some(b));
    }
}
