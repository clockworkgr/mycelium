# ADR-014: Origin-Authenticated Emergency Broadcasts

## Status

Accepted (2026-11-12). **Partially implemented (2026-11-13) — ROADMAP T-37.**
The origin authentication below is built; the per-level behaviour is not. See
the note at the end.

## Context

ADR-010 made a level-3 broadcast's co-signatures real and ADR-013 stopped a
forged copy suppressing a genuine alert. Neither authenticates the *originator*.

Levels 1 and 2 carry no signature at all, and `envelope.source` is cleartext
and unverified, so the trust gate scores the id in the packet rather than the
peer that sent it. **The sender needs no standing of its own**: an unvouched
stranger in radio range can emit an alert naming a source the receiver trusts,
and the gate will score that source. Its own trust affects only how often it
may do so — an unknown peer is allowed five messages an hour by the
per-neighbour limit, while a vouched one (by hand, or auto-vouched because its
beacon carried a matching group-discovery hash, which anyone in range can copy
— ROADMAP T-04) sits in a tier with no bound at all. Level 3 is bound by its
co-signatures, which cover the originator, so this is levels 1 and 2.

Separately, spec §9.5 describes three per-level behaviours and the code
implements none of them. Every accepted broadcast floods to every peer;
nothing consults the level when queueing a relay; and the per-originator rate
limit is skipped for *all* emergency levels, since it is charged only for
`EncryptedMessage`, `GroupMessage` and `ChannelMessage`. The only thing a level
selects today is its trust threshold.

## Decision

### The broadcast carries the originator's key and signature

The body gains `identity_key(32) ‖ signature(64)`. A receiver drops the
broadcast unless `SHA-256(identity_key) == envelope.source` and the signature
verifies — the binding rule spec §14.3 already applies to `SessionInit` and
`PrekeyResponse`, and the reason it works here is the same: the key is
self-verifying against the id it claims, so no prior contact is needed.

The signature covers **its own digest, over the alert and the whole approval
list**:

```
SHA-256( b"mycelium-emergency-origin-v1:"
       ‖ broadcast_digest (32)   // ADR-013: id, originator, level, date, message
       ‖ cosigner_count   (1)
       ‖ for each: node_id(32) ‖ signature(64) )
```

Signing `broadcast_digest` alone would leave the approvals unauthenticated,
which is the hole ADR-013 records under "a relay can weaken the approval set it
passes on" and which ROADMAP T-37 exists to close. With the list inside the
digest, a stripped or padded copy fails the origin signature, so "more
approvals" becomes a claim a receiver can check.

**The approvals stay out of the dedup identity.** Flood dedup and capacity
remain keyed on `broadcast_digest`, as ADR-013 has it. Keying on the origin
digest instead would hand the *originator* an amplifier: holding the signing
key, it can pad the approval list with junk entries and re-sign, producing
arbitrarily many distinct identities for one alert — each accepted, each
flooded, each occupying an entry — with no new co-signatures needed, which is
precisely the capacity argument ADR-013 rests on ("one capture yields exactly
one digest"). One alert must be one entry however its approvals are presented.

A copy whose authenticated approval list differs from the one already forwarded
may therefore be forwarded again only under a **bounded counter per
`broadcast_digest`**, the same shape as ADR-013's reach rule: a small number of
improvements, then nothing. The bound is what keeps the originator's padding
worthless; the authentication is what keeps a relay's stripping worthless.

There is no circularity: a co-signer signs `broadcast_digest`, which does not
include the list, and the originator signs last, over the approvals it
collected. The sequencing that implies is real and belongs with T-05's
collection work — an alert cannot be signed before its approvals are in, so for
level 3 the originator signs after collection, while levels 1 and 2 have an
empty list and sign immediately.

That is what makes refusing the alternative safe. Requiring a *held* key would
mean a receiver with no prior contact refuses a genuine alert — the partitioned
-mesh failure ADR-010 already accepts for co-signatures, which would now extend
to every level and every hop. Carrying the key costs 96 bytes on the one
message type that already bypasses routing.

The signature is mandatory at every level, and is checked **before** the trust
gate: an alert whose origin does not verify is not an alert, whatever its
claimed source scores. The trust gate stays a separate question — a verified
originator may still be untrusted, and then the thresholds apply as now.

### The levels get the behaviour the spec promises

- **Level 1 (Priority)** — boosted priority in relay queues, and a reach below
  a level-3 flood.
- **Level 2 (Urgent)** — exempt from the per-originator rate limit, which no
  other level is; the per-neighbour limit still applies, as it does to every
  message, since it is charged before a payload is parsed.
- **Level 3 (Critical)** — the only level that floods mesh-wide, at the full
  clamped TTL.

So levels 1 and 2 need a reach limit of their own rather than the single
`MAX_FLOOD_TTL` clamp ADR-013 introduced, and the relay path needs a priority
notion it does not have. The alternative — rewriting §9.5 to say a level
selects only its trust threshold — was rejected deliberately: the tiers exist
so that the cheap levels are cheap for the mesh, and collapsing them means a
level-1 alert costs the network exactly as much as a mesh-wide emergency.

## Consequences

**Easier:**

- An alert's origin is a fact rather than a claim, at every level. A neighbour
  that knows the group seed phrase can no longer speak as anyone else.
- A forged copy is rejected after one signature check, before any co-signature
  is looked at — which is also the bound ADR-013 could not give for the
  verification work a replayed copy can ask for.
- The levels mean what the spec says, so a level-1 alert no longer costs the
  mesh what a level-3 one does.

**Harder:**

- Breaking wire change: +96 bytes on `0x90`, and the signature is mandatory, so
  every sender must have an identity to sign with. Protocol stays `0.1-draft`,
  version field unchanged (ADR-005, ADR-009, ADR-010, ADR-011, ADR-013).
- The originator signs after collecting approvals, so the signature cannot be
  computed until the co-signature exchange T-05 builds has finished. A level-3
  alert therefore has an ordering constraint its API shape must respect.
- **An alert can no longer fit BLE.** On the wire an alert is

  ```
  217 + message_bytes + 96 × approvals
  ```

  (106-byte envelope, 111-byte body overhead including this record's key and
  signature), against the BLE transport's 512-byte message cap, which it
  enforces by refusing the send. So three approvals leave 7 bytes of message,
  and no approvals leave 295 — where before this record they left 391. The
  familiar "522 bytes" is one point on that line: three approvals and a
  17-byte message. Recorded as ROADMAP T-39; the choices are message-level
  fragmentation in the BLE transport or a smaller co-signer entry, and neither
  belongs in this decision.

  What this record does do about it: a node refuses to raise an alert larger
  than the narrowest transport it has registered, and says so, rather than
  flooding the links that can carry it and stopping silently at the rest. On a
  phone that is BLE's 512 bytes; on a daemon with only internet links it is
  whatever those allow.
- The relay path gains a priority queue, and reach becomes per level. Both are
  new behaviour on the emergency path, which means new tests rather than
  adapted ones.
- An originator with no identity cannot raise an alert. That is the intended
  direction, and it means the API must refuse to send one rather than sending
  something no receiver will take.

## Alternatives Considered

1. **Require a held identity key, as co-signature verification does.** Simple,
   and it refuses genuine alerts from anyone the receiver has never met —
   across a partition, that is most of the mesh.
2. **Accept an unverifiable alert at level 1.** Keeps reach, and adds a second
   class of alert to reason about while still flooding something
   unauthenticated.
3. **Leave origin authentication out and rely on the trust gate.** The status
   quo: the gate scores the cleartext id in the packet, not the peer that sent
   it, so it gates nothing at all — any neighbour can name a source the
   receiver trusts. A vouch only removes the rate bound on doing so.
4. **Collapse the levels to a trust threshold each (spec follows code).** Less
   work and honest about today's behaviour, but it gives up the tiering that
   justifies having levels at all.

## Note (2026-11-12)

Two things this record left open are now decided.

**"Boosted priority in relay queues" means a queue that does not exist yet.**
The realtime relay path sends as it decides, with no queue to prioritise;
`pending_routes` and `pending_messages` are per-destination waits, not an
ordering structure. The decision is to build a **two-class send queue** in the
relay path, so the spec's wording means what it says, rather than
reinterpreting priority as a DTN-store property (spray order and eviction
preference), which was the cheaper reading.

The cost is accepted and belongs on the record: a queue on the hot path
introduces ordering, latency and backpressure behaviour where today there is
none, and the failure modes it adds — a full queue, a starved low class, a
message delayed behind a burst — are new. Whatever is built needs a test for
each of those, not only for "level 1 goes first".

**The reach limits for levels 1 and 2 are a shape, not yet a number.** Levels 1
and 2 travel less far than a level-3 flood; the constants are to be set against
the testbed (ROADMAP T-19) or real hardware (T-15), not guessed here, because
what a useful reach is depends on mesh diameter and density. The rule they must
satisfy: level 3's reach is `MAX_FLOOD_TTL`, and 1 and 2 are strictly below it.

## Note (2026-11-13)

The authentication half is implemented. What that meant in practice, beyond
what is written above:

- **The id and date are fixed before approvals are collected.** A co-signature
  covers both (ADR-010), so a send path that minted the id itself would make
  every collected approval useless. `Node::draft_emergency` fixes them,
  `emergency_cosign_digest` says what a co-signer signs, and
  `raise_emergency(draft, cosigners)` signs last and floods. The API delegates
  to those rather than building envelopes itself.
- **One cap, before signing and serializing.** The co-signer count is a single
  byte; signing a longer list than the wire can carry produced broadcasts whose
  own signature could never verify.
- **Dedup tracks reach per approval list, not per alert.** The rule above —
  forward a copy carrying a better-authenticated list, up to a ceiling — needs
  to know how far *each* list has already travelled. One `(list, reach)` pair
  per entry was not enough: a relay delivering a new list with its TTL spent
  recorded the list while forwarding nothing, and then the copy that could
  carry it looked like a duplicate; and once the ceiling was reached, any copy
  with a higher TTL slipped past it whatever list it carried. An entry now
  keeps up to three `(approval-list digest, reach forwarded)` pairs — the
  first list plus two improvements — and a copy is worth forwarding only if it
  reaches further than *its own* list already did, or brings a list with a
  free slot.

**What remains (the second half of this record):** the per-level behaviour.
Every accepted broadcast still floods at the same reach, nothing consults the
level when relaying, and the per-originator rate limit is skipped for all
levels. The reach limits and the two-class send queue are the work; the queue's
scope — floods only, all relayed traffic, or every outbound send — is the
question to settle before building it, because it decides whether this is a
contained change or one that touches every forward path.
