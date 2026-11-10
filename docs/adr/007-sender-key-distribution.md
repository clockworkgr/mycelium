# ADR-007: Sender-Key Distribution over Pairwise Sessions

## Status

Accepted (2026-09-04)

## Context

Group messaging used sender keys (spec §6.2, simplified MLS) but no node ever
sent its sender key to anyone: the API and FFI "add member" calls inserted a
locally generated placeholder key, and the only wire handler accepted a bare
`SenderKeyDistribution` (0x71) envelope from any source, unauthenticated,
creating groups and injecting members at will. Cross-device group chat could
not decrypt a single message.

## Decision

- A sender-key distribution is only ever carried as the plaintext of a
  pairwise Double-Ratchet `EncryptedMessage` with content type `System`.
  Top-level 0x71 envelopes are ignored. The payload carries the sender's
  chain key and iteration, the sender's roster, and an explicit list of
  removed members (`SenderKeyDistributionPayload`).
- `Node::add_group_member` adds the member without a key and sends our key
  plus the roster to every member. `Node::remove_group_member` rotates our
  key and sends it, with the member listed in `removed`, to the remaining
  members. Both are exposed unchanged through REST and FFI.
- On receipt (`install_sender_key`): an unknown group is created (an
  invitation) with the sender and roster as members; for a known group the
  sender must already be a member. Rosters are **union-only**: a member that
  has not yet heard of a newer addition sends a shorter roster, which must
  not be mistaken for a removal. Removals are explicit; a removal naming us
  makes us leave the group. The receiver then sends its own key to every
  roster member it has not sent it to (`key_sent_to`, in-memory; a restart
  re-sends once).
- Because members now open sessions with each other concurrently, the
  simultaneous-initiation race became routine. When two peers initiate
  within 60 seconds of each other, the peer with the lower NodeId keeps its
  session and decrypts the other side's first message without installing the
  competing session; the other peer replaces its session when the winner's
  `SessionInit` arrives. Messages the loser sent under its own session
  between the two inits are lost (normally none beyond the distribution).
- Distributions and other System messages are not stored in the
  conversation history.

## Consequences

**Easier:**
- Groups work across devices with no admin protocol: any member can add or
  remove, and every pair ends up holding each other's keys after one
  exchange (verified by `tests/group_pipeline.rs`).

**Harder:**
- No admin/authorization model: any member can remove any other. Rotation
  after removal only covers the remover's own key; other members keep their
  keys until they rotate (unchanged from spec §6.2 simplification).
- Skipped group message keys are not persisted across restarts.

## Alternatives Considered

1. **Roster as authoritative snapshot** — Rejected after it made a stale
   roster from an earlier-informed member evict a freshly added one.
2. **Full MLS tree** — Still deferred (spec §21); sender keys are adequate
   for groups under 20 members.
