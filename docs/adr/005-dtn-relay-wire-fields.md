# ADR-005: DTN Relay Payload Carries Spray Copies and TTL

## Status

Accepted (2026-09-04)

## Context

The `DtnRelay` wire payload (type `0x40`) carried only the message id and the
opaque bundle. Two consequences, found in review:

1. A relay had no way to learn how many spray copies it had been given, so it
   stored every bundle with `copies_remaining = 1`. Binary spray-and-wait
   therefore degenerated: the originator sprayed 8→4→2→1 to three relays and
   none of them could spray further. The network held at most four copies
   instead of L=8, and second-level spraying never happened.
2. A relay re-derived `expires_at = now + 72h` for every bundle it stored, so
   the TTL restarted at each hop and a bundle could live far longer than the
   72 hours the originator intended.

Separately, the node's generic "forward if not for us" path caught `DtnRelay`
envelopes before the DTN handler, so intermediate relays dropped bundles for
which they had no AODV route instead of storing them. Store-and-carry only
worked between the originator and the destination directly.

## Decision

- Extend the `DtnRelay` body to
  `message_id(16) + copies_remaining(1) + ttl_secs(4 LE) + payload_len(4 LE) + payload`
  (minimum body 25 bytes, was 20). The originator sends the copies it hands
  over and the remaining lifetime in seconds; the relay stores exactly that,
  clamped to the 72-hour maximum so a peer cannot pin storage indefinitely.
- `DtnRelay` envelopes destined to another node bypass the generic forward
  path and always reach `handle_dtn_relay`, which stores them when no route
  exists.
- Wire-level representation is the `DtnRelayPayload` struct in
  `mycelium-protocol::wire`.

This is a breaking wire change. The protocol is still `0.1-draft` and no
deployed nodes exist, so no compatibility shim is provided; the protocol
version field remains `1`.

## Consequences

**Easier:**
- Spray-and-wait behaves as specified (L copies, halving at each relay).
- Bundle lifetime is end-to-end.

**Harder:**
- Nodes built before this change cannot exchange DTN bundles with nodes built
  after it.

## Alternatives Considered

1. **Keep the old format and infer copies** — Impossible; the information is
   not on the wire.
2. **Carry an absolute expiry timestamp** — Nodes have no synchronized clocks
   (spec §8.2), so a relative TTL is the only meaningful value.
