# ADR-008: LoRa Fragmentation, Peer Discovery and Broadcast

## Status

Accepted (2026-09-04)

## Context

The Rust LoRa transport rejected any send larger than the radio MTU (51 bytes
at SF10-12, the default), while the smallest Mycelium envelope is 106 bytes.
Nothing could ever be sent, so adaptive data rate never adjusted. The
transport also had no notion of who was on the air: the platform bridge
passes an all-zero peer id (LoRa frames carry no link-layer address), and a
node only ever beacons to peers it already knows, so two LoRa radios could
never discover each other.

## Decision

- Every LoRa frame carries a 6-byte header: sender tag (u16, random per
  transport instance), fragment id (u16), index (u8), count (u8). `send()`
  splits a message into frames sized for the peer's current spreading
  factor and charges the duty cycle with the sum of the frames' airtime.
  The transport MTU becomes the largest reassembled message (2048 bytes).
- The receiver reassembles by (sender tag, fragment id), keeps at most 64
  partial messages, and drops partials older than 120 s.
- The peer of a reassembled message is the envelope's source field (the
  first 32 bytes) unless the bridge supplied a real peer id. Hearing a node
  is discovering it: the transport emits `NeighborDiscovered` on first
  contact, tracks `last_seen`, and reports a peer lost after 300 s of
  silence.
- `Transport::supports_broadcast()` (default false) marks broadcast media;
  `TransportManager::broadcast()` sends to `NodeId::ZERO` on each such
  transport, and the node's beacon loop calls it every interval. Broadcasts
  use the discovery spreading factor so every radio can decode them.

## Consequences

**Easier:**
- LoRa can carry every envelope type at every spreading factor, discovery
  converges from beacons alone, and ADR gets the TX feedback it needs.

**Harder:**
- Peer identity on LoRa is whatever the envelope claims (the same trust
  level as BLE's identity characteristic). Sender tags can collide with
  probability 2^-16, in which case two interleaved messages are corrupted
  and dropped.
- A 106-byte envelope costs three frames at SF10; airtime budgets are
  consumed faster than the payload size suggests.

## Alternatives Considered

1. **`LoraFrame` compact header (27 bytes, truncated ids)** — Would save
   ~80 bytes per message but truncated ids collide, receipts would reference
   the wrong message id, and every relay would need an id resolver. Kept as
   a future optimisation for beacon-only traffic.
2. **Broadcast from the node without a trait method** — Would require the
   node to know which transports are radios; the trait default keeps the
   knowledge in the transport.

## Note (2026-11-14)

**The outbox now orders by priority (ADR-014).** LoRa shares the
`PriorityOutbox` the other platform transports use: an emergency alert queues
ahead of ordinary traffic and keeps its own order, a full outbox drops the
oldest *ordinary* frame to make room for an alert and refuses ordinary traffic
rather than evicting one, and — because this transport fragments — a message is
admitted **whole or not at all**, so it cannot evict its own earlier fragments
and report success for something that can never be reassembled.

Duty-cycle airtime is charged only once frames are admitted, and the check, the
admission and the charge happen under one lock. Charging before admission meant
a refused send spent airtime it never used; separate locks let two concurrent
sends pass against the same remaining allowance.

**Four defects in this record's own guarantees, found reviewing it against the
code.** None is caused by the above; all are recorded as ROADMAP T-40.

1. The spreading factor chosen for a peer affects fragmentation and airtime
   accounting only. Nothing carries it to the radio through the outbox and FFI
   bridge, so this record's discovery-SF behaviour is not implemented.
2. Peer expiry runs only when a packet arrives, so a silent radio keeps dead
   peers indefinitely rather than the 300 s this record states.
3. Reassembly does not enforce the 2048-byte limit: 47 valid 45-byte fragments
   produce a 2115-byte message.
4. Colliding sender tags and fragment ids are described here as causing a
   dropped message. Two messages with the same tag, id and fragment count can
   instead combine into a *complete* corrupted one, which nothing at this layer
   detects. Whether that is acceptable depends on upper-layer validation, and
   this record should say which layer is responsible.
