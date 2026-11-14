# ADR-022: Message Fragmentation for Frame-Capped Transports

## Status

Accepted (2026-11-14). **Implemented — ROADMAP T-39.**

## Context

The BLE transport refused any message over 512 bytes, its negotiated GATT MTU,
by returning `ExceedsMtu`. That made the frame size the *message* size, and
T-37's origin authentication pushed the one message type that must arrive past
it: an alert is

```
217 + message_bytes + 96 × approvals
```

so three co-signatures leave 7 bytes of text, and no approvals leave 295 —
where before the originator's key and signature it was 391. A critical alert
carrying the three approvals ADR-010 requires is 522 bytes and could not cross
BLE at all, which is latent only because nothing collects co-signatures yet
(T-05, blocked on this).

Two ways out were considered: fragment at the transport, or shrink the
co-signer entry. Fragmentation was chosen first because it fixes every
oversized message rather than this one, and because the entry size can still
be revisited independently afterwards.

LoRa already fragments — it must, with 51 bytes at SF12 — and had a working
implementation with a bounded reassembler.

## Decision

### One fragmenter, shared

`transport::fragment` holds the fragmentation and reassembly both transports
need: a 6-byte header (sender tag, fragment id, index, count), `fragment()`,
and a `Reassembler` bounded in every direction. LoRa's copy is gone.

The sender tag is random per transport instance, because fragment ids are only
unique per sender: without it, two senders' fragments combine into one
reassembly and produce a corrupted message.

Where the link knows who sent a frame, the **peer is part of the key too**. A
16-bit tag collides by accident often enough on a busy mesh, and a peer that
wants to can copy another's; either way two senders' fragments would otherwise
combine into one message, attributed to whichever peer completed it. LoRa has
no link-layer address and passes `NodeId::ZERO` — one scope for every sender,
which is why the tag exists at all.

### BLE fragments, and its MTU becomes a message bound

`BleTransport::send` splits a message into frames of 512 bytes and queues them
as a batch — all of them or none, so a message cannot lose a fragment to a
full outbox and arrive unreassemblable. `on_data_received` feeds frames to the
reassembler and emits a `DataReceived` event only for whole messages, so
nothing above the transport sees a fragment.

`mtu()` now reports `BLE_MAX_MESSAGE` (4096), what a *message* may be, rather
than what one frame carries. That is what `TransportManager::min_mtu` consults,
so `Node::raise_emergency` stops refusing alerts a fragmenting transport can
carry.

### The reassembler refuses what cannot be assumed

Nothing about a stranger's frames can be trusted, so: more than `max_message`
bytes **accumulated** is refused, concurrent reassemblies are capped, and an
incomplete message expires after a TTL.

The accumulation rule is the one that was wrong before. ADR-008 documented a
2048-byte limit for LoRa and the code never enforced it: 47 valid 45-byte
fragments produced a 2115-byte message, because each fragment respected a
bound the total did not. Checking the total is not enough either — dropping
the partial reassembly lets the remaining fragments start a fresh one, so a
refused message walks back in a few frames later. A refused key is therefore
*kept*, holding nothing, until its TTL sweeps it: capacity eviction prefers a
reassembly that is still collecting, and the refusal is checked before the
single-fragment path, since a refused message must not return as a `count = 1`
frame claiming the same key.

With one exception, taken deliberately: when every entry is a marker, one is
evicted. A marker saves repeated accumulation work and is not what enforces
the size limit — a restarted message meets the same check at the same
fragment — so refusing new reassemblies instead would let an attacker block
legitimate large messages for a whole TTL by filling the table with refusals.
Re-work is the cheaper loss.

And a fragment already held is ignored rather than counted. Counting it would
push a message that fits past the limit — the same fragment twice is enough —
and the refusal is sticky, so that message would never arrive at all.

## Consequences

**Easier:**

- A co-signed critical alert crosses BLE, so T-05 is no longer blocked on
  size, and an alert's text is bounded by reassembly (4096) rather than by one
  frame (512).
- One fragmenter for both transports, so a rule fixed in one place is fixed
  for both — the accumulation bound included, which closes one of T-40's
  bullets.

**Harder:**

- Reassembly state per sender on a device with a small memory budget. Bounded
  by the message cap, the concurrent-reassembly cap and the TTL, but it is new
  state that an attacker can make a node hold.
- A lost fragment costs the whole message, where before a message either
  fitted or was refused outright. On BLE the platform layer's own write
  framing already had this property beneath us; now it exists at the message
  level too.
- Two framing layers on BLE: this 6-byte message header, and the platform
  layer's 1-byte GATT-write header below it (spec §8.4). They are independent
  and must stay so; the platform layer carries opaque bytes.
- The frame size is no longer visible above the transport, so a caller cannot
  tell whether a message will take one frame or ten. Nothing needs to today.

## Alternatives Considered

1. **Shrink the co-signer entry** — a truncated NodeId (8 bytes) would make
   three approvals 216 rather than 288, leaving 79 bytes of message. Smaller
   change and no reassembly state, but truncated ids invite collisions in the
   lookup that counts approvals, and it fixes only this message type. Still
   open as an independent option if alerts stay tight.
2. **Cap the message and document it** — refuse anything over 295 bytes (7
   with three approvals) at the API. Honest, and a 7-byte emergency says
   almost nothing.
3. **Fragment in the platform layer instead** — Kotlin and Swift already
   fragment GATT writes, so they could carry larger messages. It would put
   reassembly, its bounds and its failure modes in two platform languages
   instead of one Rust module, and the other frame-capped transport (LoRa) has
   no platform layer to put it in.
