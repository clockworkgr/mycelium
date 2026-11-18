# Mycelium Specification

**Infrastructure-independent mesh communications platform**

| | |
|---|---|
| **Spec version** | 0.2 |
| **Protocol version** | 1 (`ProtocolVersion::V0_1`) |
| **Last updated** | 2026-11-10 |
| **License** | GPL-3.0-or-later |
| **Primary audience** | Privacy-focused communities (activists, journalists, privacy-conscious groups) |

This is the single normative document for Mycelium. It specifies the wire
protocol and cryptography, and describes the architecture as built. The
companion document is [`ROADMAP.md`](ROADMAP.md), which tracks the open work.
Decisions that shaped the design are recorded in [`docs/adr/`](docs/adr/) (ADR-001 … ADR-012);
build and contribution mechanics live in [`CONTRIBUTING.md`](CONTRIBUTING.md).

### Status legend

Every feature section carries one of these markers. Anything not marked
**Implemented** must not be relied on by clients.

| Marker | Meaning |
|--------|---------|
| **Implemented** | Built, covered by the workspace test suite, and exercised end to end. |
| **Partial** | Built in part. The gap is named and carries a `ROADMAP` task reference. |
| **Planned** | Specified here, not built. Carries a target version. |

Where this document says a node *must* or *must not* do something, that is a
conformance requirement on any implementation of the protocol. Everything else
is descriptive.

---

## Table of contents

**Part I — System**
1. [Purpose and scope](#1-purpose-and-scope)
2. [System model](#2-system-model)
3. [Crate map](#3-crate-map)

**Part II — Protocol (normative)**
4. [Wire format](#4-wire-format)
5. [Cryptography](#5-cryptography)
6. [Identity and trust](#6-identity-and-trust)
7. [Routing](#7-routing)
8. [Transports](#8-transports)
9. [Messaging](#9-messaging)
10. [Discovery and onboarding](#10-discovery-and-onboarding)
11. [Node roles and power management](#11-node-roles-and-power-management)
12. [Anti-spam and rate limiting](#12-anti-spam-and-rate-limiting)
13. [Protocol versioning](#13-protocol-versioning)

**Part III — Implementation**
14. [Node runtime](#14-node-runtime)
15. [Storage](#15-storage)
16. [Local API](#16-local-api)
17. [FFI and mobile platform bridges](#17-ffi-and-mobile-platform-bridges)
18. [Protocol adapters](#18-protocol-adapters)
19. [Build, test and deploy](#19-build-test-and-deploy)

**Part IV — Status**
20. [Compliance matrix](#20-compliance-matrix)
21. [Deviations from the original design](#21-deviations-from-the-original-design)
22. [Threat model notes and open questions](#22-threat-model-notes-and-open-questions)

---

# Part I — System

## 1. Purpose and scope

Mycelium is a communications platform that operates without the internet or
cellular infrastructure. It forms an ad-hoc mesh from the radios already
present on standard smartphones (BLE, Wi-Fi Direct, Bluetooth Classic),
supplemented by OpenWRT routers acting as persistent supernodes and by optional
external radio hardware (LoRa). Every message is end-to-end encrypted. Identity
is a device-bound keypair — no phone numbers, no email, no accounts, no servers.

Three properties drive the design:

- **No infrastructure dependency.** A pair of phones in a basement is a
  complete, functioning network. Supernodes and internet uplinks improve reach;
  nothing requires them.
- **Partition tolerance.** The mesh is expected to be disconnected most of the
  time. Delay-tolerant networking (store–carry–forward) is a first-class
  delivery path, not a fallback bolted on.
- **Relays learn nothing.** A node that forwards or stores a message for
  someone else holds an opaque blob. Source and destination identifiers are
  cleartext for routing; content never is.

**Architecture shape.** A standalone Rust daemon owns the mesh — transports,
routing, crypto, storage — and exposes a local REST + WebSocket API. The
Flutter app is the first client of that API, and proves it by dogfooding. Any
other application, in any language, is a peer client: it gets mesh transport
and end-to-end encryption for free by declaring a protocol ID (§16.4).

## 2. System model

### 2.1 Node types

| Node type | Platform | Role | Characteristics |
|-----------|----------|------|-----------------|
| **Phone node** | Android, iOS | End-user device | Battery-constrained, mobile, intermittent connectivity |
| **Supernode** | OpenWRT router, server, container | Backbone | Always-on, wired power, better antennas, larger DTN storage, bridges subnets, caches prekey bundles |
| **External radio** | LoRa module over BLE GATT or USB serial | Range extension | Long-range, very low bandwidth; bridged by a phone or supernode, not an independent node |

### 2.2 Layering

```
┌─────────────────────────────────────────────────────────────────┐
│  APPLICATION          1:1 chat · groups · channels · emergency  │
│                       any API client via protocol IDs (§16.4)   │
├─────────────────────────────────────────────────────────────────┤
│  LOCAL API            REST + WebSocket, bearer token (§16)      │
├─────────────────────────────────────────────────────────────────┤
│  CRYPTO               X3DH · Double Ratchet · Sender Keys ·     │
│                       Web of Trust · SQLCipher at rest  (§5,§6) │
├─────────────────────────────────────────────────────────────────┤
│  ROUTING              AODV reactive  ·  spray-and-wait DTN (§7) │
├─────────────────────────────────────────────────────────────────┤
│  TRANSPORT            unified Transport trait, per-peer         │
│                       selection and failover               (§8)│
│   BLE · Wi-Fi Direct · BT Classic · LoRa · Internet · Plugins   │
├─────────────────────────────────────────────────────────────────┤
│  ADAPTERS (partial)   Meshtastic · Reticulum             (§18)  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Process model

The node is a library (`mycelium-node`) with two hosts:

- **`mycelium-node` binary** (built from the `mycelium-daemon` crate, ADR-004) —
  a standalone process for desktops, containers and OpenWRT. It starts the node
  and the API server, and shuts the server down before the node on `SIGINT`.
- **`libmycelium_ffi`** — a shared/static library embedded in the mobile app.
  It runs the same node in-process and also starts the API server, so the
  Flutter UI talks to it over HTTP/WebSocket exactly as a desktop client would.
  FFI is retained only for radio bridging and node lifecycle (§17).

On Android the node runs inside a foreground service
(`MyceliumDaemonService`), so it survives the UI being killed. On iOS it relies
on CoreBluetooth background modes instead.

### 2.4 Software stack

| Layer | Technology |
|-------|-----------|
| Core | Rust (edition 2021, MSRV 1.82) |
| Wire format | Custom fixed-layout binary codec, little-endian (§4) |
| Local API | `axum` 0.8, JSON (`serde_json`) |
| Storage | SQLite + SQLCipher, encrypted at rest (§15) |
| Mobile UI | Flutter/Dart, Riverpod, GoRouter |
| Android platform | Kotlin (BLE, Wi-Fi Direct, LoRa GATT, USB serial, BT Classic) |
| iOS platform | Swift (CoreBluetooth BLE, LoRa GATT) |
| OpenWRT | `.ipk` package with procd init + LuCI app |

## 3. Crate map

Ten crates, in dependency order. Arrows point from dependency to dependent.

```
mycelium-protocol  (no internal deps — wire types + codec)
    │
    ├─────────────┬──────────────────┐
    ▼             ▼                  ▼
mycelium-crypto  mycelium-storage   (used directly by adapters)
    │             │
    └──────┬──────┘
           ▼
     mycelium-core  (transports, AODV, DTN, DHT)
           │
    ┌──────┼────────────────┬─────────────────┐
    ▼      ▼                ▼                 ▼
mycelium-node   mycelium-meshtastic   mycelium-reticulum
    │
    ▼
mycelium-api  (REST + WebSocket)
    │
    ├──────────────┐
    ▼              ▼
mycelium-daemon  mycelium-ffi
(`mycelium-node`  (cdylib/staticlib
 binary)           for Flutter)
```

| Crate | Responsibility |
|-------|----------------|
| `mycelium-protocol` | Wire types (`NodeId`, `MessageId`, `LamportClock`, flags), envelope codec, payload codecs, compact LoRa frame. Zero internal dependencies. |
| `mycelium-crypto` | Identity, X3DH, Double Ratchet, session manager, Sender Key groups, Web of Trust, group-discovery key derivation. |
| `mycelium-storage` | SQLCipher database, schema migrations, per-domain CRUD. |
| `mycelium-core` | `Transport` trait and the transport implementations, `TransportManager`, AODV router, DTN spray-and-wait engine, routing coordinator, Kademlia DHT, plugin registry. |
| `mycelium-node` | The node: event loop, message pipeline, all protocol handlers, beacon, rate limiter, battery manager, config. |
| `mycelium-api` | Local REST + WebSocket server, bearer-token auth, event bridge. |
| `mycelium-daemon` | The `mycelium-node` binary: CLI and env config, identity file, node + API lifecycle (ADR-004). |
| `mycelium-ffi` | 64 `extern "C"` functions bridging the node to Dart/Kotlin/Swift. |
| `mycelium-meshtastic` | Meshtastic protocol adapter (`TransportPlugin`). **Partial** — §18.1. |
| `mycelium-reticulum` | Reticulum protocol adapter (`TransportPlugin`). **Partial** — §18.2. |

The binary is named `mycelium-node` but lives in the `mycelium-daemon` crate,
because the API crate depends on the node library and a crate cannot depend on
a crate that depends on it (ADR-004). Run it with
`cargo run -p mycelium-daemon`.

---

# Part II — Protocol (normative)

## 4. Wire format

**Status: Implemented.**

All multi-byte integers are **little-endian**. All layouts are fixed-offset;
there is no self-describing framing, no protobuf and no Cap'n Proto.

Implementations **must** perform every length check on the trusted side of the
comparison (`data.len() - offset < needed`, never `offset + needed >
data.len()`) so a hostile length prefix cannot wrap on a 32-bit target.
`LamportClock` arithmetic **must** saturate rather than wrap.

### 4.1 Envelope

The envelope is the routing wrapper for every mesh message: a 106-byte fixed
header followed by a variable payload.

| Offset | Size | Field | Type |
|--------|------|-------|------|
| 0 | 32 | `source` | `NodeId` |
| 32 | 32 | `destination` | `NodeId` (all-zero = broadcast) |
| 64 | 16 | `message_id` | random, `OsRng` |
| 80 | 1 | `ttl` | u8 |
| 81 | 1 | `hop_count` | u8 |
| 82 | 2 | `flags` | u16 LE |
| 84 | 8 | `lamport_clock` | u64 LE |
| 92 | 8 | `device_timestamp` | u64 LE (unix seconds, best-effort) |
| 100 | 2 | `protocol_version` | u16 LE |
| 102 | 4 | `payload_length` | u32 LE |
| 106 | * | `payload` | bytes |

`forward()` decrements `ttl` and increments `hop_count`; hop counts saturate.

**Flags** (`MessageFlags`, bitfield):

| Bit | Name | Meaning |
|-----|------|---------|
| `0x01` | `DTN` | Carried by the delay-tolerant path |
| `0x02` | `PRIORITY` | Emergency level 1 |
| `0x04` | `URGENT` | Emergency level 2 |
| `0x08` | `CRITICAL` | Emergency level 3 |
| `0x10` | `RECEIPT` | Delivery/read receipt |
| `0x20` | `GROUP` | Group-addressed |
| `0x40` | `SYSTEM` | Control message (key exchange, group management, trust) |

**Metadata tradeoff.** `source` and `destination` are cleartext so that any
relay can route without decrypting. This is deliberate: it buys efficient
multi-hop routing at the cost of traffic-pattern privacy against an adversary
who observes the radio. Content is always encrypted and opaque to relays.

### 4.2 Payload types

Each payload begins with a 1-byte type discriminator. Twenty types are
defined.

| Byte | Name | Min body | Purpose |
|------|------|----------|---------|
| `0x10` | `EncryptedMessage` | 45 | Double Ratchet header (40) + ciphertext |
| `0x11` | `SessionInit` | 69 | X3DH ephemeral + identity key + encrypted first message |
| `0x20` | `PrekeyRequest` | 32 | Requester's identity key |
| `0x21` | `PrekeyResponse` | 66 | Prekey bundle: SPK + signature + optional OTP |
| `0x22` | `SessionReject` | 129 | Refusal of a `SessionInit`: reason + identity key + the refused init's transcript + signature (ADR-012) |
| `0x30` | `AodvRreq` | 78 | Route request |
| `0x31` | `AodvRrep` | 77 | Route reply |
| `0x32` | `AodvRerr` | 68 | Route error |
| `0x40` | `DtnRelay` | 25 | `message_id` + `copies_remaining` + `ttl_secs` + opaque inner envelope (ADR-005) |
| `0x50` | `Beacon` | var | Node heartbeat (§10.1) |
| `0x51` | `GroupProofChallenge` | 40 | Group discovery hint + nonce: prove you hold the key behind the hint (§10.2, ADR-019) |
| `0x52` | `GroupProofResponse` | 32 | The MAC that answers it (§10.2, ADR-019) |
| `0x60` | `Receipt` | 17 | Delivery/read confirmation |
| `0x70` | `GroupMessage` | 37 | Sender-key-encrypted group message |
| `0x71` | `SenderKeyDistribution` | 68 | Sender key + roster + explicit removals (ADR-007) |
| `0x80` | `ChannelMessage` | 33 | Public channel broadcast |
| `0x81` | `ChannelSubscribe` | 32 | Channel subscription announcement |
| `0x82` | `ChannelUnsubscribe` | 32 | Channel unsubscription |
| `0x83` | `ChannelModeration` | 65 | Signed moderation action |
| `0x90` | `EmergencyBroadcast` | 110 | Tiered emergency alert: level + `signed_at` + originator key and signature + message + co-signatures (§9.5, ADR-013, ADR-014) |

`SenderKeyDistribution` (`0x71`) is valid **only** as the plaintext of a
pairwise `EncryptedMessage` carrying the `SYSTEM` flag. A bare `0x71` envelope
**must** be ignored — accepting one would let any neighbour inject itself into
a group (ADR-007).

`DtnRelay` carries `copies_remaining` and `ttl_secs` on the wire so a relay can
spray further and honour the originator's end-to-end TTL instead of resetting
it (ADR-005).

`GroupProofChallenge` (`0x51`) and `GroupProofResponse` (`0x52`) are
link-local: `ttl = 1`, never forwarded, and refused unless the envelope's
source is the transport peer that delivered it and the destination is the
receiving node. Both bodies are a fixed length, and a body with bytes to spare
is refused rather than parsed (§10.2).

### 4.3 Compact LoRa frame

**Status: Implemented** (`mycelium-protocol/src/lora_frame.rs`).

LoRa MTUs are 51–222 bytes depending on spreading factor, which a 106-byte
envelope header alone would consume. The compact frame reduces the header to 27
bytes by truncating identifiers.

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | `source_short` (NodeId truncated) |
| 8 | 8 | `dest_short` (NodeId truncated) |
| 16 | 4 | `message_id_short` |
| 20 | 1 | `ttl` |
| 21 | 1 | `hop_count` |
| 22 | 1 | `flags` (truncated to 8 bits) |
| 23 | 2 | `lamport_clock` u16 LE (wrapping) |
| 25 | 1 | `payload_length` |
| 26 | 1 | `sf_hint` (ADR spreading factor) |
| 27 | * | `payload` |

At SF10–12 (51 B MTU) this leaves 24 bytes of payload; at SF7 (222 B), 195
bytes. `to_envelope()` requires a resolver to expand truncated NodeIds back to
full ones. The LoRa transport currently fragments full envelopes (§8.4) rather
than using this frame; adopting it is a future bandwidth optimisation
(ROADMAP T-12).

## 5. Cryptography

**Status: Implemented.** Signal-protocol design: X3DH for asynchronous session
setup, Double Ratchet for per-message forward secrecy, Sender Keys for groups.

### 5.1 Identity and key derivation

```
Ed25519 seed (32 B, OsRng)
  ├─ Ed25519 SigningKey → VerifyingKey            (signing, vouches, prekeys)
  ├─ SHA-512(seed)[0..32], clamped per RFC 7748
  │    → X25519 StaticSecret → PublicKey          (Diffie-Hellman)
  └─ SHA-256(VerifyingKey) → NodeId (32 B)        (the identity)
```

The Edwards→Montgomery public-key conversion goes through
`curve25519-dalek::CompressedEdwardsY`. Identity serialises to 96 bytes
(signing seed 32 ‖ keypair seed 32 ‖ X25519 secret 32).

**The NodeId is `SHA-256` of the Ed25519 public key.** This binding is load
bearing: a node **must** reject any `PrekeyResponse` or `SessionInit` whose
`identity_key` does not hash to the claiming envelope's `source`. Without that
check a neighbour can answer a prekey request on someone else's behalf and
become a transparent man in the middle (§14.3).

### 5.2 X3DH

Each node publishes a prekey bundle:

- `identity_key: [u8; 32]` — long-term Ed25519 public key
- `signed_prekey: [u8; 32]` — medium-term X25519, rotated ~weekly
- `signed_prekey_signature` — Ed25519 over the SPK
- `one_time_prekeys: Vec<([u8; 32], u32)>` — ephemeral X25519, consumed once

```
DH1 = X25519(our_identity_secret, their_signed_prekey)
DH2 = X25519(ephemeral_secret,    their_identity_key)
DH3 = X25519(ephemeral_secret,    their_signed_prekey)
DH4 = X25519(ephemeral_secret,    their_one_time_prekey)   [if present]

shared_secret = HKDF-SHA256(
    salt = zeros(32),
    ikm  = DH1 ‖ DH2 ‖ DH3 [‖ DH4],
    info = b"MyceliumX3DH-v2:" ‖ init_binding,
    len  = 32)

init_binding = ephemeral_public(32) ‖ identity_key(32)
             ‖ signed_prekey_id(4 LE) ‖ has_otp(1) [‖ one_time_prekey_id(4 LE)]
             ‖ carries_message(1)
```

**The init's own bytes are in the derivation** (ADR-015). `init_binding` is the
`SessionInit` header exactly as it appears on the wire, plus one byte for
whether the init encloses a message — the initiator binds what it is about to
serialize, the responder what it received — and
`mycelium_protocol::wire::session_init_binding` is the single definition both
sides use.

`carries_message` is in there although it is not a header field, because the two
forms are different handshakes: they take different X3DH variants and they are
answered on different paths, one authenticated and one not. Without it,
stripping the payload from an init left the binding untouched, so the stripped
copy was answered on the unauthenticated path and the genuine init — same
binding, already answered — was met with silence, losing its message. With it, a
stripped copy derives a different secret and cannot stand in for the real
handshake.

This is the mitigation RFC 7748 §7 names, and it is not optional. For any
X25519 public key `u` there are other, publicly computable keys that produce
the same shared secret, and `u⁻¹ mod p` is **canonical**, so the
canonical-encoding check at ingress cannot tell it from the original. Without
the binding, a relay could swap an init's ephemeral for the inverse and the
responder would derive the same secret from different wire bytes — a second
identity for one handshake, which is what lets a replay of the original collect
an actionable signed rejection (§5.2 Rejection, ADR-012). A handshake is
therefore identified by what the AEAD authenticates, not by a hash of bytes it
does not cover.

**A one-time prekey is retired only after the init authenticates.** The
derivation peeks at the prekey; the caller spends it once the enclosed first
message decrypts, including on ADR-007's tie-break path where the responder
keeps its own session and decrypts only that message. Spending it earlier let a
corrupted copy of an init burn the prekey and leave the genuine init to fail
and draw a rejection; leaving it unspent after a success let a replay of the
same init, under a fresh envelope id, derive the handshake again.

**A `SessionInit` carrying no message uses the signed-prekey-only X3DH
variant** — `DH1 ‖ DH2 ‖ DH3`, no `DH4`. Such an init **must not** name a
one-time prekey and is refused if it does: nothing in it authenticates the
initiator, so there is no event on which a prekey could be spent. The initiator
therefore ignores any one-time prekey the bundle offers when it builds this
form, in the derivation, the binding and the id it names — using the offered one
produced an init the responder could only reject, against any bundle with
prekeys left in it. That
handshake gets no one-time-prekey forward secrecy, which is the honest price
for an init with nothing to authenticate. A non-empty nested payload whose type
is not `EncryptedMessage` is refused outright, never treated as message-less.

A one-time prekey **must** be issued at most once: `PrekeyState::issue_bundle()`
reserves the OTP it hands out, while `bundle()` only peeks. Two concurrent
initiators therefore never share an OTP — but a *cached* bundle, served from a
supernode (§16.2), reaches many initiators, and a bundle is public in any case.
Whoever holds one can initiate with it and consume the prekey it names, so an
initiator whose prekey is taken that way draws an honest refusal and recovers
through it. The prekey is not bound to the initiator it was issued to
(ROADMAP T-43).

Bundles are fetched from a nearby supernode's cache (§16.2, `GET
/v1/prekeys/{node_id}`) or over the mesh by `PrekeyRequest`/`PrekeyResponse`.

**Rotation and retention.** A responder **must** run X3DH with the signed
prekey the initiator names in `signed_prekey_id`, not whichever is current, and
**must** seed the Double Ratchet's initial DH key from that same secret.
Rotated secrets are retained — `MAX_RETAINED_SIGNED_PREKEYS = 2`, covering the
weekly rotation against the 7-day bundle cache — so a conversation started from
a cached bundle survives a rotation. An id outside the retention window is a
hard error, never a silently mismatched derivation (ADR-009).

**Rejection.** When a `SessionInit` cannot be accepted the responder sends
`SessionReject` (`0x22`), **signed** (ADR-012):

```
reason(1) ‖ identity_key(32) ‖ init_transcript(32) ‖ signature(64)

init_transcript = SHA-256( b"mycelium-session-init-transcript-v1:"
                         ‖ len(payload)(4 LE) ‖ session_init_payload )
signature       = Ed25519( SHA-256( b"mycelium-session-reject-v1:"
                         ‖ init_transcript ‖ initiator ‖ rejecter ‖ reason ) )
```

An initiator acts on a reject only when the identity key hashes to the
envelope source (§14.3), the signature verifies under that key — X3DH already
gave it that key — and the transcript is the one it recorded for the
`SessionInit` it is waiting on.

The transcript, rather than the rejected envelope's id, is what makes the
signature worth having. An id and a source are cleartext and a public key is
public, so an attacker can have the responder sign a genuine rejection of a
`SessionInit` it fabricated under the initiator's name; it cannot make the
responder reject the init the initiator actually sent. ADR-012 records the
attack.

The AEAD associated data for a pairwise message is
`source(32) ‖ destination(32) ‖ content_type(1)`. The content type is in there
because it travels in the clear: unauthenticated, a relay could retype a
message, and a retyped copy that still decrypted could also be used to mint a
second identity for one `SessionInit` (ADR-012).

**A rejection is sent only when no session with that peer exists.** If we hold
any session with it, a failing `SessionInit` draws silence. That covers the
replay of an init we accepted — its prekey is spent and its message already
decrypted, so refusing it would mean signing a valid rejection of an init the
peer really sent — and ADR-007's tie-break, where the initiator is the loser and
will accept ours. The rule is a question about state rather than a timer, so it
survives a restart by construction: sessions are persisted (ADR-015).

The case this gives up is a stale session of ours plus a genuinely dead bundle,
where the initiator learns nothing from us. That recovers by handshake timeout
instead, below.

**A handshake is answered once.** Answering one twice means either signing a
valid rejection of an init the peer really sent, or — worse — installing that
handshake's session a second time over one that has moved on, which rewinds a
ratchet and so reuses message keys. Both records below are keyed on
`SHA-256(init_binding)`, never on a hash of the payload: the nested message is
free to vary, and a captured later ciphertext from the same chain decrypts on a
fresh ratchet, so an init carrying the original header and a substituted message
derives the same session. The derivation refuses a second answer with
`HandshakeAlreadyAnswered`, before any DH, and a node holding the record answers
such an init with **silence** rather than a signed rejection.

| Record | Holds | Lives | Covers |
|--------|-------|-------|--------|
| `Session::accepted_binding` | one entry | with the session | the init a session was accepted from, including the message-less form |
| `PrekeyState::answered_handshakes` | up to `MAX_ANSWERED_HANDSHAKES` (1024) | until the signed prekey retires | every handshake that has authenticated, including ADR-007's tie-break losers |

The shapes differ for a reason. The prekey-scoped record is written only where
the AEAD has verified, because an unauthenticated path would let an attacker
generating identities fill a bound shared with every real handshake; it must
outlive the session, because an init stays derivable while its signed prekey is
retained, so a record that died with a session left the init replayable after an
expiry or a re-handshake. The session-scoped record is the opposite: a single
slot cannot be grown by a forgery, which is what lets it cover the message-less
init — the one form that authenticates nothing.

**The first decrypt promotes the one into the other**, and the blob is written
on that decrypt. A successful decrypt authenticates the peer, so the session's
entry is copied into the durable record and gains its lifetime; a promotion
never persisted is gone on the next start and the init it covers is answerable
again. The session's entry is **kept**, not moved: a handover across two stores
has an order to get wrong, and a promotion followed by a lost write would leave
neither marker, while two independent records mean losing either leaves the
other. Promotion is also the earliest moment that matters, because a responder
has no sending chain until something of the initiator's arrives — before it the
session has carried no traffic in either direction and reinstalling an identical
one costs nothing.

`rotate_signed_prekey` drops the prekey-scoped entries whose prekey has gone,
which is when the replay stops being possible, and a promotion naming a retired
prekey is refused rather than recorded — a long-lived session re-offers its entry
on every decrypt, and obsolete entries would evict live ones at capacity. The
bound evicts oldest, and an evicted entry's init becomes replayable again until
its prekey retires (ADR-015).

**An init encloses message 0 of its chain, or it is not that init.** The
initiator encrypts it on a ratchet it has just built, so a copy carrying a later
message of the same chain is a relay's work, and `NotTheFirstMessage` refuses it
before any DH. Without that rule a relay could reorder: wrap a captured later
message into a copy of the init, get *that* answered first, and leave the
genuine init — now a handshake already answered — to be met with silence, losing
the first message of the conversation. Silently, because the session works and
nothing retries. The captured message is not lost either; it arrives as what it
always was, an ordinary message on the ordinary path.

A reject still acts **only** on a handshake the peer has not confirmed. A
handshake is **confirmed** the moment the initiator successfully decrypts
anything from that peer: only the peer's own ratchet could have produced it.
Until then, a reject discards the unconfirmed session, the cached bundle (in
memory and in storage) and reports every message sent under the handshake as
failed. A confirmed session **must not** be torn down by a reject.
Confirmation is a state, not a deadline: an elapsed-time cutoff was tried
first and was wrong both ways (ADR-009).

**A handshake the peer never confirms is given up on.** An initiator installs
its session as soon as the `SessionInit` goes out, so a responder that stays
silent — the rule above has it reject only when it holds no session — would
otherwise leave that session in place for ever, with every later message going
out as a bare `EncryptedMessage` the peer cannot read. The 30-second maintenance
tick lists the handshakes past their deadline and, for each one it abandons,
does what a rejection does: discards the session, the
cached bundle in memory and in storage, and reports the messages sent under the
handshake as failed, so the next send starts a fresh handshake against a fresh
bundle. The deadline is two DTN delivery windows — the init's and the reply's,
which together are the slowest a legitimate handshake can confirm. Only one of
them is ours: the init travels under the configured `dtn.ttl_hours`, the reply
under the peer's, and nothing on the wire says what that is. So the
deadline scales with `dtn.ttl_hours` and never falls below two of the documented
72-hour default. The asymmetry is deliberate — waiting too long keeps a stale
optimistic session, while waking too early discards one whose init was still
queued and loses the reply it earns.

That floor is an **assumption about the peer**, and a node raising its own
`dtn.ttl_hours` above 72 should expect peers to expire its handshakes on the
default: a reply still queued under a longer window arrives for a session they
have dropped. Carrying the window on the wire is capability negotiation
(ROADMAP T-20).

The teardown commits in storage before anything is forgotten in memory, and
it commits as **one transaction**. A failed write would otherwise leave durable
state — a session row that reloads unreachable, a cached bundle the next send
initiates from, a message still claiming "sent" — with no handshake left to
retry the cleanup; a failure instead leaves the handshake in place, still stale,
and the next tick retries.

Ordering alone was not enough, because the retry is not guaranteed to come. As
three independent writes, a failure part-way through had already deleted the
session row while the live session stayed in memory, and a single follow-up
receipt could then acknowledge that handshake — which takes it out of the sweep
for good, by the rule below — leaving a working session with no row to reload.
All or nothing is what makes "the next tick retries" true.

**A handshake the peer has acknowledged is kept.** "Unconfirmed" means nothing
of the peer's has arrived for us to decrypt, which is not the same as the peer
not having the session: a peer that reads and acknowledges but never replies
produces no confirmation ever. A delivery or read receipt is only sent for a
message that decrypted, so it is evidence the peer accepted the init, and
abandoning that session costs real traffic — the peer keeps sending under it and
we drop everything until our own next send. The acknowledgement is recorded on
the handshake, which knows the messages it sent: a receipt counts only if it
names one sent **after** the init, since receipts arrive late and one from a
session long gone must not vouch for a newer handshake. The init's own message
is excluded because an ADR-007 tie-break winner decrypts it with a session it
then discards, and receipts it honestly — such a receipt proves the peer read
the message, not that it holds the session the message arrived under. A
follow-up travels under the installed session, so decrypting one is possible
only for a peer that kept it. A conversation of exactly one message therefore
cannot be acknowledged, and is re-handshaked after the timeout. It is noted without consulting the message
rows at all, because those can be deleted — reading the evidence back from
history meant clearing a conversation, or clearing it before a late receipt
arrived, left a healthy session to be abandoned.

Receipts are unauthenticated (§14.3), so a forged one suppresses the sweep for
that pairing; that returns it to the behaviour from before the sweep existed
rather than to something worse, which is why a receipt gates *keeping* a
handshake and does **not** confirm one. Confirmation by an acknowledgement the
peer cannot forge is ROADMAP T-42.

The handshake record is in memory only, so a restart loses it and neither the
sweep nor a late rejection can fire — ROADMAP T-41.

**The two answered-handshake records can also diverge across a restart**, and
for the same reason: they are separate rows, written separately. A lost
prekey-blob write leaves the marker on the session alone, where the next
handshake with that peer overwrites its single slot; and the ADR-007 tie-break
winner, which records the loser's init in the durable record *only* — the
session it keeps has none of its own — loses that marker outright. In memory
both are retried on the next successful write, so a restart is required for
either to bite. Reconciling them at startup from the session rows is **not**
sound: a session built from a message-less init authenticates nothing, so
re-asserting every loaded session's marker would let forged inits across free
identities evict the authenticated markers out of the bounded record. Closing
this needs authentication evidence stored with the marker, or the session row
and the prekey blob written in one transaction — ROADMAP T-41.

Accepting an authenticated `SessionInit` clears any unconfirmed handshake of
our own that it supersedes, and reports the messages sent *after* that init as
failed — not the one carried inside it, which the peer decrypted under
ADR-007's tie-break. A status write never undoes a settled outcome: "sent"
does not apply to a message a rejection has failed, and "failed" does not
apply to one the peer has acknowledged.

### 5.3 Double Ratchet

```
Root KDF:     HKDF-SHA256(root_key, dh_output, info=b"MyceliumRatchet")
                → (new_root_key, chain_key)
Chain KDF:    SHA-256(chain_key ‖ 0x01) → message_key
              SHA-256(chain_key ‖ 0x02) → next_chain_key
Message AEAD: HKDF-SHA256(message_key, info=b"MyceliumAEAD")
                → AES-256-GCM key (32) + nonce (12)
              AES-256-GCM(key, nonce, plaintext, AD = source ‖ destination)
```

`decrypt()` **must** be transactional. The DH ratchet step, chain advance and
skipped-key bookkeeping happen on a clone of the state and are committed only
once the AEAD tag verifies. Otherwise a relay flipping one bit of the cleartext
ratchet header permanently desynchronises the session — a trivial denial of
service by any node on the path.

Skipped message keys are retained to tolerate reordering, bounded at
`max_skip = 1000` per jump and 2000 in total.

**State must be durable before the ciphertext leaves.** `encrypt` advances the
sending chain in memory; if that advance is lost while the ciphertext has
already gone out, the next start re-encrypts a different plaintext at the same
chain position and re-uses an AES-GCM nonce under the same key. A node
therefore **must** persist the advance before handing the ciphertext to any
transport, and **must** fail the send if it cannot — the receive path may log
and continue, because its advance is idempotent on replay. A session created
for a handshake that was never transmitted must be discarded, not left
installed. Key material (root key, chain keys, retained skipped keys, derived
message keys, the X3DH DH concatenation and the serialized state buffer) is
zeroized once it falls out of use.

### 5.4 Sender Key groups

Groups use sender keys rather than a full MLS tree ratchet. Each member holds a
32-byte chain key plus an iteration counter and distributes it to the other
members over their **pairwise Double Ratchet sessions**, as a `SYSTEM` message
(ADR-007).

```
Message key:  HKDF-SHA256(chain_key, iteration, info=b"MyceliumGroupMK")
Chain ratchet: SHA-256(chain_key ‖ b"MyceliumGroupCK")   (one-way)
AEAD:         HKDF-SHA256(message_key, info=b"MyceliumGroupAEAD")
                → AES-256-GCM key + nonce
              AES-256-GCM(key, nonce, plaintext, AD = group_id)
```

Membership rules:

- **Any member may add** a member; adding sends our sender key and roster to
  every member over pairwise sessions.
- **Removal rotates our own key** and redistributes it with the removed member
  named in an explicit `removed` list. Other members' keys are unaffected until
  they rotate too, so a removal is only fully effective once every remaining
  member has rotated.
- Rosters merge **union-only**, with explicit removals applied on top; a node
  named in `removed` leaves the group. This makes roster convergence
  partition-tolerant without a central admin.
- `install_sender_key` replies with our own key to any roster member that has
  not yet received it, so a late joiner converges without the adder having to
  re-run anything.
- For a known group the sender **must** already be a member; an unknown group
  id is treated as an invitation.

Out-of-order delivery is supported by retaining skipped iterations per sender,
bounded at `MAX_GROUP_SKIP = 1000`, and chain state is committed only after the
AEAD tag verifies (same transactional rule as §5.3). A group send, like a
pairwise one, must persist the advanced chain key before transmitting.

Trade-off versus MLS: sender keys are O(n) to distribute and give per-epoch
rather than per-operation forward secrecy. They are adequate for groups below
~20 members, which is the v0.1 target. Full MLS remains a possible future
change; it is not scheduled.

### 5.5 Safety numbers

```
SHA-256(b"MyceliumSafetyNumber" ‖ min(key_a, key_b) ‖ max(key_a, key_b))
  → 16 groups of 4 decimal digits (60 digits displayed)
```

Sorting the keys makes the number symmetric, so both parties read the same
string. A session is "unverified" until the users compare numbers out of band
and confirm; verified status is local and surfaced in the UI.

### 5.6 HKDF info strings

Ten info strings provide domain separation. Reusing one across contexts would
let a key derived for one purpose be substituted for another.

| Info string | Purpose |
|-------------|---------|
| `b"MyceliumX3DH-v2:" ‖ init_binding` | X3DH shared-secret derivation. The suffix is the `SessionInit` header as it appeared on the wire plus its carries-a-message byte, which is what makes an equivalent ephemeral — or a stripped payload — derive a different key (§5.2, ADR-015) |
| `b"MyceliumRatchet"` | Double Ratchet root KDF |
| `b"MyceliumAEAD"` | Per-message AEAD key + nonce |
| `b"MyceliumSafetyNumber"` | Safety number generation |
| `b"MyceliumGroupMK"` | Group message key derivation |
| `b"MyceliumGroupCK"` | Group chain key advancement |
| `b"MyceliumGroupAEAD"` | Group AEAD key + nonce |
| `b"MyceliumGroupDiscovery"` | Group discovery key from a passphrase (§10.2) |
| `b"MyceliumGroupProof"` | The MAC key behind a group key, separated from the hint its beacon publishes (§10.2, ADR-019) |
| `b"frame:" ‖ ephemeral_public` | Internet channel frame keys, one per direction. Separated additionally by the HKDF salt, which is the channel transcript and carries its own context tag (§8.4, ADR-011) |

### 5.7 Security properties

| Property | Mechanism | Status |
|----------|-----------|--------|
| Confidentiality | AES-256-GCM, keys never leave the endpoints | Implemented |
| Forward secrecy | DH ratchet on direction change | Implemented |
| Post-compromise security | DH ratchet + ephemeral keys | Implemented |
| Authenticated encryption | AES-256-GCM with AD = `source ‖ destination` (pairwise) or `group_id` (groups) | Implemented |
| Identity authentication | Ed25519 signatures on prekey bundles; NodeId ↔ identity-key binding enforced at ingress | Implemented |
| Reorder tolerance | Bounded skipped-key retention | Implemented |
| Relay opacity | Relays store/forward ciphertext only | Implemented |
| Key material at rest | SQLCipher for the database | **Partial** — the identity key is a plaintext file and the DB key is derived from it (ROADMAP T-08) |
| Memory hygiene | Key material zeroized on drop and on every return path | Implemented |
| Metadata privacy | Not a goal: routing headers are cleartext by design (§4.1) | n/a |

## 6. Identity and trust

### 6.1 Web of Trust

**Status: Partial** (the graph and the scoring; the vouch signature is defined
and unused — see below).

There is no certificate authority and no key server. Trust comes from
in-person attestation.

- Users **vouch** for each other by scanning a QR code containing the public
  key. A vouch is defined as an Ed25519 signature over
  `b"mycelium-vouch-v1:" ‖ voucher_id ‖ vouchee_id ‖ display_name ‖ timestamp`
  — defined, and implemented in `wot::Vouch`, but **not used**: every path
  that writes a vouch stores an empty signature, nothing verifies one on
  load, and `Vouch::create`/`Vouch::verify` have no caller outside their own
  tests. Harmless while a vouch never leaves the node that made it, which is
  true today; it is what a vouch has to carry before trust can be transitive
  across nodes (ROADMAP T-53).
- Trust propagates transitively with exponential decay, computed by BFS over
  the vouch graph: 1 hop = 1.0, 2 hops = 0.5, 3 hops = 0.25, 4 hops = 0.125.
  `max_hops` defaults to 4.
- Trust scores drive relay priority, rate limits (§12) and emergency broadcast
  eligibility (§9.5).

### 6.2 Sybil resistance

**Status: Implemented** (as rate limiting; the defence is social).

The primary defence is the cost of in-person attestation. A new identity has
zero trust until someone vouches for it face to face, so manufacturing
thousands of identities means meeting thousands of people. Unvouched nodes can
still send and receive, but are throttled hard (5 messages/hour) and get no
relay priority.

The one way to be vouched without meeting anyone is a seed-phrase group, and
that path costs the group key: a beacon hint grants nothing until the holder
answers a challenge over it (§10.2, ADR-019). Copying eight bytes out of a
beacon used to be enough, which made the defence above free to bypass for
exactly the population onboarding exists to serve. Vouching for a misbehaving node is intended to damage the
voucher's score — reputation staking — which is not yet implemented.

### 6.3 Threshold key revocation

**Status: Planned (v0.4).**

A key is revoked when a majority of its direct vouchers publish signed
revocation certificates (if five people vouched, three revocations). Threshold
rather than single-party revocation stops one angry contact from revoking
someone. Certificates gossip through the mesh; revoked keys are blacklisted and
their messages dropped.

## 7. Routing

Two layers, tried in order. AODV when a path exists right now; DTN when it does
not.

### 7.1 AODV reactive routing

**Status: Implemented** (`mycelium-core/src/routing/aodv.rs`).

Routes are discovered on demand. A Route Request (RREQ) floods outward, a Route
Reply (RREP) travels back along the reverse path, and a Route Error (RERR)
invalidates a broken path.

```rust
pub struct AodvRouter {
    local_id: NodeId,
    routing_table: HashMap<NodeId, RouteEntry>,   // destination → next hop + metrics
    sequence_number: u32,
    request_id: u32,
    seen_rreqs: HashMap<(NodeId, u32), Instant>,  // dedup
    known_supernodes: HashSet<NodeId>,
}
```

Required behaviours — each one exists because its absence caused a real
failure:

- **Direct links win.** A direct-neighbour route always beats a learned
  multi-hop route and is not displaced by a later RREP.
- **Own RREQs are pre-seeded** into the dedup set, so a node ignores the echo
  of its own flood.
- **Intermediate replies are loop-free**: an intermediate node never answers
  with a route that points back through the requester.
- **RERR does not storm.** `handle_rerr(rerr, received_from)` invalidates both
  routes *via* the unreachable node and routes *to* it whose next hop is the
  RERR sender. Only a valid→invalid transition triggers a rebroadcast, and the
  rebroadcast skips the hop it came from.
- **Supernode preference.** With equal sequence number and hop count, prefer
  the next hop that is a known supernode. Supernodes register via their beacon
  `node_type` (§10.1).
- **Bounded state.** Hop counts saturate; the table is capped at 4096 entries;
  long-invalid entries are pruned.

**What a route can be learned from.** Not only AODV messages: *every* received
envelope whose `source` is neither the sending peer nor this node, and whose
`hop_count` is above zero, installs a reverse route to that source via that
peer. `envelope.source` is cleartext and nothing authenticates it (§14.3), so
a neighbour can name any id and have a route to it installed pointing at
itself, then attract unicast traffic for that id and drop it. The hop count it
can claim is at least 2, so a live direct link is never displaced — but an id
with no valid route, or one reachable only through a longer learned path, is
taken over. The route is installed before the payload type is parsed, so no
rate limit has been charged at that point, whatever the type. Content stays end-to-end encrypted, so this is a denial of service
rather than a disclosure. See ROADMAP T-55.

Route entries live for 300 s by default and are refreshed for active
neighbours; the RREQ dedup window is 10 s. `AodvAction` is the router's output
(`Forward`, `BroadcastRreq`, `UnicastRrep`, `RouteFound`, `BroadcastRerr`,
`None`); the node executes it against the transport layer.

### 7.2 Spray-and-wait DTN

**Status: Implemented** (`mycelium-core/src/dtn/spray_and_wait.rs`).

When no route exists, the message becomes a DTN bundle.

- **Spray phase** — binary spray: on meeting a relay, hand it half the
  remaining copies. Default `L = 8`.
- **Wait phase** — each copy is carried until its holder meets the destination.
- **Opacity** — relays store `(message_id, encrypted_blob, destination, TTL,
  size)` and cannot read the blob.
- **TTL** — 72 hours by default, carried on the wire so relays honour the
  originator's deadline (ADR-005).
- **Storage** — 256 MB on phones, 2 GB on supernodes; per-identity quotas of
  10 MB and 50 MB respectively.
- **Eviction** — TTL expiry first, then relay traffic oldest-first; local
  bundles are never evicted (see below).
- Storing the same message twice does not double-count storage, and per-source
  accounting entries are dropped at zero.

**Eviction is origin-aware.** A bundle records whether this node originated it.
Only relay traffic is ever evicted, oldest-first; a locally originated bundle is
a message the user composed and cannot re-create, so nothing displaces it — not
even another local bundle. When only local bundles remain the store is full and
the send fails visibly rather than silently deleting mail. The origin flag and
the spray history are both persisted, so a restart neither reclassifies the
user's own bundles as relay traffic nor spends copies re-spraying peers that
already hold one.

### 7.3 Decision flow

```
Node.send_message(destination, data)
  └─ RoutingCoordinator.route_message(destination)
       ├─ DeliverLocal          destination == self → error
       ├─ SendRealtime{next_hop}  AODV has a route → transport_manager.send()
       ├─ DiscoveryPending      broadcast RREQ, queue in pending_routes[dest]
       │                          └─ on timeout → EnterDtn
       └─ EnterDtn              DtnEngine.store_outgoing(.., copies=8, ttl=72h)
```

A destination gets **one** discovery attempt, shared by every envelope queued
for it, with one retry before the fallback. A dedicated 1 s sweep evaluates the
5 s timeout — not the 30 s maintenance tick — so a message to an unreachable
peer enters DTN in roughly 11 s. Implementations **must not** start a discovery
per queued envelope: all of them are waiting for the same route, and one RREQ
per message floods the mesh N times for a single unreachable peer.

### 7.4 Geographic hash overlay

**Status: Planned (v0.4).**

For scale beyond a region, messages to unknown destinations would route toward
the destination's last-known region. Regions are inferred from topology —
supernode affiliation, hop counts to landmarks, Wi-Fi BSSID databases — so no
GPS is required. Moving nodes would leave forwarding pointers at their old
region's supernodes, garbage-collected after 24 hours. Flat routing is
sufficient at v0.1 scale.

## 8. Transports

**Status: Implemented** (abstraction and five transports; platform bridges vary).

### 8.1 The `Transport` trait

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    fn transport_type(&self) -> TransportType;
    async fn start(&self) -> Result<(), TransportError>;
    async fn stop(&self) -> Result<(), TransportError>;
    async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError>;
    fn events(&self) -> broadcast::Receiver<TransportEvent>;
    fn link_quality(&self, peer: &NodeId) -> Option<LinkQuality>;
    fn connected_peers(&self) -> Vec<NodeId>;
    fn mtu(&self) -> usize;
    fn supports_broadcast(&self) -> bool { false }
}
```

`TransportType`: `Ble`, `WifiDirect`, `Lora`, `BtClassic`, `InternetTunnel`,
`WifiAware`, `Meshtastic`, `Reticulum`, `Mock`. Foreign-protocol bridges carry
their own variant rather than borrowing the one for the radio they ride on, so
per-transport accounting and the diagnostics API can tell them apart.

`TransportEvent`: `NeighborDiscovered`, `NeighborLost`, `DataReceived`,
`LinkQualityChanged`.

`LinkQuality` carries `rssi: Option<i16>`, `packet_loss: f32`, `latency_ms`,
`throughput_bps` and a composite `score()`.

A transport's `send()` **must** fail with `PeerNotConnected` for an unknown
peer. If it silently succeeds, the manager's fallback logic reports delivery
for an unreachable node and the message is lost rather than queued.

### 8.2 `TransportManager`

Multiplexes every transport behind one interface.

- `add_transport()` registers a transport, starts it if the manager is already
  running, and spawns an event forwarder. `start()` is idempotent;
  `replace_transport()` re-registers without orphaning an outbox.
- `send(peer, data)` tries each transport that reports `peer` connected.
- `known_peers()` is the union of all transports' peers, de-duplicated per
  transport type and seeded from each transport's own `link_quality()`. Ties in
  score break on a static priority: **Wi-Fi Direct > Wi-Fi Aware > BT Classic >
  Internet > BLE > LoRa**.
- `broadcast()` sends to `NodeId::ZERO` on every transport whose
  `supports_broadcast()` is true (today: LoRa).
- Event forwarders survive `broadcast` channel lag (log and continue) and are
  cancelled by `stop()`. Lost peers are removed from `known_peers()`.

**Known gap:** the manager sends via the first available transport. It does not
migrate an active session between transports, so handoff is a reconnect rather
than a seamless migration (ROADMAP T-03).

### 8.3 Transport summary

| Transport | MTU | Throughput | Range | Status |
|-----------|-----|-----------|-------|--------|
| **BLE** | 4035 B message / 512 B frame | ~100 kbps | 10–30 m | **Implemented, untested on hardware** — dual-role GATT on Android + iOS, proved peer identity (ADR-021); the handshake has never run on a radio (T-15) |
| **Wi-Fi Direct** | 65474 B message / 16 KB frame | ~50 Mbps | 50–200 m | **Implemented, untested on hardware** — Android only (iOS does not expose it), proved peer identity (ADR-021) |
| **BT Classic (SPP)** | 16 KB | ~2 Mbps | 10–100 m | **Implemented, untested on hardware** — Android only |
| **LoRa** | 2 KB message / 51–222 B frame | 0.25–37 kbps | 1–15 km | **Implemented, untested on hardware** — bridges on Android (BLE + USB) and iOS (BLE) |
| **Internet tunnel** | 1 MiB − 53 B (see §8.4) | varies | global | **Implemented** — keyed authenticated channel, binary framed (ADR-011) |
| **Plugins** | per plugin | — | — | **Partial** — API complete, adapters not wired (§18) |
| **Wi-Fi Aware (NAN)** | — | — | — | **Planned (v0.4)** |
| **Ultrasonic audio** | — | — | — | **Planned (future)** — last-resort bootstrap when all radios are blocked |

### 8.4 Per-transport notes

**BLE.** Dual-role: every device runs a GATT server and client simultaneously.

```
Service UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
├─ Data TX  (…7892) Write  — central writes frames to peripheral
└─ Data RX  (…7893) Notify — peripheral notifies central with frames
```

**Peer identity is proved, not asserted** (ADR-021, ROADMAP T-34). The Node ID
(`…7891`) and Identity (`…7894`) characteristics are gone: both carried a bare
32-byte NodeId with no key, no signature and nothing bound to the connection,
so anything in radio range could claim a neighbour's id and have its traffic
delivered to it and dropped. What replaces them is the internet transport's
handshake (ADR-011), run over this transport's own fragmentation layer — one
proof format and one implementation across BLE, Wi-Fi Direct and internet.

The platform layer no longer knows, or reports, who is on the other end. It
reports **links**, named by an address it already holds and prefixed by the
role carrying them (`c:` where we are the central, `s:` where we are the
server — on Android both roles can be live with the same device, and they are
two links with two channels), and relays opaque frames. A link is announced
only once it can carry frames in both directions, which on the central side is
after its subscription to Data RX completes and on the server side when a
central subscribes; announcing it earlier leaves a handshake waiting for a
reply that cannot arrive.

The Identity characteristic existed to map a BLE Random Private Address to a
NodeId. That problem dissolves rather than moving: a link is keyed by whatever
address the platform reports for it, identity is proved over the link, and an
address nobody can correlate is exactly as usable as one anybody can.

On the link:

```
→ Hello   { identity_key, ephemeral_public, listen_port = 0, signature }  (cleartext)
← Hello   { identity_key, ephemeral_public, listen_port = 0, signature }
→ Confirm { transcript }                                                 (sealed, frame 0)
← Confirm { transcript }
then: counter(8 LE) ‖ AES-256-GCM( MeshData { … } )                      (sealed, frame n)
```

The signed payload, the transcript and the key schedule are the internet
transport's, below; `listen_port` is zero because a radio has no dialable
address, and the ephemeral key is what makes a captured hello useless. The
peer's NodeId is **derived** from the `identity_key` it signed, so §14.3's
binding holds by construction, and nothing is installed until the peer has
sealed a frame under the channel its key produced: no peer, no
`NeighborDiscovered`, and therefore no route. A link that proves our own
identity key is closed, which is what now catches a loopback the platform
cannot see. A `Dht` frame is refused: the codec is shared with the internet
transport, and a radio has no DHT.

**Why frames carry their counter here.** The internet transport leaves the
AEAD frame counter implicit, which is safe on TCP, where ordering is
guaranteed and a loss ends the connection anyway. A sealed frame crossing BLE
is split into 512-byte fragments that nothing above the ATT layer retries, so
one lost fragment means the frame never reassembles, the receiver never opens
it, and an implicit counter would stay a frame behind for good — every later
frame failing under the wrong nonce. The counter therefore travels with the
frame and the receiver keeps a *floor*: a counter at or above it is opened and
moves the floor past itself. Loss is survivable, replay and reordering are
refused, and altering the counter in flight only picks a nonce the frame
cannot open under. A frame that fails to open is dropped and the link kept,
because tearing it down would let anything in range kill an established link
by injecting noise.

The counter is taken as a frame **leaves**, not as it is queued: the outbox
puts an emergency ahead of ordinary traffic (§9.5), so sealing on the way in
would hand the peer counters in a different order from the frames and
everything the alert overtook would be refused as stale. Handshake frames have
their own queue, drained first and never evicted — two per link, a hello and a
confirmation — because an emergency displacing another link's confirmation
would leave that peer waiting for one that never comes. One frame's fragments
are drained before the next frame is taken.

**Two framing layers, independent of each other.** A *message* is sealed into
one frame and that frame is split by the transport into fragments of 512 bytes
with the same 6-byte header LoRa uses (sender tag u16, fragment id u16, index
u8, count u8). The transport MTU is therefore the largest reassembled frame
less what sealing costs — `BLE_MAX_MESSAGE` (4096) less 61 bytes of counter,
`MeshData` header and AEAD tag, so **4035 bytes per message** — not one
frame's worth: without fragmentation a co-signed critical alert (522 bytes)
could not cross BLE at all, and an alert's text was capped at 295 bytes
(ADR-022, ROADMAP T-39). Reassembly is keyed by (link, sender tag, fragment
id) — by the link rather than the peer, because a frame arrives before the
peer behind it is proved — and is shared with LoRa: bounded to 64 partials,
expired after 120 s, refused past the limit by accumulated bytes, with a
duplicate fragment ignored rather than counted and a refused message kept
marked so its later fragments cannot start it over.

Below that, each fragment is written to GATT by the platform layer with a
1-byte header of its own: `0x01` first, `0x02` last, `0x03` single, `0x00`
middle. Fragment size is `min(max(negotiated_MTU - 4, 19), 511)`: an ATT MTU
of 23 carries 20 bytes of attribute value and one of those is this header, so
19 are payload, and the upper cap exists because a negotiated MTU of 517 would
otherwise produce a 513-byte value, which Android refuses outright — so every
full fragment of a multi-fragment frame would be rejected. Android permits one outstanding GATT operation, so writes go through
a sequential queue driven by `onCharacteristicWrite`/`onNotificationSent`,
and a purge that leaves the connection alive quarantines that link for 5 s so
that the completion it abandoned cannot be mistaken for a later operation's —
the platform supplies no operation token, and on a closed connection the
completion may never arrive at all. Each native queue is bounded in its own
right — 128 operations on BLE, 32 per Wi-Fi Direct socket — because polling
frees the Rust outbox's capacity as soon as a frame is handed across, and a
handshake fragment is never what a full queue sacrifices. Which *ordinary*
frame is lost differs: BLE drops the oldest, as the outbox above it does,
while Wi-Fi Direct refuses the newest, because its backlog is a thread pool's
queue of opaque tasks that cannot be inspected to tell a handshake write from
a data write. Which fragments belong
to a handshake is an out-parameter of the dequeue rather than something the
platform layer infers: a link counts as established in Rust as soon as the
peer's confirmation arrives, which can be before our own has left. Those
fragments are written ahead of ordinary traffic and after any handshake
already queued, so a link's hello and confirmation keep their order. The platform layer's own reassembly is capped
at one Rust frame (512 bytes) and expires after 10 s, since the bounded
reassembler above it never sees an incomplete frame. A connection that never
becomes announceable — a central that does not subscribe, a discovery that
stalls — is closed after 20 s, because nothing above this layer knows it
exists. Connections stagger 500–1500 ms with jitter and retry with exponential
backoff (1 s, 2.5 s, 4 s, max 3).

**Bounds and directives.** A link has 10 s to finish its handshake, links are
capped at 32, and a newcomer past the cap is refused rather than admitted by
evicting a proved peer. There is no background task: the table is swept on
every call, which the app's 50 ms outbox poll makes a reaper. Authentication
is decided in Rust and sockets are the bridge's to close, so the bridge polls
a directive queue beside the outbox: `established` (stop retrying) and `close`
(drop it, and leave that link alone for 30 s), one entry per link; when it is
full what goes is an entry for an address no longer held, never one for a live
link — a lost `close` leaks a socket, and an `established` is what stops the
bridge's own sweep closing a proved peer. The bridge does not rely on
that queue for liveness: it closes a link itself once it has been announced
for 20 s without becoming established. On Android a refused inbound link is
disconnected with `BluetoothGattServer.cancelConnection`; iOS has no way for a
peripheral to disconnect a central, so there the link is only forgotten
(ADR-021 records it). A frame on a link the bridge never announced is dropped
and answered with `close`, so a link just closed cannot reopen itself with
what was still in flight — except for the first frame of a connection the
bridge already holds, which announces its link rather than losing a handshake
to the race with its own subscription callback. A peer may hold several links —
BLE's two roles — and is reported lost only when its last one goes.

**Wi-Fi Direct (ADR-003).** `WifiP2pManager` groups plus Bonjour service
discovery and TCP sockets on port 9740. Wire protocol: 1-byte type
(`Frame = 0x02`) + 4-byte big-endian length + payload, where the payload is
one opaque frame for the transport above. The `Hello = 0x01` that exchanged a
bare NodeId is gone, and the mDNS TXT record no longer advertises a node id
prefix: the same proof BLE runs now runs here (ADR-021, ROADMAP T-34), over
the same fragmentation layer, with links named by the remote socket endpoint.
TCP handles segmentation, so a 16 KB fragment is one TCP frame, and the
transport MTU is `WIFI_MAX_MESSAGE` (65535) less the 61 bytes sealing costs —
**65474 bytes per message**. Links are capped at 16. The Android bridge
refuses a frame whose length prefix exceeds the *fragment* MTU rather than the
message MTU — 16384, paired with `WIFI_FRAME_MTU` — because a fragment is what
crosses that layer (T-56 corrected a 65535 there, left behind when ADR-022
gave this transport a fragmentation layer).

**LoRa (ADR-008).** Messages are fragmented into frames with a 6-byte header
(sender tag u16, fragment id u16, index u8, count u8), sized for the peer's
current spreading factor; the transport MTU is the largest reassembled message
(`LORA_MAX_MESSAGE = 2048`). Reassembly is shared with BLE (ADR-022): keyed by
(sender tag, fragment id), bounded to 64 partials, expired after 120 s, and
refused past the message limit by accumulated bytes rather than per fragment —
which ADR-008 documented and the code did not do. Duty cycle is charged per frame
against an hourly window (1 % for EU 868 MHz; unlimited for US 915 MHz).

The radio exposes no link-layer address, so the bridge passes `NodeId::ZERO`
and the peer is taken from the reassembled envelope's `source`. First contact
emits `NeighborDiscovered`; a peer silent for `LORA_PEER_TIMEOUT` (300 s) is
reported lost. `supports_broadcast()` is true, so the node can beacon before
any peer is known.

Adaptive data rate negotiates spreading factor per peer: start at the
configured SF, lower after 10 consecutive successes, raise after 2 consecutive
failures. Broadcasts use the discovery SF (SF12) for maximum range.

**Internet tunnel (ADR-011).** TCP overlay, default listen port 9736, with a
configurable bootstrap node list and a Kademlia DHT (256 k-buckets, k = 20,
XOR distance, Ping/FindNode/FindValue/Store) for peer discovery.

Every connection is a **keyed, mutually authenticated channel**, established
before any state exists for the peer. Each side signs a fresh X25519 ephemeral
public key, both derive directional AES-256-GCM keys from the shared secret,
and each proves possession of its key before the peer is installed:

```
→ Hello { identity_key, ephemeral_public, listen_port, signature }   (cleartext)
← Hello { identity_key, ephemeral_public, listen_port, signature }
→ Confirm { transcript }                                             (sealed)
← Confirm { transcript }

signature  = Ed25519( b"mycelium-internet-hello-v2:"
                    ‖ ephemeral_public(32) ‖ identity_key(32)
                    ‖ listen_port(2 LE) )
shared     = X25519(my_ephemeral_secret, peer_ephemeral_public)
transcript = SHA-256( b"mycelium-internet-channel-v1:"
                    ‖ min(eph)‖max(eph) ‖ min(id)‖max(id) )
prk        = HKDF-Extract(salt = transcript, ikm = shared)
k_send     = HKDF-Expand(prk, b"frame:" ‖ my_ephemeral_public)
k_recv     = HKDF-Expand(prk, b"frame:" ‖ peer_ephemeral_public)
```

Signing the **ephemeral key** rather than exchanged nonces is what makes the
handshake unrelayable. An attacker can forward a victim's signed `Hello` and
the signature still verifies, but the channel key comes from an ephemeral
secret the attacker does not hold, so it cannot send the `Confirm` frame or
read anything. A nonce-based signature cannot achieve this at any field
ordering, because the attacker always chooses its own nonce last — ADR-011
records the attack in full.

Every frame after the two `Hello`s is sealed under the sending direction's key
with the frame counter as the nonce. Counters are per direction and advance
only on a successful open, so injected, altered, replayed and reordered frames
are all refused and cannot desynchronise the channel. A peer that echoes our
ephemeral key, or offers one yielding an all-zero shared secret, is refused.

The peer's NodeId is **derived** from the `identity_key` in its `Hello` and
never carried on the wire, so the §14.3 binding holds by construction. The
`listen_port` is signed because it becomes the peer's dialable address in the
DHT. An *inbound* peer's address is its socket IP with that signed port, since
the socket's source port is ephemeral; an *outbound* connection keeps the
address it dialled, which has just been proved to work — substituting the
signed port would break a peer behind a port forward. A handshake that does
not complete closes the socket and installs nothing: no connection, no DHT
contact, no `NeighborDiscovered`, so no route. The whole exchange is bounded by
a 10 s timeout; duplicates and self-connections are refused; the transport is
restartable, and `stop()` waits for the listener to close and for every
connection slot to come back. Neither call wedges the transport when its
caller walks away mid-flight: `start()` marks itself started only once its
tasks are registered, and `stop()` restores the usable stopped state — fresh
cancellation token, shutdown flag cleared — from a drop guard rather than from
its own tail.

`max_connections` (default 64) is enforced as semaphore permits, taken *before*
the handshake and held for the connection's lifetime, inbound and outbound, so
a peer that opens sockets and stalls still counts against the limit. Over the
limit, the socket is closed without a hello.

Framing is binary, little-endian, a 4-byte body length then a 1-byte tag:
`MeshData 0x01`, `Dht 0x02`, `DhtReply 0x03`, `Hello 0x05`, `Confirm 0x06`.
A `Dht`/`DhtReply` body carries an 8-byte `request_id` and then a sub-tag:
requests `Ping 0x01`, `FindNode 0x02` + target(32), `FindValue 0x03` + key(32),
`Store 0x04` + record; replies `Pong 0x01`, `FoundNodes 0x02` + count(2) and
that many `node(32) ‖ addr` entries (at most 64), `FoundValue 0x03` + record,
`Stored 0x04`, `Rejected 0x05`. An address is `family(1)` — 4 with four
octets, 6 with sixteen — then the port; a record is
`public_key(32) ‖ addr ‖ published_at(8) ‖ signature(64)`. That address
encoding is also what the record's signature covers, so a signature verifies
only against the address bytes the signer meant. The AEAD nonce is the frame
counter alone: 12 bytes, the first four zero, the counter in the last eight,
with no associated data.
The wire frame cap is 1 MiB including the 16-byte AEAD tag; a cleartext
handshake frame is capped at 1 KiB, and the sealed `Confirm` — read before the
peer has proved the channel key — at its exact 49 bytes, so an unproven peer
cannot make the node allocate more. `mtu()` is the frame cap minus the tag and
the 37 bytes `MeshData` framing costs, so a send at the advertised MTU is
exactly one acceptable frame; anything larger is refused with `ExceedsMtu`
rather than transmitted.

Each connection owns a **writer task** holding the sealed write half, fed by a
bounded outbox (128 frames). Sealing advances the direction's frame counter, so
sealing and writing must happen together: a caller cancelled between them — a
DHT lookup hitting its deadline — would leave a truncated frame and mis-number
every frame after it. Queuing is therefore synchronous, a full outbox is a
failed send rather than a wait, and a write that fails or stalls shuts the
write half down so both ends tear the connection down. `send()` returning `Ok`
means the frame is queued, not that it is on the wire.

Each connection also has its own cancellation token, a child of the
transport's, and the read loop and writer task share the connection's permit.
Either task cancels the token on the way out, so a connection that can no
longer be written to is torn down rather than left blocking a reconnect, and
the slot returns only once both tasks are gone. Dials are refused while a
`stop()` is draining, and the replacement cancellation token is published only
afterwards, so no connection can attach to it and outlive the shutdown. A dial
takes its cancellation token before it reads that shutdown flag, so a dial
descheduled across an entire `stop()` still holds the token that `stop()`
cancels rather than its replacement.

When two connections to one peer exist — both ends dialling at once, or two
lookups dialling the same peer — both ends keep the one with the **lower
channel transcript**: identical at both ends of a connection, different between
connections, and needing no extra exchange. Neither local arrival order nor
"the lower NodeId dialled" works, the first because the two ends can disagree
and the second because it cannot separate two connections opened by the same
node. A displaced connection closing emits no `NeighborLost`, or the routing
layer would drop a peer that is still connected; both that event and
`NeighborDiscovered` are emitted under the connection-map lock, so neither can
overtake the mutation it describes. A dial made for a particular peer refuses a
different proven identity before anything is installed.

Every DHT contact records whether its address was **dialled** or
**claimed** — an inbound connection's derived address and a referral from a
third node are claims — and when that was established. A claim never replaces
a dialled address, because a peer behind a port forward signs a port that is
unreachable from here; within a level the fresher evidence wins, so a claim
does replace an older claim and a peer that moved is re-learned. The age is
that of the *address*, not of the last frame: a connection refreshes its
contact on every DHT request it answers, and each refresh carries the address
that connection was dialled on, so an old channel must not outrank a newer
dial. A dialled address is recorded as soon as its handshake completes, even
if that channel then loses the tie-break, because the dial proved the endpoint
either way; a claim waits for the connection to be admitted, so a channel that
lost the tie-break never rewrites the contact of the one that was kept.

**DHT records are signed.** A record is a node's claim about its own address —
`public_key(32) ‖ addr ‖ published_at(8) ‖ signature(64)`, signed over
`b"mycelium-dht-record-v1:" ‖ public_key ‖ addr ‖ published_at` and keyed under
`SHA-256(public_key)`. A record is refused, in order, if the signature fails or
the NodeId does not bind to the key; if it is dated more than 300 s ahead; if it
is older than the 3600 s TTL; if its address is a wildcard (`0.0.0.0` or `::`),
which nothing could dial; if it is no newer than one already held; if it is
older than the newest ever admitted for that publisher; if the peer that
delivered it already holds its share of the store; and finally if the store is
full. Each refusal has its own reason and its own test. The store is capped at
4096 records, swept of expired entries before each insert, and evicts the entry
closest to expiry when at capacity. A record found over the network is subjected
to the same checks and returned only if they pass.

**A replayed older record cannot roll an address back, and that no longer
depends on still holding the newer one (ADR-016).** The node keeps a persisted
`node_id → newest published_at` **high-water mark** per publisher, in the
`dht_marks` table (§15), which outlives both the record's eviction and the
process. The table holds 8192 marks in two regions: *established* publishers,
seen continuously for a full replay window (TTL + a 86 400 s clock-regression
grace, so 25 h), which are never evicted inside that window and are dropped only
by the retention sweep; and *probationary* ones, evicted
least-recently-refreshed first, of which a full table always holds at least 512
because establishment is capped at the remaining 7680 — a floor for newcomers to
evict, not a ceiling. The reserve is what
guarantees a publisher the node has never seen is always admitted rather than
refused when the table is full — an attacker minting identities churns only that
slice. **The cost of that reserve: a probationary mark can be evicted inside the
replay window, so rollback protection is unconditional for established
publishers and lasts only as long as a probationary slot for publishers seen
recently and briefly.** A record admitted raises its mark; a mark is never
lowered in memory, and never un-established. Persisting an update is best
effort: a write is lost if the writer's queue is full, if the backend refuses
it, or if the process ends without an orderly stop — the last being the ordinary
case on a phone. So the watermark restored after a restart is the last one that
reached storage, and a replay dated between that and the value the previous run
held is accepted until the publisher's next record, within one TTL, carries it
forward. Deletions are retried instead, because a lost deletion leaves a row
nothing in memory points at. The two regions also assume a fixed configuration:
shrinking the table between runs demotes or discards established marks that no
longer fit, inside the replay window.

Marks are written through a single writer task rather than on the admission
path, because admission holds a lock and a caller can be cancelled: each
durable write is conditional on the stored row rather than a delta — a write
states the publisher's whole mark unless the stored watermark is newer, and a
deletion applies only while the stored mark is no newer than the one the sweep
saw — so neither cancellation nor reordering can lower a watermark. A deletion
is never applied to an id the table still holds, decided when the delete runs
rather than when it was queued. Writing the whole mark rather than merging
fields is what lets retention end a publisher's lifetime (otherwise it banks
establishment across a silence longer than the replay window) and lets
restoration withdraw establishment it had to demote.

Those guarantees belong to the engine's single writer, which applies writes in
the order they were issued, so **one mark store serves one engine**: a node
builds one, and the FFI refuses to register a second internet transport rather
than replace the first, because a replacement cannot be made safe without the
old engine being provably quiet and `stop()` does not give that (ROADMAP T-46). The marks are read
once before anything is admitted, and admission itself reads them if nothing
has — dialling does not require starting the transport. An unreadable mark store
refuses admission rather than being treated as an empty one.

**A single delivering peer may occupy at most 256 of the 4096 record slots.**
The principal is the peer the channel handshake authenticated, not the record's
signer — the store already holds at most one record per signer, so a signer
quota would be vacuous, and identities are free, so this is fairness rather than
the rollback defence. A replacement from the same peer is exempt; one from a
different peer is not. A DHT request carries no sender identity: the
sender is whoever holds that channel's key, and in-flight requests are tracked
per connection so no peer can answer another's. A node offers its own record to
every peer it authenticates, and re-signs and re-offers it every TTL/3.

Lookups are iterative and bounded: α = 3 parallel `FindValue` rounds, replies
correlated by request id, terminating at the first of — record found, every one
of the k closest known nodes queried, 16 rounds, or a 10 s deadline that bounds
the requests in flight (2 s each). A visited set means a referral cycle costs
each peer one query. A `FoundValue` counts only if its derived NodeId is the
target and the record is acceptable, so a peer cannot answer with someone
else's record. If the answer is no newer than one already held, the lookup
returns the cached record rather than nothing — that is what a second,
concurrent lookup looks like.

**Known gaps:** a node listening on a wildcard address (the `0.0.0.0` default)
neither stores nor publishes a record, because signing `0.0.0.0` would be valid
and useless — external address discovery is ROADMAP T-31. A mark deletion that
cannot be queued is retried through a bounded list, and when that list overflows
the rows it was holding survive until the next start reconciles them
(ROADMAP T-44). A high-water mark records when, not what, so a publisher that
signed two addresses with the same `published_at` has no protection between them
once its record is evicted (ROADMAP T-45). Nothing prunes a DHT
contact whose peer is gone for good, so a k-bucket can fill with dead entries
(ROADMAP T-32). Resolution is available but not automatic: `resolve()` will
find a peer's address through the DHT, and no send path calls it, so a send to
an unconnected peer still fails (ROADMAP T-33). The channel gives
authentication and integrity, not a forward secrecy claim; message
confidentiality is the Double Ratchet's job (§5.3).

**Outbox pattern.** BLE, Wi-Fi Direct, BT Classic and LoRa all follow the same
Rust↔platform shape: `send()` pushes to a bounded queue, Dart polls it every
50 ms over FFI, and inbound data is injected back through FFI. BT Classic and
LoRa queue *frames* (512 packets; 256 for LoRa). BLE and Wi-Fi Direct queue
whole *messages* — 128 and 64 — because a frame's AEAD counter is taken as it
leaves rather than as it is queued (ADR-021, §8.4), and what they are
addressed to is a link rather than a peer. The direct send callbacks are gone:
nothing registered them, Dart cannot hand out a synchronous C callback, and a
second send path into an authenticated link is the kind nobody looks at.

### 8.5 Transport plugin API

**Status: Implemented** (trait and registry; instantiation is ROADMAP T-13).

```rust
pub trait TransportPlugin: Transport {
    fn plugin_name(&self) -> &str;
    fn plugin_version(&self) -> &str;
    fn plugin_description(&self) -> &str;
    fn configure(&mut self, config: &PluginConfig) -> Result<(), TransportError>;
    fn requires_platform_bridge(&self) -> bool { false }
}
```

`PluginRegistry` registers a `PluginFactory` by name and creates instances from
`PluginConfig { name, enabled, settings: HashMap<String, String> }`.
`NodeConfig.plugins: Vec<PluginConfigEntry>` holds the TOML configuration.

Once added via `TransportManager::add_transport()`, a plugin is
indistinguishable from a built-in transport: it carries routed envelopes,
forwards AODV messages and relays DTN bundles.

The full plugin development guide is [`docs/plugin-api.md`](docs/plugin-api.md).

**Known gap:** nothing reads `NodeConfig.plugins` — no plugin is ever
instantiated. Doing so needs trait upcasting (MSRV 1.86) or a wrapper type. See
ROADMAP T-13.

### 8.6 iOS strategy

iOS does not expose Wi-Fi Direct to third-party apps. Mycelium handles this by
making BLE a first-class transport rather than a degraded one:

- iOS nodes use dual-role CoreBluetooth GATT as their primary transport,
  mirroring the Android stack.
- An iOS node reaches the wider Wi-Fi Direct mesh through any Android node or
  supernode in BLE range, which relays as an ordinary multi-hop router — so an
  iOS node is always one hop from the full mesh.
- iOS↔iOS works directly over BLE. Apple Multipeer Connectivity is not used.

## 9. Messaging

### 9.1 Content types

**Status: Implemented.** Seven types, sized for low-bandwidth mesh links.

| Type | Max size | Description |
|------|----------|-------------|
| `Text` | 64 KB | UTF-8 |
| `Image` | 500 KB | Compressed (JPEG/WebP) |
| `File` | 500 KB | Arbitrary small files |
| `GpsPin` | 32 B | Latitude/longitude |
| `VoiceNote` | 500 KB | Compressed audio (Opus) |
| `Receipt` | 64 B | Delivery/read confirmation |
| `System` | 1 KB | Key exchange, group management, trust operations |

### 9.2 Ordering

**Status: Implemented.** Lamport logical clocks with device-timestamp
tiebreaking. Each node ticks its counter on send and merges (max + 1) on
receive, giving causal ordering: if A caused B, A sorts before B. Concurrent
messages order by device timestamp. There is no NTP, so clock drift is
tolerated and timestamps are best-effort.

### 9.3 Receipts

**Status: Implemented.**

A delivery receipt is sent automatically when a message reaches the destination
device, on every delivery path including DTN. A read receipt is sent when the
user opens the message. Receipts travel back through the mesh by the same
routing (AODV or DTN), so in DTN mode a receipt can take as long as the
original message.

A receipt **must** be accepted only from the recipient of one of our own
outgoing messages, never for an incoming one. Otherwise any node can forge
delivery confirmations for traffic it merely relayed.

### 9.4 Public channels

**Status: Implemented** (topic channels; regional channels are Planned).

Channels are broadcast boards: messages flood to subscribers rather than
routing to a destination.

- **Topic channels** — named channels that nodes subscribe to. Subscriptions
  are announced; messages flood to connected peers within TTL, deduplicated by
  a digest of the message — id, source, channel, content type and body — and
  not by the envelope id alone, which any relay can copy. A copy that arrives
  with more remaining TTL than the one already seen is forwarded again, so a
  spent-TTL copy cannot halt a flood, and a copy addressed to one node rather
  than to `NodeId::ZERO` is refused (ADR-013).
- **Regional channels** — **Planned**, dependent on the geographic overlay
  (§7.4).
- **Moderation** — the creator has moderation powers and can delegate.
  Moderators issue signed removal notices (`ChannelModeration`, `0x83`) which
  propagate through the mesh; receiving nodes hide the content. Moderation is
  per-channel, never network-wide.

Floods skip the originator, ourselves and the previous hop.

**Known gap:** an incoming channel message is reported to API clients as a
direct message because `NodeEvent` has no channel variant, and a stored
channel message is keyed on the envelope's `message_id` under
`INSERT OR IGNORE`, so a forged copy stored first keeps the row even though
the flood now carries the genuine message onward. Flood dedup itself expires
by age with a bounded set (ADR-013), but a channel message carries no signed
date — `device_timestamp` is a relay's to edit — so its dedup entry is a plain
900 s bound rather than a validity window: once it expires, a captured message
is accepted, reported and flooded again. All three need the originator
signature in ROADMAP T-14.

### 9.5 Emergency broadcast

**Status: Partial.**

| Level | Name | Behaviour | Requirement |
|-------|------|-----------|-------------|
| 1 | **Priority** | Reach 4 hops; queued ahead of ordinary traffic | sender trust > 0.3 |
| 2 | **Urgent** | Reach 8 hops; exempt from the per-originator rate limit | sender trust > 0.6 |
| 3 | **Critical** | Reach 20 hops — the mesh-wide flood | 3+ co-signers with trust > 0.8 |

Reach counts the nodes that receive the alert, the first transmission
included, so an alert goes on the wire with `reach - 1` and is clamped to the
same figure on receipt and on forwarding: a level-1 alert claiming twenty hops
travels four nodes from the node that forwards it. It is **not** a bound
relative to the originator: the TTL carries no signature — every hop
decrements it — so a relay can re-send a spent alert at the full figure and
buy it another four hops. The content stays authenticated, a node accepts it
once per validity window, and the per-list reach rule limits re-forwarding, so
the cost is extra traffic rather than a forged or endless flood (ADR-014). The figures are provisional until measured against a real
topology (ROADMAP T-19, T-15); what is fixed is that each level reaches
strictly less far than the one above.

The per-neighbour rate limit applies to every level — it is charged before a
payload is parsed — and the level-2 exemption is from a **separate**
per-originator limiter reserved for emergencies, charged only once an alert's
origin signature verifies and once per alert rather than per copy, however the
alert reached us. Sharing the general limiter would let unauthenticated packets
claiming an originator's id spend its alert quota and silence it; skipping the
charge for a direct neighbour would let an originator spend that quota twice
(ADR-014).

Thresholds are enforced as specified. Emergency messages carry the sender's
identity — they are deliberately non-anonymous, for accountability — and a
false emergency is intended to incur a trust penalty.

**Body.** `level(1) ‖ signed_at(8 LE) ‖ identity_key(32) ‖ signature(64) ‖
msg_len(4 LE) ‖ message ‖ cosigner_count(1) ‖ cosigners(N × 96)`, parsed
strictly: the length must match exactly and the level must be one of the
three. At most 255 co-signers fit, and a sender cuts the list to that before
signing, since signing a longer one would produce a broadcast whose own
signature cannot verify.

**The originator is authenticated.** The broadcast carries the originator's
Ed25519 key and a signature over

```
SHA-256( b"mycelium-emergency-origin-v1:"
       ‖ broadcast_digest (32)
       ‖ cosigner_count   (1)
       ‖ for each: node_id(32) ‖ signature(64) )
```

A receiver drops the broadcast unless `SHA-256(identity_key) ==
envelope.source` and the signature verifies, **before** the trust gate — that
gate scores the id in the packet rather than the peer that sent it, so until
the signature verifies there is nothing to score. The key is carried rather
than looked up so a receiver with no prior contact can check an alert at all;
what makes that safe is the §14.3 binding. Because the digest covers the
approval list, a relay can neither strip approvals a downstream node could
have verified nor pad the list (ADR-014).

A co-signature covers the broadcast id and date, so both are fixed before
approvals are collected: a sender drafts the alert, co-signers sign that
draft, and the originator signs last over what it collected.

**Co-signatures are verified.** A co-signer entry is
`node_id(32) + signature(64)`; the signature covers the broadcast digest

```
SHA-256( b"mycelium-emergency-broadcast-v2:"
       ‖ broadcast_id (16)      // the envelope's message_id
       ‖ originator  (32)
       ‖ level        (1)
       ‖ signed_at    (8 LE)
       ‖ message_len  (4 LE)
       ‖ message )
```

so an approval cannot be replayed under a new envelope id, reused by another
originator, promoted to a higher level or re-dated. A receiver counts an entry
only when it holds an identity key for that NodeId, the key hashes to the id,
the signature verifies, and the co-signer's trust exceeds 0.8; three distinct
such entries are required, and at most 16 entries reach the trust and
signature checks — entries whose identity key the receiver does not hold are
dismissed by an indexed lookup first, so padding a list cannot hide genuine
approvals behind it (ADR-010, ADR-013). Identity keys are recorded by the
ingress paths that already verify them against the NodeId.

**Freshness.** A broadcast dated more than 300 s ahead of the receiver's clock,
or raised more than 3600 s ago, is refused — the rule §8.4 applies to signed
DHT records, and for the same reasons. This is what bounds replay: a captured
alert stops verifying, instead of the bound resting on a dedup cache.

**Addressing.** A broadcast whose envelope destination is not `NodeId::ZERO`
is refused. Such a copy verifies — the destination is in neither the digest
nor the signatures — but it is not routed away, and forwarding would preserve
a destination that makes every downstream node unicast it back instead of
flooding it, leaving the genuine broadcast behind it looking like a duplicate.
The same rule applies to channel messages (ADR-013).

**Flood dedup.** A broadcast is remembered only **after** it has been
accepted, and is keyed on the digest above rather than on the envelope's
cleartext `message_id`. A copy that brings nothing new is dropped before any
verification — the entry is proof the work was done — while one that does is
verified and forwarded again, without being reported locally a second time.

"Something new" is reach **per approval list**: an entry holds up to three
`(approval-list digest, reach already forwarded)` pairs, and a copy qualifies
if it reaches further than its own list did, or if it carries a list the entry
has no slot for yet. One figure per entry would not do, because a relay can
deliver a new list with its TTL spent — recording the list while forwarding
nothing — and the copy that could carry it would then look like a duplicate;
and a copy claiming a fourth list must not get past the ceiling by carrying a
higher TTL. Remaining TTL is clamped to the level's own figure in both
directions — 3, 7 or 19 on the wire — which bounds how far any one node sends a
copy onward. It does not bound distance from the originator: the TTL is
unsigned, so a relay can reset it (§9.5).

An entry is dropped by **age** only when both clocks agree it is spent: the
monotonic retention (3901 s — validity plus skew, plus a second for rounding)
has elapsed, *and* the wall clock is more than 300 s past the second at which
its broadcast stops being acceptable. Retention must be monotonic because a
flood's age is measured from arrival, freshness must be wall-clock because it
is measured against a time the originator wrote, and expiring on either alone
lets a clock correction retire an entry whose broadcast is still acceptable —
a replay — or retire one early. Separately, at **capacity** the oldest eighth
is evicted rather than the set being cleared; that is the one way a live entry
can be lost while the node runs, and it is why the sets are kept apart. The
sets are not persisted, so a restart inside a broadcast's validity window lets
it be accepted once more. Channel and emergency
floods use separate sets, and the emergency sets are kept apart per level, so
neither channel volume nor a cheap level-1 flood can evict a co-signed level-3
entry. Remembering an id *before* checking the broadcast let one unverifiable
packet suppress a verified alert; clearing the set let a captured one be
replayed (ADR-013).

**Known gap:** nothing *collects* co-signatures. There is no request protocol
and no approval UI, and `POST /v1/emergency/broadcast` sends an empty list, so
a level-3 broadcast is refused by every receiver. Unusable is the correct
failure direction for a mesh-wide flood, but level 3 is not available until
collection exists. See ROADMAP T-05.

**Priority is queue ordering.** An emergency is sent and relayed at `Alert`
priority, which every transport applies to the queue it already has. BLE,
Wi-Fi Direct, LoRa and Bluetooth Classic share one bounded outbox with three
rules: an alert queues after the alerts already waiting and ahead of all
ordinary traffic, so alerts keep their own order; a full outbox makes room for
an alert by dropping the **oldest ordinary** frame, and sacrifices the oldest
alert only when nothing ordinary is left; and **nothing but a larger alert
batch ever evicts an alert**. Ordinary traffic makes room only from ordinary
traffic: arriving at an outbox that holds enough of it, it displaces the
oldest of it; arriving at one that does not, it is refused outright rather
than taking an alert's place. A batch larger than the whole outbox is refused
whatever its priority, since nothing it could evict would make it fit. A fragmented message
is admitted whole or not at all, so it cannot evict its own fragments, and
LoRa charges duty-cycle airtime only once frames are admitted. The internet
transport has a second channel its writer drains first.

The relay path itself has nothing to order — it sends as it decides — and an
emergency never enters the DTN store, so these queues are the only place
ordering can happen (ADR-014). It does not reach frames already handed to the
platform layer or the operating system.

**Known gap:** the level-2 rate-limit exemption is implemented but nearly
inert, because an originator that clears trust > 0.6 is 1 hop away and already
unlimited. See ROADMAP T-37.

**Size.** An alert is `217 + message_bytes + 96 × approvals` bytes on the
wire, so a critical alert with three approvals is 522 — more than one 512-byte
BLE frame. The BLE transport fragments at the message level (ADR-022), so what
bounds an alert is a whole message rather than a frame — and on BLE that is
**4035 bytes**, not the 4096-byte reassembly limit: sealing a local link costs
61 bytes of counter, header and AEAD tag (§8.4, ADR-021). A node refuses to
raise an alert larger than its narrowest registered transport's message bound
rather than flooding only the links that can carry it, so with BLE registered
the refusal is at 4035.

### 9.6 Multi-device support

**Status: Planned (v0.3).**

The first device holds the master identity. Secondary devices generate their
own keypairs and are authorised by the primary via in-person QR exchange,
producing a signed certificate. All linked devices share one logical mesh
identity, and messages to that identity are delivered to all of them. History
syncs through a CRDT message log with Lamport-timestamp + device-id conflict
resolution, giving eventual consistency across partitions.

## 10. Discovery and onboarding

### 10.1 Beacon

**Status: Implemented.**

```
[4]   magic "MYCO"
[32]  node_id
[1]   node_type          (0 = Phone, 1 = Supernode, 2 = ExternalRadio)
[1]   name_length        (≤ 255)
[*]   display_name
[2]   protocol_version   u16 LE
[1]   battery_level
[2]   neighbor_count     u16 LE
[8]   lamport_clock      u64 LE
[1]   group_discovery_hash_flag
[8?]  group_discovery_hash   (present iff flag = 1)
```

Beacons go to all neighbours with `ttl = 1` — they are never forwarded — every
30 s from phones and 10 s from supernodes. They are also broadcast on LoRa via
`TransportManager::broadcast()` (ADR-008).

A beacon **must** be dropped unless the body's `node_id` equals both the
transport peer and the envelope source. Otherwise a neighbour can inject
contacts and supernode registrations on other nodes' behalf.

### 10.2 Seed phrase groups

**Status: Implemented** (hint, challenge, vouch; nothing wires a passphrase to
a node — see the gaps below).

A community agrees a passphrase. `derive_group_discovery_key(passphrase)` —
HKDF-SHA256 with info `b"MyceliumGroupDiscovery"` — turns it into a 32-byte
group key, and that key, hex-encoded, is what a node's `group_seed` carries
(§14.5). Two values are derived from it at startup, and the node works from
those — the decoded key is wiped, though the hex form stays in the config, and
on the daemon path in the config file (ROADMAP T-08):

| Value | Derivation | Where it goes |
|-------|------------|---------------|
| discovery hint | `SHA-256(key)[..8]` | `group_discovery_hash` in every beacon (§10.1) |
| proof key | HKDF-SHA256 over the key, info `b"MyceliumGroupProof"` | never leaves the node |

The hint is public by construction — eight static bytes in the clear in every
beacon, which anyone in radio range can copy. So a hint matching the local one
is a **hint, not a credential**: it earns a challenge, and the vouch waits for
the answer.

```
verifier  → responder   GroupProofChallenge (0x51)   hint(8) ‖ nonce(32)
responder → verifier    GroupProofResponse  (0x52)   mac(32)

mac = HMAC-SHA256(proof_key, nonce ‖ verifier_node_id ‖ responder_node_id)
```

A correct MAC vouches for the peer at 1 hop, which is the trust foothold
onboarding needs without a prior in-person meeting. Everything else about the
exchange is there to keep that foothold earned (ADR-019):

- **Both ids come from each side's own view, never from the payload.** The
  responder MACs the peer that asked and itself; the verifier checks itself and
  the peer it asked. An answer therefore belongs to one pairing in one
  direction — which is what makes answering a stranger's challenge safe, since
  a MAC collected by challenging a real member carries the collector's id in
  the verifier's place and cannot be moved to the responder's.
- **Both messages are link-local** (§4.2), so the two ids in the MAC are the
  ones the link itself proved (§8.4, ADR-021). A challenge addressed to the
  broadcast id is refused: it would make every member in earshot answer one
  packet.
- **One guess per nonce.** The first response spends it, right or wrong. A
  nonce is valid for 30 s.
- **One attempt per peer per 120 s.** Beacons arrive every 10–30 s; without the
  cooldown an unvouched peer in range would be challenged twice a minute.
- **A per-peer budget of 30 messages an hour** for the exchange, in a book of
  its own (§12). The trust tiers cannot price this path — it runs before any
  trust exists, and the unknown-peer tier of five an hour would be spent on a
  real member before it could answer.
- **Failure is silent and local.** A wrong or missing answer means no vouch and
  nothing on the wire, so a prober learns nothing about how close it was.
- A peer this node already vouches for is not challenged again, and a node in
  no group neither challenges nor answers.

A node that does not implement these payload types never becomes vouched,
which is the correct outcome: it cannot prove possession.

**Known gaps:**

- **No node is ever in a group through the app.** The onboarding screen writes
  the phrase to `SharedPreferences` and `mycelium_node_new` has no parameter
  for it, so `group_seed` is `None`, no hint is advertised and the exchange
  never runs. It is reachable only from a daemon TOML that sets `group_seed`,
  and the passphrase → key step above has no caller in the tree at all
  (ROADMAP T-51).
- **The passphrase is not stretched.** One HKDF pass, no salt, no iterations,
  with eight bytes of the key's hash in every beacon: a guessable passphrase
  can be recovered offline, and a recovered key answers challenges correctly.
  No challenge can close that — the passphrase has to carry real entropy
  (ROADMAP T-52).
- A vouch earned here is stored unsigned, as every local vouch is
  (ROADMAP T-53).
- **A vouch granted before this existed is still granted.** Vouches are
  persisted and reloaded into the trust graph, and a row written by the old
  hash-match path is indistinguishable from one the user made by hand — both
  are unsigned, both name this node as voucher. So an upgrade does not undo an
  unearned vouch, and the holder is not challenged again, because this node
  already vouches for it. Nothing in the tree ever sets `group_seed`, so only
  a hand-configured daemon can have such a row (ROADMAP T-54).

### 10.3 First-launch flow

**Status: Partial.** Generate identity → set display name → enter a seed
phrase **or** scan a contact's QR code → scan for peers on all transports → key
exchange on first match → ready. Four onboarding screens plus the QR scanner.

The seed-phrase branch is a screen, not a feature: the phrase it collects is
stored locally and never reaches the node, so the group it names is never
joined (§10.2, ROADMAP T-51).

## 11. Node roles and power management

### 11.1 Supernode mode

**Status: Partial** — software complete, not validated on router hardware.

Supernodes are the optional backbone: always-on, wired, better antennas. They
serve three functions — routing backbone and subnet bridge, opportunistic
internet gateway, and persistent cache for DTN bundles and prekey bundles.

Enable with `--supernode` or `MYCELIUM_SUPERNODE=1`:

| Parameter | Phone default | Supernode |
|-----------|---------------|-----------|
| DTN storage | 256 MB | 2 GB |
| Per-identity DTN quota | 10 MB | 50 MB |
| Beacon interval | 30 s | 10 s |
| Prekey cache | — | serves `GET /v1/prekeys/{id}` |
| Battery policy | adaptive | always `PowerMode::Full` |
| API bind | `127.0.0.1` | `0.0.0.0` |
| Internet transport | off | on |

A config file loaded alongside `--supernode` is upgraded to at least these
values. The OpenWRT package ships a procd init script, UCI config and a LuCI
status/config app; `scripts/build-openwrt.sh` cross-compiles for
`aarch64-unknown-linux-musl` and `x86_64-unknown-linux-musl` (mipsel needs
nightly `-Zbuild-std`).

**Known gap:** never run on real router hardware (ROADMAP T-15).

### 11.2 Battery-adaptive power modes

**Status: Implemented.** Five modes, chosen from battery level, charge state
and neighbour count. The platform injects battery state over FFI every 30 s.

| Battery | Charging | Neighbours | Mode | Behaviour |
|---------|----------|-----------|------|-----------|
| unknown/wired | — | — | `Full` | All radios, relay for others |
| any | yes | — | `Full` | All radios, relay for others |
| 50–100 % | no | ≤ 2 | `Full` | This node is critical to connectivity |
| 50–100 % | no | > 2 | `Moderate` | Relay on Wi-Fi only; BLE for discovery |
| 20–49 % | no | — | `Light` | Own connections; relay only for direct trust |
| 5–19 % | no | — | `Leaf` | Receive only, no relaying |
| 0–4 % | no | — | `Hibernate` | Disconnect, queue outgoing |

**Cooperative scheduling** (**Partial**): nodes share battery level in the
beacon and the manager prefers higher-battery neighbours when link quality is
similar. Supernodes are always preferred (§7.1).

## 12. Anti-spam and rate limiting

**Status: Implemented.**

Rate limits are a function of the sender's trust distance from *the enforcing
node*. Every relay enforces independently against its own view of the trust
graph — there is no global reputation.

| Trust distance | Messages/hour | DTN relay quota |
|----------------|---------------|-----------------|
| Direct vouch (1 hop) | unlimited | 50 MB |
| 2 hops | 500 | 10 MB |
| 3 hops | 100 | 2 MB |
| 4 hops | 20 | 500 KB |
| Unknown (no path) | 5 | 100 KB |

Enforcement details:

- A violation drops the message. No error is returned — a spammer gets no
  feedback and no oracle.
- Auto-blacklist after 10 violations in a window; blacklist lasts 1 hour.
  Violation counters reset hourly. Two of the books below do not do it: the
  alert book, for the reason given there, and the group-proof book, because
  the peer it would blacklist is the one that may be trying to join — and the
  blacklist is consulted by the *other* books, so an hour of silence for
  exceeding a 30-an-hour onboarding budget would be a punishment out of all
  proportion to work that refusing already bounds.
- A direct neighbour is charged **once** for user data (the previous-hop
  gate), not once per check. Four books are kept apart, because they answer
  different questions — one of them is charged for claims nothing has
  verified, and one prices work asked for before there is any trust to price
  it by:
  - **per peer** — what this link delivered, charged on every message;
  - **per claimed origin** — relayed user data attributed to an
    `envelope.source` that is still unchecked at that point;
  - **per alert originator** — emergency broadcasts, charged only once the
    origin signature verifies, at every level but 2, and however the alert
    arrived. This book does not auto-blacklist: the id it would blacklist is
    the one that might be raising a real alert, and refusing the alert already
    bounds the work (ADR-014).
  - **per peer, for the group-proof exchange** — a flat 30 messages an hour,
    independent of trust, because this is the one ingress path whose whole
    purpose is to run *before* any trust exists: on the unknown-peer tier a
    real member would spend its five an hour on beacons and routing and have
    nothing left to prove itself with (§10.2, ADR-019). Keyed on the transport
    peer rather than on `envelope.source`, so nobody can spend another node's
    allowance and keep it from ever being vouched.

  A sender close enough to deliver directly therefore spends a different
  allowance from one relaying through others. Merging the first two books
  would close that gap and reopen a worse one: five malformed packets naming a
  peer would exhaust that peer's own allowance and silence everything it sent,
  alerts included (ADR-014).
- DTN relay quota is charged only when a bundle is actually stored.

Supernodes sharing violation data to detect coordinated attacks is **Planned**.

## 13. Protocol versioning

**Status: Partial.** The envelope carries `protocol_version` (currently 1).
There is no capability negotiation yet.

The intent is full backwards compatibility: every version understands all
previous versions, new features are additive, and a node never excludes an
older peer. Unknown payload types should be preserved and forwarded unmodified
so new message types can transit old relays. Neighbours should exchange version
and capability lists at discovery and negotiate the highest common set.

Note that the original design assumed Cap'n Proto schema evolution for this.
With a fixed-layout binary codec (§4), compatibility has to come from the
payload-type discriminator and additive payload fields instead — the envelope
header itself is frozen. See ROADMAP T-20.

---

# Part III — Implementation

## 14. Node runtime

### 14.1 Structure

```rust
pub struct Node {
    pub node_id: NodeId,
    pub identity: Identity,
    pub db: Arc<Database>,
    pub transport_manager: Arc<TransportManager>,
    pub ble_transport:      Arc<RwLock<Option<Arc<BleTransport>>>>,
    pub wifi_transport:     Arc<RwLock<Option<Arc<WifiDirectTransport>>>>,
    pub internet_transport: Arc<RwLock<Option<Arc<InternetTransport>>>>,
    pub prekey_cache: Arc<RwLock<HashMap<NodeId, (PrekeyBundle, Instant)>>>,
    routing:          Arc<RwLock<RoutingCoordinator>>,
    session_manager:  Arc<RwLock<SessionManager>>,
    prekey_state:     Arc<RwLock<PrekeyState>>,
    trust_graph:      Arc<RwLock<TrustGraph>>,
    groups:           Arc<RwLock<HashMap<[u8; 32], SenderKeyGroup>>>,
    pending_messages: Arc<RwLock<HashMap<NodeId, Vec<PendingMessage>>>>,
    pending_routes:   Arc<RwLock<HashMap<NodeId, Vec<PendingRouteEnvelope>>>>,
    lamport_clock:    Arc<RwLock<LamportClock>>,
    battery:          Arc<RwLock<BatteryManager>>,
    rate_limiter:     Arc<RwLock<RateLimiter>>,
    cancel_token:     CancellationToken,
    config:           NodeConfig,
}
```

`start()` spawns four tasks, all cancelled by `cancel_token`:

1. **Transport event listener** — `NeighborDiscovered`, `NeighborLost`,
   `DataReceived`.
2. **Beacon broadcaster** — every `beacon_interval_secs`.
3. **Route-discovery sweep** — every 1 s, so the 5 s discovery timeout (§7.3)
   is honoured. It has its own ticker precisely because the maintenance
   interval is too coarse.
4. **Maintenance timer** — every 30 s: expire AODV routes, expire DTN bundles,
   clean up the rate limiter, expire cached prekey bundles, and rotate the
   signed prekey weekly. The rotation interval is coupled to the retained-key
   count and the bundle-cache lifetime (§5.2, ADR-009): the retained keys must
   span the cache, or a peer initiating from a still-valid cached bundle
   fails.

### 14.2 Send pipeline

```
send_message(destination, plaintext, content_type)
  ├─ session exists?       → Double Ratchet encrypt → EncryptedMessage
  │                            → envelope → route_and_send_envelope()
  ├─ prekey cached?        → X3DH initiate → ratchet init → encrypt
  │                            → SessionInit → route
  └─ neither?              → queue in pending_messages
                               → send PrekeyRequest → route
```

On `NeighborDiscovered` the node adds a direct AODV route, processes DTN
actions (deliver local bundles, spray copies) and flushes
`pending_routes[peer]`.

### 14.3 Ingress handlers and checks

| Payload | Handler | Action |
|---------|---------|--------|
| `EncryptedMessage` | `handle_encrypted_message` | Decrypt → store → delivery receipt |
| `SessionInit` | `handle_session_init` | Accept X3DH → decrypt first message → store |
| `PrekeyRequest` | `handle_prekey_request` | Reply with our bundle |
| `PrekeyResponse` | `handle_prekey_response` | Cache bundle → flush `pending_messages` |
| `AodvRreq`/`Rrep`/`Rerr` | `handle_aodv_*` | Update routing table, broadcast/unicast |
| `Beacon` | `handle_beacon` | Create/update contact, merge Lamport clock |
| `Receipt` | `handle_receipt` | Update message status |
| `DtnRelay` | `handle_dtn_relay` | Deliver locally or store for relay |
| `GroupMessage` | `handle_group_message` | Sender-key decrypt → store |
| `SenderKeyDistribution` | `install_sender_key` | Install key, merge roster |
| `ChannelMessage` | `handle_channel_message` | Verify subscription → store → flood |
| `EmergencyBroadcast` | `handle_emergency_broadcast` | Freshness → origin signature → trust/co-signature gate → remember → flood |

The checks below are conformance requirements. Each one closes an attack that
a plain reading of the protocol allows:

- **Identity binding** — drop `PrekeyResponse` (direct or cached while
  forwarding), `SessionInit`, `SessionReject` and `EmergencyBroadcast` unless
  `SHA-256(identity_key) == envelope.source`. Other handlers in the table
  above carry no key to bind: `PrekeyRequest`, for instance, has an empty
  body.
- **Authenticated origin** — an `EmergencyBroadcast` is dropped unless its
  signature verifies over the alert *and* its approval list, checked before
  the trust gate, which scores a claimed id rather than the sender (§9.5,
  ADR-014).
- **Authenticated rejection** — a `SessionReject` is acted on only if its
  signature verifies under that key *and* its `init_transcript` is the one
  recorded for the `SessionInit` awaiting confirmation (§5.2, ADR-012).
- **Non-destructive session accept** — the first message enclosed in a
  `SessionInit` must decrypt before the new session replaces an existing one; a
  `SessionInit` without a message is refused when a session exists, and refused
  outright if it names a one-time prekey; a non-empty nested payload that is not
  an `EncryptedMessage` is refused rather than treated as message-less; replays
  of a known message id are ignored (§5.2, ADR-015).
- **Rejection only without a session** — a `SessionInit` we cannot accept draws
  a `SessionReject` only when we hold no session with that peer; otherwise
  silence, and the initiator recovers by handshake timeout (§5.2, ADR-015).
- **One answer per handshake** — an init whose binding is already on either
  record installs nothing and draws no rejection, before any DH. Keyed on the
  binding, which covers whether the init carries a message, so neither
  substituting the nested message nor stripping it makes an answered handshake
  answerable again (§5.2, ADR-015).
- **The enclosed message is the first of its chain** — an init carrying any
  other message of that chain is refused before the derivation, so a relay
  cannot reorder one into it and have the handshake answered on the wrong
  message (§5.2, ADR-007, ADR-015).
- **Simultaneous initiation** — if a `SessionInit` arrives from a peer we
  initiated with in the last 60 s, the node with the **lower NodeId** keeps its
  session; the other side's first message is still decrypted (ADR-007). It no
  longer decides whether to reject: that is the rule above.
- **Duplicates** — an `EncryptedMessage` or DTN delivery for an already-stored
  message id must not touch the ratchet; re-send the delivery receipt instead.
- **Beacons** — body `node_id` must equal the transport peer *and* the envelope
  source.
- **Receipts** — accepted only from the recipient of one of our outgoing
  messages.
- **Sender keys** — only inside pairwise-encrypted `SYSTEM` messages (§4.2).
- **Rate limiting** — charge a direct neighbour once for user data; keep the
  per-peer, per-claimed-origin and per-alert-originator books separate (§12);
  charge an emergency to its originator only after the origin signature
  verifies, at every level but 2; charge DTN quota only on store; reset
  violation counters hourly.
- **Emergency freshness and dedup** — refuse a broadcast dated beyond the
  300 s skew tolerance or raised more than 3600 s ago; remember it only after
  it is accepted, keyed on its digest, never on the envelope id (§9.5,
  ADR-013).
- **Flooding** — a channel message or emergency broadcast is accepted only
  when its destination is `NodeId::ZERO`; floods skip the originator,
  ourselves and the previous hop; RERR rebroadcasts skip the hop they came
  from. A flood is deduplicated on a digest of the message, entries expire by
  age rather than the set being cleared, and a copy that reaches further than
  the one already seen is forwarded again. Remaining TTL is clamped on receipt
  and on forwarding: to 20 for a channel message, and to its level's reach for
  an emergency — 3, 7 or 19 on the wire for levels 1, 2 and 3, since reach
  counts the receiving nodes and the first transmission is the first hop
  (§9.5).
- **DTN** — a `DtnRelay` for another node always reaches `handle_dtn_relay`,
  which stores it with the wire copies/TTL when no route exists. All three
  local-delivery paths funnel through `finalize_incoming_message()`
  (store → `MessageReceived` event → delivery receipt), with `SYSTEM` messages
  dispatched to `install_sender_key` instead of being stored.

### 14.4 Group operations

`create_group`, `add_group_member` and `remove_group_member` are `Node`
methods; REST and FFI both delegate to them. Adding sends our sender key and
roster to every member as a `SYSTEM` message over the pairwise session;
removing rotates our key and names the member in `removed` (§5.4, ADR-007).

### 14.5 Configuration

```rust
pub struct NodeConfig {
    pub data_dir: String,                  // "./mycelium-data"
    pub display_name: String,              // the *initial* name; the live one
                                           // is on the node (§17.4, T-49)
    pub node_type: NodeTypeConfig,         // Phone | Supernode
    pub transports: TransportConfig,       // per-transport enable flags
    pub dtn: DtnStorageConfig,             // 256 MB / 10 MB / 72 h / 8 copies
                                           // ttl_hours also sets the handshake
                                           // deadline: 2 × it, never under
                                           // 2 × 72 h (§5.2)
    pub beacon_interval_secs: u64,         // 30 phones, 10 supernodes
    pub api: ApiConfig,                    // bind, port, enabled, auth_token
    pub group_seed: Option<String>,        // group discovery key, 32 bytes
                                           // hex — not the passphrase
                                           // (§10.2, T-51). Anything else
                                           // is logged and ignored
    pub plugins: Vec<PluginConfigEntry>,   // not yet read — ROADMAP T-13
}

pub struct InternetTransportConfig {     // transports.internet
    pub listen_port: u16,                // 9736
    pub bootstrap_nodes: Vec<String>,    // "ip:port" entries
    pub max_connections: usize,          // 64, enforced (§8.4, ADR-011)
}
```

CLI and environment (flags win over environment):

```
mycelium-node [OPTIONS] [CONFIG_FILE]
  --supernode        Supernode mode (§11.1)
  --data-dir DIR     Override data directory
  --port PORT        Override API port
  --help

MYCELIUM_CONFIG  MYCELIUM_DATA_DIR  MYCELIUM_DISPLAY_NAME
MYCELIUM_PORT    MYCELIUM_SUPERNODE=1
```

Environment variables exist so containers can configure the daemon without a
config file; the Docker testbed sets `MYCELIUM_DATA_DIR` and
`MYCELIUM_DISPLAY_NAME` per node.

The identity is stored at `<data_dir>/identity.key` with mode 0600, and the
database key is `SHA-256(b"mycelium-db-key:" ‖ identity_bytes)`. That makes the
identity file the root of all at-rest security — see ROADMAP T-08.

## 15. Storage

**Status: Implemented.** SQLCipher, made `Send + Sync` for Tokio by a
`Mutex<Connection>`.

```rust
pub fn open(path: &str, encryption_key: &[u8]) -> Result<Self, StorageError> {
    let conn = Connection::open(path)?;
    conn.execute_batch(&format!("PRAGMA key = x'{}';", hex(encryption_key)))?;
    // read sqlite_master to actually verify the key — cipher_version() does not
    // touch the file, so a wrong key would go unnoticed until the first query
    Self::run_migrations(&conn)?;
    Ok(Database { conn: Mutex::new(conn) })
}
```

A wrong key yields `StorageError::WrongKey`. The build uses the
`bundled-sqlcipher-vendored-openssl` feature so OpenSSL is vendored for
cross-compilation.

### Schema — 13 tables

| Table | Key | Purpose |
|-------|-----|---------|
| `schema_version` | `version` | Migration tracking |
| `messages` | `message_id` | Decrypted message store |
| `sessions` | `peer_id` | Serialized Double Ratchet state |
| `contacts` | `node_id` | Contact directory with trust scores |
| `vouches` | `(voucher_id, vouchee_id)` | Signed attestations |
| `prekey_cache` | `node_id` | Cached remote prekey bundles |
| `our_prekeys` | `prekey_id` | Our signed + one-time prekeys |
| `dtn_store` | `message_id` | DTN bundles |
| `channels` | `channel_id` | Channel metadata |
| `channel_messages` | `message_id` | Channel message store |
| `channel_subscriptions` | `channel_id` | Subscription state |
| `config` | `key` | Key-value store: prekey state, group blobs |
| `dht_marks` | `node_id` | Newest DHT record ever admitted per publisher (ADR-016) |

Design choices: all writes are `INSERT OR REPLACE` (idempotent upserts); status
is `TEXT` for extensibility; group and prekey state are opaque blobs (groups
live in `config` as `group:<hex_id>`, which avoids a schema for a type that is
still changing); BLOB columns convert through `blob_to_array`, which returns a
conversion error rather than panicking on a malformed row.

`MessageStatus`: `Pending`, `Sent`, `DtnPending`, `Delivered`, `Read`,
`Failed`.

## 16. Local API

**Status: Implemented.** `axum` 0.8, JSON, default bind `127.0.0.1:9735`.

### 16.1 Authentication (ADR-006)

Every request requires `Authorization: Bearer <token>`. The WebSocket upgrade
also accepts `?token=<token>`.

The token is generated on first start and written to `<data_dir>/api.token`
(mode 0600) by both the daemon and the FFI layer, or supplied as
`api.auth_token` in the config. A missing or wrong token gets `401` plus
`WWW-Authenticate: Bearer`. A WebSocket upgrade carrying a non-loopback browser
`Origin` gets `403`. CORS allows loopback origins only; preflight needs no
token. The middleware is in `mycelium-api/src/auth.rs`.

Authentication is effectively mandatory: `ApiConfig.auth_token = None` would
disable it, but both the daemon and the FFI layer always populate it — from the
config field or by generating the token file — so no shipped path starts an
unauthenticated server. Loopback binding alone is not a trust boundary on a
phone, where any local app could otherwise drive the node. Per-app tokens
remain future work (ROADMAP T-18).

### 16.2 REST endpoints

38 routes over 31 unique paths, in 9 modules.

| Group | Endpoints |
|-------|-----------|
| `/v1/node/` | `status`, `identity`, `trust` |
| `/v1/messages/` | `POST /`, `GET /{peer}`, `DELETE /{peer}`, `POST /{peer}/read` |
| `/v1/conversations/` | `GET /`, `GET /unread` |
| `/v1/contacts/` | list, add, delete, `{id}/trust`, `{id}/vouch`, `{id}/verify`, `{id}/safety-number` |
| `/v1/groups/` | create, list, `{id}/members` (list/add/remove), `{id}/messages` |
| `/v1/channels/` | create, list, `{id}/subscribe` (POST/DELETE), `{id}/messages` (GET/POST) |
| `/v1/prekeys/{node_id}` | `GET` — cached bundle (supernode cache) |
| `/v1/emergency/` | `broadcast`, `history` |
| `/v1/network/` | `status`, `routes`, `dtn`, `transports`, `peers`, `pending`, `events` |

The `/v1/network/*` group is the diagnostics surface behind the app's debug
panel: AODV table, DTN queue, per-transport status with outbox depth, unified
peer list, pending message/route queues, and a 50-entry event ring buffer.

Notable semantics: `POST /v1/contacts` on an existing contact changes only the
display name — public key, verification state, trust and last-seen are
preserved. Channel subscribe/post return `404` for an unknown channel. IPv4 and
IPv6 bind addresses are both accepted; an unparsable one is an `io::Error`, not
a panic.

### 16.3 WebSocket

Connect to `/v1/ws`. All frames are JSON text, tagged by `type`.

**Client → server:**

| Tag | Payload |
|-----|---------|
| `subscribe` | `protocol_ids: [String]` — filter incoming messages |
| `send` | `destination`, `data`, `protocol_id`, `content_type` |

**Server → client:**

| Tag | Payload |
|-----|---------|
| `message` | `source`, `message_id`, `data`, `protocol_id`, `content_type`, `timestamp` |
| `peer` | `event` (`discovered`/`lost`), `peer_id`, `transport` |
| `network` | `neighbor_count`, `is_connected`, `dtn_queue_size` — pushed every 5 s |
| `receipt` | `message_id`, `status` (`sent`/`delivered`/`read`/`failed`) |
| `channel_message` | `channel_id`, `source`, `message_id`, `data`, `content_type`, `timestamp` |
| `emergency` | `source`, `level`, `message` |
| `send_result` | `destination`, `message_id` on success or `error` — reply to that client's `send` only |

A connection with no `subscribe` receives all events.

`start_server` returns an `ApiServerHandle`. Its `shutdown()` cancels the
`NodeEvent` bridge, the 5 s status broadcaster, every WebSocket session and the
listener, so a stopped server no longer pins the `Node` — which is what lets
the FFI layer restart cleanly.

### 16.4 Protocol IDs

**Status: Partial.** The id travels in the payload and clients can declare
interest, but REST and WebSocket sends currently discard the supplied id and
incoming events hardcode `mycelium.chat.v1`, so a second application would
receive the chat app's traffic. Beacon advertisement of supported protocols is
also absent. See ROADMAP T-29.

A protocol ID is a free-form string, conventionally reverse-DNS
(`mycelium.chat.v1`, `com.example.game`). It rides in the envelope payload
beside the encrypted data, so every application sharing a node gets its own
logical channel over one mesh identity — and gets Mycelium's end-to-end
encryption without implementing any crypto.

| Protocol ID | Purpose |
|-------------|---------|
| `mycelium.chat.v1` | Text and media messaging |
| `mycelium.groups.v1` | Group messaging |
| `mycelium.system.v1` | Internal control messages |

Clients declare the IDs they care about with a WebSocket `subscribe` frame.
Until T-29 lands, treat a node as single-application: the platform claim in §1
is the design intent, not the current behaviour.

## 17. FFI and mobile platform bridges

**Status: Implemented** (64 functions), including the robustness work of
ADR-018 and T-01: every exported function runs inside a panic guard, blocking
calls refuse re-entrancy, and the node handle is reference-counted.

### 17.1 Shape

A single global Tokio runtime (`OnceLock<Runtime>`) bridges synchronous C to
async Rust via `block_on`. Two thread-locals carry per-thread state:
`LAST_ERROR` (retrieved by `mycelium_last_error()`, cleared by
`mycelium_clear_error()`) and `MESSAGE_PLAINTEXTS`, which owns the buffers
behind `MessageInfo.plaintext` — those pointers are valid only until the next
`mycelium_get_messages()` call on the same thread.

Conventions: `0` success, `-1` invalid pointers, `-2` operation failed (check
`last_error`). The `*_dequeue_send` functions return `1`/`0`/`-1`, and `-3`
when a packet exceeds the caller's buffer (the packet is dropped and the
required size returned in `out_data_len`). Two more codes come from the guards
described in §17.4: `MYCELIUM_ERR_PANIC` (`-99`) from any `i32` function, and
`MYCELIUM_ERR_REENTRANT` (`-98`) from one that blocks on the runtime. Functions
returning a pointer, `bool`, `f32` or nothing report both conditions as their
own failure value instead, which only the stored message distinguishes. Every lifecycle function
null-checks;
a second `mycelium_node_start` is a no-op; `mycelium_node_stop` shuts the API
server down through `ApiServerHandle`; transports register via
`replace_transport` so re-registration after a restart never orphans an outbox.

### 17.2 Function groups (64)

| Group | Functions |
|-------|-----------|
| Error | `last_error`, `clear_error` |
| Lifecycle | `node_new`, `node_start`, `node_stop`, `node_id`, `node_free`, `node_get_existing`, `set_node_display_name` |
| Diagnostics | `api_check`, `api_handle_status` |
| Messaging | `send_message`, `get_messages`, `set_message_callback` |
| Conversations | `get_conversations`, `delete_conversation`, `mark_read`, `unread_count`, `total_unread_count` |
| Contacts | `contact_count`, `get_contacts`, `set_display_name`, `get_display_name` |
| Groups | `create_group`, `add_group_member`, `remove_group_member`, `group_member_count`, `get_group_members`, `send_group_message` |
| Trust | `add_vouch`, `trust_score`, `verify_session`, `safety_number` |
| Network | `network_status`, `update_battery` |
| Transport registration | `register_{ble,wifi_direct,lora,lora_configured,bt_classic,internet,internet_configured}_transport` |
| Internet | `internet_connect_to`, `internet_peer_count` |
| Platform → Rust links | `ble_on_link_{up,down,data}`, `wifi_on_link_{up,down,data}` — an address and opaque frames, never a peer id (ADR-021) |
| Platform → Rust events | `lora_on_*` + `lora_report_tx_{success,failure}` (5), `bt_classic_on_*` (3) |
| Rust → platform outbox | `ble_dequeue_send`, `wifi_dequeue_send` (each yields the link to write on), `lora_dequeue_send`, `bt_classic_dequeue_send` |
| Rust → platform link directives | `ble_dequeue_link_event`, `wifi_dequeue_link_event` — `MYCELIUM_LINK_ESTABLISHED` or `MYCELIUM_LINK_CLOSE` |

The C header is `crates/mycelium-ffi/include/mycelium.h`; Dart bindings are
generated from it by `ffigen`.

`mycelium_set_node_display_name` renames the running node: the name reaches
the next beacon and `GET /v1/node/status`, because both read the live value
rather than the configured one. It is not persisted — the name comes from
`mycelium_node_new` (or the daemon's config) on every start.

### 17.3 Platform bridges

The BLE and Wi-Fi Direct bridges carry **links**, not peers: they report an
address they already hold, prefixed by the role carrying it, and relay opaque
frames. Identity is settled by the handshake inside Rust (§8.4, ADR-021), so
no FFI entry point takes a NodeId from the platform, and the bridges keep no
identity bookkeeping of their own. LoRa and BT Classic still hand over an
asserted id — ROADMAP T-47.

**Android** — Kotlin. `MainActivity` hosts the platform channels
(`com.mycelium.ble`, `…wifidirect`, `…daemon`, `…lora`, `…btclassic`) and the
battery bridge. `BleService` is the dual-role GATT stack; `WifiDirectService`
is `WifiP2pManager` + TCP; `LoraService` and `UsbSerialService` bridge external
radios; `BtClassicService` is SPP/RFCOMM; `MyceliumDaemonService` is the
foreground service that keeps the node alive when the UI dies. Permissions:
`BLUETOOTH_SCAN` (with `neverForLocation`), `BLUETOOTH_ADVERTISE`,
`BLUETOOTH_CONNECT`, `ACCESS_FINE_LOCATION`, `CAMERA`.

`WifiDirectService` holds at most sixteen native sockets, counted from the
accept rather than from registration, because a handler is scheduled
asynchronously and a burst would otherwise get a reader thread each before
anything refused it. `LinkBudget` keeps that count, and a slot is a token
rather than a number, so the count is the number outstanding: releasing one
twice frees one slot, and a reader still unwinding from a stopped service
releases a token the stop dropped, which cannot spend a slot the restarted
service holds and cannot drive the count below zero. A slot also carries the
socket it counts, so a stop closes what it drops instead of leaving it to a
handler that has not run, and the generation it was taken in, which answers
"did this service accept this socket". That generation is read where the work
was justified rather than where it runs: when the connection event is seen,
carried through `requestConnectionInfo`'s callback, and fixed for the life of
an accept loop along with the one listener it belongs to. A handler that
waited for a thread across a stop checks that its own token survived before it
registers the link, and `stop()` closes the listener before it tears down what
it accepted. The `AtomicInteger` this replaced leaked in both
directions (ROADMAP T-56, fixed 2026-11-18); `LinkBudget` has the bridges' only
unit tests, run by `make android-test` and counted apart from the workspace's.

**iOS** — Swift. `BleService` is dual-role CoreBluetooth with state
restoration (`CBCentralManagerOptionRestoreIdentifierKey`), `LoraService` is a
GATT client for external radios, `AppDelegate` hosts the platform channels. The
static library is vendored through a local CocoaPods podspec, with
`-force_load` to stop the linker stripping symbols that are only resolved at
runtime via `DynamicLibrary.process()`. `Info.plist` declares the
`bluetooth-central` and `bluetooth-peripheral` background modes, Bluetooth and
local-network usage strings, and the `_mycelium._tcp` Bonjour service.
Deployment target iOS 15.5.

Differences that matter: Android needs a foreground service and scan cycling
(the OS kills scans at 30 s) and negotiates MTU with `gatt.requestMtu(512)`;
iOS needs neither, uses `maximumWriteValueLength(for:)`, and has no Wi-Fi
Direct at all.

**External LoRa module GATT profile:**

```
Service UUID: a1b2c3d4-e5f6-7890-abcd-ef12345678a0
├─ Data TX  (…78a1) Write        — phone → module, outgoing packets
├─ Data RX  (…78a2) Notify       — module → phone, received packets
├─ Config   (…78a3) Read/Write   — frequency, SF, bandwidth, TX power
└─ Status   (…78a4) Read/Notify  — RSSI, SNR, duty cycle, error count
```

**Flutter app.** 49 Dart files: 14 screens (conversations, chat, contacts,
groups, channels, channel chat, settings, debug, 4 onboarding, QR scanner,
verify), 10 services (`ApiClient`, `WsService`, `MyceliumService`,
`NotificationService`, and the BLE/Wi-Fi/LoRa/BT Classic managers), 8 Riverpod
providers, 7 models, 6 widgets, GoRouter with a 6-tab shell and an onboarding
redirect. The REST API is the primary data interface and the WebSocket carries
real-time events; FFI is used only for node lifecycle and radio bridging.

### 17.4 Failure at the boundary

**Status: Implemented** (T-01, ADR-018, ADR-023).

Every exported function's body runs inside one of two guard macros, and a test
over this crate's own source refuses a function that does not use one — or that
uses the non-blocking flavour while its body blocks on the runtime.

- **A panic is caught**, its message and location are stored for
  `mycelium_last_error`, and the function returns the failure value for its own
  return shape: a negative code (`MYCELIUM_ERR_PANIC`, `-99`) for `i32`, NULL
  for a pointer, `false` for `bool`, `-1.0` for `f32`. A `void` function leaves
  only the message. **The process is not aborted** (ADR-018): on current
  compilers an unguarded unwind out of an `extern "C"` function is a defined
  abort rather than undefined behaviour, but the app still vanishes with no
  diagnostic, which is what the guard removes.
- **A blocking call from a thread that is already driving the runtime is
  refused**, before the body runs and so before any side effect. Tokio answers
  such a `block_on` with a panic, not a deadlock. The check is
  `Handle::try_current()`, which is also true in `spawn_blocking` and
  `block_in_place` contexts where blocking is in fact legal; tokio exposes
  nothing that separates them, so the refusal is deliberately conservative
  (ADR-023). The refusal is reported as the shape's failure value:
  `MYCELIUM_ERR_REENTRANT` (`-98`) from an `i32`, `false` from
  `mycelium_node_start`, `-1.0` from `mycelium_trust_score`, and only the
  stored message from the two `void` ones.
- **Out-parameters are unspecified when a function returns its failure value**:
  a panic may have landed part-way through filling one.
- A caught panic is a defect, not a handled condition — the invariant it broke
  is still broken, and the stored message is what makes it reportable.
- **A poisoned lock is recovered, not propagated.** Poisoning only became a
  reachable state once panics stopped ending the process, and every lock in
  this crate guards something a panic cannot leave half-written. Reporting it
  instead would turn one caught panic into an FFI that can never create a node
  again, or into a running API server that `mycelium_node_stop` can no longer
  reach. `mycelium_api_handle_status` therefore reports the server's state
  either way.
- **An unrecognised panic payload is leaked rather than dropped.** Disposing of
  it happens after `catch_unwind` has returned, so a `Drop` implementation that
  panicked there would unwind across the boundary. `panic!`'s own `&str` and
  `String` payloads cannot, and are dropped normally.
- **A rename longer than the beacon field is truncated, not refused.** A
  beacon carries at most 255 bytes of display name (§10.1), and truncation
  lands on a character boundary so no peer shows a replacement character. The
  API reports the full name, so a name over the
  limit means the mesh shows a truncated name while `GET /v1/node/status`
  reports the whole one; that is accepted rather than validated, because
  `mycelium_node_new` and the config file accept the same names and a setter
  stricter than them would be the surprising one. The FFI has no getter for the
  node's own name — `mycelium_get_display_name` reads a *contact's* stored
  name — so the API is where the full value is observable. An **empty** rename
  is refused with `-1`: a beacon's empty name field means "no information" to a
  receiver, which keeps the name it already holds (§10.1), so accepting it
  would change only what the API reports. `mycelium_node_new` still accepts an
  empty name, because then no peer has a previous one to keep.
- **A start and a stop do not interleave.** Both hold one lock for their whole
  duration, so the `started` flag, the node's tasks and the API server's handle
  cannot be left disagreeing by an interleaving — and two concurrent starts
  cannot both bind the API port (ADR-023).
- **The start path commits each piece of state as it becomes true.** A panic
  gives `mycelium_node_start` a third way out, so the "started" flag it takes
  on the way in needs an owner on that exit. The flag is restored if the panic
  lands *before* `Node::start` returns, and kept if it lands after — by then
  the event loop, the beacon and the transports are live, and a retry calling
  `Node::start` again would duplicate all three. Starting the local API server
  is a separate state for the same reason: a panic can leave the node live with
  the server unstarted, so every start attempt, including the "already
  started" one, tries the server if nothing holds its handle. The residual is
  that `Node::start` is not itself transactional — a panic *inside* it leaves
  some tasks spawned and the flag restored, so a retry duplicates them, which
  is ROADMAP T-50.
- **A stop that panics leaves the flag describing the node.** `Node::stop`
  cancels every task part-way through its work, so the two halves of a stop
  need opposite answers; the FFI asks the node whether its tasks are cancelled
  rather than tracking the transition. A stop can only clear the flag, never
  set it, so an unwinding stop that had not yet cancelled anything leaves the
  handle as it found it — startable if it was never started. Once the
  cancellation has happened the node is finished either way, and a later start
  is refused (below).
- **A stopped node cannot be restarted, and says so.** `Node::stop` cancels a
  token nothing resets, so `Node::start` on a stopped node would spawn tasks
  that exit immediately and report success. `mycelium_node_start` refuses with
  `false` instead, before touching the flag or the API server; the way back is
  a new handle, which is a second engine over the same database and therefore
  ROADMAP T-46.

The node handle is reference-counted. Every handle returned by
`mycelium_node_new` and by each `mycelium_node_get_existing` is one reference
that must reach `mycelium_node_free` exactly once; the node is destroyed when
the last one goes, so freeing one handle no longer invalidates another. All
handles to one node share the same address. `mycelium_node_free` also
unregisters the node, so `mycelium_node_get_existing` hands out no further
references to it, and the ADR-016 mark drain runs on every free rather than on
a "last reference" test that two concurrent frees could both lose. Because it
drains, `mycelium_node_free` blocks, so a call from a thread inside the runtime
is refused like any other blocking call — which leaks that reference rather
than dropping a node whose marks were never drained.

## 18. Protocol adapters

Adapters bridge foreign mesh protocols at the **edge**. A Mycelium node running
an adapter can exchange messages with users on the foreign network, but foreign
nodes do not participate in Mycelium routing — no transit routing through a
foreign network. The adapter is a translator at the protocol boundary.

Neither adapter is instantiated by the node today (ROADMAP T-13), and neither
is interoperable with real hardware yet.

### 18.1 Meshtastic — Partial

| | |
|---|---|
| `MeshtasticTransport` | `Transport` + `TransportPlugin`, MTU 237, outbox pattern |
| `NodeIdBridge` | Meshtastic 4-byte node numbers ↔ NodeIds via `SHA-256(b"meshtastic:" ‖ node_num_le)` |
| `ChannelKey` | Placeholder: AES-256 key from `SHA-256(passphrase)` |
| `MeshtasticConfig` | Channel name, local node number, hop limit (default 3) |

| Feature | Meshtastic | Mycelium |
|---------|-----------|----------|
| Node ID | 4-byte number | 32-byte key hash |
| Encryption | AES-256-CTR with a channel PSK | X3DH + Double Ratchet |
| Routing | Flood with hop limit | AODV + DTN |
| Framing | Protobuf | Fixed-layout binary |

**What works:** serial stream framing (`0x94 0xC3` + big-endian length, ≤ 512
bytes) matches upstream; node-ID bridging; MTU and unknown-peer enforcement on
`send()`.

**What does not:** the packet body is a Mycelium-specific 15-byte layout rather
than `ToRadio`/`FromRadio` protobuf, and `ChannelKey` implements none of
Meshtastic's channel crypto (PSK-based AES-CTR with an `id‖from‖0` nonce, and
the `xor_fold(name) ^ xor_fold(psk)` channel hash). See ROADMAP T-16.

### 18.2 Reticulum — Partial

| | |
|---|---|
| `ReticulumPacket` | `[1B flags][1B hops][16/32B addresses][1B context][data]` |
| `HeaderFlags` | header type, context flag, propagation type, destination type, packet type |
| `AddressBridge` | Reticulum 16-byte destination hashes ↔ NodeIds via `SHA-256(b"reticulum:" ‖ dest_hash)` |
| `AnnounceData` | 64 B public key, 10 B name hash, 10 B random hash, 64 B signature, optional app data |
| `HdlcFraming` | flag `0x7E`, escape `0x7D`, XOR mask `0x20` |
| Constants | MTU 500, MDU 465, max hops 128, address length 16 |

**What works:** packet header layout, HDLC framing and announce field order all
match upstream; IFAC-flagged packets are rejected rather than mis-parsed;
`send()` fails for unknown peers instead of emitting a zero destination hash.

**What does not:** data packets carry no source address, so the peer cannot be
derived from them and must come from announces — but announce parsing is never
called from the transport; outbound data to `DEST_SINGLE` is not encrypted;
announces are not signature-verified; there is no path-request support, no IFAC
support and no TCP/UDP/serial I/O. See ROADMAP T-17.

## 19. Build, test and deploy

Full mechanics are in [`CONTRIBUTING.md`](CONTRIBUTING.md). Summary:

| Target | Command | Output |
|--------|---------|--------|
| Host | `make build` / `make test` / `make lint` | Workspace build, tests, `fmt --check` + `clippy -D warnings` |
| Android | `make android` | `libmycelium_ffi.so` for `arm64-v8a`, `armeabi-v7a`, `x86_64` → `android-libs/<abi>/` |
| iOS | `make ios` | `libmycelium_ffi.a` → `ios-libs/` and the CocoaPods vendor dir |
| OpenWRT | `make openwrt` | musl binaries for `aarch64` and `x86_64` |
| Flutter | `make flutter-apk` | Debug APK (Gradle triggers the Rust cross-build) |
| Everything | `make check` | lint + test + `flutter analyze` |

On macOS without an accepted Xcode license, set
`SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk` and
`DEVELOPER_DIR=/Library/Developer/CommandLineTools`.

The Android NDK is pinned to `27.0.12077973`. `scripts/build-android.sh`
prepends the rustup toolchain to `PATH` (Homebrew `rustc` otherwise shadows it)
and sets `CC_*`, `AR_*` and `RANLIB_*` per target for OpenSSL's Makefile.

### Testing strategy

| Layer | Status |
|-------|--------|
| Unit + integration (Rust) | **Implemented** — the workspace suite covers codec round-trips, crypto (including tampering and out-of-order cases), AODV behaviours, DTN, storage, the full node pipeline, group key distribution and the REST/WS API. |
| Mock-transport multi-node | **Implemented** — 3- and 4-node topologies exercise multi-hop AODV, RERR, DTN fallback after partition, and group messaging. |
| Flutter | **Partial** — `flutter analyze` is clean; there is one widget test. |
| Docker mesh testbed | **Partial** — `testbed/` has a Dockerfile, a 5-node linear-chain compose file, a netem script and two scenario files. There is no scenario runner, and containers start with no transport that can reach each other. ROADMAP T-19. |
| Hardware | **Not started** — LoRa, BT Classic and OpenWRT have never run against real hardware. ROADMAP T-15. |
| CI | **Not started** — there is no CI configuration in the repository. ROADMAP T-21. |

Target testbed scenarios, once the runner exists: linear chain (10 nodes),
partition/merge, supernode failure, transport failover, 100-node scale, and a
50-identity Sybil flood.

---

# Part IV — Status

## 20. Compliance matrix

Each row maps a specified feature to its implementation state. Task references
point into [`ROADMAP.md`](ROADMAP.md).

| § | Feature | Status | Notes |
|---|---------|--------|-------|
| 2 | Rust core + mobile client | **Implemented** | Flutter, not native UI toolkits |
| 2.3 | Standalone daemon + local API | **Implemented** | ADR-001, ADR-002, ADR-004 |
| 4 | Envelope + 20 payload types | **Implemented** | Custom binary codec |
| 4.3 | Compact LoRa frame | **Implemented** | Defined and tested; not yet used by the transport (T-12) |
| 5.1 | Ed25519/X25519 identity | **Implemented** | Device-bound, NodeId ↔ key binding enforced |
| 5.2 | X3DH | **Implemented** | SPK + OTP issued once, signature verified, rotated SPKs retained, stale bundles rejected and recovered (ADR-009). The init's own bytes are in the derivation, a handshake is answered once, and a prekey is retired only on authentication (ADR-015) |
| 5.3 | Double Ratchet | **Implemented** | Transactional decrypt, bounded skips, ratchet state durable before transmit, key material zeroized |
| 5.4 | Group encryption | **Implemented** | Sender keys over pairwise sessions (ADR-007), not an MLS tree. No admin model, and any member can forge messages attributed to another (T-24) |
| 5.5 | Safety numbers | **Implemented** | 60-digit, symmetric, verify flow in the app |
| 6.1 | Web of Trust | **Partial** | BFS with decay; the vouch signature is defined and implemented but no path writes or checks one (T-53) |
| 6.2 | Sybil resistance | **Implemented** | Trust-gated rate limits + blacklisting; the one vouch that needs no meeting is earned by proof of possession (§10.2, ADR-019) |
| 6.3 | Threshold revocation | **Planned** | v0.4 |
| 7.1 | AODV | **Implemented** | Supernode + direct-link preference, storm-free RERR, one shared discovery attempt per destination on a 1 s sweep |
| 7.2 | DTN spray-and-wait | **Implemented** | Copies/TTL on the wire (ADR-005), quotas, origin-aware eviction, persisted origin + spray history |
| 7.4 | Geographic hash overlay | **Planned** | v0.4 |
| 8.1 | BLE | **Implemented, untested** | Dual-role GATT, fragmentation, write queue, Android + iOS. Peer identity proved by ADR-011's handshake over the frame layer, NodeId derived from the proved key (ADR-021); never run on a radio (T-15) |
| 8.1 | Wi-Fi Direct | **Implemented, untested** | ADR-003, Android only. Same proved identity as BLE; the bare-NodeId `Hello` is gone (ADR-021); the bridge's sixteen-socket bound is kept in both directions (T-56); never run on hardware (T-15) |
| 8.1 | BT Classic | **Implemented, untested** | Rust + Kotlin SPP + Dart bridge; no hardware test (T-15) |
| 8.1 | LoRa | **Implemented, untested** | Fragmentation, ADR, duty cycle, broadcast beacons (ADR-008); no hardware test (T-15) |
| 8.1 | Internet tunnel | **Implemented** | Keyed mutually authenticated channel with per-frame AEAD, binary framing, enforced connection cap, signed and expiring DHT records, bounded iterative lookup (ADR-011) |
| 8.4 | DHT rollback protection | **Implemented** | Persisted per-publisher high-water marks that outlive record eviction and the process, wildcard refusal in common admission, per-peer record share (ADR-016). Probationary marks are evicted inside the replay window — see §8.4 |
| 8.2 | Transport handoff | **Partial** | First-available selection; no session migration (T-03) |
| 8.4 | Local transport authentication | **Implemented, untested** | BLE and Wi-Fi Direct run ADR-011's handshake over their fragmentation layer; the NodeId is derived from the proved key and no path installs an asserted one (ADR-021). BT Classic and LoRa still do — T-47. Never run on a radio (T-15) |
| 8.5 | Plugin API | **Implemented** | Trait, registry, config, distinct `TransportType` per adapter. Nothing instantiates plugins (T-13) |
| 8.6 | iOS strategy | **Implemented** | Dual-role CoreBluetooth, background restoration, LoRa bridge |
| 9.1 | Content types | **Implemented** | All seven |
| 9.2 | Lamport ordering | **Implemented** | Tick on send, merge on receive |
| 9.3 | Receipts | **Partial** | Recipient-only, WS push, UI indicators. Dropped when no route exists, so DTN deliveries are never acknowledged (T-27) |
| 9.4 | Public channels | **Implemented** | Wire types, storage, flooding, 6 REST endpoints, 2 screens. Dedup expires by age and is keyed on the message (ADR-013); the channel `NodeEvent` variant is still open (T-14) |
| 9.4 | Regional channels | **Planned** | Needs the geographic overlay |
| 9.5 | Emergency broadcast | **Partial** | Thresholds enforced, co-signatures verified, origin authenticated over the alert and its approvals, `signed_at` freshness bound, dedup after verification keyed on the digest, reach and rate limiting per level, and alerts ordered ahead of ordinary traffic in every transport's send queue (ADR-010, ADR-013, ADR-014). Nothing collects co-signatures, so level 3 is refused everywhere (T-05) |
| 9.6 | Multi-device / CRDT sync | **Planned** | v0.3 |
| 10.1 | Beacon | **Implemented** | Node type, battery, neighbour count, group hash; LoRa broadcast |
| 10.2 | Seed phrase groups | **Implemented** | Beacon hint, HMAC challenge over a fresh nonce and both node ids, vouch only on a correct answer, link-local, one guess per nonce, own rate-limit book (ADR-019). Nothing wires a passphrase to a node: the app never joins a group (T-51), and the derivation is unstretched (T-52) |
| 10.3 | First-launch flow | **Partial** | 4 onboarding screens + QR; the seed-phrase branch collects a phrase that never reaches the node (T-51) |
| 11.1 | Supernode | **Partial** | CLI, auto-config, prekey cache, `.ipk`, LuCI app. No router hardware test (T-15) |
| 11.2 | Battery management | **Partial** | 5 modes computed and reported, but Moderate/Light share one relay flag and Hibernate does not disconnect (T-30) |
| 12 | Rate limiting | **Implemented** | Per-tier limits, auto-blacklist, wired to the trust graph |
| 13 | Protocol versioning | **Partial** | Version in the envelope; no negotiation (T-20) |
| 16 | Local API | **Implemented** | 38 endpoints, 7 WS event types, bearer auth (ADR-006). Per-app tokens open (T-18) |
| 17 | FFI | **Implemented** | 64 functions, panic-guarded, re-entrancy refused, handle reference-counted (T-01) |
| 18.1 | Meshtastic adapter | **Partial** | Framing + ID bridge; no protobuf, no channel crypto (T-16) |
| 18.2 | Reticulum adapter | **Partial** | Packet/HDLC/announce layout; no I/O, no encryption (T-17) |
| 19 | Docker testbed | **Partial** | Images and compose exist; no runner, no inter-container transport (T-19) |
| 19 | CI | **Not started** | No CI configuration (T-21) |

## 21. Deviations from the original design

The 2026-03 design document made calls that implementation changed. Each
deviation and why:

1. **UI framework.** Flutter/Dart, not Jetpack Compose + SwiftUI. One codebase
   for both platforms; the thin-shell-over-Rust goal is preserved.
2. **Wire format.** Custom fixed-layout binary codec, not Cap'n Proto. The
   `capnp` toolchain was not available in the build environment, and the
   envelope is small and fully fixed-layout, so zero-copy framing bought
   little. The schemas are kept in `mycelium-protocol/schemas/` as
   documentation only. **Consequence:** schema-evolution-based backwards
   compatibility is gone, so versioning has to work differently (§13).
3. **API serialization.** JSON, not protobuf. The API is loopback-local, so
   payload size is not a constraint, and readable frames make third-party
   clients and debugging much cheaper.
4. **Group crypto.** Sender keys, not an MLS tree ratchet. MLS in a
   delay-tolerant, partition-heavy context is a research problem; sender keys
   are adequate below ~20 members, which is the v0.1 target (§5.4).
5. **API authentication.** Mandatory bearer token, not the optional API key the
   design allowed. Loopback binding is not a trust boundary on a phone
   (ADR-006).
6. **Daemon crate layout.** The `mycelium-node` binary lives in
   `mycelium-daemon` because `mycelium-api` depends on the node library
   (ADR-004).
7. **Onboarding.** Both seed-phrase groups *and* QR vouching are implemented;
   the design specified only seed phrases.
8. **Delivery scope.** Features the design deferred — iOS (v0.2), channels
   (v0.2), emergency broadcast (v0.3), protocol adapters (v0.3) — are
   implemented or partially implemented now. Features it put in v0.1 —
   geographic overlay, Wi-Fi Aware, threshold revocation, multi-device — are
   not. The ordering followed what unblocked real two-device testing.
9. **DTN wire fields.** `DtnRelay` carries `copies_remaining` and `ttl_secs`
   so relays can spray onward and honour the originator's TTL (ADR-005).

## 22. Threat model notes and open questions

### What the design does not protect against

- **Traffic analysis.** Source and destination are cleartext in every envelope
  (§4.1). An adversary who can observe the radio learns who talks to whom, when
  and how much. This is a deliberate trade for routing efficiency. Nothing in
  the current design mitigates it.
- **Device seizure.** The database is encrypted at rest, but its key is derived
  from a plaintext identity file on the same device (§14.5). An attacker with
  the filesystem has the messages. See ROADMAP T-08.
- **A malicious relay dropping traffic.** Relays cannot read or forge messages,
  but nothing forces them to forward. DTN spray to `L` relays limits the damage
  probabilistically; there is no accountability mechanism.
- **A nearby node claiming a neighbour's identity on BT Classic or LoRa.**
  BLE, Wi-Fi Direct and the internet transport now prove identity at the
  transport layer: a peer appears only once it has signed a fresh ephemeral
  key and sealed a frame under the channel that key produced, and its NodeId
  is derived from the key it proved (§8.4, ADR-011, ADR-021). Two transports
  were left behind. BT Classic installs whatever id its bridge reports, and
  LoRa has no link layer at all, so a neighbour's id comes from the
  envelope's own `source` field — an assertion by whoever sent the frame.
  Messages stay unreadable and sessions cannot be hijacked (§14.3), but
  traffic for an impersonated node can be swallowed and its routes poisoned
  on those two links — ROADMAP T-47.
- **Compromise of a vouched identity.** Trust is transitive with decay, so a
  compromised well-connected identity inherits standing. Threshold revocation
  (§6.3) is the planned answer and is not built.

### Open questions

1. **NAT traversal for the internet tunnel.** Nodes behind NAT cannot reach
   each other directly. STUN/TURN, or a lightweight rendezvous role for
   supernodes?
2. **Meshtastic integration depth.** Track the stock protocol (fragile across
   firmware releases, but works with hardware people already own), or maintain
   a custom firmware (tighter integration, much narrower reach)?
3. **LoRa regulatory compliance.** Duty cycle and band rules vary by country.
   Should the app enforce limits per region, or surface them and leave
   compliance to the operator? Currently enforced only for the EU 868 MHz
   preset.
4. **Key backup.** Losing the device loses the identity, with no recovery. An
   optional encrypted backup — Shamir shares across trusted contacts — would
   help, but it adds a new place for the key to leak.
5. **Group size ceiling.** Sender keys are O(n) to distribute. At what measured
   group size does that become the binding constraint, and is MLS the answer or
   is a tree of sender keys enough?

---

*This specification tracks the implementation. When behaviour and spec
disagree, the disagreement is a bug in one of them — fix both in the same
change.*
