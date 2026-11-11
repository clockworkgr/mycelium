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
Decisions that shaped the design are recorded in [`docs/adr/`](docs/adr/) (ADR-001 … ADR-011);
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

Each payload begins with a 1-byte type discriminator. Eighteen types are
defined.

| Byte | Name | Min body | Purpose |
|------|------|----------|---------|
| `0x10` | `EncryptedMessage` | 45 | Double Ratchet header (40) + ciphertext |
| `0x11` | `SessionInit` | 69 | X3DH ephemeral + identity key + encrypted first message |
| `0x20` | `PrekeyRequest` | 32 | Requester's identity key |
| `0x21` | `PrekeyResponse` | 66 | Prekey bundle: SPK + signature + optional OTP |
| `0x22` | `SessionReject` | 33 | Refusal of a `SessionInit`: reason + identity key (ADR-009) |
| `0x30` | `AodvRreq` | 78 | Route request |
| `0x31` | `AodvRrep` | 77 | Route reply |
| `0x32` | `AodvRerr` | 68 | Route error |
| `0x40` | `DtnRelay` | 25 | `message_id` + `copies_remaining` + `ttl_secs` + opaque inner envelope (ADR-005) |
| `0x50` | `Beacon` | var | Node heartbeat (§10.1) |
| `0x60` | `Receipt` | 17 | Delivery/read confirmation |
| `0x70` | `GroupMessage` | 37 | Sender-key-encrypted group message |
| `0x71` | `SenderKeyDistribution` | 68 | Sender key + roster + explicit removals (ADR-007) |
| `0x80` | `ChannelMessage` | 33 | Public channel broadcast |
| `0x81` | `ChannelSubscribe` | 32 | Channel subscription announcement |
| `0x82` | `ChannelUnsubscribe` | 32 | Channel unsubscription |
| `0x83` | `ChannelModeration` | 65 | Signed moderation action |
| `0x90` | `EmergencyBroadcast` | 2 | Tiered emergency alert |

`SenderKeyDistribution` (`0x71`) is valid **only** as the plaintext of a
pairwise `EncryptedMessage` carrying the `SYSTEM` flag. A bare `0x71` envelope
**must** be ignored — accepting one would let any neighbour inject itself into
a group (ADR-007).

`DtnRelay` carries `copies_remaining` and `ttl_secs` on the wire so a relay can
spray further and honour the originator's end-to-end TTL instead of resetting
it (ADR-005).

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
    info = b"MyceliumX3DH",
    len  = 32)
```

A one-time prekey **must** be issued at most once: `PrekeyState::issue_bundle()`
reserves the OTP it hands out, while `bundle()` only peeks. Two concurrent
initiators therefore never share an OTP.

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
`SessionReject` (`0x22`). A reject is unauthenticated by construction — no
confirmed session exists yet to sign it with — so it acts **only** on a
handshake the peer has not confirmed.

A handshake is **confirmed** the moment the initiator successfully decrypts
anything from that peer: only the peer's own ratchet could have produced it.
Until then, a reject discards the unconfirmed session, the cached bundle (in
memory and in storage) and reports the messages sent under it as failed. A
confirmed session **must not** be torn down by a reject, which is what stops a
forgery from killing working traffic. Confirmation is a state, not a deadline:
an elapsed-time cutoff was tried first and was wrong both ways. See ADR-009.

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

Nine info strings provide domain separation. Reusing one across contexts would
let a key derived for one purpose be substituted for another.

| Info string | Purpose |
|-------------|---------|
| `b"MyceliumX3DH"` | X3DH shared-secret derivation |
| `b"MyceliumRatchet"` | Double Ratchet root KDF |
| `b"MyceliumAEAD"` | Per-message AEAD key + nonce |
| `b"MyceliumSafetyNumber"` | Safety number generation |
| `b"MyceliumGroupMK"` | Group message key derivation |
| `b"MyceliumGroupCK"` | Group chain key advancement |
| `b"MyceliumGroupAEAD"` | Group AEAD key + nonce |
| `b"MyceliumGroupDiscovery"` | Group discovery key from a passphrase (§10.2) |
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

**Status: Implemented.**

There is no certificate authority and no key server. Trust comes from
in-person attestation.

- Users **vouch** for each other by scanning a QR code containing the public
  key. A vouch is an Ed25519 signature over
  `b"mycelium-vouch-v1:" ‖ voucher_id ‖ vouchee_id ‖ display_name ‖ timestamp`.
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
relay priority. Vouching for a misbehaving node is intended to damage the
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
| **BLE** | 512 B | ~100 kbps | 10–30 m | **Implemented** — dual-role GATT on Android + iOS |
| **Wi-Fi Direct** | 65 KB | ~50 Mbps | 50–200 m | **Implemented** — Android only (iOS does not expose it) |
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
├─ Node ID  (…7891) Read   — the server's 32-byte NodeId
├─ Data TX  (…7892) Write  — central writes to peripheral
├─ Data RX  (…7893) Notify — peripheral notifies central
└─ Identity (…7894) Write  — client writes its own NodeId to the server
```

The Identity characteristic solves BLE Random Private Addresses: the client
reads the server's NodeId, then writes its own, so both ends have an
address ↔ NodeId mapping despite the addresses differing per direction.

**Peer identity on BLE is asserted, not proved** — `Partial`, ROADMAP T-34.
Both characteristics carry a bare 32-byte NodeId: no identity key, no
signature, nothing bound to the connection. An attacker in radio range can
therefore claim a neighbour's id, and `TransportManager` installs a route for
it, so that node's traffic is delivered to the attacker and dropped and its
AODV routes are poisoned. Payloads stay encrypted (§5.3) and no session can be
established under a borrowed id (§14.3), so this is denial of delivery and
route poisoning rather than impersonation. Wi-Fi Direct's `Hello` is the same
bare id exchange. The internet transport proves identity instead (§8.4,
ADR-011), and the fix here has the same shape.

Fragmentation uses a 1-byte header: `0x01` first, `0x02` last, `0x03` single,
`0x00` middle. Fragment size is `max(negotiated_MTU - 4, 20)`. Android permits
one outstanding GATT operation, so writes go through a sequential queue driven
by `onCharacteristicWrite`/`onNotificationSent`. Connections stagger
500–1500 ms with jitter and retry with exponential backoff (1 s, 2.5 s, 4 s,
max 3).

**Wi-Fi Direct (ADR-003).** `WifiP2pManager` groups plus Bonjour service
discovery and TCP sockets on port 9740. Wire protocol: 1-byte type
(`Hello = 0x01`, `MeshData = 0x02`) + 4-byte big-endian length + payload. TCP
handles segmentation, so no fragmentation layer.

**LoRa (ADR-008).** Messages are fragmented into frames with a 6-byte header
(sender tag u16, fragment id u16, index u8, count u8), sized for the peer's
current spreading factor; the transport MTU is the largest reassembled message
(`LORA_MAX_MESSAGE = 2048`). Reassembly is keyed by (sender tag, fragment id),
bounded to 64 partials, expired after 120 s. Duty cycle is charged per frame
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
`SHA-256(public_key)`. A record is refused if the signature fails, if it is
dated more than 300 s ahead, if it is older than the 3600 s TTL, if it is no
newer than one already held (so a replayed older record cannot roll an address
back), or if the store is full. The store is capped at 4096 records, swept of
expired entries before each insert, and evicts the entry closest to expiry when
at capacity. A record found over the network is subjected to the same checks
and returned only if they pass. A DHT request carries no sender identity: the
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
and useless — external address discovery is ROADMAP T-31. Nothing prunes a DHT
contact whose peer is gone for good, so a k-bucket can fill with dead entries
(ROADMAP T-32). Resolution is available but not automatic: `resolve()` will
find a peer's address through the DHT, and no send path calls it, so a send to
an unconnected peer still fails (ROADMAP T-33). The channel gives
authentication and integrity, not a forward secrecy claim; message
confidentiality is the Double Ratchet's job (§5.3).

**Outbox pattern.** BLE, Wi-Fi Direct, BT Classic and LoRa all follow the same
Rust↔platform shape: `send()` pushes to a bounded `VecDeque` (512 packets;
256 for LoRa), Dart polls it every 50 ms over FFI, and inbound data is injected
back through FFI. A direct send callback is used where the platform supports it.

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
  message id.
- **Regional channels** — **Planned**, dependent on the geographic overlay
  (§7.4).
- **Moderation** — the creator has moderation powers and can delegate.
  Moderators issue signed removal notices (`ChannelModeration`, `0x83`) which
  propagate through the mesh; receiving nodes hide the content. Moderation is
  per-channel, never network-wide.

Floods skip the originator, ourselves and the previous hop.

**Known gap:** an incoming channel message is reported to API clients as a
direct message because `NodeEvent` has no channel variant, and flood dedup
never expires by time. See ROADMAP T-14.

### 9.5 Emergency broadcast

**Status: Partial.**

| Level | Name | Behaviour | Requirement |
|-------|------|-----------|-------------|
| 1 | **Priority** | Boosted priority in relay queues | sender trust > 0.3 |
| 2 | **Urgent** | Bypasses per-identity rate limits | sender trust > 0.6 |
| 3 | **Critical** | Floods the whole mesh, bypasses routing rules | 3+ co-signers with trust > 0.8 |

Thresholds are enforced as specified. Emergency messages carry the sender's
identity — they are deliberately non-anonymous, for accountability — and a
false emergency is intended to incur a trust penalty.

**Co-signatures are verified.** A co-signer entry is
`node_id(32) + signature(64)`; the signature covers
`broadcast_id ‖ originator ‖ level ‖ message`, so an approval cannot be
replayed under a new envelope id, reused by another originator, or promoted to
a higher level. A receiver counts an entry only when it holds an identity key
for that NodeId, the key hashes to the id, the signature verifies, and the
co-signer's trust exceeds 0.8; three distinct such entries are required
(ADR-010). Identity keys are recorded by the ingress paths that already verify
them against the NodeId.

**Known gap:** nothing *collects* co-signatures. There is no request protocol
and no approval UI, and `POST /v1/emergency/broadcast` sends an empty list, so
a level-3 broadcast is refused by every receiver. Unusable is the correct
failure direction for a mesh-wide flood, but level 3 is not available until
collection exists. See ROADMAP T-05.

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

**Status: Implemented** (discovery and auto-vouch; proof of possession is a gap).

A community publishes a shared passphrase. A new user enters it, and
`derive_group_discovery_key(passphrase)` — HKDF-SHA256 with info
`b"MyceliumGroupDiscovery"` — produces a 32-byte key. Its first 8 bytes ride in
the beacon as `group_discovery_hash`. When an incoming beacon's hash matches
the local key, the sender is auto-trusted with an initial vouch, giving the
newcomer a trust foothold without a prior in-person meeting.

**Known gap:** the 8-byte hash is cleartext and replayable, so anyone who
observes one beacon can claim group membership. It needs a challenge/response
proof of possession. See ROADMAP T-04.

### 10.3 First-launch flow

**Status: Implemented.** Generate identity → set display name → enter a seed
phrase **or** scan a contact's QR code → scan for peers on all transports → key
exchange on first match → ready. Four onboarding screens plus the QR scanner.

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
  Violation counters reset hourly.
- A direct neighbour is charged **once** (the previous-hop gate), not once per
  check.
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
| `EmergencyBroadcast` | `handle_emergency` | Trust gate → flood at level 3 |

The checks below are conformance requirements. Each one closes an attack that
a plain reading of the protocol allows:

- **Identity binding** — drop `PrekeyResponse` (direct or cached while
  forwarding) and `SessionInit` unless `SHA-256(identity_key) ==
  envelope.source`.
- **Non-destructive session accept** — the first message enclosed in a
  `SessionInit` must decrypt before the new session replaces an existing one; a
  `SessionInit` without a message is refused when a session exists; replays of
  a known message id are ignored.
- **Simultaneous initiation** — if a `SessionInit` arrives from a peer we
  initiated with in the last 60 s, the node with the **lower NodeId** keeps its
  session; the other side's first message is still decrypted (ADR-007).
- **Duplicates** — an `EncryptedMessage` or DTN delivery for an already-stored
  message id must not touch the ratchet; re-send the delivery receipt instead.
- **Beacons** — body `node_id` must equal the transport peer *and* the envelope
  source.
- **Receipts** — accepted only from the recipient of one of our outgoing
  messages.
- **Sender keys** — only inside pairwise-encrypted `SYSTEM` messages (§4.2).
- **Rate limiting** — charge a direct neighbour once; charge DTN quota only on
  store; reset violation counters hourly.
- **Flooding** — channel and emergency floods skip the originator, ourselves
  and the previous hop; RERR rebroadcasts skip the hop they came from.
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
    pub display_name: String,
    pub node_type: NodeTypeConfig,         // Phone | Supernode
    pub transports: TransportConfig,       // per-transport enable flags
    pub dtn: DtnStorageConfig,             // 256 MB / 10 MB / 72 h / 8 copies
    pub beacon_interval_secs: u64,         // 30 phones, 10 supernodes
    pub api: ApiConfig,                    // bind, port, enabled, auth_token
    pub group_seed: Option<String>,        // group discovery key (hex)
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

### Schema — 12 tables

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

**Status: Implemented** (64 functions); **robustness is Partial** — see ROADMAP
T-01.

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
required size returned in `out_data_len`). Every lifecycle function null-checks;
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
| Platform → Rust events | `ble_on_*` (3), `wifi_on_*` (3), `lora_on_*` + `lora_report_tx_{success,failure}` (5), `bt_classic_on_*` (3) |
| Rust → platform outbox | `ble_dequeue_send`, `wifi_dequeue_send`, `lora_dequeue_send`, `bt_classic_dequeue_send` |
| Direct send callbacks | `ble_set_send_callback`, `wifi_set_send_callback` |

The C header is `crates/mycelium-ffi/include/mycelium.h`; Dart bindings are
generated from it by `ffigen`.

**Known gaps:** no `extern "C"` function is wrapped in `catch_unwind`, so a
panic unwinds across the FFI boundary and aborts the app; `block_on` is
unguarded against re-entrancy from a runtime thread;
`mycelium_set_node_display_name` is a no-op that returns success; the node
handle is not reference-counted, so `node_get_existing` can race
`node_free`. See ROADMAP T-01.

### 17.3 Platform bridges

**Android** — Kotlin. `MainActivity` hosts the platform channels
(`com.mycelium.ble`, `…wifidirect`, `…daemon`, `…lora`, `…btclassic`) and the
battery bridge. `BleService` is the dual-role GATT stack; `WifiDirectService`
is `WifiP2pManager` + TCP; `LoraService` and `UsbSerialService` bridge external
radios; `BtClassicService` is SPP/RFCOMM; `MyceliumDaemonService` is the
foreground service that keeps the node alive when the UI dies. Permissions:
`BLUETOOTH_SCAN` (with `neverForLocation`), `BLUETOOTH_ADVERTISE`,
`BLUETOOTH_CONNECT`, `ACCESS_FINE_LOCATION`, `CAMERA`.

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
| 4 | Envelope + 17 payload types | **Implemented** | Custom binary codec |
| 4.3 | Compact LoRa frame | **Implemented** | Defined and tested; not yet used by the transport (T-12) |
| 5.1 | Ed25519/X25519 identity | **Implemented** | Device-bound, NodeId ↔ key binding enforced |
| 5.2 | X3DH | **Implemented** | SPK + OTP issued once, signature verified, rotated SPKs retained, stale bundles rejected and recovered (ADR-009) |
| 5.3 | Double Ratchet | **Implemented** | Transactional decrypt, bounded skips, ratchet state durable before transmit, key material zeroized |
| 5.4 | Group encryption | **Implemented** | Sender keys over pairwise sessions (ADR-007), not an MLS tree. No admin model, and any member can forge messages attributed to another (T-24) |
| 5.5 | Safety numbers | **Implemented** | 60-digit, symmetric, verify flow in the app |
| 6.1 | Web of Trust | **Implemented** | BFS with decay, signed vouches |
| 6.2 | Sybil resistance | **Implemented** | Trust-gated rate limits + blacklisting |
| 6.3 | Threshold revocation | **Planned** | v0.4 |
| 7.1 | AODV | **Implemented** | Supernode + direct-link preference, storm-free RERR, one shared discovery attempt per destination on a 1 s sweep |
| 7.2 | DTN spray-and-wait | **Implemented** | Copies/TTL on the wire (ADR-005), quotas, origin-aware eviction, persisted origin + spray history |
| 7.4 | Geographic hash overlay | **Planned** | v0.4 |
| 8.1 | BLE | **Implemented** | Dual-role GATT, fragmentation, write queue, Android + iOS |
| 8.1 | Wi-Fi Direct | **Implemented** | ADR-003, Android only |
| 8.1 | BT Classic | **Implemented, untested** | Rust + Kotlin SPP + Dart bridge; no hardware test (T-15) |
| 8.1 | LoRa | **Implemented, untested** | Fragmentation, ADR, duty cycle, broadcast beacons (ADR-008); no hardware test (T-15) |
| 8.1 | Internet tunnel | **Implemented** | Keyed mutually authenticated channel with per-frame AEAD, binary framing, enforced connection cap, signed and expiring DHT records, bounded iterative lookup (ADR-011) |
| 8.2 | Transport handoff | **Partial** | First-available selection; no session migration (T-03) |
| 8.5 | Plugin API | **Implemented** | Trait, registry, config, distinct `TransportType` per adapter. Nothing instantiates plugins (T-13) |
| 8.6 | iOS strategy | **Implemented** | Dual-role CoreBluetooth, background restoration, LoRa bridge |
| 9.1 | Content types | **Implemented** | All seven |
| 9.2 | Lamport ordering | **Implemented** | Tick on send, merge on receive |
| 9.3 | Receipts | **Partial** | Recipient-only, WS push, UI indicators. Dropped when no route exists, so DTN deliveries are never acknowledged (T-27) |
| 9.4 | Public channels | **Implemented** | Wire types, storage, flooding, 6 REST endpoints, 2 screens. Channel `NodeEvent` + dedup expiry open (T-14) |
| 9.4 | Regional channels | **Planned** | Needs the geographic overlay |
| 9.5 | Emergency broadcast | **Partial** | Thresholds enforced, co-signatures verified and replay-bound (ADR-010). Nothing collects co-signatures, so level 3 is refused everywhere (T-05) |
| 9.6 | Multi-device / CRDT sync | **Planned** | v0.3 |
| 10.1 | Beacon | **Implemented** | Node type, battery, neighbour count, group hash; LoRa broadcast |
| 10.2 | Seed phrase groups | **Partial** | Derivation + beacon match + auto-vouch; no proof of possession (T-04) |
| 10.3 | First-launch flow | **Implemented** | 4 onboarding screens + QR |
| 11.1 | Supernode | **Partial** | CLI, auto-config, prekey cache, `.ipk`, LuCI app. No router hardware test (T-15) |
| 11.2 | Battery management | **Partial** | 5 modes computed and reported, but Moderate/Light share one relay flag and Hibernate does not disconnect (T-30) |
| 12 | Rate limiting | **Implemented** | Per-tier limits, auto-blacklist, wired to the trust graph |
| 13 | Protocol versioning | **Partial** | Version in the envelope; no negotiation (T-20) |
| 16 | Local API | **Implemented** | 38 endpoints, 7 WS event types, bearer auth (ADR-006). Per-app tokens open (T-18) |
| 17 | FFI | **Implemented** | 64 functions. Panic guards, callback rework, handle refcount open (T-01) |
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
- **A nearby node claiming a neighbour's identity.** BLE and Wi-Fi Direct
  exchange bare NodeIds, so identity on the local transports is asserted
  rather than proved (§8.4). Messages stay unreadable and sessions cannot be
  hijacked (§14.3), but traffic for the impersonated node can be swallowed and
  its routes poisoned. The internet transport proves identity (ADR-011); the
  local ones need the same treatment — ROADMAP T-34.
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
