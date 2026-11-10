# Mycelium Roadmap

**Last updated:** 2026-11-10 · **Current version:** 0.1 (pre-release)

The companion document is [`MYCELIUM_SPEC.md`](MYCELIUM_SPEC.md), which
specifies the protocol and describes what is built. This document tracks only
what is **not** done. Completed work is not listed here — it is in the spec's
compliance matrix (§20), in [`docs/adr/`](docs/adr/) and in the git history.

## Baseline

Verified on 2026-11-10 against the working tree, after the T-06/07/10/11 work:

| Check | Result |
|-------|--------|
| `cargo test --workspace --all-targets` | **307 passed, 0 failed** |
| `cargo clippy --workspace --all-targets -- -D warnings` | **clean** |
| `cargo fmt --check` | **clean** |
| `cd flutter && flutter analyze` | **no issues** |

10 Rust crates (~26.6k lines), 49 Dart files, 38 REST endpoints + 7 WebSocket
event types, 64 FFI functions, 17 wire payload types, 12 database tables.

Everything specified for v0.1 is implemented except the items below. The
remaining work is concentrated in four places: **FFI robustness**, **protocol
hardening of features that already work**, **validation against real
hardware**, and **adapter interoperability**.

## How to read this

Each task has a stable ID (`T-nn`) referenced from the spec, a priority, and
acceptance criteria written so that "done" is not a judgement call. Priorities:

| Priority | Meaning |
|----------|---------|
| **P0** | Blocks a v0.1 release. A correctness, security or crash problem in a shipped feature. |
| **P1** | Needed for v0.1 to be honest about what it claims — validation, observability, completeness. |
| **P2** | v0.2. Real features, but v0.1 is usable without them. |
| **Deferred** | v0.3+. Specified, scoped, not scheduled. |

---

## P0 — Correctness and security

These are the gate on v0.1. Each one is a defect in a feature that is already
shipped and claimed to work.

**Landed 2026-11-10:** T-06 (signed-prekey retention + session rejection,
ADR-009), T-07 (ratchet/chain durability + zeroization), T-10 (discovery
timeout on its own sweep, one attempt per destination), T-11 (origin-aware DTN
eviction, persisted origin + spray history). Five tasks remain below.

### T-01 · FFI robustness

**Area:** `mycelium-ffi` · **Spec:** §17.2

Four distinct problems in the FFI layer, all of which can crash or hang the
mobile app:

1. No `extern "C"` function is wrapped in `catch_unwind`. A panic in Rust
   unwinds across the FFI boundary, which is undefined behaviour and aborts the
   process — users see the app vanish with no error.
2. `block_on` is called in 48 places with no guard against re-entrancy. Calling
   an FFI function from a thread already inside the runtime deadlocks.
3. `mycelium_set_node_display_name` validates its arguments, logs, and returns
   `0` without doing anything. Callers believe the name was set.
4. The node handle is a raw `Box::into_raw` pointer with no reference count, so
   `mycelium_node_get_existing` can hand out a pointer that
   `mycelium_node_free` then invalidates.

Also: `mycelium_api_check` and `mycelium_api_handle_status` are resolved by hand
in Dart rather than through generated bindings, so a signature change will fail
at runtime instead of at build time.

**Acceptance:**
- Every `extern "C"` function body is inside `catch_unwind`; a panic returns the
  error code and sets `last_error` instead of unwinding.
- A re-entrancy guard makes an FFI call from a runtime thread return an error
  rather than deadlock.
- `mycelium_set_node_display_name` either updates the running node's display
  name (requires interior mutability on the config the beacon task reads) or
  returns a distinct "unsupported at runtime" code.
- The handle is reference-counted; `node_free` on an outstanding reference is
  safe.
- `dart run ffigen` regenerated; no hand-written FFI lookups remain.
- A test asserts that a deliberately panicking path returns an error code.

### T-04 · Group-discovery proof of possession

**Area:** `mycelium-crypto`, `mycelium-node` · **Spec:** §10.2

The seed-phrase group hash is 8 cleartext bytes in a beacon, and matching it
earns an automatic vouch. Anyone who overhears one beacon can replay the hash
and be auto-trusted by the whole group — which collapses the Sybil defence
(§6.2) for exactly the population that onboarding is meant to protect.

**Acceptance:**
- Auto-vouch requires a challenge/response proving possession of the derived
  key, not merely knowledge of its prefix.
- A replayed beacon hash alone never produces a vouch.
- Test: a node that knows only a captured hash fails the exchange; a node with
  the passphrase succeeds.

### T-05 · Emergency level-3 co-signer signatures

**Area:** `mycelium-node`, `mycelium-storage` · **Spec:** §9.5

Level 3 floods the entire mesh and bypasses routing rules. It is supposed to
require three co-signers with trust > 0.8, but co-signers are carried as bare
NodeIds and are never signature-verified. Any node can list three trusted
NodeIds it does not control and trigger a network-wide flood.

Blocked on storing contacts' Ed25519 identity keys — the contact record
currently has no key to verify against.

**Acceptance:**
- Contacts persist an identity key; it is populated from prekey bundles and
  vouches.
- A level-3 broadcast carries a signature per co-signer over the broadcast
  content, and all are verified before the flood.
- An unverifiable or insufficient co-signer set is dropped and logged.
- Test: forged co-signer list rejected; correctly signed set accepted.

### T-08 · Identity key at rest

**Area:** `mycelium-daemon`, `mycelium-ffi`, platform · **Spec:** §5.7, §14.5, §22

`<data_dir>/identity.key` is plaintext at mode 0600, and the SQLCipher database
key is `SHA-256(b"mycelium-db-key:" ‖ identity_bytes)`. One file read therefore
yields the identity *and* every stored message. Encryption at rest currently
protects against nothing an attacker with filesystem access cannot bypass.

**Acceptance:**
- On mobile the identity key is held in Android Keystore / iOS Keychain and
  never written to the app's data directory.
- On desktop/OpenWRT, where no keystore exists, the key is encrypted with a
  user-supplied passphrase or the limitation is documented explicitly in the
  spec's threat model.
- The database key is derived through a KDF that does not expose the identity
  key if the database key leaks.
- A migration moves existing plaintext identities without data loss.

### T-09 · Internet transport authentication and framing

**Area:** `mycelium-core` · **Spec:** §8.4

Three problems in one transport:

1. The Hello handshake is unsigned. A node claims a NodeId and is believed, so
   any internet peer can impersonate any node — and `TransportManager` will
   then route that node's traffic to the impostor.
2. `max_connections` is configured but not enforced; an attacker opens
   connections until the node runs out of descriptors.
3. Frames are JSON with byte arrays as decimal number lists. Measured
   expansion is 5.0x, and both `mtu()` and the receiver's `MAX_WIRE_MESSAGE`
   are 1 MiB, so a send at the advertised MTU is rejected and the real ceiling
   is about 210 KB. (The previous text here said "a tenth of the advertised
   65 KB MTU"; both figures were wrong — `mtu()` returns 1 MiB.)

The DHT underneath has matching gaps: no iterative lookup with termination and
timeouts, no TTL or cap on stored records, no record signatures.

**Acceptance:**
- The Hello carries an Ed25519 signature over a server-provided nonce; an
  unverified peer is refused and no route is installed for it.
- `max_connections` is enforced, with the limit covered by a test.
- Framing is binary (length-prefixed), and a payload up to the advertised MTU
  round-trips. `mtu()` and `MAX_WIRE_MESSAGE` must agree after the change.
- DHT lookups terminate deterministically; stored records carry a TTL, a total
  cap and a signature.

---

## P1 — v0.1 completeness

### T-02 · Mobile platform gaps

**Area:** Android Kotlin, Flutter · **Spec:** §17.3

1. The Android GATT server does not handle prepared writes (long writes). A
   central that uses them sends data the server silently drops. Either handle
   them or cap fragments at the ATT MTU for every peer.
2. When the Activity is destroyed while `MyceliumDaemonService` keeps running,
   Rust is never told the BLE peers are gone, so AODV keeps routing through
   dead links until the route expires.
3. The Wi-Fi Direct client does not retry its TCP connect to the group owner;
   one failed connect leaves the group formed but unusable.
4. `android-libs/x86_64/libmycelium_ffi.so` is now produced by
   `scripts/build-android.sh` and `jniLibs.srcDirs` picks it up, so the old
   "Node not initialized" emulator failure is probably fixed — this needs
   confirming on an emulator, or `abiFilters` set explicitly.

**Acceptance:** each of the four confirmed on a device or emulator; (4) either
closed with a verification note or fixed.

### T-14 · Channel events and flood dedup expiry

**Area:** `mycelium-node`, `mycelium-api` · **Spec:** §9.4

`NodeEvent` has no channel variant, so an incoming channel message reaches API
clients as `MessageReceived` — a direct message from the channel poster. The
WebSocket `channel_message` event exists but is not fed from the receive path
for relayed channel traffic. Separately, channel flood dedup never expires by
time, so the dedup set grows without bound on a long-lived supernode.

**Acceptance:**
- `NodeEvent::ChannelMessageReceived` exists and drives the WebSocket
  `channel_message` event; channel traffic never appears as a direct message.
- Flood dedup entries expire on a time basis with a bounded set size.
- Test: a relayed channel message produces a `channel_message` event and no
  `message` event.

### T-15 · Hardware validation

**Area:** LoRa, BT Classic, OpenWRT · **Spec:** §8.3, §11.1, §19

Three transports and one deployment target are implemented, tested in software,
and have never touched real hardware. Until they do, the spec's "Implemented,
untested on hardware" markers must stay, and the README must not claim
otherwise.

- **LoRa** — a real module over BLE GATT and over USB serial: fragmentation and
  reassembly at SF7 and SF12, duty-cycle enforcement, ADR stepping, broadcast
  beacon discovery.
- **BT Classic** — SPP/RFCOMM between two Android phones.
- **OpenWRT** — the `.ipk` installed on an aarch64 router: daemon starts under
  procd, survives reboot, LuCI pages render, a phone reaches the mesh through
  it.
- **Meshtastic / Reticulum hardware** — gated behind T-16/T-17; listed there.
- **Previously claimed complete, with no evidence** — 3-phone multi-hop,
  transport failover on real radios, and BLE/Wi-Fi reconnection walk-tests. The
  old task list marked these done; the only evidence in the repository is
  mock-transport integration tests.

**Acceptance:** a short test report per target recording hardware, firmware
version and observed behaviour, and the corresponding spec markers updated.

### T-19 · Testbed scenario runner

**Area:** `testbed/` · **Spec:** §19

`testbed/` has a Dockerfile, a 5-node linear-chain compose file, a netem script
and two scenario YAML files — and nothing that runs them. Worse, the containers
start with no transport that can reach each other, so the testbed as committed
cannot form a mesh at all.

**Acceptance:**
- Each node's compose entry configures the internet transport with the right
  listen port and bootstrap peers, and a 5-node chain forms a mesh.
- A runner executes `testbed/scenarios/*.yml`, applies the declared netem
  conditions, and exits non-zero on a failed assertion.
- `linear_chain.yml` and `partition_merge.yml` both pass.
- Scenarios for supernode failure, transport failover and a Sybil flood are
  added or explicitly deferred.

### T-21 · Continuous integration

**Area:** repository · **Spec:** §19

There is no CI configuration in the repository. Every quality gate — the four
baseline checks above, cross-compilation for three Android ABIs, iOS, OpenWRT —
depends on someone remembering to run it locally with the right environment
variables. The spec claims the testbed runs on every commit; nothing runs on
any commit.

**Acceptance:**
- A workflow runs `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test --workspace` and `flutter analyze` on push and pull request.
- Android and OpenWRT cross-compiles run at least on the default branch.
- The testbed scenarios run once T-19 lands.
- Branch protection requires the workflow.

---

## P2 — v0.2

### T-03 · Transport session migration

**Area:** `mycelium-core` · **Spec:** §8.2

`TransportManager::send()` picks the first transport that reports the peer
connected. There is no notion of migrating an active session, so a peer moving
from Wi-Fi Direct to BLE is a reconnect with whatever in-flight messages get
dropped or retried — not the seamless handoff the design calls for.

**Acceptance:** link-quality degradation triggers a migration that preserves
in-flight messages; a test degrades one mock transport mid-conversation and
asserts no loss and no reordering beyond what Lamport ordering already permits.

### T-12 · Use the compact LoRa frame for beacons

**Area:** `mycelium-core`, `mycelium-protocol` · **Spec:** §4.3

The 27-byte compact frame is implemented and tested but unused: the LoRa
transport fragments full 106-byte-header envelopes. At SF12's 51-byte MTU that
is roughly a 4x overhead penalty on the most constrained link in the system.

**Scoped to beacons only.** ADR-008's rejected alternative #1 turned the
compact frame down for general traffic: truncated NodeIds collide, a truncated
message id would make receipts reference the wrong message, and every relay
would need an id resolver. None of that applies to beacons, which are never
forwarded (`ttl = 1`) and carry no message id. Widening it beyond beacons
requires superseding ADR-008.

**Acceptance:** LoRa beacons go out as compact frames and are reassembled by a
peer; measured beacon airtime at SF12 drops; general traffic still uses full
envelopes.

### T-13 · Instantiate transport plugins from config

**Area:** `mycelium-core`, `mycelium-node` · **Spec:** §8.5, §18

`NodeConfig.plugins` is parsed and then ignored. Nothing reads it, so no plugin
is ever created and the adapter crates are unreachable dead code from the
node's perspective. The blocker is turning a `Box<dyn TransportPlugin>` into
the `Arc<dyn Transport>` the manager wants, which needs trait upcasting
(MSRV 1.86) or a wrapper type.

**Acceptance:** enabled plugins in the config are instantiated through
`PluginRegistry` factories and added to the manager; a test registers a mock
plugin via config and asserts it carries a routed envelope. Either raise the
MSRV deliberately (recorded in an ADR) or land the wrapper.

### T-16 · Meshtastic interoperability

**Area:** `mycelium-meshtastic` · **Spec:** §18.1

The serial stream framing matches upstream, but the packet body is a
Mycelium-specific 15-byte layout rather than `ToRadio`/`FromRadio` protobuf,
and `ChannelKey` implements none of Meshtastic's channel crypto — no PSK, no
AES-CTR with the `id‖from‖0` nonce, no `xor_fold(name) ^ xor_fold(psk)` channel
hash. The adapter cannot talk to any real Meshtastic device.

**Acceptance:** protobuf `ToRadio`/`FromRadio` encode/decode; channel crypto
matching upstream; a round-trip against a stock T-Beam or T-Echo on the default
`LongFast` channel; interop notes recorded against a named firmware version.

### T-17 · Reticulum interoperability

**Area:** `mycelium-reticulum` · **Spec:** §18.2

Packet headers, HDLC framing and announce field order match upstream, but there
is no transport I/O at all (no TCP, UDP or serial), announce parsing is never
called from the transport, outbound data to `DEST_SINGLE` is unencrypted,
announces are not signature-verified, and there is no path-request or IFAC
support. Peers cannot be derived from data packets, which carry no source
address — they must come from announces.

**Acceptance:** TCP/UDP/serial interfaces with streaming HDLC; announce-driven
peer discovery with signature verification and ratchet awareness;
`DEST_PLAIN` or identity encryption for outbound data; path requests; IFAC;
a message exchanged with a real Reticulum node over a TCP interface.

### T-18 · Per-app API tokens

**Area:** `mycelium-api` · **Spec:** §16.1

One bearer token grants every client full control of the node. The protocol-ID
design (§16.4) assumes multiple applications share a node, so a game client
can currently read every chat message and send as the user.

**Acceptance:** apps register and receive distinct tokens scoped to their
protocol IDs; a token is confined to its own protocols for both REST and
WebSocket; revocation works without restarting the node; the single-token mode
remains the default for the chat app.

### T-20 · Protocol capability negotiation

**Area:** `mycelium-protocol`, `mycelium-node` · **Spec:** §13

The envelope carries a version and nothing acts on it. The original design
relied on Cap'n Proto schema evolution for compatibility; with a fixed-layout
codec that mechanism is gone and nothing replaced it, so the first protocol
change will break older peers.

**Acceptance:** neighbours exchange version and capability lists at discovery
and negotiate the highest common set; unknown payload types are preserved and
forwarded unmodified by relays; a test proves a v1 and a synthetic v2 node
interoperate at v1.

---

## Deferred (v0.3+)

Specified in the spec, scoped, not scheduled. Each needs design work before it
can be broken into tasks.

| Item | Target | Spec | Note |
|------|--------|------|------|
| Multi-device linked chain + CRDT sync | v0.3 | §9.6 | Needs a conflict-resolution design that survives long partitions |
| Geographic hash overlay | v0.4 | §7.4 | Unlocks regional channels (§9.4) and unbounded scale |
| Threshold key revocation | v0.4 | §6.3 | N-of-M voucher revocation, gossiped |
| Wi-Fi Aware (NAN) transport | v0.4 | §8.3 | Android 8+ |
| Reputation staking | v0.4 | §6.2 | Vouching for a bad actor should cost the voucher |
| Supernode violation sharing | v0.4 | §12 | Detect coordinated attacks across relays |
| Ultrasonic audio transport | future | §8.3 | Last-resort bootstrap when radios are blocked |
| Full MLS group ratchet | future | §5.4 | Only if measured group size makes sender keys the binding constraint (§22 Q5) |
| Encrypted key backup | future | §22 Q4 | Shamir shares across trusted contacts |

---

## Repository hygiene

Small items found during the 2026-11-10 review. Not release-blocking.

- **Stale task claims corrected.** The previous task list marked
  `channel_create_screen.dart` and `channel_discover_screen.dart` complete.
  Neither file exists: channel creation is a dialog inside
  `channels_screen.dart`, and there is no discovery screen at all. Channel
  discovery is unbuilt — decide whether to build it or drop it from scope.
- **Live multi-device test claims.** The previous list marked 3-phone
  multi-hop, transport failover on hardware, and BLE/Wi-Fi reconnection
  walk-tests complete. The evidence in the repository is mock-transport
  integration tests. Treat these as unverified on hardware and fold them into
  T-15.
- **Empty `android/` directory.** A leftover from the pre-Flutter native
  Android shell. `.gitignore` still carries four `/android/*` rules for it.
  Remove both.
- **Flutter test coverage** is one widget test. Worth a thin suite over
  `ApiClient` and `WsService` parsing, which is where protocol drift between
  Rust and Dart would show up first.
