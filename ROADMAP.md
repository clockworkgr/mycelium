# Mycelium Roadmap

**Last updated:** 2026-11-11 · **Current version:** 0.1 (pre-release)

The companion document is [`MYCELIUM_SPEC.md`](MYCELIUM_SPEC.md), which
specifies the protocol and describes what is built. This document tracks only
what is **not** done. Completed work is not listed here — it is in the spec's
compliance matrix (§20), in [`docs/adr/`](docs/adr/) and in the git history.

## Baseline

Verified on 2026-11-11 against the working tree, after the T-06/07/09/10/11
work:

| Check | Result |
|-------|--------|
| `cargo test --workspace --all-targets` | **397 passed, 0 failed** |
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
ADR-009), T-07 (ratchet/chain durability + zeroization), T-09 (authenticated
internet transport, binary framing, signed DHT records, ADR-011), T-10
(discovery timeout on its own sweep, one attempt per destination), T-11
(origin-aware DTN eviction, persisted origin + spray history). Seven tasks
remain below. Three of them came out of reviewing T-09's ADRs against the
code: T-34 is the defect T-09 fixed, still open on the local transports, and
T-35 and T-36 are defects in the T-06 and T-05 work that the ADRs' own claims
turned out not to hold.

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

### T-05 · Collect emergency level-3 co-signatures

**Area:** `mycelium-node`, `mycelium-api`, Flutter · **Spec:** §9.5 · **ADR-010**

**Verification landed on 2026-11-10.** Co-signer entries are now
`node_id(32) + signature(64)`; the signature covers
`broadcast_id ‖ originator ‖ level ‖ message`, and a receiver counts an entry
only when it holds an identity key for that NodeId, the key hashes to the id,
the signature verifies and the co-signer's trust exceeds 0.8. Contacts now
record real Ed25519 identity keys at the ingress paths that already verify
them. See ADR-010.

**What remains: nothing collects co-signatures.** There is no request protocol,
no approval UI, and `POST /v1/emergency/broadcast` sends an empty list — so a
level-3 broadcast is now refused by every receiver. Unusable is the correct
failure direction for a mesh-wide flood (it was previously forgeable), but
level 3 is unavailable until this is built.

**Acceptance:**
- A wire exchange by which an originator requests approval from trusted peers
  and receives signed co-signatures, with a bounded wait and no amplification.
- An approval prompt in the app showing who is asking, the level and the exact
  message, since a co-signer is vouching for a mesh-wide flood.
- `POST /v1/emergency/broadcast` accepts or gathers co-signatures for level 3
  and returns a clear error when fewer than three are obtained.
- An end-to-end test: four nodes, three approve, the flood is accepted; with
  two approvals it is refused everywhere.

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

### T-34 · Local transport peer identity is asserted, not proved

**Area:** `mycelium-core`, Android Kotlin, iOS Swift · **Spec:** §8.4, §22

The BLE Node ID characteristic (`…7891`) serves a bare 32-byte NodeId and the
Identity characteristic (`…7894`) takes one; Wi-Fi Direct's `Hello` exchanges
the same. No identity key is carried, nothing proves possession of one, and
nothing binds the claim to the connection — so `mycelium_ble_on_peer_discovered`
installs whatever id the platform layer reports. An attacker in radio range can
claim any node's id: `TransportManager` installs a route for it, AODV prefers
the fake neighbour, and that node's traffic is delivered to the attacker and
dropped. Payloads stay encrypted and no session can be established under a
borrowed id (§14.3), so the damage is denial of delivery and route poisoning,
not disclosure.

This is the defect T-09 fixed for the internet transport, and the fix has the
same shape (ADR-011): carry the identity key, prove possession of it against
something fresh and connection-bound, and *derive* the NodeId instead of
accepting one. The local transports need it in a form their platform layers can
carry — the Identity characteristic becomes a key plus a signature over a
channel-binding value rather than an id.

**Acceptance:**
- A peer's NodeId is derived from a proved identity key on BLE and Wi-Fi
  Direct; no code path installs a peer from an asserted id.
- The proof is bound to the connection, so a replayed identity frame
  authenticates nobody.
- Test: a peer that replays a captured identity exchange installs no transport
  peer and no route; one that holds the key succeeds.
- Spec §8.4 and §22 updated, and an ADR for the local-transport handshake.

### T-35 · Unconfirmed-handshake bookkeeping is not maintained

**Area:** `mycelium-crypto`, `mycelium-node` · **Spec:** §5.2, §14.3 · **ADR-009**

A `SessionReject` is unauthenticated, and ADR-009 bounds the damage by acting
only on an *unconfirmed* handshake: the worst a forgery should achieve is one
discarded optimistic session. The bookkeeping that bound holds depends on is
wrong in three places, so a forged reject can do considerably more.

1. `SessionManager::accept_session_with_first_message` installs an
   authenticated responder session — the peer's first message decrypted, so
   only their ratchet could have produced it — without clearing that peer's
   `unconfirmed_handshakes` entry from our own earlier initiation. After a
   simultaneous initiation, a reject therefore passes the "unconfirmed" gate
   and `remove_session` deletes a working, authenticated session, along with
   its stored row and cached bundle.
2. `Node` marks the handshake pending *after* `route_and_send` returns
   (`node.rs`). A reject that arrives before that is ignored, leaving the
   optimistic session installed and its message marked "sent"; worse, a reply
   that arrives first and *confirms* the handshake has its confirmation undone
   by the insertion, so a later forged reject can kill a confirmed session.
3. Messages sent through the existing-session branch are never added to the
   unconfirmed handshake's list, so a reject reports only the first message as
   failed and leaves the rest claiming "sent" though the peer discarded the
   session they were encrypted under.

Found while reviewing ADR-009 against the code during T-09.

**Landed 2026-11-11 (ADR-012).** The bookkeeping above is fixed: accepting an
authenticated session clears the handshake it supersedes and reports the
messages that died with it, the pending marker is registered atomically with
the initiation under the lock that creates the session, every message sent
while a handshake is unconfirmed is recorded against it, and status writes no
longer undo a settled outcome (a send cannot revive a failed message, a
failure cannot overwrite a delivery, and DTN cannot revive either). A reject is
now signed, bound to the init it refuses and to both NodeIds, and a rejection
of an init we did not send is ignored. `content_type` joined the AEAD's
associated data, which also stops a relay retyping any message, and the
handshake payloads refuse trailing bytes, non-canonical prekey flags and
non-canonical X25519 encodings.

**What remains: the signature does not yet make a forgery useless.** Binding
the rejection to a hash of the init's wire bytes does not identify a
handshake, because several inits can be equivalent to the responder while
hashing differently. Each is a way to have the responder sign a rejection the
initiator will act on: accept the altered copy, then replay the original.

1. **Equivalent ephemeral keys.** RFC 7748 §7: for any X25519 public key there
   are other, publicly computable keys that produce the same shared secret —
   `u⁻¹ mod p` among them. Canonical encoding does not help. The mitigation the
   RFC names is to include the public key in the key derivation, so the fix is
   to bind the raw init header into the derivation or into the first message's
   associated data, and to identify the handshake by what the AEAD
   authenticates rather than by a hash of its bytes.
2. **The one-time prekey is consumed before authentication.** A corrupted copy
   burns it; the untouched original then fails and draws a rejection naming
   exactly the transcript the initiator recorded. Prekey consumption has to be
   committed only after the first message authenticates, as session
   installation already is (ADR-009). The empty-init path has the same shape
   and additionally accepts an unknown nested payload type.
3. **Simultaneous-initiation suppression is not durable.** The rule that a
   tie-break winner never rejects keys off a 60-second initiation timer and is
   lost on restart, so a discarded init can be replayed afterwards for an
   actionable rejection. The evidence has to outlive both.

**Acceptance:**
- An init that a responder would treat as equivalent to another cannot be given
  a second identity: the raw ephemeral is bound cryptographically, with a
  reciprocal-key regression test.
- A one-time prekey is spent only once the first message has authenticated, and
  an unknown nested payload type is refused.
- Replay suppression for accepted *and* discarded inits survives a restart and
  does not depend on the initiation timer.
- With all three closed, a forged or provoked `SessionReject` changes nothing:
  no discarded handshake, no dropped bundle, no failed message.
- Tests for each, delivering the altered copy before the original.

### T-36 · Emergency broadcast dedup suppresses valid alerts and allows replay

**Area:** `mycelium-node` · **Spec:** §9.5 · **ADR-010**

Two defects in the dedup set that guards emergency floods, the one message
type that bypasses routing limits:

1. The `message_id` is inserted **before** the trust threshold and
   co-signature checks. A `message_id` is cleartext in every envelope, so any
   node that relays a legitimate critical alert can immediately send a bogus
   copy carrying the same id; the real alert then arrives and is dropped as a
   duplicate. One unverifiable packet suppresses a verified mesh-wide alert.
2. At 10 000 entries the set is **cleared wholesale**. A captured,
   correctly-signed critical alert can then be flooded again under its
   original id and will be accepted, because the signed digest
   (`broadcast_id ‖ originator ‖ level ‖ message`) has no freshness bound. An
   attacker can force the clear by flooding distinct ids first.

Found while reviewing ADR-010 against the code during T-09. Related to T-14,
which covers expiry for the channel-flood dedup set; this one additionally
needs the verification order fixed and a notion of signed freshness.

**Acceptance:**
- An id is remembered only after the broadcast verifies, so an invalid copy
  cannot suppress a valid alert with the same id.
- Accepted ids are retained for as long as a signed broadcast is considered
  fresh, with eviction by age rather than by clearing the set.
- The signed payload carries, or the receiver derives, a freshness bound so a
  captured alert cannot be replayed indefinitely.
- Tests: a forged copy with a legitimate id does not suppress the real alert;
  a replay after eviction pressure is refused.

---

### T-24 · Group messages are forgeable by any member

**Area:** `mycelium-crypto`, `mycelium-protocol` · **Spec:** §5.4

Sender keys are symmetric: every member holds every other member's chain key so
it can decrypt their messages. That also means any member can *encrypt* a
message under another member's chain key and have it attributed to them. The
spec presents groups as authenticated; within a group they are not.

Found by the ADR review on 2026-11-10 against §5.4. This is inherent to plain
sender keys and is the strongest argument for the MLS migration the spec keeps
deferring; a cheaper fix is a per-sender signing key with group messages signed
as well as encrypted.

**Acceptance:** a member cannot produce a message that another member's node
attributes to a third member; a test attempts exactly that and fails to.
Spec §5.4 states the property either way rather than leaving it implied.

### T-25 · DTN eviction leaves rows in the database

**Area:** `mycelium-core`, `mycelium-node` · **Spec:** §7.2

`DtnEngine::remove_bundle` drops the in-memory bundle but nothing deletes the
`dtn_store` row. Evicted and expired bundles therefore come back on the next
start, and the persisted store grows past the configured quota — which also
undermines the eviction policy T-11 just landed.

**Acceptance:** eviction and expiry return the removed ids and the caller
deletes their rows; `dtn_storage_used()` after a restart matches the engine's
accounting; a test fills the store, restarts, and asserts the quota holds.

### T-26 · DTN delivery drops group messages and first-contact prekey requests

**Area:** `mycelium-node` · **Spec:** §7.2, §9.4

`handle_dtn_relay`'s local-delivery path handles only `EncryptedMessage` and
`SessionInit`. A bundled `GroupMessage` or a `PrekeyRequest` carried across a
partition is silently discarded, so group traffic and first contact do not
survive the delay-tolerant path the spec promises for them.

**Acceptance:** inner envelopes are dispatched through the shared ingress path
rather than a private match; tests cover partitioned first contact and
partitioned group delivery.

### T-27 · Receipts are dropped when no route exists

**Area:** `mycelium-node` · **Spec:** §9.3

§9.3 says receipts travel back by the same routing as messages, "so in DTN mode
a receipt can take as long as the original message". They do not: the receipt
send path drops the receipt when AODV has no route, with no DTN fallback. A
message delivered over DTN is therefore never acknowledged to the sender.

**Acceptance:** a receipt with no route enters DTN and is delivered on reunion;
the partition test asserts the sender's message reaches `delivered`.

### T-28 · DTN spray copies are spent before the send is attempted

**Area:** `mycelium-core`, `mycelium-node` · **Spec:** §7.2

`on_neighbor_encountered` decrements `copies_remaining` and records the peer in
`sprayed_to` in the same call that *builds* the actions — before the caller has
touched a transport. The `Err` branch logs "keeping bundle", but the copy is
already spent and the peer is already recorded as a holder. A flaky link burns
the budget of L=8 without delivering anything.

**Acceptance:** a failed transport send leaves `copies_remaining` and
`sprayed_to` unchanged; a successful one updates both. Test: a mock transport
configured to fail, asserting the budget is intact.

### T-29 · Protocol IDs are not carried end to end

**Area:** `mycelium-node`, `mycelium-api`, `mycelium-protocol` · **Spec:** §16.4

§16.4 presents protocol IDs as implemented — the mechanism by which several
applications share one node. They are not: REST and WebSocket sends discard the
supplied id, and incoming events hardcode `mycelium.chat.v1`. Any second client
would receive the chat app's traffic and vice versa, so the platform claim in
§1 does not hold yet.

**Acceptance:** the id is carried through encryption, storage and events, and a
client subscribed to one id never receives another's traffic; or §16.4 is
marked Partial and this task carries the remaining work. (Spec has been marked
Partial pending this.)

### T-30 · Battery power policies are not enforced

**Area:** `mycelium-node` · **Spec:** §11.2

§11.2 tabulates five modes with distinct behaviour. `Moderate` and `Light`
share one unrestricted relay boolean, and `Hibernate` neither disconnects
transports nor queues outgoing sends. The modes are computed and reported but
only two of them change anything.

**Acceptance:** each mode's documented behaviour is enforced and tested, or
§11.2 is reduced to what the code does.

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

### T-31 · External address discovery for DHT records

**Area:** `mycelium-core` · **Spec:** §8.4 · **ADR-011**

A DHT record is a node's signed claim about its own address. A node listening
on the `0.0.0.0:9736` default has no address worth signing, so it publishes
nothing — which is honest, but means the record store only ever holds entries
for nodes configured with a concrete address. Nothing learns the address a peer
actually sees us on.

**Acceptance:**
- A peer reports the socket address it observed us on, and that observation
  feeds the published record.
- Agreement between two or more independent peers is required before an
  observed address is published, so one peer cannot steer our record.
- Test: a node on a wildcard listen address publishes a record carrying the
  address its peers observed, and publishes nothing when the observations
  disagree.

### T-32 · DHT bucket liveness

**Area:** `mycelium-core` · **Spec:** §8.4 · **ADR-011**

Contacts are deliberately kept after a disconnect, because the stored address
is what lets a peer be dialled again. Nothing prunes a contact whose peer is
gone for good, and a full k-bucket drops new entries, so dead contacts can
permanently crowd out live ones.

**Acceptance:**
- A full bucket pings its least-recently-seen contact before refusing a new
  one, and replaces it if it does not answer (standard Kademlia eviction).
- Test: a bucket filled with unresponsive contacts admits a live one.

### T-33 · Dial an unconnected peer through the DHT

**Area:** `mycelium-core` · **Spec:** §8.4 · **ADR-011**

`InternetTransport::resolve` performs a bounded iterative lookup and returns a
peer's address, and nothing calls it. A `send` to a peer with no open
connection fails with `PeerNotConnected` even when the DHT holds a current,
signed record for it, so internet reachability still depends on an explicit
bootstrap or an inbound connection.

Kept separate from T-09 because it changes *when* the transport opens
connections, not how it authenticates them.

**Acceptance:**
- A send to an unconnected peer resolves its address through the DHT, dials it,
  and delivers — subject to `max_connections` and without a dial per message.
- Failed resolutions are negatively cached, so an unreachable peer does not
  trigger a lookup on every send.
- A lookup's own dials do not permanently consume connection slots: a
  connection opened only to ask a DHT question gets a lease or idle eviction.
- Test: three nodes where A and C know only B; A sends to C and it arrives,
  and a send to an unknown id fails without an unbounded lookup.
- Test: repeated lookups do not exhaust `max_connections`.

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
