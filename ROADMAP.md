# Mycelium Roadmap

**Last updated:** 2026-11-13 · **Current version:** 0.1 (pre-release)

The companion document is [`MYCELIUM_SPEC.md`](MYCELIUM_SPEC.md), which
specifies the protocol and describes what is built. This document tracks only
what is **not** done. Completed work is not listed here — it is in the spec's
compliance matrix (§20), in [`docs/adr/`](docs/adr/) and in the git history.

## Baseline

Verified on 2026-11-13 against the working tree, after T-37's origin
authentication:

| Check | Result |
|-------|--------|
| `cargo test --workspace --all-targets` | **460 passed, 0 failed** |
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
(origin-aware DTN eviction, persisted origin + spray history).

**Landed 2026-11-12:** T-36 (emergency broadcasts are checked before they are
remembered, keyed on their digest, bounded in time by a signed `signed_at`,
and the flood-dedup set expires by age instead of clearing itself — ADR-013).
T-35's bookkeeping half landed the day before (ADR-012); what remains of it is
below.

T-34, T-35, T-37 and T-38 came out of reviewing ADRs against the code: T-34 is
the defect T-09 fixed, still open on the local transports; T-35 is a defect in
the T-06 work; T-37 is what reviewing ADR-010 during T-36 turned up next — an
emergency broadcast's origin is not authenticated at all; and T-38 is how
capacity eviction undoes the rollback protection ADR-011 claims.

**Decided 2026-11-12, not yet implemented.** Every P0 below now has its design
on record: T-37 (ADR-014), T-35's remainder (ADR-015), T-38 (ADR-016), T-14's
row identity (ADR-017), T-01 (ADR-018), T-04 (ADR-019), T-08 (ADR-020) and
T-34 (ADR-021). Each ADR names the task that implements it and flips its own
status in that commit; the acceptance criteria below carry the decisions.

Planned order: **T-37, then T-35, then T-38**, with T-14's migration after —
by severity, since anyone holding the group seed phrase can inject a mesh-wide
alert today, while T-35's residual costs one discarded handshake. The remaining
four (T-01, T-04, T-08, T-34) are designed but unsequenced.

Two standing rules from those decisions: constants are **shapes now, numbers
later** — the DHT publisher quota, the level-1/2 reach limits and the dedup
retention period are to be measured against the testbed (T-19) or hardware
(T-15), not guessed; and the radio features (T-04, T-34) keep "Implemented,
untested on hardware" until T-15's report, however complete the software
tests are.

### T-01 · FFI robustness

**Area:** `mycelium-ffi` · **Spec:** §17.2 · **ADR-018** (design decided
2026-11-12)

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
- Every `extern "C"` function body is inside `catch_unwind`, applied by one
  macro rather than hand-written per function; a panic stores its message in
  the existing `LAST_ERROR` channel and returns the failure value for that
  signature — negative for `i32`, null for a pointer, false for a bool. The
  process is **not** aborted (ADR-018).
- A re-entrancy guard makes an FFI call from a runtime thread return an error
  rather than deadlock.
- `mycelium_set_node_display_name` either updates the running node's display
  name (requires interior mutability on the config the beacon task reads) or
  returns a distinct "unsupported at runtime" code.
- The handle is reference-counted; `node_free` on an outstanding reference is
  safe.
- `dart run ffigen` regenerated; no hand-written FFI lookups remain.
- A test per return shape asserts that a deliberately panicking path returns
  that shape's sentinel and leaves a readable message: a guard that is never
  exercised is not a guard.

### T-04 · Group-discovery proof of possession

**Area:** `mycelium-crypto`, `mycelium-node` · **Spec:** §10.2 · **ADR-019**
(design decided 2026-11-12)

The seed-phrase group hash is 8 cleartext bytes in a beacon, and matching it
earns an automatic vouch. Anyone who overhears one beacon can replay the hash
and be auto-trusted by the whole group — which collapses the Sybil defence
(§6.2) for exactly the population that onboarding is meant to protect.

**Acceptance** (design per ADR-019):
- A beacon match is a hint, not a credential. The verifier sends a fresh nonce
  and the peer must return
  `HMAC(group_discovery_key, nonce ‖ verifier_id ‖ responder_id)`; the vouch
  happens only on a correct response. Both ids are in the MAC so a response
  cannot be lifted into another pairing.
- The beacon hash itself stays static — a rotating hint would not prove
  possession and adds a bucket constant and a clock to agree on.
- Two new payload types, each rate-limited per peer, since answering a
  challenge is work a stranger can ask for.
- The group key's two uses (discovery hash, challenge MAC) are
  domain-separated.
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

**Blocked on T-39 for BLE:** a three-approval alert is 522 bytes against
BLE's 512-byte cap, so collection delivers alerts that cannot traverse the
project's primary transport until that is fixed.

**Acceptance:**
- A wire exchange by which an originator requests approval from trusted peers
  and receives signed co-signatures, with a bounded wait and no amplification.
- An approval prompt in the app showing who is asking, the level and the exact
  message, since a co-signer is vouching for a mesh-wide flood.
- `POST /v1/emergency/broadcast` accepts or gathers co-signatures for level 3
  and returns a clear error when fewer than three are obtained.
- ~~The originator signs the broadcast **including** its co-signer list, so a
  relay can neither strip approvals a downstream node could have verified nor
  pad the list.~~ Landed with T-37 (ADR-014). Note the correction: flood-dedup
  identity stays `broadcast_digest` and must **not** cover the approvals, or
  the originator can pad and re-sign one alert into arbitrarily many accepted
  entries; forwarding for a better-authenticated list is tracked separately,
  per list, under a ceiling.
- An end-to-end test: four nodes, three approve, the flood is accepted; with
  two approvals it is refused everywhere.

### T-08 · Identity key at rest

**Area:** `mycelium-daemon`, `mycelium-ffi`, platform · **Spec:** §5.7, §14.5,
§22 · **ADR-020** (design decided 2026-11-12)

`<data_dir>/identity.key` is plaintext at mode 0600, and the SQLCipher database
key is `SHA-256(b"mycelium-db-key:" ‖ identity_bytes)`. One file read therefore
yields the identity *and* every stored message. Encryption at rest currently
protects against nothing an attacker with filesystem access cannot bypass.

**Acceptance** (designs per ADR-020):
- On mobile the identity key is held in Android Keystore / iOS Keychain and
  never written to the app's data directory.
- On desktop and OpenWRT the OS keyring holds it where one exists (Secret
  Service, macOS Keychain), and a passphrase supplied at start where one does
  not — with no plaintext fallback, since a fallback is what everything would
  use. The daemon refuses to run without one.
- The database has its **own random key**, stored wrapped by the same keystore,
  keyring or passphrase. Neither key is a function of the other, so a leak of
  one yields nothing about the other and the database can be rekeyed without
  touching the identity.
- **No migration.** A data directory written by an older build is refused with
  a message saying to re-onboard; the protocol is `0.1-draft` with no deployed
  nodes, and an in-place re-encryption would hold two copies of a secret on
  disk at the riskiest moment for data that exists only on developer machines.
  Revisit when a node first runs on someone else's device.
- The threat model says plainly that a keyring unlocked by the login session
  protects against a stolen disk, not against code running as that user.

### T-34 · Local transport peer identity is asserted, not proved

**Area:** `mycelium-core`, Android Kotlin, iOS Swift · **Spec:** §8.4, §22 ·
**ADR-011**, **ADR-021** (design decided 2026-11-12)

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

**Acceptance** (designs per ADR-021):
- ADR-011's authenticated-channel handshake runs over the local transports'
  fragmentation layer, rather than a second BLE-shaped proof: one proof format
  and one implementation across BLE, Wi-Fi Direct and internet.
- A peer's NodeId is derived from the proved identity key; `…7891` stops being
  an input and no code path installs a peer from an asserted id. Wi-Fi Direct's
  `Hello` is removed rather than left as a weaker second path.
- The Rust side and both platform bridges land in **one task**, so there is no
  build where a peer is installed from an asserted id and no flag to remember
  to flip. The bridges stop reporting a discovered peer by id and must rebuild
  their address-to-peer bookkeeping around a handshake that completes later.
- Test: a peer that replays a captured identity exchange installs no transport
  peer and no route; one that holds the key succeeds.
- Spec §8.4 and §22 updated. The marker stays "Implemented, untested on
  hardware" until T-15's report — the handshake has to survive real
  reassembly and reconnection churn before it can claim more.

### T-35 · Unconfirmed-handshake bookkeeping is not maintained

**Area:** `mycelium-crypto`, `mycelium-node` · **Spec:** §5.2, §14.3 ·
**ADR-009**, **ADR-012**, **ADR-015** (design decided 2026-11-12)

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

**Acceptance** (designs per ADR-015):
- The raw init header's bytes are an input to the X3DH key derivation, so a
  copy carrying an equivalent ephemeral (`u⁻¹ mod p`) derives a different key
  and its first message does not decrypt. Regression test: `u` and `u⁻¹` must
  not both work.
- A one-time prekey is retired only once the enclosed first message
  authenticates; a message-less init that would spend one is refused, as is an
  unknown nested payload type.
- A rejection is sent only when no session with that peer exists, which
  replaces the 60-second initiation timer and survives a restart because
  sessions are persisted. The cost is accepted: a stale session plus a dead
  bundle recovers by timeout.
- With all three closed, a forged or provoked `SessionReject` changes nothing:
  no discarded handshake, no dropped bundle, no failed message.
- Tests for each, delivering the altered copy before the original.

### T-37 · Emergency broadcasts are not origin-authenticated

**Area:** `mycelium-node`, `mycelium-protocol` · **Spec:** §9.5 · **ADR-010**,
**ADR-013**, **ADR-014** (design decided 2026-11-12)

**Landed 2026-11-13 (ADR-014): the origin is authenticated.** A broadcast
carries the originator's identity key and a signature over the alert *and* its
approval list, verified against `SHA-256(identity_key) == envelope.source`
before the trust gate. A stranger can no longer name a source its neighbours
trust, a relay can no longer strip or pad the approvals, and the id and date
are fixed before collection so co-signatures can be gathered over them
(`draft_emergency` → `emergency_cosign_digest` → `raise_emergency`). Flood
dedup stays keyed on the alert, with reach tracked per approval list under a
ceiling of three.

**Landed 2026-11-13, second half: the levels differ.** Each level has its own
reach, clamped on receipt and on forwarding (4, 8, 20 hops — provisional until
T-19/T-15 measure them; the ordering is the rule), and only level 2 is exempt
from the per-originator rate limit, charged once per alert rather than per
copy.

**Landed 2026-11-13, third: priority.** The two-class relay queue first
decided for this task was withdrawn — it would have made relaying asynchronous
and moved send failures away from the call site that reports them — and
ordering went where the queues already are:
`Transport::send_with_priority` carries an `Alert`, defaulting to `send` so
transports without a queue and older plugins are unchanged. The four platform
transports share one bounded outbox: alerts keep their own order ahead of
ordinary traffic, a full outbox drops the oldest *ordinary* frame for an alert
and refuses ordinary traffic rather than evicting one, and a fragmented
message is admitted whole or not at all. The internet transport drains a
second channel first. None of it reaches frames already handed to the platform
layer.

**T-37 is complete.** What remains of §9.5 is recorded on T-05 (nothing
collects co-signatures) and T-39 (a co-signed alert exceeds the BLE cap), plus
the standing note that the level-2 rate-limit exemption is nearly inert while
an originator clearing trust > 0.6 is 1 hop away and already unlimited. Also noted: the level-2 rate-limit exemption is
implemented but nearly inert, since an originator clearing trust > 0.6 is 1 hop
away and already unlimited — it bites only if the tiers change (ADR-014).

Two related defects, found while fixing T-36:

1. **Nothing authenticates the originator.** Levels 1 and 2 carry no signature
   at all, and `envelope.source` is cleartext and unverified, so any neighbour
   can emit a level-2 "Urgent" claiming a trusted id. It passes the trust gate,
   which scores the id in the packet rather than the peer that sent it, and is
   flooded onward. The sender needs no standing of its own — an unvouched
   stranger gets five messages an hour from the per-neighbour limit, which is
   plenty for one alert. Being vouched (by hand, or auto-vouched because its
   beacon carried a matching group-discovery hash, a hash anyone in range can
   copy — T-04) removes the bound entirely. Level 3 is bound by its co-signatures, which cover
   the originator, so this is levels 1 and 2. T-36 stopped a forgery
   *suppressing* a real alert; it does not stop one being injected.
2. **The levels do not differ in behaviour at all.** `handle_emergency_broadcast`
   floods any accepted broadcast to every peer, while spec §9.5 reserves
   mesh-wide flooding for level 3 and gives level 1 "boosted priority in relay
   queues" and level 2 "bypasses per-identity rate limits". None of those
   three distinctions is implemented: every level floods, nothing consults the
   level when queueing a relay, and the per-originator rate limit is skipped
   for *all* emergency levels (it is charged only for `EncryptedMessage`,
   `GroupMessage` and `ChannelMessage`) while the per-neighbour limit applies
   to all of them. So the only thing a level selects today is its trust
   threshold. Code and spec disagree; which one is wrong is a design
   decision, since a level-1 alert addressed to `NodeId::ZERO` reaches nobody
   without a flood.

**Acceptance:**
- ~~An emergency broadcast carries the originator's `identity_key(32)` and a
  `signature(64)`, verified against `SHA-256(identity_key) ==
  envelope.source` before the trust gate.~~ Landed 2026-11-13.
- ~~The signature covers its own digest over the alert and the approval list,
  while dedup stays keyed on the alert; a copy with a different authenticated
  list is forwarded again only under a ceiling.~~ Landed 2026-11-13, with
  reach tracked per list rather than per alert. This is the half T-36 could not close: a receiver
  cannot distinguish an approval it cannot verify from one invented on the
  spot. No circularity, since a co-signer signs the alert digest and the
  originator signs last, over the approvals it collected — which means a
  level-3 alert cannot be signed until T-05's collection has finished.
- ~~An originator with no identity cannot raise an alert.~~ Structural:
  `Node::raise_emergency` signs with the node's own identity.
- ~~Level 1 reaches less far than level 2, which reaches less far than level 3;
  level 2 alone is exempt from the per-originator rate limit.~~ Landed
  2026-11-13.
- ~~Level 1 gets relay priority by ordering within the send queue each
  transport already has.~~ Landed 2026-11-13, with tests that an alert queued
  behind ordinary traffic leaves first and that a full outbox drops ordinary
  traffic rather than the alert.
- Tests: a level-2 alert forged under a trusted id is dropped; a genuine one
  is accepted; the flood scope per level is asserted.

---

### T-38 · DHT record eviction undoes the rollback protection

**Area:** `mycelium-core` · **Spec:** §8.4 · **ADR-011**, **ADR-016**
(design decided 2026-11-12)

ADR-011 states that a replayed old address cannot displace a current one:
`store_record` refuses a record no newer than the one it holds. That rule
depends on *holding* the current record, and capacity eviction throws it away.
At `max_records` the store drops whatever is closest to expiring and admits
the newcomer, so a peer can fill it with records for identities it generates
itself — a record is self-signed, and identities are free — evict a victim's
current record, and then replay that victim's older, still-fresh record. It is
accepted, and lookups answer with the stale address.

The consequence is the one ADR-011 exists to prevent: traffic for the victim
sent to an address it no longer holds, chosen by the attacker.

Found by reviewing ADR-011 against the code during T-36. The eviction policy
and the rollback rule need to be reconciled: a high-water mark per NodeId that
outlives the record, admission bounded per publisher so one identity cannot
fill the store, or both.

**Acceptance** (designs per ADR-016 — both halves, not either):
- A record for a wildcard address (`0.0.0.0`, `::`) is refused in
  `store_record`, not only in the publish path. Today the internet transport
  declines to sign one while a peer's correctly signed wildcard record is
  admitted and served to `FindValue`, where nothing can dial it (ADR-011's
  appended note).
- A persisted `NodeId → newest published_at` table outlives the record, so a
  record older than one ever held for that id is refused whether or not that
  record is still resident. **A mark inside the replay window is never
  evicted**: when the table is full, a publisher it has never seen is refused
  instead. That inversion is the decision, because identities are free — a
  per-publisher quota does not survive an attacker rotating keypairs, and an
  evictable table inherits the attack it was meant to stop. Test rotating
  publishers explicitly.
- Admission is still bounded per publisher, as fairness rather than as the
  rollback defence: one identity must not crowd out records for peers the node
  actually talks to.
- Admission order is fixed and each refusal is tested: signature and NodeId
  binding, freshness, wildcard address, high-water mark, publisher quota,
  capacity.
- Tests: eviction pressure followed by a replay of an evicted record is
  refused; a store filled by one publisher still admits records from others.

---

### T-39 · A co-signed emergency alert does not fit BLE

**Area:** `mycelium-core`, `mycelium-protocol` · **Spec:** §8.4, §9.5 ·
**ADR-014**

The BLE transport caps a message at 512 bytes and enforces it by refusing the
send (`TransportError::ExceedsMtu`). A critical alert carrying three approvals
is larger than that:

```
wire size = 217 + message_bytes + 96 × approvals

  217 = 106 envelope header
      + 111 body overhead: type(1) level(1) signed_at(8)
             identity_key(32) signature(64) msg_len(4) count(1)
   96 = one co-signer entry: node_id(32) + signature(64)   (ADR-010)
```

Against 512 that leaves **7 bytes of message with three approvals** and **295
with none** — where before T-37's key and signature it was 391. A
three-approval alert carrying "evacuate sector 7" is 522 bytes, which is the
figure this task is usually quoted with, but the constraint is the formula, not
that example. The Rust BLE transport has no message-level fragmentation — the 1-byte
fragment header in spec §8.4 is the platform layer's GATT-write framing, below
this cap — so an oversized alert simply does not traverse BLE.

Nothing collects co-signatures yet (T-05), so the three-approval case is
latent and becomes live the moment collection lands; the long-message case is
live now. Found by reviewing T-37's size against the transports.

**Mitigated, not fixed (2026-11-13):** `Node::raise_emergency` refuses an
alert larger than the narrowest transport the node has registered
(`TransportManager::min_mtu`) and the API returns 400, so an originator learns
instead of the mesh truncating silently. A relay that cannot pass a flood on
logs it. Neither makes the alert fit.

**Acceptance:**
- A critical alert with three approvals and a 200-byte message traverses BLE,
  by message-level fragmentation in the transport or a smaller co-signer
  entry — the choice decided in an ADR, with the reassembly limits stated.
- A send that cannot be delivered for size is reported, not discarded, on
  every flood path (landed with T-37 for the emergency paths).
- Tests: the worst-case alert round-trips over the BLE transport's own send
  path; a fragment lost mid-reassembly does not strand the rest.

---

### T-40 · LoRa transport does not keep ADR-008's guarantees

**Area:** `mycelium-core`, platform bridges · **Spec:** §8.3 · **ADR-008**

Four defects found by reviewing ADR-008 against the code during T-37, none of
them caused by that work:

1. **The spreading factor never reaches the radio.** Per-peer SF affects
   fragmentation and airtime accounting only; nothing carries it through the
   outbox and FFI bridge, so ADR-008's discovery-SF behaviour is unimplemented
   and a receiver's settings are never coordinated.
2. **Peer expiry runs only on incoming traffic.** A silent radio keeps dead
   peers indefinitely instead of the 300 s ADR-008 states, so routing keeps
   offering them.
3. **Reassembly does not enforce the 2048-byte limit.** 47 valid 45-byte
   fragments produce a 2115-byte message; the cap is documented but never
   checked against accumulated bytes.
4. **A fragment-id collision can produce a complete corrupted message.**
   ADR-008 says colliding sender tags and ids cause a drop; two messages
   sharing tag, id and fragment count can instead combine into something whole
   and wrong, which nothing at this layer detects.

**Acceptance:**
- SF travels with each frame to the platform layer, and a receiver is told
  which to listen on; test the discovery-SF path end to end.
- Peer and partial-message expiry run from periodic maintenance, not only on
  receipt; test that a silent peer ages out.
- Reassembly refuses a message whose accumulated fragments exceed the limit,
  before storing more payload.
- Either fragment reassembly is integrity-checked, or ADR-008 states which
  layer is responsible for detecting a corrupted reassembly and why that is
  sufficient.

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
for relayed channel traffic. Channel flood dedup no longer grows without
bound: entries expire by age and the set evicts its oldest rather than
clearing itself (landed 2026-11-12 with T-36, ADR-013).

Separately, `store_channel_message` is an `INSERT OR IGNORE` keyed on the
envelope's `message_id`. A forged copy stored first therefore keeps the row,
and the genuine message's content never appears in local history — even though
the flood now carries it onward, because dedup is keyed on a digest of the
message rather than its id. This half is a suppression defect of the same
class as T-36 and is worth weighing as P0 when this task is scheduled; it is
bounded only by channel messages being unauthenticated in the first place, so
anyone can post anything under any source id.

The handler also discards the result of `store_channel_message`, so a storage
failure is silent: a message for a channel whose `channels` row is missing
hits the foreign key and vanishes with nothing in the logs. Not reachable
through the REST API, which calls `ensure_channel_exists` before subscribing.

And because a channel message carries no signed date, its dedup entry is a
plain 900 s bound rather than a validity window (ADR-013): once it expires the
same captured message is accepted, reported to API clients and flooded again.
A freshness bound a relay can rewrite is not a bound, so this needs the
originator signature too.

**Acceptance:**
- `NodeEvent::ChannelMessageReceived` exists and drives the WebSocket
  `channel_message` event; channel traffic never appears as a direct message.
- ~~Flood dedup entries expire on a time basis with a bounded set size.~~
  Landed 2026-11-12 with T-36.
- A channel message carries an originator signature, so a captured one cannot
  be re-flooded after its dedup entry expires and a forged one cannot be
  stored at all. This is the piece the other two bullets defer to.
- A stored channel message's primary key is the digest its flood is keyed on,
  with the envelope `message_id` kept as a column and a migration for existing
  rows (ADR-017). Channel origin authentication is deliberately *not* part of
  this: it needs the key-availability design ADR-014 settles for emergencies,
  and is its own task.
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
