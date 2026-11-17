# Mycelium Roadmap

**Last updated:** 2026-11-17 · **Current version:** 0.1 (pre-release)

The companion document is [`MYCELIUM_SPEC.md`](MYCELIUM_SPEC.md), which
specifies the protocol and describes what is built. This document tracks only
what is **not** done. Completed work is not listed here — it is in the spec's
compliance matrix (§20), in [`docs/adr/`](docs/adr/) and in the git history.

## Baseline

Verified on 2026-11-17 against the working tree, after T-04's group-discovery
challenge:

| Check | Result |
|-------|--------|
| `cargo test --workspace --all-targets` | **649 passed, 0 failed** |
| `cargo clippy --workspace --all-targets -- -D warnings` | **clean** |
| `cargo fmt --check` | **clean** |
| `cd flutter && flutter analyze` | **no issues** |
| `./gradlew :app:compileDebugKotlin` + `flutter build apk --debug` | **builds**, FFI packaged for all three ABIs |
| `swiftc -typecheck` of the iOS `Runner` module | **clean** |

10 Rust crates (32.1k lines of `src` outside the test modules, 14.5k inside
them, measured 2026-11-17 — the "~26.6k" carried here before was stale), 49
Dart files, 38 REST endpoints + 7 WebSocket event types, 64 FFI functions, 20
wire payload types, 13 database tables.

The Kotlin, Swift and APK rows above are from 2026-11-16: T-04 changes no FFI
function, no platform bridge and no Dart, so they were not re-run.

Everything specified for v0.1 is implemented except the items below. The
remaining work is concentrated in three places: **protocol hardening of
features that already work**, **validation against real hardware**, and
**adapter interoperability**.

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

**Landed 2026-11-15:** T-38 (a persisted per-publisher high-water mark that
outlives both the record's eviction and the process, so ADR-011's rollback rule
no longer depends on still holding the record; wildcard addresses refused in
common admission; a per-peer share of the record store — ADR-016). What it left
behind is T-44.

**Landed 2026-11-17:** T-04 (a beacon's group hint earns a challenge, not a
vouch: the peer must return `HMAC(proof_key, nonce ‖ verifier ‖ responder)`
over a nonce valid for 30 s, both ids taken from each side's own view, one
guess per nonce, link-local, in a rate-limit book of its own — ADR-019). The
hint itself is unchanged, as ADR-019 decided. What it left behind is T-51,
T-52 and T-53, and what it uncovered on the way is that the app never joins a
group at all (T-51): the exchange is live only on the daemon path.

**Landed 2026-11-16:** T-34 (BLE and Wi-Fi Direct prove peer identity instead
of asserting it: ADR-011's handshake runs over their fragmentation layer, the
NodeId is derived from the key the peer signed, and the two characteristics and
the `Hello` that carried a bare id are gone from the wire — ADR-021. The
platform bridges carry links and frames and no identity at all, which is the
same commit by design). What it left behind is T-47 and T-48, and the marker
stays "Implemented, untested on hardware" until T-15.

**Landed 2026-11-12:** T-36 (emergency broadcasts are checked before they are
remembered, keyed on their digest, bounded in time by a signed `signed_at`,
and the flood-dedup set expires by age instead of clearing itself — ADR-013).
T-35's bookkeeping half landed the day before (ADR-012); what remains of it is
below.

T-34, T-35, T-37 and T-38 came out of reviewing ADRs against the code: T-34
was the defect T-09 fixed, still open on the local transports; T-35 is a defect
in the T-06 work; T-37 is what reviewing ADR-010 during T-36 turned up next — an
emergency broadcast's origin is not authenticated at all; and T-38 is how
capacity eviction undoes the rollback protection ADR-011 claims.

**Decided 2026-11-12.** Every P0 below has its design on record: T-14's row
identity (ADR-017) and T-08 (ADR-020). ADR-014, ADR-015, ADR-016, ADR-018,
ADR-019 and ADR-021 have been implemented (T-37, T-35, T-38, T-01, T-04,
T-34), ADR-018 alongside ADR-023. Each ADR names the task that implements it
and flips its own status in that commit; the acceptance criteria below carry
the decisions.

T-37, T-35, T-38, T-34, T-01 and T-04 have landed in that order. T-14's
migration is next by the same reasoning — severity — and T-08 is designed but
unsequenced.

Two standing rules from those decisions: constants are **shapes now, numbers
later** — the DHT publisher quota, the level-1/2 reach limits and the dedup
retention period are to be measured against the testbed (T-19) or hardware
(T-15), not guessed — T-38 added four more to that list (`mark_capacity` 8192,
`mark_first_seen_reserve` 512, `mark_retention_grace_secs` 86 400 and
`max_records_per_peer` 256, each with its basis in ADR-016's 2026-11-15 note),
and T-04 four more (`PROOF_TTL` 30 s, `PROOF_RETRY_AFTER` 120 s,
`MAX_PENDING_PROOFS` 256 and `PROOF_MESSAGES_PER_HOUR` 30 — reasoned from the
beacon interval and from what one HMAC costs, measured against neither, and
the first two are what a flaky radio will argue with first);
and the radio features keep "Implemented, untested on hardware" until T-15's
report, however complete the software tests are — which is why BLE and Wi-Fi
Direct carry that marker now that T-34 has landed, rather than a better one.

### T-56 · Wi-Fi Direct's native socket count leaks both ways

**Area:** Android Kotlin · **Spec:** §17.3 · **ADR-021**

`WifiDirectService` bounds concurrent native links at `MAX_NATIVE_LINKS = 16`
with one `AtomicInteger`. Two paths get its accounting wrong, in opposite
directions.

1. **The refusal path never releases.** Both paths that take a socket
   increment the counter and then call `handleClient(socket, counted = true)`,
   which releases it in a `finally`. `handleClient` returns early — *before*
   that `try` — when the address is one the node recently refused
   (`WifiDirectService.kt:510`), so the slot is never given back. Sixteen
   attempts from a refused address exhaust the transport for the life of the
   service: every later socket, from any peer, is closed as soon as it is
   accepted. Getting refused is the easy part — fail the handshake once — and
   sixteen reconnections inside the refusal window finish the job, so a
   neighbour can do this deliberately, and a legitimate peer that fails the
   handshake and retries with backoff can do it by accident.
2. **`stop()` resets the count under live readers.** `stop()` closes the
   sockets and sets the counter to zero (`WifiDirectService.kt:236`), but each
   reader thread is still unwinding; its `finally` then decrements a counter
   that is already zero, leaving it negative by however many readers were
   alive. A service restarted after that admits 16 *plus* that many sockets.

Neither cancels the other reliably — they depend on different peer behaviour —
and nothing but a process restart puts the count right. Found while reviewing
T-04; both belong to the T-34 work (ADR-021), which is where the bound and the
refusal window came from.

**Acceptance:**
- Every path that increments `nativeSockets` releases it exactly once,
  including the refusal path and anything else that returns before the `try`.
- Stopping and restarting the service leaves the count at zero, whatever the
  readers were doing — by draining counted readers before resetting, or by
  making the accounting per service generation so a late `finally` cannot
  touch the new one.
- Repeated connections from a refused address leave the capacity unchanged.
- `./gradlew :app:compileDebugKotlin` and the debug APK still build; the
  bridge has no unit tests, so say plainly what was verified and what was not.

### T-51 · The app never joins a group

**Area:** `mycelium-ffi`, Flutter · **Spec:** §10.2, §10.3, §17.4

The seed-phrase onboarding screen is a screen and nothing more.
`seed_phrase_screen.dart` writes the phrase to `SharedPreferences`, and
`mycelium_node_new` takes a data directory and a display name — there is no
parameter for a group. So `NodeConfig::group_seed` is `None` on every app
start, no hint is advertised, no beacon ever matches, and T-04's exchange
never runs outside a daemon that was configured by hand. A user who types
their community's phrase is told they have joined and has not.

`derive_group_discovery_key` has no caller in the tree either: the config
takes the 32-byte key as hex, not the phrase, so even the daemon path expects
somebody to have run the derivation elsewhere.

**Acceptance:**
- A passphrase entered at onboarding reaches the node, and the node advertises
  the hint derived from it — one exported function, the four FFI files, the
  regenerated Dart bindings, and the screen that calls it.
- The derivation happens in one place that both the app and the daemon use.
  The daemon keeps accepting a hex key; a phrase and a key are distinguishable
  config, not the same field read two ways.
- Changing the passphrase, or clearing it, takes effect without reinstalling —
  and note that the running node derives the hint at construction, so this is
  a restart or a setter, not a config edit.
- T-52 is settled first or in the same change: wiring a human passphrase to a
  derivation that does not stretch it is what makes T-52 exploitable.
- Test: a node built from a passphrase and one built from the matching hex key
  advertise the same hint and vouch for each other.

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

**Landed 2026-11-14 (ADR-015).** All three are closed.

1. `session_init_binding` — the `SessionInit` header exactly as it travels —
   is an input to the X3DH derivation, under the info string
   `MyceliumX3DH-v2:`. An equivalent ephemeral now derives a different secret,
   so its first message does not decrypt and it cannot mint a second identity
   for one handshake. The regression test carries a real `u`/`u⁻¹ mod p` pair,
   re-derives their equivalence from the responder's own prekeys so a wrong
   constant cannot make it pass vacuously, and runs the real responder
   derivation on both encodings.
2. The derivation peeks at the one-time prekey; the caller spends it when the
   enclosed message decrypts, on the tie-break path as well as the ordinary
   one. A message-less init that names a prekey is refused
   (`PrekeyWithoutMessage`) and uses the signed-prekey-only variant instead; a
   non-empty nested payload that is not an `EncryptedMessage` is refused
   outright.
3. The 60-second timer is gone: a rejection is sent only when no session with
   that peer exists. The maintenance tick's handshake sweep
   (two DTN delivery windows — `2 × max(dtn.ttl_hours, 72)`) is what makes
   the legitimate case recover, since a responder sitting on a stale session
   says nothing at all. It keeps a handshake the peer has acknowledged, because
   a one-way conversation never confirms; the acknowledgement lives on the
   handshake rather than in the message rows, which can be deleted. **T-41**
   (the record is in memory, so a restart loses it) and **T-42** (receipts are
   forgeable, so confirmation needs an authenticated acknowledgement) are what
   remain.
4. A handshake is answered once, on two records keyed on the binding — which
   now covers whether the init carries a message, so neither substituting the
   nested message nor stripping it makes an answered handshake answerable
   again. `Session::accepted_binding` is one slot, ungrowable by a forgery and
   so able to cover the unauthenticated message-less form; the first successful
   decrypt copies it into `PrekeyState::answered_handshakes`, which retires
   with the signed prekey and is written to the blob on that decrypt. A
   recognised init installs nothing and draws no rejection, and nothing is
   delivered from it either: an init encloses message 0 of its chain or it is
   refused, so by the time a handshake is on record its message has been
   delivered or has failed in a way a second attempt cannot change. Found in
   review, in five steps: retiring the
   prekey only covers an init that named one; a record of the payload is
   bypassed by substituting the message; a per-session record dies while the
   prekey lives on; a prekey-scoped record cannot cover the message-less init
   without giving a forgery something to fill; and a promotion never persisted
   is gone on the next start.

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
   plenty for one alert. Being vouched removes the bound entirely — by hand, or
   by proving possession of a group key, which since T-04 is the only way a
   beacon can earn it (a matching hint used to be enough, and the hint is
   eight bytes anyone in range can copy). Level 3 is bound by its
   co-signatures, which cover the originator, so this is levels 1 and 2. T-36 stopped a forgery
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

**Landed 2026-11-14 (ADR-022): the BLE transport fragments.** A message is
split into 512-byte frames with the 6-byte header LoRa already used, queued as
a batch so it cannot lose a fragment to a full outbox, and reassembled before
anything above the transport sees it. BLE's MTU is now the reassembly bound
(4096) rather than one frame, so a co-signed alert crosses it and an alert's
text is no longer capped at 295 bytes. The fragmenter is shared with LoRa, and
its accumulation check closes the unenforced 2048-byte limit in T-40's third
bullet.

`Node::raise_emergency` still refuses an alert larger than the narrowest
registered transport's *message* bound, and the API returns 400, so an
originator learns rather than the mesh truncating silently.

**What remains:** the co-signer entry is still 96 bytes, so a three-approval
alert is 522 and leaves little room on a 2048-byte LoRa link. Shrinking it —
a truncated NodeId — stays an independent option (ADR-022's alternatives), to
be taken only if alerts prove tight in practice.

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
3. ~~**Reassembly does not enforce the 2048-byte limit.**~~ Fixed
   2026-11-14 with T-39: the shared reassembler checks accumulated bytes, and
   keeps a refused message marked so its later fragments cannot restart it
   (ADR-022).
4. **A fragment-id collision can produce a complete corrupted message.**
   ADR-008 says colliding sender tags and ids cause a drop; two messages
   sharing tag, id and fragment count can instead combine into something whole
   and wrong, which nothing at this layer detects.

**Acceptance:**
- SF travels with each frame to the platform layer, and a receiver is told
  which to listen on; test the discovery-SF path end to end.
- Peer and partial-message expiry run from periodic maintenance, not only on
  receipt; test that a silent peer ages out.
- ~~Reassembly refuses a message whose accumulated fragments exceed the
  limit.~~ Landed 2026-11-14 with T-39.
- Either fragment reassembly is integrity-checked, or ADR-008 states which
  layer is responsible for detecting a corrupted reassembly and why that is
  sufficient.

---

### T-41 · An unconfirmed handshake does not survive a restart

**Area:** `mycelium-crypto`, `mycelium-node` · **Spec:** §5.2 · **ADR-012**,
**ADR-015**

A `SessionInit` the peer never answers is given up on after
its deadline: the sweep landed with T-35 on 2026-11-14 and
is what makes ADR-015's rule 3 — reject only when no session with the peer
exists — safe for the legitimate case. But the record it sweeps,
`SessionManager::unconfirmed_handshakes`, is in memory only. The session itself
is persisted, so a restart during an unconfirmed handshake leaves a session
with no handshake behind it: the sweep cannot fire, and a late `SessionReject`
is ignored for the same reason (`handshake_transcript` returns `None`). Every
later message to that peer goes out as a bare `EncryptedMessage` it cannot
read, for ever.

Narrow but permanent, and it predates the sweep rather than being caused by it:
before T-35 the restart lost the same record and with it the only thing that
made a rejection actionable.

The **answered**-handshake records have a restart problem of their own, found
reviewing this work on 2026-11-15 and added to this task because the fix is the
same fix. They live in two separately written rows, so a lost prekey-blob write
leaves a marker on the session's single slot, which the next handshake with that
peer overwrites; and the ADR-007 tie-break winner records the loser's init in
the durable record *only*, so a lost write there leaves nothing to repair it
from. Both are retried in memory and need a restart to bite.

Reconciling from the session rows at startup was implemented and withdrawn: a
session built from a message-less init authenticates nothing, so re-asserting
every loaded marker lets forged inits across free identities evict the
authenticated markers out of the bounded record — a cheaper attack than the one
it closes (ADR-015, note of 2026-11-15).

**Additional acceptance, from that:**
- Authentication evidence is stored with the marker, so only an authenticated
  one is ever reconciled — or the session row and the prekey blob commit in one
  transaction, which this task's own persistence work may give for free.
  `RatchetState::recv_count` is not usable as the evidence: it resets on every
  DH ratchet step.
- The tie-break winner's record of the loser's init survives a restart.
- Tests: a message-less init cannot displace an authenticated marker across a
  restart; a failed blob write on the tie-break path, followed by a restart,
  still refuses the discarded init.

**Acceptance:**
- The unconfirmed-handshake record — transcript, the message ids sent under it,
  and when the init went out — survives a restart, so both the sweep and a late
  rejection still work. Storing it with the session row is the obvious place;
  a new table needs a reason.
- Tests: a node restarted mid-handshake still gives the handshake up on time,
  and still acts on a rejection that names it.
- Spec §5.2 states what a restart keeps, since it is now load-bearing for
  recovery.

---

### T-42 · A handshake is confirmed only by traffic, and receipts are forgeable

**Area:** `mycelium-node`, `mycelium-protocol` · **Spec:** §5.2 · **ADR-015**

A handshake is confirmed when the initiator decrypts something from the peer:
only that peer's ratchet could have produced it. A conversation where the peer
reads and acknowledges but never replies therefore never confirms, and T-35's
sweep would abandon a working session every
the handshake deadline. The sweep now keeps a handshake whose
message has been acknowledged (`handshake_was_acknowledged`), which covers the
honest case — but receipts are unauthenticated (§14.3), so a forged receipt
suppresses the sweep for that pairing, and a forged one is also the reason a
receipt must not count as *confirmation*: that would strip a live handshake of
its rejection protection and pin a dead session indefinitely.

The fix is an acknowledgement the peer cannot forge: on accepting a
`SessionInit`, the responder sends something encrypted under the new session —
an empty `SYSTEM` message, or a payload of its own — which confirms the
handshake on arrival by the ordinary rule, within one round trip, with no
reliance on receipts.

**Acceptance:**
- Accepting a session produces an authenticated acknowledgement, and the
  initiator's handshake is confirmed by it; a one-way conversation survives
  the handshake deadline with no receipt involved.
- The acknowledgement is not surfaced to API clients as a message.
- It is not itself a `SessionInit`, so it cannot start a handshake loop between
  two nodes that both accept.
- Tests: a one-way conversation across the timeout; an acknowledgement for a
  handshake we do not have is ignored.
- Covers two cases receipts cannot. A session carrying only sender-key
  distribution never confirms *and* never draws a receipt, because
  `finalize_incoming_message` returns early for `ContentType::System` — so it
  is swept and re-handshaked at every deadline. And a
  conversation of exactly one message cannot be acknowledged at all, since a
  receipt for an init's own message is no evidence the peer kept the session
  (§5.2).
- Spec §5.2 states what confirms a handshake, and §14.3 what is accepted.

---

### T-43 · A one-time prekey is not bound to the initiator it was issued to

**Area:** `mycelium-crypto`, `mycelium-api` · **Spec:** §5.2 · **ADR-009**,
**ADR-015**

A prekey bundle is public. Any node holding Bob's bundle can initiate with it —
under its own identity, with its own valid first message — and so consume the
one-time prekey that Alice's init names. Alice's untouched init then fails with
`UnknownOneTimePrekey` and draws a rejection that is entirely honest, because
Bob really cannot complete it; but a third party has forced that pairing to
re-handshake at the cost of one prekey. Bundles served from a supernode cache
make the collision ordinary rather than adversarial: the same cached bundle goes
to many initiators, which is why stale bundles have their own recovery
(ADR-009).

Found by the ADR review on 2026-11-14 against ADR-015, whose consequence
"a forged or provoked `SessionReject` changes nothing" holds for a forgery and
for a replay but not for this — it provokes a *true* refusal. The cost is one
handshake per prekey spent, against a responder that replenishes to 100 when it
drops below 20, so this is a nuisance rather than a denial of service; it is
listed because the guarantee is worded more strongly than the code can keep.

**Acceptance:**
- Either an issued prekey names the NodeId it was issued to and a mismatch is
  refused — which needs the bundle request to carry an authenticated requester,
  and a policy for bundles served from a cache — or §5.2 states the property and
  why it is acceptable, and ADR-015's rejection guarantee is reworded to match.
- Tests: a third party consuming the prekey another initiator named; whichever
  rule is chosen, the genuine initiator's recovery still works.

---

### T-44 · A lost DHT mark deletion can outlive the run that lost it

**Area:** `mycelium-core`, `mycelium-storage` · **Spec:** §8.4 · **ADR-016**

A high-water mark deletion that cannot be queued — the writer's bounded queue
full — is remembered in a bounded retry list (`MAX_PENDING_DROPS`, 4096) and
folded into the next attempt. When that list overflows, the oldest entries are
dropped, and the `dht_marks` rows they named are left with nothing in memory
pointing at them: no later sweep can target them, because the marks they
belonged to are gone from the table. They are reclaimed only by the next start,
which reconciles the whole store against the table.

Found by the Codex reviews on 2026-11-15 while implementing T-38, in two parts.
Row by row it is narrow: rows and deletions are produced in pairs — the
eviction's deletion is queued immediately before the new mark's write — so under
saturation *both* are lost and the store does not grow. Growth that way needs
the queue to reject a deletion and then accept the write issued right after it,
repeatedly, which is not an interleaving an attacker can drive.

**In bulk it is not narrow.** The retention sweep returns every expired mark at
once, so a single failed sweep carrying more than 4096 deletions overflows the
list in one step and discards the surplus. On a node that has tracked many
publishers that is one bad moment rather than thousands, which is why this is
worth its own task rather than a footnote. On a long-running daemon the growth
is unbounded over time, and the only thing that reclaims it is a restart.

The fix is reconciliation that does not need one: the writer already has both
the store and the mark table in hand, so a `Reconcile` message it answers by
loading the store and dropping what the table does not hold is the same work
`restore_marks` does at startup. It needs a guard so it cannot run before
restoration, which is the part that makes it more than a few lines.

**Acceptance:**
- Repeated retry-list overflow within one run does not grow `dht_marks` past
  `mark_capacity`, with no restart.
- A single sweep whose deletion batch exceeds `MAX_PENDING_DROPS` and fails is
  covered: that is the reachable case, and the one the first analysis missed.
- Reconciliation cannot run before the marks have been restored, and a test
  covers that ordering — deleting rows whose marks have not been read yet would
  discard live protection.
- §8.4's "Known gaps" paragraph loses the sentence that points here.

---

### T-45 · A DHT high-water mark remembers when, not what

**Area:** `mycelium-core`, `mycelium-storage` · **Spec:** §8.4 · **ADR-016**,
**ADR-011**

The rollback rule refuses a record **strictly older** than the newest ever
admitted for that publisher. The strictness is deliberate — a node that lost a
record to capacity eviction has to be able to re-learn the very record the mark
was set from, and refusing an equal timestamp would make a peer's current
address unlearnable — but it means the mark records *when*, not *what*.

A publisher that signed two records with the same `published_at` and
**different addresses** therefore has no protection between them. Once its
record is evicted, either is admissible, and an attacker holding the other can
install it and have lookups answer with it. The mark survives the eviction and
does not help.

Found by the ADR review on 2026-11-15 while implementing T-38. Nothing in the
implementation signs two addresses in one second — `store_self` publishes one
address per re-sign, every TTL/3 — so reaching it needs a publisher that
double-signed inside a second, by restarting onto a different port within it or
by its own choice. Narrow, and a real hole in a claim ADR-011 and ADR-016 both
state unconditionally.

**Acceptance:**
- A mark remembers the record it was set from, not only its timestamp, and an
  equal `published_at` is admitted only for that same record.
- A column and a migration for it, with the `Mark` type and both `MarkStore`
  implementations carrying it.
- Tests: two addresses signed at one timestamp, the second refused after the
  first's record is evicted; and the case the strictness exists for — the same
  record re-learned after eviction — still works.
- The residual notes in ADR-016, ADR-011 and §8.4 lose their pointers here.

---

### T-46 · The internet transport cannot be replaced while a node runs

**Area:** `mycelium-ffi`, `mycelium-core` · **Spec:** §8.4 · **ADR-016**,
**ADR-011**

`mycelium_register_internet_transport` and
`mycelium_register_internet_transport_configured` used to replace an already
registered internet transport. Since T-38 they refuse with `-3` instead, and
changing the internet transport means stopping the node and starting it again.

The reason is the DHT's high-water marks. A second engine over the same
database brings its own mark writer, and there is no ordering between two
writers: one engine's eviction can land after the other's restoration and erase
a mark it had just adopted, which is exactly the rollback protection the
database exists to hold. Every invariant in ADR-016's persistence contract is a
property of *one* writer applying writes in issue order.

Four successive attempts to sequence a safe swap each uncovered the next hole,
and the Codex reviews on 2026-11-15 found them in this order: draining before
the stop proved nothing because the old transport was still serving; stopping
first and draining after left the manager able to restart it; deregistering
first fixed that but `add_transport` starts what it is given; and underneath all
of them, **`stop()` cannot promise quiescence at all** — its connection drain is
bounded and only warns, so a stuck handler can still be admitting records when
`stop()` returns, whatever the mark writer reports. Refusing the replacement
closes the class rather than narrowing it.

Handle recreation is the same defect one level out: two node handles over one
database file are two engines, `mycelium_node_new` does not refuse the second,
and nothing could stop a second process opening the same file. Freeing a handle
now drains the mark writer first, but that is less than it reads as: T-01 made
the handle reference-counted, so freeing one handle need not end the engine at
all, and the API server task holds its own `Arc<Node>` regardless — and the
drain proves only that what the writer had queued was *processed*, since a
failed write is logged and dropped before `Flush` is acknowledged (ADR-016's
2026-11-16 note). A drain that times out still leaves a detached writer holding
deletions that can land after the new engine has restored them.

**Acceptance:**
- Either `stop()` reports whether every connection handler actually exited, and
  replacement is refused unless it did — which makes the drain's outcome part
  of the transport's contract, affecting every caller — or the engine is made
  shareable across transport instances so no second writer exists.
- A deletion cannot erase a row written since the sweep read it, whoever wrote
  it: a revision column the delete must still match, rather than the watermark
  alone, which is what makes the invariant hold across engines instead of only
  within one. This also subsumes the equal-timestamp case in T-45, so the two
  share a migration if they land together.
- Registration replaces again, with a test that a replacement cannot lose a
  mark the new engine has adopted: a stalled handler on the old transport, a
  replacement, and a restart that still refuses the replay.
- The notes in ADR-016, ADR-011 and §8.4 lose their pointers here, and the FFI
  return codes are documented without `-3`.

---

### T-47 · BT Classic and LoRa still install an asserted peer id

**Area:** `mycelium-core`, Android Kotlin · **Spec:** §8.3, §8.4, §22 ·
**ADR-021** (for the shape of the fix)

T-34 proved peer identity on BLE and Wi-Fi Direct. Two transports were left
behind, and after that change they are the only ones that still install a peer
from an id nobody proved:

1. **BT Classic** is the same defect in the same shape.
   `mycelium_bt_classic_on_peer_connected` takes 32 bytes from the Kotlin
   bridge and installs a peer and a route for them; `BtClassicService.kt`
   exchanges them over RFCOMM. ADR-021's design applies unchanged — links
   named by the socket, the shared handshake over the frame layer, the NodeId
   derived from the proved key — and the work is the Rust transport plus one
   Kotlin service and one Dart manager. The transport is "Implemented,
   untested on hardware" (T-15), so nothing is deployed behind it.

2. **LoRa is different and worse.** It has no link layer at all: the bridge
   passes `NodeId::ZERO` and the peer is taken from the reassembled
   envelope's `source` field (`lora.rs`), which is an assertion by whoever
   sent the frame. A two-way channel handshake per peer does not fit a
   broadcast medium with a 51-byte frame and a 1 % duty cycle, so this needs a
   design of its own rather than ADR-021's: signing the beacon, or binding
   neighbour state to the envelope's own signature chain, are the directions
   to weigh. T-40 collects LoRa's other ADR-008 divergences; this is not one
   of them.

**Acceptance:**
- BT Classic installs a peer only after the ADR-021 handshake, with the
  replay-refused and honest-peer pair of tests the local transports have.
- Either LoRa proves a neighbour's identity by a mechanism a broadcast
  medium can carry, or spec §8.4 and §22 state plainly that a LoRa
  neighbour's id is asserted, what that costs, and why the alternatives were
  refused — with a new ADR for whichever way it goes.
- §22's "a nearby node claiming a neighbour's identity" bullet shrinks to
  whatever is still true.

---

### T-48 · A local link's name is not unique across its incarnations

**Area:** `mycelium-core`, Android Kotlin, iOS Swift, Flutter · **Spec:** §8.4
· **ADR-021** (residual 8)

T-34 names a link by the address the platform layer holds for it, prefixed by
the GATT role: `c:AA:BB:CC:DD:EE:FF`, or a Wi-Fi Direct endpoint. A
reconnection reuses that name, and by then some of the previous incarnation's
work has already been dispatched through the app — a frame, a `close`, an
`established`. Rust purges its own queues when a link goes, and the bridges
check identity where they hold an object to compare, but nothing can retract
what has already crossed a layer boundary.

Found by the ADR review on 2026-11-16. The consequences are bounded, which is
why it is a task and not a fix in T-34: a stale frame on a live link fails to
open and is dropped (the counter floor and the AEAD see to that), and a stale
`close` costs a healthy link a reconnection and the 30-second backoff. One is
worse than a lost frame: a stale `established` *is* accepted by a replacement
of the same name, because the bridge checks only that it still holds the link,
and that exempts the replacement's unfinished handshake from the bridge's own
stale-link sweep — leaving only the Rust side's ten-second deadline to close
it. Nothing is installed wrongly and no peer is impersonated; what is lost is
time, and one layer of defence in depth.

Closing the class properly means carrying a **connection instance** in the
link name, end to end: Rust, the FFI, the app and both bridges. The one thing
that must *not* follow the instance is the refusal backoff, which is about a
device and a role and has to outlive an incarnation — so it needs its own key.

**Acceptance:**
- A link's name identifies one incarnation. A frame, a directive or an event
  from a previous one names a link that no longer exists and is dropped by
  the existing unknown-link path, rather than being checked for by each
  layer separately.
- The refusal backoff still holds across a reconnection, with a test that a
  refused peer is not redialled inside the backoff even though its link name
  has changed.
- A test that a reconnection arriving before the previous incarnation's
  cleanup has finished keeps the replacement, on both local transports.
- ADR-021's residual 8 is retired and §8.4 states what a link name means.

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

### T-52 · A group passphrase is not stretched

**Area:** `mycelium-crypto` · **Spec:** §5.6, §10.2 · **ADR-019**

`derive_group_discovery_key` is one HKDF extract-and-expand over the
passphrase bytes: no salt, no iterations, no memory cost. Every beacon
publishes `SHA-256(key)[..8]` of the result, which is a free offline verifier
for a guess. A human-memorable community phrase — which is what a *seed
phrase* group is for — therefore falls to a dictionary run over eight bytes
captured once, and the recovered key answers T-04's challenge correctly. The
challenge cannot help: it proves possession of the key, and the attacker now
has the key.

P1 and not P0 only because no passphrase reaches a node today: the config
takes a 32-byte hex key, which an operator generates rather than types
(T-51). Wiring a phrase through without fixing this is what would make it
exploitable, so it gates T-51.

**Acceptance:**
- A password hash — Argon2id, scrypt or PBKDF2 at a documented cost — stands
  between the phrase and the key, with the parameters in §5.6 and the choice
  in an ADR. Check the workspace dependencies before adding one.
- The salt problem is answered explicitly: a group's members must derive the
  same key from the same phrase, so the salt is a constant or derived from the
  group name, and the ADR says which and what that costs against a rainbow
  table.
- Whether the beacon hint stays eight bytes is reconsidered in the same
  breath: the shorter it is, the more phrases collide with it, and the cost of
  a guess is what this task is about.
- Test: the derivation takes a measured minimum time per attempt, and the
  vector for a known phrase is pinned so the parameters cannot drift silently.

### T-54 · A vouch the old group path granted survives the upgrade

**Area:** `mycelium-node`, `mycelium-storage` · **Spec:** §10.2 · **ADR-019**

Before T-04, a beacon whose group hint matched earned a vouch outright, and
that vouch was persisted. `Node::new` reloads every stored vouch into the
trust graph, so a peer admitted on a replayed hint is still trusted at 1 hop
after the upgrade — and is never challenged, because `has_vouched` is exactly
what stops this node challenging a peer it already vouches for. T-04 closed
the door; it did not take back what went through it.

The stored rows cannot be told apart. A hash-match vouch and one the user made
in person are both unsigned and both name this node as the voucher (T-53), so
"drop the unearned ones" has nothing to select on, and "drop the unsigned
ones" is all of them. Automatic revocation on a failed challenge is worse than
the problem: a member whose challenge is lost on a flaky radio would lose a
vouch it had earned.

Nothing in the tree ever sets `group_seed` (T-51), so the only database that
can carry such a row is a daemon someone configured by hand — which is why
this is P1 and not P0. Until it is done, the remedy is to delete the vouch
row.

**Acceptance:**
- Vouches carry their provenance — in person, by API, by group proof — either
  as a column or as the signature T-53 adds, and a row without it is treated
  as what it is: unverified history, not a credential.
- A node decides *once*, explicitly, what to do with pre-provenance rows, and
  the decision is in an ADR rather than in a migration nobody reads.
- A peer whose vouch did not come from a proof is challenged again when its
  beacon claims the group, and the vouch stands or falls on the answer — with
  silence left meaning "ask again later", never "revoke".
- Test: a database carrying a hash-match vouch, opened by the new code, does
  not leave that peer trusted without a fresh proof.

### T-55 · A reverse route is learned from an unauthenticated source

**Area:** `mycelium-node`, `mycelium-core` · **Spec:** §7.1, §14.3

The ingress path learns a route from every envelope it receives, not just from
AODV messages: when `envelope.source` is neither the sending peer nor this
node and `hop_count > 0`, a route to that source is installed via that peer.
`envelope.source` is cleartext and nothing authenticates it, so a neighbour
can name any id — one it does not hold, one that is not even on the mesh — and
have this node route traffic for that id to it, where it can be dropped.

Bounded, but not harmless. The claimed hop count is at least 2, so a live
direct link always wins; an id with no valid route, or one reachable only
through a longer learned path, does not. Content is end-to-end encrypted, so
this is traffic denial rather than disclosure — and it is cheap: the route is
installed at `node.rs:2469`, before the payload type is even parsed, so no
rate limiter has been consulted yet whatever the type. One packet per id.

Found while reviewing T-04. It is not specific to the group-proof exchange —
every payload type reaches this code, and the proof types are the two that
cannot be used for it, since both are refused unless their source is the
sending peer. Checking the source earlier for *those two* would fix nothing:
an attacker would send a receipt instead.

**Acceptance:**
- A route is learned only from a source the node has grounds to believe: an
  AODV message whose own rules cover it, a packet whose source is the peer
  that delivered it, or a source proved some other way. The decision goes in
  an ADR, because "which packets may teach us routing" is a protocol rule and
  the answer affects every payload type.
- Whatever the rule, a 1-hop link proved at the transport layer (ADR-021)
  stays the authority on its own peer.
- Test: a packet carrying a forged source leaves the routing table unchanged,
  and the legitimate route for that id still decides where its traffic goes.

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

### T-53 · Local vouches are stored unsigned

**Area:** `mycelium-crypto`, `mycelium-node`, `mycelium-api` · **Spec:** §6.1

`VouchRecord::signature` is empty everywhere one is written: the group-proof
path (§10.2), `POST /v1/contacts/:id/vouch` and the FFI both store
`Vec::new()`. `mycelium_crypto::wot::Vouch::create` and `Vouch::verify` — which
sign and check `voucher_id ‖ vouchee_id ‖ timestamp` against the voucher's key
— have no caller outside their own unit tests.

Harmless today, because a vouch never leaves the node that made it: the trust
graph is rebuilt from the local database, and nothing on the wire carries a
vouch. It stops being harmless the moment trust is transitive across nodes,
which is what §6.1's web of trust is for — an unsigned vouch is one any node
could invent on another's behalf, and a stored one has no way to prove which
key made it.

**Acceptance:**
- Every vouch written is signed by the voucher's identity key, and the
  signature is verified on load, with a stored vouch that fails verification
  dropped rather than trusted.
- Unsigned rows already in a database are migrated or discarded on an explicit
  decision, not silently honoured.
- Test: a vouch row whose signature does not match its voucher is not in the
  trust graph after a reload.

### T-50 · A panic inside `Node::start` leaves it half-started

**Area:** `mycelium-node`, `mycelium-ffi` · **Spec:** §17.4 · **ADR-018**

`Node::start` spawns the event loop, the beacon timer, the DTN sweeper and the
transport pollers in sequence, and is not transactional: a panic part-way
leaves some of them running and the rest not. That cost nothing while a panic
ended the process. Since T-01 it survives, `mycelium_node_start` reports the
failure, and the `started` flag is correctly left false — so a retry calls
`Node::start` again and duplicates whatever the first attempt had already
spawned: two beacon timers announcing the same node, two event loops competing
for the same inbound queue.

This is the one hazard T-01 introduced rather than removed, and it is narrow: a
panic inside `Node::start` is itself a defect, and the window is the handful of
statements before the last task is spawned. It is a task because the FFI layer
cannot fix it — the flag can only describe what `Node::start` reports, and what
it reports today is all-or-nothing about something that is neither.

**Acceptance:** `Node::start` either completes or leaves nothing spawned — a
cancellation token cancelled on the way out of a failed start, or a guard that
aborts the tasks it has already created; a test that panics part-way through a
start asserts that a second start spawns exactly one of each task, counted
rather than inferred.

### T-49 · A renamed node reverts on restart

**Area:** `mycelium-node`, `mycelium-ffi`, `mycelium-storage` · **Spec:** §17.4
· **ADR-023**

T-01 made `mycelium_set_node_display_name` work: the name reaches the next
beacon and `GET /v1/node/status`. It reaches nothing durable. The name is held
in memory on the node, and every start takes it from `mycelium_node_new`'s
argument or the daemon's config, so a rename made in the app is silently lost
the next time the process starts — and the app has no way to make it stick
short of remembering the name itself and passing it in.

Left out of T-01 deliberately (ADR-023): persisting it means deciding what
takes precedence between a stored name, a config file and a constructor
argument, and that precedence belongs in its own decision rather than being
settled by whichever code path happens to write last.

**Acceptance:** a renamed node reports the new name after a restart; the
precedence between the stored name, `NodeConfig::display_name` and
`mycelium_node_new`'s argument is written down in the spec (§14.5 and §17.4)
and asserted by a test for each of the three; the daemon's
`MYCELIUM_DISPLAY_NAME` override still wins where it is set, or the spec says
why not.

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
