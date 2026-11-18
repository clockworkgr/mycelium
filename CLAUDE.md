# Mycelium — AI Assistant Instructions

## Project Overview

Mycelium is an infrastructure-independent mesh communications platform. It uses
BLE and Wi-Fi Direct for local mesh transport, Signal Protocol cryptography
(X3DH + Double Ratchet) for end-to-end encryption, AODV reactive routing for
multi-hop, and DTN spray-and-wait for delay-tolerant delivery. The architecture
is a standalone Rust daemon exposing a local WebSocket + REST API, with the
Flutter app and future clients connecting as API consumers.

## Before Starting Work

The repository keeps **two** living documents. Read both:

1. [`MYCELIUM_SPEC.md`](MYCELIUM_SPEC.md) — the spec. Wire protocol,
   cryptography, routing, transports, and the architecture as built, with a
   status marker on every feature and a compliance matrix (§20).
2. [`ROADMAP.md`](ROADMAP.md) — the plan. Everything still open, with task IDs
   (`T-nn`), priorities and acceptance criteria. The spec references these IDs
   wherever it describes a gap.

Then, as needed:

3. [`CONTRIBUTING.md`](CONTRIBUTING.md) — build setup, test commands, project
   structure, commit conventions.
4. [`docs/adr/`](docs/adr/) — Architecture Decision Records (ADR-001 …
   ADR-023). Append-only; never rewrite one. ADR-017 and ADR-020 are decided
   but not yet implemented — one per open P0 — and each names its ROADMAP task
   and flips its own status in the commit that implements it.
5. [`docs/plugin-api.md`](docs/plugin-api.md) — transport plugin development
   guide (external audience).

**Do not create a third overview document.** This repository previously carried
`ARCHITECTURE.md`, `IMPLEMENTATION_SPEC.md` and `REMAINING_WORK.md` alongside
the spec; they duplicated each other, drifted out of sync with the code and
with each other, and were consolidated away on 2026-11-10. If something needs
documenting, it belongs in the spec, the roadmap, or an ADR.

## Build & Test

### Rust

```bash
# Environment setup (macOS without an accepted Xcode license)
export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
export DEVELOPER_DIR=/Library/Developer/CommandLineTools

make build        # cargo build
make test         # cargo test
make lint         # cargo fmt --check && cargo clippy -- -D warnings
make android      # ./scripts/build-android.sh
```

### Flutter

```bash
make flutter-get      # flutter pub get
make flutter-gen      # dart run ffigen  (after C header changes)
make flutter-analyze  # flutter analyze
make flutter-apk      # flutter build apk --debug
make android-test     # ./gradlew :app:testDebugUnitTest (Kotlin bridges)
```

Flutter SDK is at `/Volumes/Tendermint/flutter/` and is not on `PATH` by
default.

### Running tests

- `cargo test` runs the whole workspace (currently 649 tests).
- `make android-test` runs the Kotlin bridges' JVM tests — the logic that
  touches no Android framework class. They are **not** part of the 649, and
  `make check` does not run them.
- Some `mycelium-node` integration tests take 60+ seconds (DTN fallback).
- `cargo test -p <crate>` for one crate; `RUST_LOG=debug cargo test` for
  tracing.

---

## Pre-Commit Checklist (MANDATORY)

Every commit must complete all four steps. Do not commit if any step fails.

### Step 1 — Quality gates

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings   # zero warnings
cargo test                                               # all tests pass
```

Fix failures and warnings. Do **not** use `--allow` flags or `#[allow(...)]` to
suppress a legitimate warning.

### Step 2 — Flutter analysis (if any Dart file changed)

```bash
cd flutter && flutter analyze    # zero issues
```

If any Kotlin file changed:

```bash
make android-test                # zero failures
cd flutter/android && ./gradlew :app:compileDebugKotlin
```

### Step 3 — Documentation

Documentation changes go in the **same commit** as the code they describe. The
rule is short on purpose — a long checklist is what let the old documents drift.

| If you changed… | Update |
|-----------------|--------|
| Wire format, payload types, crypto, KDF, info strings | `MYCELIUM_SPEC.md` §4 / §5 |
| Routing, transport, or DTN behaviour | `MYCELIUM_SPEC.md` §7 / §8 |
| REST endpoints, WebSocket events, auth | `MYCELIUM_SPEC.md` §16 |
| FFI functions, platform bridges, Flutter structure | `MYCELIUM_SPEC.md` §17 |
| Database schema | `MYCELIUM_SPEC.md` §15 |
| Node config, CLI flags, environment variables | `MYCELIUM_SPEC.md` §14.5 |
| The implementation status of any feature | the status marker in that section **and** the row in `MYCELIUM_SPEC.md` §20 |
| A roadmap task: finished, newly found, re-scoped | `ROADMAP.md` (keep `T-nn` IDs stable; the spec references them) |
| A significant decision (new crate, library, protocol or API change) | a new ADR from `docs/adr/000-template.md` |
| The workspace test count | `README.md` and `CONTRIBUTING.md` — the only two places that carry it |
| The plugin trait or registry | `docs/plugin-api.md` |

Two rules that matter more than the table:

- **Never mark something Implemented that is not verified.** If it works in
  software but has never run on real hardware, the marker is
  "Implemented, untested on hardware" and it belongs in ROADMAP T-15. The old
  task list claimed completed 3-phone tests and Flutter screens that did not
  exist; that is the failure mode to avoid.
- **If behaviour and spec disagree, fix both in the same change.** The
  disagreement is a bug in one of them.

### Step 4 — Commit

```bash
# Stage specific files (never `git add -A` or `git add .`)
git add <specific files>

git commit --no-gpg-sign -m "<scope>: <description>

<body explaining what changed and why>"
```

**Commit message rules:**

- Format: `<scope>: <description>`
- Scopes: `protocol`, `crypto`, `core`, `storage`, `node`, `api`, `ffi`,
  `flutter`, `ble`, `docs`, `build`, `test`
- Description: imperative mood, lowercase, no trailing period ("add X", not
  "Added X.")
- Body: explain *what* and *why*, not *how*
- Multi-scope change: use the primary scope, mention the others in the body
- Reference ADRs and roadmap tasks where applicable: `(ADR-005)`, `(T-07)`
- **No AI attribution anywhere** — no `Co-Authored-By` trailer, no "Generated
  with" line, no mention of Claude or AI in commit messages, PR
  titles/descriptions, PR comments or code comments.

### Step 5 — Verify

Run `cargo test` once more after committing to confirm the commit is clean.

---

## Implementation Rules

### Code quality

- `cargo clippy --workspace --all-targets -- -D warnings` must be clean.
- `cargo fmt --check` must be clean.
- No `unsafe` outside `mycelium-ffi`. That crate is the only place it belongs.
- Do not add dependencies without checking the workspace deps first.

### Testing requirements

| Change | Required test |
|--------|---------------|
| New Rust function or module | At least one test |
| New REST endpoint | Integration test in `crates/mycelium-api/tests/api_test.rs` |
| New wire payload type | Serialization round-trip test in `mycelium-protocol` |
| New transport | Lifecycle test (start / stop / send), plus unknown-peer send fails |
| Bug fix | A regression test that fails before the fix |

### Architecture Decision Records

Create an ADR for any significant decision — a new crate, a library choice, a
protocol change, an API design. Copy `docs/adr/000-template.md` to
`docs/adr/NNN-short-title.md`, numbered sequentially. Check the existing ones
first; reference the ADR in the commit message.

---

## Key Technical Details

Quick reference. The spec is authoritative — follow the section links when the
detail matters.

### Crypto (spec §5)

- Ed25519 signing + X25519 DH keys. Ed25519→X25519 is SHA-512 of the seed,
  first 32 bytes clamped; Edwards→Montgomery via
  `curve25519-dalek::CompressedEdwardsY`.
- `NodeId = SHA-256(Ed25519 public key)`. This binding is enforced at ingress
  and is load-bearing against MITM — see spec §14.3.
- 9 HKDF info strings for domain separation (spec §5.6):
  `MyceliumX3DH-v2:` ‖ the raw `SessionInit` header (ADR-015),
  `MyceliumRatchet`, `MyceliumAEAD`, `MyceliumSafetyNumber`,
  `MyceliumGroupMK`, `MyceliumGroupCK`, `MyceliumGroupAEAD`,
  `MyceliumGroupDiscovery`, and `b"frame:" ‖ ephemeral_public` for internet
  channel frame keys (§8.4).
- Double Ratchet `decrypt()` and group decrypt are transactional: state is
  committed only after the AEAD tag verifies.

### Database (spec §15)

- SQLCipher. Key is `SHA-256("mycelium-db-key:" || identity_bytes)`.
- Feature flag `bundled-sqlcipher-vendored-openssl` (vendors OpenSSL for
  cross-compilation).
- 13 tables. Groups and prekey state are opaque blobs in `config`, not their
  own tables.

### Wire format (spec §4)

- 106-byte envelope header + variable payload, little-endian throughout.
- 20 payload types. `SenderKeyDistribution` (`0x71`) is valid only inside a
  pairwise-encrypted `SYSTEM` message, never top-level (ADR-007).
- `DtnRelay` (`0x40`) carries `copies_remaining` + `ttl_secs` so relays spray
  onward and honour the end-to-end TTL (ADR-005).
- Length checks subtract on the trusted side; Lamport arithmetic saturates.

### Android cross-compilation (spec §19)

- Homebrew `rustc` shadows rustup — the build scripts prepend the rustup
  toolchain bin to `PATH`.
- `CC_*`, `AR_*`, `RANLIB_*` must be set per target for OpenSSL; the NDK
  toolchain bin must be on `PATH` for OpenSSL's Makefile.
- NDK pinned to `27.0.12077973`.

### FFI boundary (spec §17.4)

- Every `extern "C"` body opens with `ffi_guard!("name", { .. })`, or
  `ffi_guard_blocking!` when it calls `runtime().block_on` —
  `test_every_exported_function_is_guarded` reads the crate's own source and
  fails on a function that forgets, names itself wrongly, or picks the wrong
  flavour (ADR-018).
- A caught panic returns the failure value for the signature's shape
  (`MYCELIUM_ERR_PANIC` = -99 for `i32`, NULL, `false`, `-1.0`) and stores the
  message with its location. A blocking call from a runtime thread is refused
  before the body runs, reported the same way: -98 from an `i32`, and otherwise
  the shape's own failure value, which only the stored message distinguishes
  from a panic (ADR-023). A refused `mycelium_node_free` has **not** released
  its reference.
- Anything in the guard's recovery path must be panic-free: a second panic
  unwinds across the boundary and aborts. Locks in this crate recover from
  poisoning for the same reason.
- The handle is `Arc::into_raw`. Every handle handed out is one reference and
  needs exactly one `mycelium_node_free`, including each one from
  `mycelium_node_get_existing`.
- Changing the exported set means four files: `src/lib.rs`, `include/mycelium.h`
  (then `dart run ffigen`), `flutter/ios/Runner/mycelium_exported_symbols.txt`
  and the `-u` lists in all three `flutter/ios/Flutter/*.xcconfig`.

### BLE transport (spec §8.4)

- Dual-role GATT (server + client), 2 characteristics: Data TX (`…7892`) and
  Data RX (`…7893`). The Node ID (`…7891`) and Identity (`…7894`)
  characteristics are **gone** (ADR-021, T-34): they carried a bare NodeId
  nobody proved.
- Peer identity is proved by ADR-011's handshake run over the frame layer, and
  the NodeId is derived from the key the peer signed. The platform bridges
  carry **links** — an address they already hold, prefixed `c:` (we are the
  central) or `s:` (we are the server) — and opaque frames; they report no
  identity at all. Random Private Addresses stop mattering for the same
  reason.
- Sealed frames carry their counter (8 bytes LE) and the receiver keeps a
  floor, because a lost fragment on a radio would wedge an implicit counter
  for good. The counter is taken as a frame *leaves*, since the outbox
  reorders for emergencies.
- Fragmentation: Rust splits a sealed frame into 512-byte fragments with a
  6-byte header; the platform layer splits each of those into ATT writes with
  a 1-byte header (`0x01` first, `0x02` last, `0x03` single, `0x00` middle).
- Outbox polling: Dart polls the Rust `VecDeque` every 50 ms over FFI, and
  polls a link-directive queue beside it (`established` / `close`).

### Group discovery (spec §10.2)

- A group key yields two values and the key itself is dropped: the beacon hint
  `SHA-256(key)[..8]`, and the MAC key `HKDF(key, "MyceliumGroupProof")`. They
  are taken as a pair (`GroupProofCtx::group`), never one without the other.
- A matching hint earns a challenge, never a vouch. The vouch waits for
  `HMAC(proof_key, nonce ‖ verifier ‖ responder)`, and **both ids come from
  each side's own view of the link, never from the payload** — that is what
  makes answering a stranger's challenge safe (ADR-019).
- `GroupProofChallenge` (`0x51`) and `GroupProofResponse` (`0x52`) are
  link-local: `ttl = 1`, refused unless `envelope.source` is the transport peer
  and the destination is this node. A broadcast challenge is refused.
- One guess per nonce (30 s), one attempt per peer per 120 s, 256 outstanding
  at most — and at capacity the table refuses rather than evicting a live
  challenge. A fourth rate-limit book bounds the exchange at 30 messages an
  hour per peer, flat, because this path runs before any trust exists.
- `config.group_seed` is a 32-byte hex **key**, not a passphrase, and nothing
  derives one from a phrase yet: the app never joins a group at all (T-51).

## Crate Dependency Order

```
mycelium-protocol
    ↓
mycelium-crypto        mycelium-storage
    ↓                        ↓
        mycelium-core
    ↓            ↓              ↓
mycelium-node  mycelium-meshtastic  mycelium-reticulum
    ↓
mycelium-api
    ↓            ↓
mycelium-daemon  mycelium-ffi
```

The `mycelium-node` **binary** lives in `crates/mycelium-daemon` (ADR-004),
because `mycelium-api` depends on the node library. Run it with
`cargo run -p mycelium-daemon`.

## Current State

v0.1, pre-release. Verified 2026-11-18: 649 tests pass, clippy clean, fmt
clean, `flutter analyze` clean.

- 10 Rust crates (32.1k lines of `src` outside the test modules), 49 Dart
  files / 14 screens.
- Local API: 38 REST endpoints (31 paths, 9 modules) + WebSocket with 7 event
  types, bearer token at `<data_dir>/api.token` (ADR-006).
- Everything in the v0.1 scope is implemented. What remains is hardening of
  shipped features, validation against real hardware, and v0.2 adapter work.
- **See [`ROADMAP.md`](ROADMAP.md) for the authoritative list of open work** —
  prioritised P0/P1/P2. T-06, T-07, T-09, T-10 and T-11 landed on 2026-11-10.
  Do not re-derive the list from the code; update it as tasks land.

The highest-priority open items (all P0, all defects in shipped features):
the app never joining a group at all (`T-51` — the seed-phrase screen stores
the phrase locally and nothing reads it), emergency co-signer signatures
(`T-05`, wire format and verification landed; collecting co-signatures is not
built), identity key at rest (`T-08`).

Landed: T-36 on 2026-11-12 (ADR-013); T-37, T-39 and T-35 on 2026-11-14
(ADR-014, ADR-022, ADR-015); T-38 on 2026-11-15 (ADR-016) — persisted DHT
high-water marks, so a replayed record cannot roll an address back once the
newer one has been evicted, with `T-44` for what it left behind; T-34 on
2026-11-16 (ADR-021) — BLE and Wi-Fi Direct prove peer identity instead of
asserting it, in Rust and both platform bridges at once, with `T-47` for the
two transports (BT Classic, LoRa) that still assert one and `T-48` for link
names that are not unique across a reconnection; T-01 on 2026-11-16
(ADR-018, ADR-023) — every FFI function is panic-guarded, blocking calls refuse
re-entrancy, the node handle is reference-counted and
`mycelium_set_node_display_name` renames the running node, with `T-49` for the
rename not surviving a restart.
T-04 on 2026-11-17 (ADR-019) — a beacon's group hint earns a challenge rather
than a vouch, and the vouch waits for `HMAC(proof_key, nonce ‖ verifier ‖
responder)`, with `T-51` for the app path that never advertises a hint in the
first place, `T-52` for the unstretched passphrase derivation behind it and
`T-53` for vouches being stored unsigned.
T-56 on 2026-11-18 (ADR-021) — the Wi-Fi Direct bridge keeps the sixteen-socket
bound it was always documented to keep. A slot is a token, so the count cannot
leak upward when a path returns early or downward when `stop()` runs under live
readers; it carries the socket it counts, so a stop closes what it drops; and it
carries the generation it was taken in, read where the work was justified rather
than where it runs, so nothing accepted by a stopped service is admitted by its
replacement. `LinkBudget` brings the Kotlin bridges their first unit tests
(`make android-test`), which cover the accounting and not the call sites.
`T-40` collects four LoRa defects found reviewing
ADR-008 against the code. `T-41` and `T-42` are what T-35 left behind — the
unconfirmed-handshake record is in memory, so a restart loses both the sweep
and a late rejection, and receipts are unauthenticated, so confirming a
handshake needs an acknowledgement the peer cannot forge.
