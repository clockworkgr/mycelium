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
   ADR-010). Append-only; never rewrite one.
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
```

Flutter SDK is at `/Volumes/Tendermint/flutter/` and is not on `PATH` by
default.

### Running tests

- `cargo test` runs the whole workspace (currently 308 tests).
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
- 8 HKDF info strings for domain separation (spec §5.6): `MyceliumX3DH`,
  `MyceliumRatchet`, `MyceliumAEAD`, `MyceliumSafetyNumber`,
  `MyceliumGroupMK`, `MyceliumGroupCK`, `MyceliumGroupAEAD`,
  `MyceliumGroupDiscovery`.
- Double Ratchet `decrypt()` and group decrypt are transactional: state is
  committed only after the AEAD tag verifies.

### Database (spec §15)

- SQLCipher. Key is `SHA-256("mycelium-db-key:" || identity_bytes)`.
- Feature flag `bundled-sqlcipher-vendored-openssl` (vendors OpenSSL for
  cross-compilation).
- 12 tables. Groups and prekey state are opaque blobs in `config`, not their
  own tables.

### Wire format (spec §4)

- 106-byte envelope header + variable payload, little-endian throughout.
- 17 payload types. `SenderKeyDistribution` (`0x71`) is valid only inside a
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

### BLE transport (spec §8.4)

- Dual-role GATT (server + client), 4 characteristics.
- Fragmentation: 1-byte header (`0x01` first, `0x02` last, `0x03` single,
  `0x00` middle).
- Outbox polling: Dart polls the Rust `VecDeque` every 50 ms over FFI.
- The Identity characteristic (`…7894`) is what solves BLE Random Private
  Address mapping.

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

v0.1, pre-release. Verified 2026-11-10: 308 tests pass, clippy clean, fmt
clean, `flutter analyze` clean.

- 10 Rust crates (~26.6k lines), 49 Dart files / 14 screens.
- Local API: 38 REST endpoints (31 paths, 9 modules) + WebSocket with 7 event
  types, bearer token at `<data_dir>/api.token` (ADR-006).
- Everything in the v0.1 scope is implemented. What remains is hardening of
  shipped features, validation against real hardware, and v0.2 adapter work.
- **See [`ROADMAP.md`](ROADMAP.md) for the authoritative list of open work** —
  prioritised P0/P1/P2. T-06, T-07, T-10 and T-11 landed on 2026-11-10. Do not
  re-derive the list from the code; update it as tasks land.

The highest-priority open items (all P0, all defects in shipped features): FFI
panic guards (`T-01`), group-discovery proof of possession (`T-04`), emergency
co-signer signatures (`T-05`, wire format and verification landed; collecting
co-signatures is not built), identity key at rest (`T-08`), internet-transport
peer authentication (`T-09`).
