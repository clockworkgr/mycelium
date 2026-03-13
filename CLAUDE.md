# Mycelium - AI Assistant Instructions

## Project Overview

Mycelium is an infrastructure-independent mesh communications platform. It uses BLE (Bluetooth Low Energy) and Wi-Fi Direct for local mesh transport, Signal Protocol cryptography (X3DH + Double Ratchet) for end-to-end encryption, AODV reactive routing for multi-hop, and DTN spray-and-wait for delay-tolerant delivery. The architecture is a standalone Rust daemon exposing a local WebSocket + REST API, with the Flutter app and future clients connecting as API consumers.

## Before Starting Work

**Always read these documents first** to understand context:

1. `MYCELIUM_SPEC.md` — Protocol specification (wire format, crypto, routing)
2. `ARCHITECTURE.md` — Comprehensive codebase documentation (all crates, all modules)
3. `IMPLEMENTATION_SPEC.md` — Current implementation roadmap and design decisions
4. `CONTRIBUTING.md` — Build setup, test commands, project structure
5. `REMAINING_WORK.md` — Task tracking with completion status
6. `docs/adr/` — Architecture Decision Records for past decisions

## Build & Test

### Rust

```bash
# Environment setup (macOS without Xcode license)
export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
export DEVELOPER_DIR=/Library/Developer/CommandLineTools

# Build and test
make build        # or: cargo build
make test         # or: cargo test
make lint         # or: cargo fmt --check && cargo clippy -- -D warnings

# Android cross-compilation
make android      # or: ./scripts/build-android.sh
```

### Flutter

```bash
make flutter-get      # flutter pub get
make flutter-gen      # dart run ffigen (after C header changes)
make flutter-analyze  # flutter analyze
make flutter-apk      # flutter build apk --debug
```

### Running Tests

- `cargo test` runs all 186 workspace tests
- Some `mycelium-node` integration tests take 60+ seconds (DTN fallback tests)
- Use `cargo test -p <crate>` to test a single crate
- Use `RUST_LOG=debug cargo test` for tracing output

---

## Pre-Commit Checklist (MANDATORY)

**Every commit MUST complete ALL of the following steps.** Do not skip any step. Do not commit if any step fails.

### Step 1: Code Quality Gates

Run these commands and verify they all pass with zero errors:

```bash
cargo fmt             # Auto-format all Rust code
cargo clippy -- -D warnings   # Zero warnings allowed
cargo test            # All workspace tests must pass
```

If any test fails, fix the issue before proceeding. If clippy has warnings, fix them. Do not use `--allow` flags or `#[allow(...)]` annotations to suppress legitimate warnings.

### Step 2: Flutter Analysis (if Dart files changed)

If any Flutter/Dart files were modified:

```bash
cd flutter && flutter analyze   # Zero issues allowed
```

### Step 3: Documentation Updates

**Every code change requires corresponding documentation updates in the SAME commit.** This is not optional. Check each item below and update if applicable:

#### ARCHITECTURE.md
- [ ] **New module/file added?** → Add to Section 2 (Repository Structure) file tree
- [ ] **New struct, trait, or enum?** → Document in the relevant crate section
- [ ] **New REST endpoint?** → Add to Section 10 (mycelium-api) endpoint table
- [ ] **New WebSocket event?** → Add to Section 10 WebSocket subsection
- [ ] **New request/response type?** → Mention in Section 10 Key Types
- [ ] **New transport?** → Add to Section 7 (mycelium-core) with description
- [ ] **New wire payload type?** → Add to Section 5 payload type table AND Section 15 wire format reference
- [ ] **New FFI function?** → Update function count and add to Section 11 function group table
- [ ] **New test(s)?** → Update test counts in Section 18 (Test Coverage) for the affected crate AND the total
- [ ] **New Dart file/screen?** → Update Section 12 (Flutter App)
- [ ] **New dependency?** → Update Section 3 (Dependency Graph) if relevant
- [ ] **New HKDF info string?** → Add to Section 16 info strings table
- [ ] **Changed beacon format?** → Update Section 9 beacon subsection
- [ ] **Changed config fields?** → Update Section 9 configuration subsection
- [ ] **Spec compliance changed?** → Update Section 19 (Spec Compliance Matrix)

#### REMAINING_WORK.md
- [ ] **Completed a task?** → Mark the checkbox `[x]` and update the Task Count Summary table at the bottom

#### IMPLEMENTATION_SPEC.md
- [ ] **Completed a phase?** → Update the phase status and description in Section 2
- [ ] **Made a design decision?** → Update the relevant section

#### CONTRIBUTING.md
- [ ] **Test count changed?** → Update the test count in the Building section
- [ ] **New crate or directory?** → Update the Project Structure tree

#### CLAUDE.md (this file)
- [ ] **Test count changed?** → Update the count in "Running Tests" and "Current State"
- [ ] **New payload types?** → Update Wire Format bullet
- [ ] **New HKDF info strings?** → Update Crypto bullet
- [ ] **Major feature completed?** → Update "Current State" section

#### README.md
- [ ] **New major feature?** → Update Features section
- [ ] **Test count changed?** → Update counts in Quick Start and Project Structure
- [ ] **New endpoint group?** → Update REST Endpoints table
- [ ] **New WebSocket event?** → Update WebSocket section
- [ ] **New transport?** → Update Transport Layer table
- [ ] **Completion percentage changed?** → Update Status section

#### C Header + Dart Bindings (if FFI changed)
- [ ] **New FFI function?** → Update `crates/mycelium-ffi/include/mycelium.h`
- [ ] **Header changed?** → Regenerate Dart bindings: `cd flutter && dart run ffigen --config ffigen.yaml`

### Step 4: Commit

```bash
# Stage specific files (never use `git add -A` or `git add .`)
git add <specific files>

# Commit with descriptive message
git commit --no-gpg-sign -m "<scope>: <description>

<body explaining what changed and why>

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

**Commit message rules:**
- Format: `<scope>: <description>`
- Scopes: `protocol`, `crypto`, `core`, `storage`, `node`, `api`, `ffi`, `flutter`, `ble`, `docs`, `build`, `test`
- Description: imperative mood, lowercase, no period ("add X" not "Added X.")
- Body: explain the "what" and "why", not just the "how"
- Multi-scope changes: use the primary scope, mention others in the body
- Reference ADRs when applicable: `(ADR-001)`
- Reference task numbers when applicable: `(task 14.2)`

### Step 5: Verify

After committing, run `cargo test` one more time to confirm the commit is clean.

---

## Implementation Rules

### Architecture Decision Records (ADRs)

- **Create an ADR** whenever making a significant implementation decision (new crate, library choice, protocol change, API design).
- Store in `docs/adr/NNN-short-title.md` using the template at `docs/adr/000-template.md`.
- Reference the ADR in commit messages: `api: add axum WebSocket server (ADR-001)`
- ADRs are numbered sequentially. Check existing ones before creating a new one.

### Code Quality

- Run `cargo clippy -- -D warnings` — no warnings allowed.
- Run `cargo fmt --check` — code must be formatted.
- Write tests for new functionality. Follow existing test patterns in each crate.
- Do not add unnecessary dependencies. Check if existing workspace deps cover the need.
- Do not introduce `unsafe` code outside of `mycelium-ffi`. The FFI crate is the only place `unsafe` is expected.

### Testing Requirements

- **New Rust function/module** → Write at least one test
- **New REST endpoint** → Add integration test in `crates/mycelium-api/tests/api_test.rs`
- **New wire payload type** → Add serialization roundtrip test in `crates/mycelium-protocol/src/wire.rs`
- **New transport** → Add lifecycle test (start/stop/send)
- **Bug fix** → Add regression test proving the fix works

---

## Key Technical Details

### Crypto

- Ed25519 signing keys + X25519 DH keys (converted via SHA-512 of seed)
- X3DH KDF info string: `"MyceliumX3DH"`
- Double Ratchet AEAD info string: `"MyceliumAEAD"`
- 8 HKDF info strings for domain separation (see ARCHITECTURE.md section 16), including `"MyceliumGroupDiscovery"` for seed phrase groups

### Database

- SQLCipher with key derived from identity: `SHA-256("mycelium-db-key:" || identity_bytes)`
- Feature flag: `bundled-sqlcipher-vendored-openssl` (bundles OpenSSL for cross-compilation)
- 12 tables: schema_version, messages, sessions, contacts, vouches, prekey_cache, our_prekeys, dtn_store, channels, channel_messages, channel_subscriptions, config

### Android Cross-Compilation

- Homebrew rustc can shadow rustup — build scripts prepend rustup toolchain bin to PATH
- `CC_*`, `AR_*`, `RANLIB_*` env vars must be set per target for OpenSSL
- NDK toolchain bin must be on PATH for OpenSSL's Makefile
- NDK version pinned to `27.0.12077973`

### BLE Transport

- Dual-role GATT (server + client) with 4 characteristics
- Fragmentation protocol: 1-byte header (0x01=first, 0x02=last, 0x03=single)
- Outbox polling pattern: Dart polls Rust VecDeque at 50ms via FFI
- Identity characteristic (UUID ...7894) solves BLE Random Private Address mapping

### Wire Format

- 106-byte envelope header + variable payload
- 17 payload types (see MYCELIUM_SPEC.md section 5): 12 original + channel (4) + emergency (1)

## Crate Dependency Order

```
mycelium-protocol (no internal deps)
    ↓
mycelium-crypto (depends on protocol)
    ↓
mycelium-core (depends on protocol, crypto, storage)
    ↓
mycelium-storage (depends on protocol, crypto)
    ↓
mycelium-node (depends on all above)
    ↓         ↓
mycelium-ffi  mycelium-api (depends on all above; axum, tower-http, hex)
```

## Current State

- 7 Rust crates with 186 passing tests
- Phases 1-13 complete (see REMAINING_WORK.md for detailed status, 124/146 tasks = 85%)
- `mycelium-api` crate: Local REST + WebSocket API server (axum, JSON, See ADR-001)
  - REST: 47 endpoints across 9 route modules (node, messages, conversations, contacts, groups, channels, prekeys, emergency, network)
  - WebSocket: `/v1/ws` with 6 event types + protocol subscriptions
  - Default bind: `127.0.0.1:9735`
- Flutter app: 47 Dart files, 14 screens, REST API + WebSocket as primary data interface
  - Android: BLE + Wi-Fi Direct transports working between phones
  - iOS: BLE transport with CoreBluetooth dual-role GATT, LoRa BLE bridge, background restoration
  - Onboarding flow, groups, channels, emergency broadcasts, debug panel
  - Notifications with active chat suppression (Android + iOS)
- AODV routing with supernode route preference, multi-hop tested (3-4 node mock tests)
- DTN spray-and-wait with 72h TTL, L=8 spray copies
- Delivery receipts working end-to-end (Rust → WS push → Flutter UI)
- LoRa: Rust transport complete, BLE bridge on Android + iOS, platform LoRa service on both
- BT Classic: Rust transport complete, platform bridges not started
- TransportPlugin API: trait + registry + config complete, no adapters yet
- Supernode mode: `--supernode` CLI flag, 2GB DTN, faster beacons, prekey cache API
- Next: External radio platform bridges, OpenWRT packaging, protocol adapters (see REMAINING_WORK.md)
