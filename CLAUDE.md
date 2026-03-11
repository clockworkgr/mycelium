# Mycelium - AI Assistant Instructions

## Project Overview

Mycelium is an infrastructure-independent mesh communications platform. It uses BLE (Bluetooth Low Energy) for local mesh transport, Signal Protocol cryptography (X3DH + Double Ratchet) for end-to-end encryption, AODV reactive routing for multi-hop, and DTN spray-and-wait for delay-tolerant delivery. The long-term architecture is a standalone Rust daemon exposing a local WebSocket + REST API, with apps connecting as clients.

## Before Starting Work

**Always read these documents first** to understand context:

1. `MYCELIUM_SPEC.md` — Protocol specification (wire format, crypto, routing)
2. `ARCHITECTURE.md` — Comprehensive codebase documentation (all crates, all modules)
3. `IMPLEMENTATION_SPEC.md` — Current implementation roadmap and design decisions
4. `CONTRIBUTING.md` — Build setup, test commands, project structure
5. `docs/adr/` — Architecture Decision Records for past decisions

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

- `cargo test` runs all 133+ workspace tests
- Some `mycelium-node` integration tests take 60+ seconds (DTN fallback tests)
- Use `cargo test -p <crate>` to test a single crate
- Use `RUST_LOG=debug cargo test` for tracing output

## Implementation Rules

### Commits

- **One feature per commit.** Each commit must leave tests passing and build green.
- **Test before committing.** Run `cargo test` and `cargo clippy` before every commit.
- **Commit message format:** `<scope>: <description>`
  - Scopes: `protocol`, `crypto`, `core`, `storage`, `node`, `ffi`, `api`, `flutter`, `ble`, `docs`, `build`, `test`
  - Example: `api: implement REST endpoints for message CRUD`
- **Update documentation in the same commit** as the feature. When modifying a module, update the relevant section of `ARCHITECTURE.md` to keep it accurate.

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

### Documentation

- Keep `ARCHITECTURE.md` up to date. When adding a new module, struct, or FFI function, document it in the relevant section.
- Update `IMPLEMENTATION_SPEC.md` when completing a phase or making design changes.
- Add doc comments (`///`) to public Rust APIs.
- Update the C header (`crates/mycelium-ffi/include/mycelium.h`) when adding FFI functions, then regenerate Dart bindings.

## Key Technical Details

### Crypto

- Ed25519 signing keys + X25519 DH keys (converted via SHA-512 of seed)
- X3DH KDF info string: `"MyceliumX3DH"`
- Double Ratchet AEAD info string: `"MyceliumAEAD"`
- 7 HKDF info strings for domain separation (see ARCHITECTURE.md section 15)

### Database

- SQLCipher with key derived from identity: `SHA-256("mycelium-db-key:" || identity_bytes)`
- Feature flag: `bundled-sqlcipher-vendored-openssl` (bundles OpenSSL for cross-compilation)

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
- 12 payload types (see MYCELIUM_SPEC.md section 5)

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
    ↓
mycelium-ffi (depends on all above)
```

## Current State

- 6 Rust crates with 133+ passing tests
- Flutter app with BLE transport working between 2 phones
- AODV routing implemented but multi-hop untested with real devices
- DTN spray-and-wait implemented with 72h TTL, L=8 spray copies
- Delivery receipts implemented in Rust but not confirmed working end-to-end in Flutter
- Next: WebSocket + REST API (see IMPLEMENTATION_SPEC.md Phase 1)
