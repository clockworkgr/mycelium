# Contributing to Mycelium

## Prerequisites

### Rust Toolchain

Install [rustup](https://rustup.rs/) (not Homebrew Rust):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

The project uses `rust-toolchain.toml` to pin the stable channel. rustup will install the correct version automatically.

Verify rustup is first on PATH (not Homebrew):

```bash
which rustc    # Should be ~/.cargo/bin/rustc or ~/.rustup/...
rustc --version
```

### Flutter SDK

Install [Flutter](https://flutter.dev/docs/get-started/install) (v3.29+). Add it to PATH:

```bash
export PATH="$HOME/flutter/bin:$PATH"  # Adjust to your install location
flutter doctor
```

### Android Development

1. Install [Android Studio](https://developer.android.com/studio) or the Android SDK command-line tools
2. Install NDK via SDK Manager. Pin version `27.0.12077973` (required by `path_provider_android`):
   ```bash
   sdkmanager "ndk;27.0.12077973"
   ```
3. Set the NDK path (or let `build-android.sh` auto-detect):
   ```bash
   export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/27.0.12077973"
   ```
4. Install Rust Android targets:
   ```bash
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
   ```

### macOS Notes

If Xcode license is not accepted (or Xcode not installed), use Command Line Tools:

```bash
xcode-select --install
export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
```

---

## Building

### Rust Workspace (host)

```bash
make build          # Debug build
make build-release  # Release build
make test           # Run all 144 workspace tests
make lint           # cargo fmt --check + cargo clippy
```

Or directly:

```bash
cargo build
cargo test
cargo clippy -- -D warnings
```

### Android Cross-Compilation

```bash
make android                   # Debug build for all 3 ABIs
make android-release           # Release build for all 3 ABIs
./scripts/build-android.sh     # Direct invocation (accepts --release)
```

The script auto-generates `.cargo/config.toml` with NDK linker paths. This file is gitignored since it contains machine-specific absolute paths.

**What the script does:**
1. Locates NDK via `$ANDROID_NDK_HOME`, `$NDK_HOME`, or common install paths
2. Generates `.cargo/config.toml` with per-target linker settings
3. Sets `CC_*`, `AR_*`, `RANLIB_*` env vars for OpenSSL cross-compilation
4. Builds `mycelium-ffi` as a shared library for each target
5. Copies `.so` files to `android-libs/<abi>/`

### Flutter App

```bash
make flutter-get     # pub get
make flutter-gen     # Regenerate FFI bindings (ffigen)
make flutter-analyze # dart analyze
make flutter-apk     # Build debug APK (triggers Rust build via Gradle)
```

Or directly:

```bash
cd flutter
flutter pub get
dart run ffigen --config ffigen.yaml  # After any C header changes
flutter analyze
flutter build apk --debug
```

The Gradle build automatically triggers `scripts/build-android.sh --release` before linking JNI libraries. To build the APK without rebuilding Rust:

```bash
cd flutter && flutter build apk --debug --no-build-native-assets
```

### FFI Bindings Regeneration

When the C header (`crates/mycelium-ffi/include/mycelium.h`) changes:

```bash
cd flutter && dart run ffigen --config ffigen.yaml
```

This regenerates `flutter/lib/src/ffi/mycelium_bindings_generated.dart`.

---

## Testing

### Rust Tests

```bash
cargo test                          # All tests
cargo test -p mycelium-core         # Single crate
cargo test -p mycelium-node         # Integration tests (some take 60s+)
cargo test -- --nocapture           # With stdout
RUST_LOG=debug cargo test           # With tracing output
```

### Flutter Tests

```bash
cd flutter && flutter test
```

### On-Device Testing

1. Build and install: `cd flutter && flutter run`
2. Two phones needed for BLE messaging tests
3. Both phones must have Bluetooth and Location enabled
4. Grant all permissions when prompted

---

## Project Structure

```
mycelium/
├── crates/
│   ├── mycelium-protocol/    # Wire format types + binary codec
│   ├── mycelium-crypto/      # Ed25519, X3DH, Double Ratchet, Sender Key
│   ├── mycelium-core/        # Transport trait, BLE/WiFi/Mock, AODV, DTN
│   ├── mycelium-storage/     # SQLCipher database, CRUD operations
│   ├── mycelium-node/        # Node daemon, event loop, message pipeline
│   ├── mycelium-api/         # Local REST + WebSocket API server (See ADR-001)
│   └── mycelium-ffi/         # C FFI bindings for mobile
├── flutter/                  # Flutter mobile app
│   ├── lib/src/
│   │   ├── ffi/              # Generated FFI bindings
│   │   ├── models/           # Data models (NodeId, Message, Contact)
│   │   ├── providers/        # Riverpod state management
│   │   ├── screens/          # UI screens
│   │   ├── service/          # MyceliumService, BleManager
│   │   ├── widgets/          # Reusable UI components
│   │   └── router/           # GoRouter navigation
│   └── android/              # Android platform code (Kotlin BLE)
├── scripts/                  # Build and utility scripts
├── openwrt/                  # OpenWrt supernode package
├── testbed/                  # Docker-based mesh simulation
├── docs/adr/                 # Architecture Decision Records
├── ARCHITECTURE.md           # Comprehensive codebase documentation
├── IMPLEMENTATION_SPEC.md    # Next-phase implementation specification
├── MYCELIUM_SPEC.md          # Protocol specification
└── CLAUDE.md                 # AI assistant instructions
```

---

## Commit Conventions

- One feature per commit. Each commit should leave tests passing and the build green.
- Commit message format: `<scope>: <description>`
  - Scopes: `protocol`, `crypto`, `core`, `storage`, `node`, `ffi`, `flutter`, `ble`, `docs`, `build`, `test`
  - Example: `core: add multi-hop message forwarding via AODV`
- Reference ADRs in commits when making architectural decisions: `See ADR-001`
- Update documentation (ARCHITECTURE.md, etc.) in the same commit as the feature they describe

---

## Architecture Decision Records (ADRs)

When making significant implementation decisions, create an ADR in `docs/adr/`:

```bash
cp docs/adr/000-template.md docs/adr/NNN-short-title.md
```

See existing ADRs for format reference. Reference ADRs in commit messages and code comments.
