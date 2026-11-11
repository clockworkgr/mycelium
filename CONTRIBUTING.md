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

### iOS Development

1. Install Xcode (v15+ recommended) from the Mac App Store
2. Accept the Xcode license: `sudo xcodebuild -license accept`
3. Install the iOS Rust target:
   ```bash
   rustup target add aarch64-apple-ios
   ```
4. Install CocoaPods:
   ```bash
   gem install cocoapods
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
make test           # Run all 385 workspace tests
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

### iOS Cross-Compilation

```bash
make ios               # Debug build for aarch64-apple-ios
make ios-release       # Release build for aarch64-apple-ios
./scripts/build-ios.sh # Direct invocation (accepts --release)
```

**What the script does:**
1. Ensures `aarch64-apple-ios` target is installed via rustup
2. Builds `mycelium-ffi` as a static library (`.a`)
3. Copies `libmycelium_ffi.a` to `ios-libs/` and `flutter/ios/MyceliumFFI/Frameworks/`
4. Copies `mycelium.h` header alongside the library

**After building, install CocoaPods:**
```bash
cd flutter/ios && pod install
```

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

**Android:**
1. Build and install: `cd flutter && flutter run`
2. Two phones needed for BLE messaging tests
3. Both phones must have Bluetooth and Location enabled
4. Grant all permissions when prompted

**iOS:**
1. Build Rust library: `make ios`
2. Install CocoaPods: `cd flutter/ios && pod install`
3. Build and install: `cd flutter && flutter run` (physical device required — BLE doesn't work in Simulator)
4. Accept Bluetooth permission prompt on first launch
5. Cross-platform testing: iPad + Android phone discover each other over BLE

---

## Project Structure

```
mycelium/
├── crates/
│   ├── mycelium-protocol/    # Wire format types + binary codec (39 tests)
│   ├── mycelium-crypto/      # Ed25519, X3DH, Double Ratchet, Sender Key, WoT, Discovery (53 tests)
│   ├── mycelium-core/        # Transports (BLE/WiFi/LoRa/BT/Internet/Plugin/Mock), AODV, DTN, DHT (77 tests)
│   ├── mycelium-storage/     # SQLCipher database, CRUD, channels (10 tests)
│   ├── mycelium-node/        # Node library: event loop, message pipeline, groups (45 tests)
│   ├── mycelium-api/         # Local REST (38 endpoints, bearer auth) + WebSocket API server (19 tests)
│   ├── mycelium-daemon/      # `mycelium-node` binary: node + API server (ADR-004)
│   ├── mycelium-ffi/         # C FFI bindings for mobile (64 extern functions)
│   ├── mycelium-meshtastic/  # Meshtastic protocol adapter (16 tests)
│   └── mycelium-reticulum/   # Reticulum protocol adapter (21 tests)
├── flutter/                  # Flutter mobile app (49 Dart files, 14 screens)
│   ├── lib/src/
│   │   ├── ffi/              # FFI library loading
│   │   ├── models/           # Data models (NodeId, Message, Contact, Group, etc.)
│   │   ├── providers/        # Riverpod state management (8 providers)
│   │   ├── screens/          # UI screens (14 screens)
│   │   ├── service/          # ApiClient, WsService, MyceliumService, BleManager, etc.
│   │   ├── widgets/          # Reusable UI components (6 widgets)
│   │   └── router/           # GoRouter navigation (6-tab shell + onboarding)
│   ├── android/              # Android platform code (Kotlin BLE, Wi-Fi Direct, LoRa GATT/USB, BT Classic)
│   └── ios/                  # iOS platform code (Swift BLE + LoRa)
├── openwrt/                  # OpenWRT .ipk Makefile, init script, LuCI app
├── testbed/                  # Docker mesh testbed (Dockerfile, compose, scenarios)
├── scripts/                  # Build scripts (build-android.sh, build-ios.sh, build-openwrt.sh)
├── docs/
│   ├── adr/                  # Architecture Decision Records
│   └── plugin-api.md         # Transport plugin development guide
├── MYCELIUM_SPEC.md          # The spec: protocol, crypto, architecture as built
├── ROADMAP.md                # The plan: open work, prioritised
└── CLAUDE.md                 # AI assistant instructions
```

The repository keeps exactly **two** living documents: `MYCELIUM_SPEC.md` for
what Mycelium is and what exists, and `ROADMAP.md` for what does not. ADRs are
an append-only record of decisions and are never rewritten. Resist adding a
third overview document — the ones this replaced had drifted out of sync with
each other and with the code.

---

## Commit Conventions

- One feature per commit. Each commit should leave tests passing and the build green.
- Commit message format: `<scope>: <description>`
  - Scopes: `protocol`, `crypto`, `core`, `storage`, `node`, `api`, `ffi`, `flutter`, `ble`, `docs`, `build`, `test`
  - Example: `core: add multi-hop message forwarding via AODV`
- Reference ADRs in commits when making architectural decisions: `See ADR-001`
- Update documentation in the same commit as the change it describes:
  - behaviour, wire format, crypto, API or architecture changed → `MYCELIUM_SPEC.md`
  - a task is finished, newly scoped, or re-prioritised → `ROADMAP.md`
  - a significant decision was made → a new ADR in `docs/adr/`
  - the test count changed → `CONTRIBUTING.md` and `README.md` (the only two
    places that carry it)

---

## Architecture Decision Records (ADRs)

When making significant implementation decisions, create an ADR in `docs/adr/`:

```bash
cp docs/adr/000-template.md docs/adr/NNN-short-title.md
```

See existing ADRs for format reference. Reference ADRs in commit messages and code comments.
