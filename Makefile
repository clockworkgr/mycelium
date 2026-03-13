.PHONY: build build-release test lint clean android android-release \
       ios ios-release \
       openwrt openwrt-release \
       flutter-get flutter-gen flutter-analyze flutter-apk flutter-run \
       check help

# --- Rust ---

build:
	cargo build

build-release:
	cargo build --release

test:
	cargo test

lint:
	cargo fmt --check
	cargo clippy -- -D warnings

fmt:
	cargo fmt

clean:
	cargo clean
	rm -rf android-libs/ openwrt-bin/

# --- Android Cross-Compilation ---

android:
	./scripts/build-android.sh

android-release:
	./scripts/build-android.sh --release

# --- iOS Cross-Compilation ---

ios:
	./scripts/build-ios.sh

ios-release:
	./scripts/build-ios.sh --release

# --- OpenWRT Cross-Compilation ---

openwrt:
	./scripts/build-openwrt.sh

openwrt-release:
	./scripts/build-openwrt.sh --release

# --- Flutter ---

flutter-get:
	cd flutter && flutter pub get

flutter-gen:
	cd flutter && dart run ffigen --config ffigen.yaml

flutter-analyze:
	cd flutter && flutter analyze

flutter-apk:
	cd flutter && flutter build apk --debug

flutter-apk-release:
	cd flutter && flutter build apk --release

flutter-run:
	cd flutter && flutter run

flutter-test:
	cd flutter && flutter test

# --- Combined ---

check: lint test flutter-analyze
	@echo "All checks passed."

# --- Help ---

help:
	@echo "Mycelium Build Targets:"
	@echo ""
	@echo "  Rust:"
	@echo "    build            Debug build (host)"
	@echo "    build-release    Release build (host)"
	@echo "    test             Run all Rust tests"
	@echo "    lint             cargo fmt --check + clippy"
	@echo "    fmt              cargo fmt (auto-fix)"
	@echo "    clean            Remove build artifacts"
	@echo ""
	@echo "  Android:"
	@echo "    android          Cross-compile FFI for Android (debug)"
	@echo "    android-release  Cross-compile FFI for Android (release)"
	@echo ""
	@echo "  iOS:"
	@echo "    ios              Cross-compile FFI for iOS (debug)"
	@echo "    ios-release      Cross-compile FFI for iOS (release)"
	@echo ""
	@echo "  OpenWRT:"
	@echo "    openwrt          Cross-compile node for OpenWRT (debug)"
	@echo "    openwrt-release  Cross-compile node for OpenWRT (release)"
	@echo ""
	@echo "  Flutter:"
	@echo "    flutter-get      flutter pub get"
	@echo "    flutter-gen      Regenerate FFI bindings (ffigen)"
	@echo "    flutter-analyze  flutter analyze"
	@echo "    flutter-apk      Build debug APK"
	@echo "    flutter-run      Run on connected device"
	@echo "    flutter-test     Run Flutter tests"
	@echo ""
	@echo "  Combined:"
	@echo "    check            Run lint + test + flutter-analyze"
	@echo ""
	@echo "  Prerequisites: see CONTRIBUTING.md"
