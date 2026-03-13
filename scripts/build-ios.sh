#!/usr/bin/env bash
#
# Build Mycelium FFI library for iOS (aarch64-apple-ios).
#
# Prerequisites:
#   1. Xcode installed with iOS SDK
#   2. Rust target installed:
#      rustup target add aarch64-apple-ios
#
# Usage:
#   ./scripts/build-ios.sh [--release]
#
# Output:
#   target/aarch64-apple-ios/{debug,release}/libmycelium_ffi.a
#   ios-libs/libmycelium_ffi.a

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# iOS builds require the Xcode iOS SDK (not CommandLineTools macOS SDK).
# Try xcrun first; fall back to manual Xcode path.
IOS_SDK="$(xcrun --show-sdk-path --sdk iphoneos 2>/dev/null || true)"
if [[ -z "$IOS_SDK" || ! -d "$IOS_SDK" ]]; then
    # Fallback: look for Xcode.app directly
    IOS_SDK="/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk"
fi
if [[ ! -d "$IOS_SDK" ]]; then
    echo "ERROR: iOS SDK not found. Install Xcode with iOS platform support."
    exit 1
fi
export SDKROOT="$IOS_SDK"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

# Set minimum iOS deployment target (must match Podfile / Xcode project).
export IPHONEOS_DEPLOYMENT_TARGET="15.5"

# Ensure rustup-managed toolchain is on PATH (ahead of Homebrew).
# When Homebrew rustc is on PATH, it won't have cross-compilation targets.
RUSTUP_TOOLCHAIN_BIN="$(rustup which cargo 2>/dev/null | xargs dirname 2>/dev/null || true)"
if [[ -n "$RUSTUP_TOOLCHAIN_BIN" && -d "$RUSTUP_TOOLCHAIN_BIN" ]]; then
    export PATH="$RUSTUP_TOOLCHAIN_BIN:$PATH"
elif [[ -d "$HOME/.cargo/bin" ]]; then
    export PATH="$HOME/.cargo/bin:$PATH"
fi

# --- Config ---
TARGET="aarch64-apple-ios"
PROFILE="debug"
PROFILE_DIR="debug"

if [[ "${1:-}" == "--release" ]]; then
    PROFILE="release"
    PROFILE_DIR="release"
fi

echo "Target: $TARGET"
echo "Profile: $PROFILE"

# --- Check target is installed ---
if ! rustup target list --installed | grep -q "$TARGET"; then
    echo "Installing Rust target: $TARGET"
    rustup target add "$TARGET"
fi

# --- Build ---
cd "$PROJECT_ROOT"

BUILD_FLAGS="-p mycelium-ffi"
if [[ "$PROFILE" == "release" ]]; then
    BUILD_FLAGS="$BUILD_FLAGS --release"
fi

echo ""
echo "=== Building $TARGET ==="

if cargo build $BUILD_FLAGS --target "$TARGET" 2>&1; then
    # Copy static library to ios-libs
    OUT_DIR="$PROJECT_ROOT/ios-libs"
    mkdir -p "$OUT_DIR"
    cp "$PROJECT_ROOT/target/$TARGET/$PROFILE_DIR/libmycelium_ffi.a" "$OUT_DIR/"
    echo "  -> $OUT_DIR/libmycelium_ffi.a"

    # Copy header
    HEADER_DIR="$OUT_DIR/include"
    mkdir -p "$HEADER_DIR"
    cp "$PROJECT_ROOT/crates/mycelium-ffi/include/mycelium.h" "$HEADER_DIR/"
    echo "  -> $HEADER_DIR/mycelium.h"

    # Copy to CocoaPods pod directory for Flutter integration
    POD_DIR="$PROJECT_ROOT/flutter/ios/MyceliumFFI/Frameworks"
    mkdir -p "$POD_DIR/include"
    cp "$PROJECT_ROOT/target/$TARGET/$PROFILE_DIR/libmycelium_ffi.a" "$POD_DIR/"
    echo "  -> $POD_DIR/libmycelium_ffi.a"
    cp "$PROJECT_ROOT/crates/mycelium-ffi/include/mycelium.h" "$POD_DIR/include/"
    echo "  -> $POD_DIR/include/mycelium.h"

    echo ""
    echo "Build successful."
    echo "Output: $OUT_DIR/"
    echo "CocoaPods: $POD_DIR/"
else
    echo "  FAILED: $TARGET"
    exit 1
fi
