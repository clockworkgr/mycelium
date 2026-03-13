#!/usr/bin/env bash
#
# Cross-compile Mycelium node daemon for OpenWRT targets.
#
# Builds a static musl binary suitable for OpenWRT routers.
# The output is a standalone binary with no runtime dependencies.
#
# Prerequisites:
#   1. Rust musl targets installed:
#      rustup target add aarch64-unknown-linux-musl
#      rustup target add mipsel-unknown-linux-musl
#      rustup target add x86_64-unknown-linux-musl
#   2. musl cross-compilation toolchains:
#      - aarch64: aarch64-linux-musl-gcc (e.g., from musl-cross-make or brew)
#      - mipsel:  mipsel-linux-musl-gcc
#      - x86_64:  x86_64-linux-musl-gcc (or just musl-gcc on x86_64 hosts)
#
# Usage:
#   ./scripts/build-openwrt.sh [--release] [--target TARGET]
#
# Targets:
#   aarch64   ARM64 routers (GL.iNet GL-MT6000, NanoPi R4S, etc.)
#   mipsel    MIPS little-endian (classic OpenWRT devices: Linksys, TP-Link)
#   x86_64    x86_64 VMs and x86 routers
#   all       Build all targets (default)
#
# Output:
#   target/<triple>/{debug,release}/mycelium-node
#   openwrt-bin/<arch>/mycelium-node
#
# Example config for target device:
#   scp openwrt-bin/aarch64/mycelium-node root@router:/usr/bin/
#   ssh root@router "chmod +x /usr/bin/mycelium-node && mycelium-node --supernode"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Use Command Line Tools SDK when Xcode license is not accepted
export SDKROOT="${SDKROOT:-/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk}"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Library/Developer/CommandLineTools}"

# Ensure rustup-managed toolchain is on PATH
RUSTUP_TOOLCHAIN_BIN="$(rustup which cargo 2>/dev/null | xargs dirname 2>/dev/null || true)"
if [ -n "$RUSTUP_TOOLCHAIN_BIN" ]; then
    export PATH="$RUSTUP_TOOLCHAIN_BIN:$PATH"
fi

# --- Configuration ---

PROFILE="debug"
TARGET="all"
OUTPUT_DIR="$PROJECT_ROOT/openwrt-bin"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --release)
            PROFILE="release"
            shift
            ;;
        --target)
            TARGET="$2"
            shift 2
            ;;
        --help|-h)
            head -35 "$0" | tail -30
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

CARGO_FLAGS="-p mycelium-node"
if [ "$PROFILE" = "release" ]; then
    CARGO_FLAGS="$CARGO_FLAGS --release"
fi

# --- Target definitions ---

declare -A TARGETS
TARGETS[aarch64]="aarch64-unknown-linux-musl"
TARGETS[mipsel]="mipsel-unknown-linux-musl"
TARGETS[x86_64]="x86_64-unknown-linux-musl"

declare -A LINKERS
LINKERS[aarch64]="aarch64-linux-musl-gcc"
LINKERS[mipsel]="mipsel-linux-musl-gcc"
LINKERS[x86_64]="x86_64-linux-musl-gcc"

# --- Build functions ---

build_target() {
    local arch="$1"
    local triple="${TARGETS[$arch]}"
    local linker="${LINKERS[$arch]}"

    echo "=== Building for $arch ($triple) ==="

    # Check if target is installed
    if ! rustup target list --installed | grep -q "$triple"; then
        echo "Installing Rust target: $triple"
        rustup target add "$triple"
    fi

    # Check for linker
    if ! command -v "$linker" &>/dev/null; then
        echo "WARNING: Linker $linker not found. Attempting build anyway."
        echo "  Install via: brew install filosottile/musl-cross/musl-cross (macOS)"
        echo "  Or:          apt install musl-tools gcc-aarch64-linux-gnu (Linux)"
    fi

    # Set linker for the target
    local linker_env_var
    linker_env_var="CARGO_TARGET_$(echo "$triple" | tr '[:lower:]-' '[:upper:]_')_LINKER"
    export "$linker_env_var=$linker"

    # SQLCipher: use vendored OpenSSL for cross-compilation
    export SQLCIPHER_LIB_DIR=""
    export OPENSSL_STATIC=1

    # Build
    cd "$PROJECT_ROOT"
    cargo build $CARGO_FLAGS --target "$triple"

    # Copy output
    local bin_dir="$OUTPUT_DIR/$arch"
    mkdir -p "$bin_dir"
    cp "target/$triple/$PROFILE/mycelium-node" "$bin_dir/mycelium-node"

    local size
    size=$(du -h "$bin_dir/mycelium-node" | cut -f1)
    echo "  Output: $bin_dir/mycelium-node ($size)"
    echo ""
}

# --- Main ---

echo "Mycelium OpenWRT Cross-Compilation"
echo "  Profile: $PROFILE"
echo "  Target:  $TARGET"
echo ""

mkdir -p "$OUTPUT_DIR"

if [ "$TARGET" = "all" ]; then
    for arch in aarch64 mipsel x86_64; do
        build_target "$arch"
    done
elif [[ -v "TARGETS[$TARGET]" ]]; then
    build_target "$TARGET"
else
    echo "Unknown target: $TARGET"
    echo "Available: aarch64, mipsel, x86_64, all"
    exit 1
fi

echo "=== Build complete ==="
echo "Binaries in: $OUTPUT_DIR/"
ls -lh "$OUTPUT_DIR"/*/mycelium-node 2>/dev/null || true
