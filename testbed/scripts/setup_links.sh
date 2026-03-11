#!/usr/bin/env bash
# Configure network emulation (tc/netem) for testbed links.
# Usage: setup_links.sh <interface> <latency_ms> <loss_pct> <bandwidth_kbps>

set -euo pipefail

IFACE="${1:?Usage: setup_links.sh <interface> <latency_ms> <loss_pct> <bandwidth_kbps>}"
LATENCY="${2:-10}"
LOSS="${3:-0}"
BANDWIDTH="${4:-50000}"

echo "Configuring $IFACE: latency=${LATENCY}ms, loss=${LOSS}%, bandwidth=${BANDWIDTH}kbps"

# Clear existing rules
tc qdisc del dev "$IFACE" root 2>/dev/null || true

# Add netem qdisc for latency and loss
tc qdisc add dev "$IFACE" root handle 1: netem \
    delay "${LATENCY}ms" \
    loss "${LOSS}%"

# Add tbf for bandwidth limiting
tc qdisc add dev "$IFACE" parent 1: handle 2: tbf \
    rate "${BANDWIDTH}kbit" \
    burst 32kbit \
    latency 400ms

echo "Done configuring $IFACE"
