# ADR-003: Wi-Fi Direct Transport

## Status

Accepted

## Context

BLE transport provides reliable short-range mesh communication but is limited to ~1 Mbps throughput with a 512-byte MTU. For scenarios involving larger payloads (file sharing, images, voice notes) or higher-density mesh networks, a higher-bandwidth transport is needed. Wi-Fi Direct provides ~50 Mbps within ~200m range without requiring infrastructure Wi-Fi.

The Rust `WifiDirectTransport` already implements the `Transport` trait, and FFI functions exist for event injection (`mycelium_wifi_on_peer_connected/disconnected/data_received`). What was missing was the outbox polling mechanism, the Android platform service, and the Dart bridge layer.

## Decision

Implement Wi-Fi Direct transport using:

1. **Android WifiP2pManager API** for discovery and group formation
2. **Bonjour/mDNS service discovery** (`_mycelium._tcp`) to find only Mycelium devices
3. **TCP sockets** over the Wi-Fi Direct group for data transfer (no fragmentation needed)
4. **Outbox polling pattern** (same as BLE) for Rust-to-platform sends at 50ms intervals

### TCP Wire Protocol

Over the Wi-Fi Direct group's TCP connection:
- 1-byte type + 4-byte big-endian length + variable payload
- Hello (0x01): 32-byte node ID exchange after TCP connect
- MeshData (0x02): variable-length mesh payload

### Architecture

```
Android WifiP2pManager (discovery + group formation)
    |
WifiDirectService.kt (TCP sockets over Wi-Fi Direct group)
    |  EventChannel                    ^  MethodChannel (sendData)
WifiDirectManager.dart (Dart bridge)
    |  FFI event injection             ^  FFI outbox polling (50ms)
WifiDirectTransport (Rust)
    |
TransportManager -> Node event loop -> AODV routing
```

### Group Owner / Group Client roles

Android assigns GO/GC roles during `WifiP2pManager.connect()`. The GO runs a `ServerSocket` on port 9740 and accepts TCP connections. GCs connect to the GO's IP. Both roles use the same `handleClient()` flow: Hello exchange followed by a read loop.

### Transport Selection

The `TransportManager` automatically selects Wi-Fi Direct over BLE when both are available for a peer, since Wi-Fi Direct reports higher `throughput_bps` (6,250,000 vs 125,000) and lower `latency_ms` (10 vs 50) in its `LinkQuality`.

## Consequences

- Devices can exchange large payloads at ~50 Mbps when in Wi-Fi Direct range
- Both BLE and Wi-Fi Direct can operate simultaneously for the same peers
- Additional Android permissions required: `ACCESS_WIFI_STATE`, `CHANGE_WIFI_STATE`, `NEARBY_WIFI_DEVICES`
- Wi-Fi Direct uses more power than BLE; battery management should consider this
- TCP handles segmentation/retransmission, so no application-level fragmentation is needed (unlike BLE)

## Alternatives Considered

1. **Wi-Fi Aware (NAN)**: Requires Android 8.0+ with hardware support, less widely available
2. **Hotspot mode**: Only one device can be AP, doesn't support true P2P
3. **mDNS over existing Wi-Fi**: Requires infrastructure Wi-Fi, defeats the mesh purpose
4. **UDP instead of TCP**: Would need application-level reliability; TCP is simpler for the payloads we send
