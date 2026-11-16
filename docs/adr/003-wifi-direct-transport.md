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

## Note (2026-11-16, T-34)

ADR-021 replaced this transport's authentication and reshaped its wire
protocol. The decisions above stand — `WifiP2pManager` groups, Bonjour service
discovery, a group owner listening on TCP 9740, both roles sharing one
`handleClient` flow — but three things it specifies are no longer what the code
does.

**The `Hello` is gone.** `Hello (0x01)` carried a bare 32-byte NodeId and the
peer was believed; that is the defect ROADMAP T-34 was about. Identity is now
proved by ADR-011's handshake, carried in the payload of ordinary frames, and
the NodeId is derived from the key the peer signed. The TXT record no longer
advertises a node id prefix either, because nothing unproved identifies a node
any more.

**`MeshData (0x02)` became `Frame (0x02)`**, an opaque frame for the transport
above rather than a mesh payload. This layer does not know what is in it: the
first frames on a socket are a handshake, and everything after them is sealed.

**"TCP handles segmentation, so no fragmentation layer" is no longer true at
the Rust level.** The transport fragments a sealed frame with the shared
6-byte header (ADR-022) before handing the pieces over, so that one
implementation serves BLE and Wi-Fi Direct; TCP still carries each piece whole,
and with a 16 KB fragment that is one frame per message in practice.

**The bridge reports links, not peers**, named by the remote socket endpoint,
and the FFI functions it calls are the link events — `wifi_on_link_{up,down,
data}`, `wifi_dequeue_send` and `wifi_dequeue_link_event` — in place of the
peer events this ADR's design implied. One socket owns one writer thread, so
frames leave a link in the order they were queued; a frame overtaken on a link
is refused by the receiver's counter floor, which is ADR-021's reason for
caring.

Appended rather than edited in place, because these records are append-only.
