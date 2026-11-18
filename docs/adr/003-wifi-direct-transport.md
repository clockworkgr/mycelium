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

## Note (2026-11-18, T-56)

"The GO runs a `ServerSocket` on port 9740 and accepts TCP connections" was
not reliably true of the implementation, for a reason that has nothing to do
with the decision above and everything to do with how the listener was kept.

The accept loop broke out of itself on any accept error, and left the service's
`serverSocket` field pointing at the dead listener. `startServer` returns early
whenever that field is set, so **one accept error stopped a group owner
listening for the rest of that group's life** — silently, because the loop logs
the error and exits, and nothing retries. Recovery needed the group to drop:
`handleGroupDisconnected` clears the field, so the next formation could listen
again, but within one group it never could, however many connection-changed
broadcasts arrived. The loop now owns its listener, closes it, and clears the
field if it is still its own, so a group that is still up gets a listener back
at its next connection event.

An earlier draft of this note said "for the life of the service", which is
wrong: the disconnect path already cleared the field. The window is one group,
not the process.

Every mutation of the field that holds the listener, and every check a decision
rests on, is also serialised under the bridge's lifecycle lock now: the
decision to listen, the bind and the publish as one critical section, and the
two teardowns that read it in order to close it. Those were separate steps
written from three different threads (the accept task, the connection-info
callback and `stop()`), which let a listener bind and escape a teardown while
still holding port 9740, and let one thread's clear erase another's live
listener. Both ended with no listener and a port that nothing could release.

An accept loop closes the listener it owns in the same critical section as it
unpublishes it: closing first left the field pointing at a dead listener, and
`startServer` returns early whenever that field is set, so a callback arriving
in the window scheduled nothing at all.

`startServer`'s early-out is the one read outside the lock, and the field it
reads means "published and not yet cleaned up", not "healthy" — a listener that
has just failed its accept is still published until its `finally` runs. A
callback in that instant schedules nothing, so recovery waits for the next
connection event or the next group. Restoring a failed listener without waiting
for an external event is **ROADMAP T-58**; this note's fix is what makes such a
recovery possible at all, since before it the field stayed set for good.

One more thing this record implies and the bridge did not keep: **"GCs connect
to the GO's IP"** says a group client does not listen. A `startServer` task
queued by a group in which this device was the owner survived that group's
disconnect — nothing invalidated work the old group had justified — so it could
bind afterwards and leave the device listening on 9740 while the *next* group
made it a client. The disconnect path now ends the group's work, closing the
listener, dropping the links and starting a new generation that such a task
fails.

The GO/GC role split, the port, and both roles sharing one `handleClient` flow
are unchanged. ROADMAP T-56 was about ADR-021's socket bound; this part of it
belongs here, because it is this record's claim that was not kept.

Appended rather than edited in place, because these records are append-only.
