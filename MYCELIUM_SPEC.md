# Mycelium Protocol Specification

## Infrastructure-Independent Mesh Communications Platform

**Version:** 0.1-draft
**Date:** 2026-03-09
**License:** GPLv3
**Primary Target:** Privacy-focused communities (activists, journalists, privacy-conscious groups)

---

## 1. Executive Summary

Mycelium is a mobile communications application that operates without reliance on the internet or existing mobile network infrastructure. It creates an ad-hoc mesh network using all available communication radios on standard smartphones, supplemented by OpenWRT routers acting as persistent supernodes and optional external radio hardware (LoRa, ESP32). The protocol is designed for unbounded scale, strong end-to-end encryption, and resilience against network partitions through a hybrid real-time + delay-tolerant networking (DTN) architecture.

---

## 2. System Architecture Overview

### 2.1 Node Types

| Node Type | Platform | Role | Characteristics |
|-----------|----------|------|-----------------|
| **Phone Node** | Android (primary), iOS (degraded) | End-user device | Battery-constrained, mobile, intermittent connectivity |
| **Supernode** | OpenWRT router | Backbone infrastructure | Always-on, wired power, better antennas, larger storage, bridges subnets |
| **External Radio** | LoRa/ESP32 via BT/USB | Range extension | Long-range low-bandwidth transport, hardware-keyed identity |

### 2.2 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        APPLICATION LAYER                         │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │ 1:1 Chat │ │ Group Chat│ │ Channels │ │ Emergency Bcast  │  │
│  └──────────┘ └───────────┘ └──────────┘ └──────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                        CRYPTO LAYER                              │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │ X3DH     │ │ MLS Groups│ │ WoT/PKI  │ │ SQLCipher Store  │  │
│  └──────────┘ └───────────┘ └──────────┘ └──────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                        ROUTING LAYER                             │
│  ┌──────────────────┐  ┌──────────────────────────────────────┐ │
│  │ AODV Real-Time   │  │ Spray-and-Wait DTN Fallback          │ │
│  └──────────────────┘  └──────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │ Geographic Hash Overlay (topology-inferred, no GPS required) ││
│  └──────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│                      TRANSPORT ABSTRACTION                       │
│  Seamless handoff between transports, unified link layer         │
│  ┌────────┐┌──────┐┌─────┐┌─────────┐┌──────┐┌──────────────┐ │
│  │WiFi    ││ BLE  ││ BT  ││WiFi     ││LoRa  ││ Internet     │ │
│  │Direct  ││      ││Classic│Aware   ││(ext) ││ Tunnel       │ │
│  └────────┘└──────┘└─────┘└─────────┘└──────┘└──────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                     PROTOCOL ADAPTER PLUGINS                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐   │
│  │ Meshtastic  │ │ Reticulum   │ │ Community Plugins       │   │
│  └─────────────┘ └─────────────┘ └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Software Stack

- **Core Logic:** Rust (compiled to all target platforms via FFI)
- **Android UI:** Jetpack Compose (thin shell calling into Rust via JNI/UniFFI)
- **iOS UI:** SwiftUI (thin shell calling into Rust via C FFI)
- **OpenWRT:** Rust binary + auto-configuration daemon, packaged as `.ipk`
- **Wire Format:** Cap'n Proto (zero-copy, minimal serialization overhead)
- **Local Storage:** SQLite + SQLCipher (encrypted at rest)
- **Device Sync:** CRDT-based message log for linked devices

---

## 3. Transport Layer

### 3.1 Supported Transports (Priority Order)

1. **Wi-Fi Direct** — Highest bandwidth (~250 Mbps), ~200m range. Primary Android-to-Android transport.
2. **Wi-Fi Aware (NAN)** — Peer-aware networking on Android 8+. Used for neighbor discovery and data transfer.
3. **Bluetooth Classic (SPP)** — ~2 Mbps, ~100m range. Reliable fallback.
4. **Bluetooth Low Energy (BLE)** — ~2 Mbps theoretical (~200 kbps practical), ~100m. Universal cross-platform transport. Critical for iOS interop.
5. **LoRa (External)** — Adaptive data rate (SF7-SF12, 250 bps to 11 kbps), 2-15km+ range. Via external hardware.
6. **Internet Tunnel** — Opportunistic. When any node has internet access, mesh traffic can tunnel through it transparently to reach distant partitions.
7. **Ultrasonic Audio** — Last resort, extremely low bandwidth. For bootstrapping when all radios are blocked.

### 3.2 Seamless Transport Handoff

All transports are abstracted behind a unified link layer. Active sessions migrate transparently between transports as link conditions change. The transport abstraction layer:

- Maintains a scored list of available transports per neighbor
- Monitors link quality (RSSI, throughput, packet loss) continuously
- Migrates active sessions without dropping messages during handoff
- Exposes a single `Link` interface to the routing layer: `send(peer_id, data) -> Result`

### 3.3 iOS Strategy

iOS does not expose Wi-Fi Direct to third-party apps. Mycelium handles this via a **hybrid relay** model:

- iOS nodes use **BLE** as their primary mesh transport
- iOS nodes connect to the nearest **Android node** or **OpenWRT supernode** via BLE
- That Android/OpenWRT node acts as a **relay bridge** into the full Wi-Fi Direct mesh
- iOS-to-iOS communication uses Apple's **Multipeer Connectivity** when available (local only)
- iOS nodes are always "one hop away" from the full mesh via their relay bridge

### 3.4 External Radio Hardware Interface

Mycelium supports external radios (LoRa modules, ESP32 boards) via three connection methods:

| Interface | Protocol | Bandwidth | Use Case |
|-----------|----------|-----------|----------|
| Bluetooth Serial (SPP) | UART over BT Classic | ~1 Mbps | Wireless connection to ESP32 |
| BLE GATT Service | Custom GATT profile | ~200 kbps | Low-power LoRa module connection |
| USB Serial (OTG) | CDC ACM / FTDI | ~1+ Mbps | Wired connection, lowest latency |

Auto-detection: the app scans for known BLE service UUIDs and USB VID/PIDs to identify supported hardware.

### 3.5 LoRa Configuration

Mycelium uses **adaptive data rate (ADR)** for LoRa:

- **Discovery phase:** SF12 (maximum range, ~250 bps) for beacon/discovery packets
- **Negotiation:** Once peers discover each other, test progressively lower spreading factors
- **Data transfer:** Use the lowest SF that maintains acceptable packet loss (<5%)
- **Fallback:** Automatically increase SF if link quality degrades
- Default frequency: 915 MHz (US) / 868 MHz (EU) — configurable per region

---

## 4. Mesh Routing

### 4.1 Hybrid Routing Protocol

Mycelium uses a **two-layer routing strategy**:

#### Layer 1: AODV Reactive Routing (Real-Time)

- Routes are discovered **on-demand** when a message needs to be sent
- Route Request (RREQ) packets flood outward, Route Reply (RREP) travels back
- Active routes are maintained with periodic keepalives
- Routes are invalidated when link quality drops below threshold
- Best for: messages where recipient is currently reachable in the mesh

#### Layer 2: Spray-and-Wait DTN (Store-and-Forward)

- When AODV fails to find a route within a timeout, message enters DTN mode
- **Spray phase:** Message is replicated to `L` distinct relay nodes (default L=8)
- **Wait phase:** Each copy is carried by its relay until it encounters the destination
- Relay nodes store messages as **encrypted opaque blobs** they cannot read
- Messages have configurable **TTL** (default: 72 hours)
- Best for: messages when no end-to-end path exists simultaneously

#### Decision Logic

```
on_send(message):
    route = AODV.find_route(message.destination, timeout=5s)
    if route exists:
        send_realtime(message, route)
    else:
        spray_and_wait(message, L=8, TTL=72h)
```

### 4.2 Geographic Hash Overlay

For unbounded scale, Mycelium uses a geographic hash overlay to route messages to unknown destinations:

- The network is divided into **virtual geographic regions**
- **Region inference is topology-based** — no GPS required. Regions are inferred from:
  - Supernode locations (known fixed infrastructure)
  - Hop counts and latencies between known landmarks
  - Wi-Fi BSSID databases (when available)
- Each node registers with its inferred region in the overlay
- Messages to unknown destinations route toward the destination's **last-known region**
- Supernodes maintain the overlay routing tables for their region

#### Mobility Handling

Since GPS is not required and regions are inferred from topology:

- Nodes detect region changes when their supernode affiliation changes
- Moving nodes leave **forwarding pointers** at their old region's supernodes
- Forwarding chains are garbage collected after TTL (default: 24 hours)
- Supernodes in a region collaboratively track which nodes are currently affiliated

### 4.3 Routing Metadata

Routing headers use **pragmatic cleartext** format for efficiency:

```
┌────────────────────────────────────────────────┐
│ Header (cleartext)                             │
│  - Source public key hash (32 bytes)           │
│  - Destination public key hash (32 bytes)      │
│  - Message ID (16 bytes, random)               │
│  - TTL (1 byte)                                │
│  - Hop count (1 byte)                          │
│  - Flags (2 bytes: DTN, priority, emergency)   │
│  - Lamport timestamp (8 bytes)                 │
│  - Device timestamp (8 bytes)                  │
├────────────────────────────────────────────────┤
│ Payload (E2E encrypted, opaque to relays)      │
│  - Encrypted content                           │
│  - Authentication tag                          │
└────────────────────────────────────────────────┘
```

Source and destination hashes are visible to relay nodes for routing. Content is always E2E encrypted and opaque. This is a deliberate tradeoff of metadata privacy for routing efficiency.

---

## 5. Identity & Trust

### 5.1 Keypair Identity

- On first launch, each device generates an **Ed25519** signing keypair and an **X25519** key exchange keypair
- The public key hash (SHA-256, truncated to 32 bytes) **IS the node identity**
- Users set a human-readable **display name** but the cryptographic identity is authoritative
- Identity is device-bound; not tied to any external identifier (phone number, email)

### 5.2 Web of Trust

Mycelium uses a **web of trust** model for identity verification:

- Users **vouch for each other in person** by scanning QR codes containing public keys
- A vouch is a signed statement: `sign(my_key, "I vouch for <their_key> as <display_name>")`
- Trust propagates **transitively** with decay: direct vouch = trust 1.0, 2 hops = 0.5, 3 hops = 0.25, etc.
- Trust scores affect: relay priority, rate limits, emergency broadcast eligibility

### 5.3 Sybil Attack Defense

The primary defense against Sybil attacks is the **social cost of in-person attestation**:

- New identities gain zero trust until vouched for in-person by an existing trusted node
- Creating thousands of fake identities requires physically meeting thousands of real people
- Unvouched nodes can still send/receive messages but face strict rate limits and no relay priority
- Vouching for a misbehaving node damages the voucher's trust score (reputation staking)

### 5.4 Threshold Key Revocation

- A key is revoked when **N out of the key's vouchers** publish signed revocation certificates
- Default threshold: majority of direct vouchers (e.g., if 5 people vouched, need 3 revocations)
- Revocation certificates are gossiped through the mesh
- Revoked keys are blacklisted; messages from revoked keys are dropped
- Prevents single-party abuse of revocation (e.g., one angry friend can't revoke you)

---

## 6. Encryption

### 6.1 Key Exchange: X3DH + In-Person Verification

1. Each node publishes **signed prekey bundles** to nearby supernodes:
   - Identity key (long-term Ed25519, converted to X25519 for DH)
   - Signed prekey (medium-term X25519, rotated weekly)
   - Set of one-time prekeys (X25519, replenished periodically)

2. To initiate a conversation, the sender:
   - Fetches the recipient's prekey bundle from a supernode (or receives it via DTN)
   - Performs X3DH to derive a shared secret
   - Begins a Double Ratchet session for forward secrecy

3. Conversations are marked **"unverified"** until users confirm safety numbers in person
   - Safety number: truncated hash of both identity keys
   - Verified status is stored locally and indicated in the UI

### 6.2 Group Messaging: MLS-Inspired Protocol

Group chats use a **tree-based key agreement** inspired by the Messaging Layer Security (MLS) protocol:

- Group members form a binary ratchet tree
- Each member holds a leaf private key; internal nodes derive keys from children
- **Add member:** new leaf inserted, path keys updated (O(log n) operations)
- **Remove member:** leaf blanked, path re-keyed from sibling (O(log n))
- **Send message:** encrypt with the group's current epoch key
- Forward secrecy is maintained per-epoch; compromise of one epoch doesn't reveal others

Adaptations for DTN context:
- Epoch changes (member add/remove) are sequenced by the group admin's Lamport clock
- Pending epoch changes are buffered and applied in order when a partitioned member reconnects
- Stale members (unreachable for >7 days) are automatically proposed for removal

### 6.3 DTN Relay Storage

Messages in DTN relay mode are stored as **encrypted opaque blobs**:

- Relay nodes store `(message_id, encrypted_blob, destination_hash, TTL, size)`
- Relay nodes **cannot decrypt** the blob (it's E2E encrypted for the destination)
- Storage limits: configurable per node (default 256 MB for phones, 2 GB for supernodes)
- Eviction policy: TTL expiry first, then oldest-first when storage is full
- Relay nodes enforce per-identity size quotas to prevent one sender from filling storage

---

## 7. Multi-Device Support

### 7.1 Linked Device Chain

- The **primary device** (first device set up) holds the master identity keypair
- Secondary devices generate their own keypairs and are **authorized by the primary** via in-person QR exchange
- Authorization is a signed certificate: `sign(primary_key, "device <secondary_key> is authorized for identity <primary_key>")`
- All linked devices share the same **logical identity** in the mesh
- Messages addressed to the identity are delivered to **all linked devices**

### 7.2 CRDT Message Log Sync

Linked devices synchronize their message history using **CRDTs**:

- Each device maintains a local CRDT-based message log
- When linked devices encounter each other (directly or through the mesh), they sync
- **Guaranteed eventual consistency** — all devices converge to the same state
- During partition, devices operate independently, collecting messages for the shared identity
- Conflict resolution: Lamport timestamps + device ID for deterministic ordering

---

## 8. Messaging Features

### 8.1 Content Types

V1 supports a lean content set optimized for low-bandwidth mesh:

| Type | Max Size | Description |
|------|----------|-------------|
| Text | 64 KB | UTF-8 text messages |
| Image | 500 KB | Compressed images (JPEG/WebP) |
| File | 500 KB | Arbitrary small files |
| GPS Pin | 32 bytes | Latitude/longitude coordinate |
| Voice Note | 500 KB | Compressed audio (Opus codec) |
| Receipt | 64 bytes | Delivery/read confirmations |
| System | 1 KB | Key exchange, group management, trust operations |

### 8.2 Message Ordering

Messages are ordered using **Lamport logical clocks** with **device timestamp tiebreaking**:

- Each node maintains a Lamport counter, incremented on send and updated on receive
- Lamport clock provides **causal ordering** — if message A caused message B, A is ordered before B
- Messages without causal relationship are ordered by device timestamp
- Clock drift (no NTP available) is tolerated; timestamps are best-effort

### 8.3 Delivery & Read Receipts

- **Delivery receipt:** Sent automatically when a message reaches the destination device
- **Read receipt:** Sent when the user opens/views the message
- Both receipts travel back through the mesh using the same routing (AODV or DTN)
- In DTN mode, receipts may take as long as the original message to arrive
- Receipts are small (64 bytes) and use the same E2E encryption as regular messages

### 8.4 Public Channels

#### Regional Broadcast Boards
- Tied to geographic regions (as defined by the overlay)
- Any node in the region can read and post
- Messages are flooded within the region, not routed to specific destinations
- Useful for: local announcements, resource sharing, community coordination

#### Topic Channels
- Named channels that nodes subscribe to (e.g., `#medical-supplies`, `#security-updates`)
- Messages propagate to all subscribers via a pub/sub overlay
- Subscription is announced to supernodes, which maintain subscriber lists per topic
- Cross-region topics route through the supernode backbone

#### Channel Moderation
- **Channel creator** has moderation powers and can **delegate** to other trusted users
- Moderators issue **signed removal notices** for content that violates channel rules
- Removal notices propagate through the mesh; nodes that receive them hide the content
- Moderation is per-channel, not network-wide

---

## 9. Emergency Broadcast System

### 9.1 Tiered Emergency Levels

| Level | Name | Behavior | Requirement |
|-------|------|----------|-------------|
| 1 | **Priority** | Message gets boosted priority in relay queues | Any node with trust score > 0.3 |
| 2 | **Urgent** | Bypasses per-identity rate limits | Trust score > 0.6 |
| 3 | **Critical** | Floods the entire mesh, bypasses all routing rules | Threshold approval: 3+ nodes with trust > 0.8 must co-sign |

### 9.2 Emergency Abuse Prevention

- Each emergency level has a **trust score threshold** the sender must meet
- Level 3 (mesh flood) requires **threshold co-signing** — multiple highly-trusted nodes must approve
- False emergencies incur severe trust score penalties
- Emergency messages include the sender's identity (non-anonymous) for accountability

---

## 10. OpenWRT Supernode

### 10.1 Role

OpenWRT supernodes serve three critical functions:

1. **Supernode:** Maintain larger routing tables, participate in geographic overlay, bridge between Wi-Fi and wired subnets
2. **Gateway:** Bridge to the internet when WAN uplink is available (opportunistic tunnel)
3. **Cache:** Persistent storage for DTN messages, prekey bundles, trust graph data, and channel history

### 10.2 Auto-Configuration

- OpenWRT node **auto-configures** when it detects the Mycelium mesh:
  1. Installs Mycelium daemon from `.ipk` package
  2. Generates node identity keypair
  3. Scans for nearby mesh nodes on all interfaces
  4. Joins the mesh as a supernode
  5. Begins advertising itself as a supernode via beacon frames
- **Zero manual setup required** for basic operation
- Advanced settings available via **LuCI web plugin** for power users (storage limits, radio config, WAN bridge policy)

### 10.3 Supernode Specifications

| Parameter | Default | Description |
|-----------|---------|-------------|
| DTN Storage | 2 GB | Encrypted blob relay storage |
| Routing Table | Unlimited | Full overlay routing table for region |
| Prekey Cache | 100 MB | Cached prekey bundles for known identities |
| Trust Graph | Full regional | Maintains trust graph for all nodes in region |
| Beacon Interval | 10 seconds | Supernode advertisement frequency |

---

## 11. Anti-Spam & Rate Limiting

### 11.1 Trust + Rate Hybrid System

Rate limits are dynamically determined by the sender's **trust distance** from the relay node:

| Trust Distance | Messages/hour | DTN Relay Quota | Description |
|----------------|---------------|-----------------|-------------|
| Direct vouch (1 hop) | Unlimited | 50 MB | Directly trusted contact |
| 2 hops | 500 | 10 MB | Friend of a friend |
| 3 hops | 100 | 2 MB | Extended network |
| 4+ hops | 20 | 500 KB | Distant acquaintance |
| Unknown (no trust path) | 5 | 100 KB | Stranger — heavily throttled |

### 11.2 Enforcement

- Each relay node independently enforces rate limits based on its own trust graph view
- Rate limit violations result in message drops (not errors — no feedback to spammer)
- Persistent violators can be temporarily blacklisted by individual relay nodes
- Supernodes share rate limit violation data to detect coordinated attacks

---

## 12. Internet Tunnel (Opportunistic)

When any node in the mesh has internet access (cellular, Wi-Fi hotspot, or OpenWRT WAN):

1. The node **announces gateway availability** to its mesh neighbors
2. Other nodes can route mesh traffic **through the gateway** to reach distant mesh partitions
3. Traffic is tunneled via a lightweight encrypted tunnel (WireGuard-inspired, or raw TCP/UDP)
4. The tunnel is **transparent to the routing layer** — it appears as just another transport link
5. Gateway nodes enforce the same rate limits and trust rules as any other relay
6. Internet is used **opportunistically** — mesh routing is always preferred when available

---

## 13. Protocol Versioning

### 13.1 Backwards Compatibility Guarantee

Mycelium commits to **full backwards compatibility**:

- All protocol versions must understand all previous versions
- New features use **optional message fields** (Cap'n Proto's schema evolution)
- A v5 node can communicate with a v1 node using only v1 features
- New features are available when both endpoints support them
- No minimum version floor — old nodes are never excluded

### 13.2 Feature Detection

- During neighbor discovery, nodes exchange their **protocol version** and **capability list**
- Each pair of nodes negotiates the highest common capability set
- Unknown message types/fields are **preserved and forwarded** (relay nodes don't strip unknown fields)
- This allows new message types to transit through old relay nodes unmodified

---

## 14. Protocol Adapter Plugin System

### 14.1 Transport Plugin API

Mycelium defines a **transport plugin API** that allows third-party protocol adapters:

```rust
trait TransportPlugin {
    /// Human-readable name of this transport
    fn name(&self) -> &str;

    /// Discover peers on this transport
    fn discover_peers(&self) -> Vec<PeerId>;

    /// Send raw bytes to a peer
    fn send(&self, peer: PeerId, data: &[u8]) -> Result<()>;

    /// Receive raw bytes from any peer
    fn recv(&self) -> Result<(PeerId, Vec<u8>)>;

    /// Get link quality metrics
    fn link_quality(&self, peer: PeerId) -> LinkQuality;
}
```

### 14.2 Maintained Plugins

| Plugin | Maintainer | Description |
|--------|-----------|-------------|
| `mycelium-meshtastic` | Core team | Meshtastic-compatible LoRa framing. Interop with existing Meshtastic hardware. |
| `mycelium-reticulum` | Core team | Reticulum network stack adapter. Bridge to Reticulum networks. |

### 14.3 Interoperation Model

Plugins provide **edge bridging**:

- Mycelium nodes running a plugin can send/receive messages to/from users on the foreign protocol
- Foreign protocol nodes **do not** participate in Mycelium routing (no transit routing through foreign networks)
- The plugin node acts as a **translator** at the protocol boundary
- Community can develop additional plugins via the published API

---

## 15. Onboarding & Discovery

### 15.1 Seed Phrase Groups

New users join the mesh via **seed phrase groups**:

1. A group publishes a **shared passphrase** (e.g., "mountain river oak seven")
2. New user enters the passphrase in the app
3. The passphrase derives a **group discovery key** used to:
   - Identify and authenticate mesh peers belonging to that group
   - Establish initial encrypted channels with group members
4. Once connected, the new user can begin building their web of trust through in-person vouching

### 15.2 First-Launch Flow

1. App generates identity keypair
2. User sets display name
3. User enters a group seed phrase OR scans a QR code from an existing user
4. App begins scanning for mesh peers on all available transports
5. Upon finding a peer in the same group, initial key exchange occurs
6. User is now part of the mesh and can begin communicating

---

## 16. Battery Management

### 16.1 Adaptive Power Strategy

Mycelium automatically adjusts mesh participation based on device state:

| Condition | Behavior |
|-----------|----------|
| Charging + strong mesh | Full participation: all radios active, relay for others, maintain all transport links |
| Battery > 50% + many neighbors | Moderate: relay, but only on Wi-Fi Direct (most efficient). BLE for discovery only. |
| Battery > 50% + few neighbors | Full participation: this node is critical to mesh connectivity |
| Battery 20-50% | Light: maintain own connections, relay only for direct trust contacts |
| Battery < 20% | Leaf mode: receive only, no relaying. BLE keepalive only. |
| Battery < 5% | Hibernate: disconnect from mesh, queue outgoing messages for later |

### 16.2 Cooperative Scheduling

- Nodes share battery status with neighbors
- When multiple nodes can serve as relay for the same path, the best-charged node is preferred
- Supernodes (wired power) always preferred for relay when available

---

## 17. User Interface

### 17.1 Layered Network Status

**Default view (simple):**
- Connection indicator: Connected to mesh / Searching / Offline
- Message status per conversation: Sent / Delivered / Read / Pending (DTN)

**Expandable detail view:**
- Number of direct neighbors and their transport types
- Hop count to each active contact
- Current transport in use per link (Wi-Fi Direct, BLE, LoRa, Internet Tunnel)
- Link quality per hop (signal strength, latency, throughput)
- Node role: Full / Light / Leaf (and why)
- DTN queue: number of messages being relayed for others

### 17.2 Core UI Screens

1. **Chat list** — Active conversations, sorted by last activity. DTN pending indicator.
2. **Chat view** — Messages with delivery/read status. Unverified contact warning banner.
3. **Contacts** — Web of trust view. Trust score, verification status, last seen.
4. **Channels** — Regional boards and topic channels. Subscribe/unsubscribe.
5. **Network** — Mesh status, neighbors, transport details (layered).
6. **Settings** — Identity, linked devices, battery mode override, transport priorities.

---

## 18. Testing Strategy

### 18.1 Docker Mesh Testbed

Primary testing infrastructure is a **Docker-based network simulator**:

- Each Mycelium node runs in its own Docker container
- Virtual network interfaces simulate radio links
- `tc`/`netem` used for realistic link conditions:
  - Configurable latency (0ms - 30s)
  - Packet loss (0% - 50%)
  - Bandwidth limiting (250 bps for LoRa simulation to 250 Mbps for Wi-Fi Direct)
  - Jitter, reordering, duplication
- Network topology is defined declaratively (YAML)
- Scenarios include: partition/merge, node mobility, supernode failure, DTN delivery
- CI/CD runs the testbed on every commit

### 18.2 Test Scenarios

| Scenario | Description | Success Criteria |
|----------|-------------|-----------------|
| Linear chain | 10 nodes in a line, message from node 1 to 10 | Delivered via multi-hop AODV |
| Partition merge | Two clusters of 5, separated, then connected | DTN messages delivered after merge, CRDT consistency |
| Supernode failure | Remove a supernode mid-operation | Mesh re-routes within 30 seconds |
| Transport failover | Degrade Wi-Fi Direct, expect BLE fallback | Seamless session migration, no message loss |
| Scale test | 100+ nodes, random topology | Routing converges, messages delivered within bounds |
| Sybil attack | 50 fake identities flood the mesh | Rate limits contain the attack, legitimate traffic unaffected |

---

## 19. MVP: v0.1 Scope

### 19.1 Included in v0.1

- **Android app** (Rust core + Jetpack Compose UI)
- **OpenWRT supernode** package (auto-configure, DTN cache, relay)
- **Transports:** Wi-Fi Direct, BLE, LoRa (via BT Serial and USB OTG)
- **Routing:** AODV real-time + spray-and-wait DTN
- **Encryption:** X3DH key exchange, Double Ratchet sessions, SQLCipher local storage
- **Identity:** Ed25519 keypair, web of trust, seed phrase onboarding
- **Messaging:** 1:1 encrypted text + small files, delivery/read receipts
- **Group chat:** MLS-inspired group encryption (small groups, <20 members)
- **Network UI:** Layered detail view
- **Battery:** Adaptive power management
- **Anti-spam:** Trust + rate hybrid
- **Testing:** Docker mesh testbed, CI/CD integration

### 19.2 Deferred to Future Versions

| Feature | Target Version |
|---------|---------------|
| iOS app | v0.2 |
| Public channels (regional + topic) | v0.2 |
| Internet opportunistic tunnel | v0.2 |
| Emergency broadcast system | v0.3 |
| Multi-device (linked device chain) | v0.3 |
| Protocol adapter plugins (Meshtastic, Reticulum) | v0.3 |
| Geographic hash overlay (for unbounded scale) | v0.4 |
| Wi-Fi Aware, Bluetooth Classic transports | v0.4 |
| Threshold key revocation | v0.4 |
| Ultrasonic audio transport | Future |

---

## 20. Project Structure (Proposed)

```
mycelium/
├── Cargo.toml                    # Workspace root
├── LICENSE                       # GPLv3
├── crates/
│   ├── mycelium-core/            # Core mesh logic (routing, DTN, transport abstraction)
│   ├── mycelium-crypto/          # X3DH, Double Ratchet, MLS, WoT, SQLCipher integration
│   ├── mycelium-protocol/        # Cap'n Proto schemas, wire format, message types
│   ├── mycelium-transport-wifi/  # Wi-Fi Direct transport implementation
│   ├── mycelium-transport-ble/   # BLE transport implementation
│   ├── mycelium-transport-lora/  # LoRa external radio transport
│   ├── mycelium-storage/         # SQLite/SQLCipher storage layer, CRDT sync
│   ├── mycelium-node/            # Node daemon (used by both phone and OpenWRT)
│   └── mycelium-ffi/             # C/JNI/Swift FFI bindings for mobile apps
├── android/                      # Jetpack Compose Android app
├── openwrt/                      # OpenWRT package build files, LuCI plugin
├── plugins/
│   ├── meshtastic/               # Meshtastic protocol adapter
│   └── reticulum/                # Reticulum protocol adapter
├── testbed/
│   ├── docker-compose.yml        # Docker mesh testbed
│   ├── scenarios/                # Test scenario YAML definitions
│   └── scripts/                  # Testbed orchestration scripts
└── docs/
    ├── protocol.md               # Detailed protocol specification
    ├── threat-model.md           # Security threat model
    └── hardware-guide.md         # Supported external hardware guide
```

---

## 21. Key Technical Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Wi-Fi Direct connection limits (Android caps at ~5 peers) | High | Use BLE for discovery, Wi-Fi Direct only for high-bandwidth transfers. Rotate Wi-Fi Direct connections. |
| Android background execution limits kill mesh participation | High | Foreground service with persistent notification. Battery optimization exemption request. |
| Cap'n Proto schema evolution may not cover all backwards-compat needs | Medium | Design schemas conservatively. Reserve field numbers. Extensive versioning tests. |
| MLS tree ratchet is complex to implement correctly in DTN context | High | Start with simpler sender keys for v0.1 groups <20. Full MLS in v0.2. |
| LoRa duty cycle regulations limit transmission time (1% in EU) | Medium | Aggressive message compression. Prioritize LoRa for discovery beacons and tiny text only. |
| Topology-inferred geographic regions may be inaccurate | Medium | Deferred to v0.4. Use flat routing for v0.1 (sufficient for moderate scale). |

---

## 22. Open Questions

1. **NAT traversal for internet tunnel:** When tunneling through the internet, how should nodes behind NAT find each other? STUN/TURN or a lightweight rendezvous server?
2. **Meshtastic firmware modification:** Should Mycelium maintain a custom Meshtastic firmware for tighter integration, or strictly use the stock Meshtastic protocol?
3. **Legal considerations:** LoRa transmission regulations vary by country. Should the app enforce duty cycle limits or leave compliance to the user?
4. **Key backup:** If a user loses their device, their identity is gone. Should there be an optional encrypted key backup mechanism (e.g., Shamir's Secret Sharing across trusted contacts)?

---

*This specification is a living document. It will be updated as implementation progresses and design decisions are validated through the Docker testbed and real-world testing.*
