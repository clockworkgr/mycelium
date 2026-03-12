# Mycelium Architecture Document

**Version:** 0.1.0
**Last Updated:** 2026-03-10
**Spec Reference:** `MYCELIUM_SPEC.md` v0.1-draft

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Repository Structure](#2-repository-structure)
3. [Dependency Graph](#3-dependency-graph)
4. [Data Flow Overview](#4-data-flow-overview)
5. [mycelium-protocol](#5-mycelium-protocol)
6. [mycelium-crypto](#6-mycelium-crypto)
7. [mycelium-core](#7-mycelium-core)
8. [mycelium-storage](#8-mycelium-storage)
9. [mycelium-node](#9-mycelium-node)
10. [mycelium-api](#10-mycelium-api)
11. [mycelium-ffi](#11-mycelium-ffi)
12. [Flutter App](#12-flutter-app)
13. [Android BLE Stack](#13-android-ble-stack)
14. [Build System](#14-build-system)
15. [Wire Format Reference](#15-wire-format-reference)
16. [Cryptographic Architecture](#16-cryptographic-architecture)
17. [Routing Architecture](#17-routing-architecture)
18. [Test Coverage](#18-test-coverage)
19. [Spec Compliance Matrix](#19-spec-compliance-matrix)

---

## 1. Executive Summary

Mycelium is a mobile mesh messaging application that operates without internet or cellular infrastructure. It creates ad-hoc mesh networks using Bluetooth Low Energy on standard smartphones, with end-to-end encryption, delay-tolerant networking, and a Web of Trust identity system.

**Architecture:** Rust core library (6 crates) compiled to a shared library (`libmycelium_ffi.so`) via C FFI, consumed by a Flutter/Dart frontend with Kotlin platform code for Android BLE.

```
┌───────────────────────────────────────────────────────────────┐
│                    Flutter UI (Dart)                           │
│  Riverpod state management, GoRouter navigation               │
├───────────────────────────────────────────────────────────────┤
│           Service Layer (Dart + Kotlin)                       │
│  MyceliumService (FFI) ←→ BleManager ←→ BleService (Kotlin)  │
│                        ←→ WifiDirectManager ←→ WifiDirectService │
├───────────────────────────────────────────────────────────────┤
│              C FFI Boundary (libmycelium_ffi.so)              │
├───────────────────────────────────────────────────────────────┤
│  mycelium-node    │ Event loop, message pipeline, beacons     │
│  mycelium-core    │ Transport, AODV routing, DTN              │
│  mycelium-crypto  │ X3DH, Double Ratchet, WoT, Groups        │
│  mycelium-storage │ SQLCipher encrypted database              │
│  mycelium-protocol│ Wire format, binary codec                 │
└───────────────────────────────────────────────────────────────┘
```

---

## 2. Repository Structure

```
mycelium/
├── Cargo.toml                          # Workspace root (resolver = "2")
├── MYCELIUM_SPEC.md                    # Protocol specification
├── ARCHITECTURE.md                     # This file
├── .cargo/config.toml                  # Android NDK linker config (auto-generated)
├── scripts/
│   └── build-android.sh                # Cross-compilation script
├── android-libs/                       # Pre-built .so files per ABI
│   ├── arm64-v8a/libmycelium_ffi.so
│   ├── armeabi-v7a/libmycelium_ffi.so
│   ├── x86_64/libmycelium_ffi.so
│   └── include/mycelium.h
├── crates/
│   ├── mycelium-protocol/              # Wire format types + binary codec
│   │   ├── src/lib.rs                  # Module exports
│   │   ├── src/types.rs                # NodeId, MessageId, LamportClock, etc.
│   │   ├── src/codec.rs                # Envelope serialize/deserialize
│   │   ├── src/wire.rs                 # Payload type codecs
│   │   └── schemas/                    # Cap'n Proto schemas (documentation only)
│   ├── mycelium-crypto/                # Cryptographic primitives
│   │   ├── src/lib.rs                  # Module exports
│   │   ├── src/identity.rs             # Ed25519/X25519 identity
│   │   ├── src/x3dh.rs                 # Extended Triple DH key exchange
│   │   ├── src/double_ratchet.rs       # Double Ratchet protocol
│   │   ├── src/session.rs              # Session management
│   │   ├── src/wot.rs                  # Web of Trust
│   │   └── src/group.rs                # Sender Key Groups
│   ├── mycelium-core/                  # Transport and routing
│   │   ├── src/lib.rs                  # Module exports
│   │   ├── src/messaging.rs            # MessageStatus, StoredMessage types
│   │   ├── src/transport/mod.rs        # Transport trait definition
│   │   ├── src/transport/manager.rs    # TransportManager
│   │   ├── src/transport/ble.rs        # BLE transport with outbox queue
│   │   ├── src/transport/wifi_direct.rs# Wi-Fi Direct transport with outbox queue
│   │   ├── src/transport/lora.rs       # LoRa long-range transport
│   │   ├── src/transport/bt_classic.rs # BT Classic SPP transport
│   │   ├── src/transport/internet.rs   # TCP internet tunnel transport
│   │   ├── src/transport/plugin.rs     # TransportPlugin trait + registry
│   │   ├── src/transport/mock.rs       # Mock transport for testing
│   │   ├── src/routing/mod.rs          # Routing module exports
│   │   ├── src/routing/aodv.rs         # AODV reactive routing
│   │   ├── src/routing/coordinator.rs  # Routing coordinator
│   │   └── src/dtn/spray_and_wait.rs   # DTN spray-and-wait engine
│   ├── mycelium-storage/               # SQLCipher database layer
│   │   ├── src/lib.rs                  # Database, schema, migrations
│   │   ├── src/messages.rs             # Message CRUD
│   │   ├── src/sessions.rs             # Session persistence
│   │   ├── src/contacts.rs             # Contact management
│   │   ├── src/vouches.rs              # Web of Trust vouches
│   │   ├── src/prekeys.rs              # Prekey storage + cache
│   │   ├── src/dtn.rs                  # DTN bundle storage
│   │   └── src/groups.rs               # Group state blobs
│   ├── mycelium-node/                  # Node daemon
│   │   ├── src/lib.rs                  # Module exports
│   │   ├── src/main.rs                 # CLI entry point
│   │   ├── src/node.rs                 # Node struct + event loop (~2600 lines)
│   │   ├── src/config.rs               # NodeConfig
│   │   ├── src/beacon.rs               # Beacon serialization
│   │   ├── src/rate_limiter.rs         # Trust-based rate limiting
│   │   ├── src/battery.rs              # Battery management
│   │   └── tests/                      # Integration tests (4 files)
│   ├── mycelium-api/                   # Local REST + WebSocket API server
│   │   ├── src/lib.rs                  # Public API
│   │   ├── src/server.rs               # axum router + server startup
│   │   ├── src/state.rs                # Shared AppState (Node + broadcast)
│   │   ├── src/types.rs                # Request/response JSON types
│   │   ├── src/ws.rs                   # WebSocket handler
│   │   ├── src/util.rs                 # Parsing helpers
│   │   ├── src/routes/                 # REST endpoint handlers
│   │   │   ├── node.rs                 # /v1/node/*
│   │   │   ├── messages.rs             # /v1/messages/*
│   │   │   ├── conversations.rs        # /v1/conversations/*
│   │   │   ├── contacts.rs             # /v1/contacts/*
│   │   │   └── network.rs              # /v1/network/* (diagnostics)
│   │   └── tests/api_test.rs           # Integration tests (11 tests)
│   └── mycelium-ffi/                   # C FFI bindings
│       ├── src/lib.rs                  # 48 extern "C" functions (~1500 lines)
│       └── include/mycelium.h          # C header
└── flutter/                            # Flutter mobile app
    ├── pubspec.yaml                    # Dependencies
    ├── ffigen.yaml                     # FFI codegen config
    ├── lib/
    │   ├── main.dart                   # App entry, permission requests
    │   └── src/
    │       ├── app.dart                # MaterialApp + GoRouter
    │       ├── ffi/
    │       │   ├── mycelium_bindings_generated.dart  # Auto-generated
    │       │   └── ffi_helpers.dart     # Type conversion utilities
    │       ├── models/
    │       │   ├── message.dart         # Message model
    │       │   ├── contact.dart         # Contact model
    │       │   ├── conversation.dart    # Conversation model
    │       │   └── network_status.dart  # NetworkStatus model
    │       ├── service/
    │       │   ├── mycelium_service.dart # Core FFI service (singleton)
    │       │   ├── ble_manager.dart      # BLE ↔ Rust bridge
    │       │   └── wifi_direct_manager.dart # Wi-Fi Direct ↔ Rust bridge
    │       ├── providers/
    │       │   └── providers.dart        # Riverpod providers
    │       └── screens/
    │           ├── conversations_screen.dart
    │           ├── chat_screen.dart
    │           ├── contacts_screen.dart
    │           ├── settings_screen.dart
    │           └── qr_scanner_screen.dart
    └── android/
        └── app/src/main/
            ├── AndroidManifest.xml       # BLE + camera permissions
            ├── kotlin/.../
            │   ├── MainActivity.kt       # Platform channels
            │   ├── BleService.kt         # Full BLE stack (~600 lines)
            │   └── WifiDirectService.kt  # Wi-Fi Direct P2P + TCP sockets
            └── build.gradle.kts          # Rust build integration
```

---

## 3. Dependency Graph

```
mycelium-protocol  (serde, rand, thiserror)
       ↑
mycelium-crypto    (ed25519-dalek, x25519-dalek, curve25519-dalek,
       ↑            hkdf, sha2, aes-gcm, rand)
       │
mycelium-storage   (rusqlite[bundled-sqlcipher-vendored-openssl],
       ↑            serde_json)
       │
mycelium-core      (tokio, async-trait)
       ↑
mycelium-node      (tracing-subscriber, anyhow, toml)
       ↑            ↑
mycelium-ffi       mycelium-api   (axum, tower-http, hex)
(cdylib+staticlib)  (REST + WebSocket API server)
```

All crates share workspace-level dependency versions. Key version constraints:
- Rust edition: 2021, MSRV: 1.75
- `rusqlite` 0.31 with `bundled-sqlcipher-vendored-openssl` (bundles OpenSSL for Android)
- `tokio` 1.x with `full` features
- `ed25519-dalek` 2.x, `x25519-dalek` 2.x, `curve25519-dalek` 4.x

---

## 4. Data Flow Overview

### Outgoing Message (Send)

```
User taps Send
  → MyceliumService.sendMessage()           [Dart]
    → mycelium_send_message() FFI           [C FFI]
      → Node.send_message()                 [Rust]
        ├─ Has session? → encrypt with Double Ratchet
        │   → route_and_send_envelope()
        │     ├─ AODV route exists? → send to next_hop
        │     ├─ No route? → RREQ broadcast + queue in pending_routes
        │     └─ DTN fallback → store in spray-and-wait engine
        ├─ Has cached prekey? → initiate X3DH session + send
        └─ Neither? → queue in pending_messages + send prekey request
```

### Incoming Message (Receive via BLE)

```
BLE GATT characteristic write received        [Kotlin BleService]
  → Fragment reassembly
    → EventChannel "dataReceived" event
      → BleManager._forwardDataReceived()    [Dart]
        → mycelium_ble_on_data_received()    [C FFI]
          → BleTransport.on_data_received()  [Rust]
            → TransportEvent::DataReceived broadcast
              → Node event loop receives event
                → Envelope deserialization
                  → Payload type dispatch:
                    ├─ EncryptedMessage → decrypt + store + send receipt
                    ├─ SessionInit → accept X3DH + decrypt first msg
                    ├─ PrekeyRequest → respond with our prekey bundle
                    ├─ PrekeyResponse → cache bundle + flush pending msgs
                    ├─ AODV RREQ/RREP/RERR → routing table update
                    ├─ Beacon → update contact last_seen
                    ├─ Receipt → update message status
                    └─ DTN Relay → store or deliver
```

### BLE Transport Data Path

```
Rust → Platform (Outgoing):
  BleTransport.send() → outbox VecDeque
    → Dart polls mycelium_ble_dequeue_send() every 50ms
      → MethodChannel "sendData" → Kotlin BleService.sendData()
        → Fragment into MTU-sized chunks
          → Sequential GATT writes (one outstanding at a time)

Platform → Rust (Incoming):
  Kotlin onCharacteristicWriteRequest / onCharacteristicChanged
    → handleFragment() → reassemble
      → EventChannel "dataReceived"
        → Dart BleManager → FFI mycelium_ble_on_data_received()
          → BleTransport.on_data_received() → broadcast event
```

### Wi-Fi Direct Transport Data Path

```
Rust → Platform (Outgoing):
  WifiDirectTransport.send() → outbox VecDeque
    → Dart polls mycelium_wifi_dequeue_send() every 50ms
      → MethodChannel "sendData" → Kotlin WifiDirectService.sendData()
        → TCP writeFrame(MeshData, payload) — no fragmentation needed

Platform → Rust (Incoming):
  Kotlin handleClient() read loop → readFrame()
    → EventChannel "dataReceived"
      → Dart WifiDirectManager → FFI mycelium_wifi_on_data_received()
        → WifiDirectTransport.on_data_received() → broadcast event
```

---

## 5. mycelium-protocol

**Purpose:** Zero-dependency wire format definitions and binary codec. Defines all types that cross crate boundaries.

### Core Types (`types.rs`)

| Type | Size | Description |
|------|------|-------------|
| `NodeId([u8; 32])` | 32 bytes | Ed25519 public key identity. Implements `Display` (first 8 hex chars). |
| `MessageId([u8; 16])` | 16 bytes | Random unique message identifier via `OsRng`. |
| `LamportClock(u64)` | 8 bytes | Logical clock with `tick()` (increment) and `merge(other)` (max + 1). |
| `MessageFlags(u16)` | 2 bytes | Bitfield: `DTN=0x01, PRIORITY=0x02, URGENT=0x04, CRITICAL=0x08, RECEIPT=0x10, GROUP=0x20, SYSTEM=0x40` |
| `LinkQuality` | 12 bytes | Transport metrics: `rssi: Option<i16>`, `packet_loss: f32`, `latency_ms: u32`, `throughput_bps: u32`. Composite `score()` method. |
| `ProtocolVersion(u16)` | 2 bytes | Current: `V0_1 = 1` |
| `ContentType` | 1 byte | Enum: Text, Image, File, GpsPin, VoiceNote, Receipt, System |
| `NodeType` | 1 byte | Enum: Phone, Supernode, ExternalRadio |

### Envelope (`codec.rs`)

The top-level routing wrapper for all mesh messages. 106-byte fixed header + variable payload.

```
Offset  Size  Field              Endianness
  0      32   source             bytes
 32      32   destination        bytes
 64      16   message_id         bytes
 80       1   ttl                u8
 81       1   hop_count          u8
 82       2   flags              u16 LE
 84       8   lamport_clock      u64 LE
 92       8   device_timestamp   u64 LE
100       2   protocol_version   u16 LE
102       4   payload_length     u32 LE
106       *   payload            bytes
```

Methods: `serialize() -> Vec<u8>`, `deserialize(&[u8]) -> Result<Self, CodecError>`, `forward()` (decrement TTL, increment hop_count).

### Payload Types (`wire.rs`)

Each payload starts with a 1-byte type discriminator:

| Type Byte | Name | Min Body Size | Description |
|-----------|------|---------------|-------------|
| `0x10` | EncryptedMessage | 45 | Double Ratchet header (40) + ciphertext |
| `0x11` | SessionInit | 69 | X3DH ephemeral + identity + encrypted first msg |
| `0x20` | PrekeyRequest | 32 | Requester's identity key |
| `0x21` | PrekeyResponse | 66 | Prekey bundle (SPK + signature + OTP) |
| `0x30` | AodvRreq | 78 | Route request |
| `0x31` | AodvRrep | 77 | Route reply |
| `0x32` | AodvRerr | 68 | Route error |
| `0x40` | DtnRelay | 20 | DTN bundle relay |
| `0x50` | Beacon | variable | Node heartbeat |
| `0x60` | Receipt | 17 | Delivery/read confirmation |
| `0x70` | GroupMessage | 37 | Sender key encrypted group msg |
| `0x71` | SenderKeyDist | 68 | Group key distribution |

All multi-byte integers use little-endian encoding. Cap'n Proto schemas in `schemas/` are kept as documentation only; the crate uses a custom binary codec.

**Tests:** 26 tests covering all type round-trips, serialization edge cases, and codec errors.

---

## 6. mycelium-crypto

**Purpose:** Signal-protocol-based cryptographic primitives. Implements the full encryption stack from identity generation to group messaging.

### Module Overview

| Module | Purpose |
|--------|---------|
| `identity.rs` | Ed25519 signing + X25519 DH keypair generation, serialization |
| `x3dh.rs` | Extended Triple Diffie-Hellman key exchange |
| `double_ratchet.rs` | Double Ratchet protocol for forward-secret messaging |
| `session.rs` | Session lifecycle management (initiate, accept, encrypt, decrypt) |
| `wot.rs` | Web of Trust graph with BFS trust scoring |
| `group.rs` | Sender Key Groups for group messaging |

### Identity (`identity.rs`)

```rust
pub struct Identity {
    signing_key: SigningKey,      // Ed25519 (32-byte seed)
    verifying_key: VerifyingKey,  // Ed25519 public key
    x25519_secret: StaticSecret,  // X25519 static secret
    x25519_public: PublicKey,     // X25519 public key
}
```

- **Node ID derivation:** `SHA-256(Ed25519_public_key)` → 32-byte `NodeId`
- **Ed25519 → X25519 conversion:** SHA-512 of Ed25519 seed, first 32 bytes clamped per RFC 7748
- **Edwards → Montgomery public key:** Via `curve25519-dalek::CompressedEdwardsY`
- **Serialization:** 96 bytes = signing_seed(32) + keypair_seed(32) + x25519_secret(32)

### X3DH Key Exchange (`x3dh.rs`)

Implements the Extended Triple Diffie-Hellman protocol for establishing shared secrets without prior interaction.

**PrekeyBundle** (published by each node):
- `identity_key: [u8; 32]` — Long-term Ed25519 public key
- `signed_prekey: [u8; 32]` — Medium-term X25519 (rotated weekly)
- `signed_prekey_signature: Vec<u8>` — Ed25519 signature over SPK
- `one_time_prekeys: Vec<([u8; 32], u32)>` — Ephemeral X25519 keys (consumed once)

**Key Derivation:**
```
DH1 = X25519(our_identity_secret, their_signed_prekey)
DH2 = X25519(ephemeral_secret, their_identity_key)
DH3 = X25519(ephemeral_secret, their_signed_prekey)
DH4 = X25519(ephemeral_secret, their_one_time_prekey)  [optional]

shared_secret = HKDF-SHA256(
    salt = zeros(32),
    ikm  = DH1 || DH2 || DH3 [|| DH4],
    info = b"MyceliumX3DH",
    len  = 32
)
```

### Double Ratchet (`double_ratchet.rs`)

Provides forward-secret per-message encryption after X3DH establishes the initial shared secret.

**RatchetState** tracks:
- Current DH keypair (regenerated on each direction change)
- Root key, sending chain key, receiving chain key
- Send/receive counters, skipped message keys (max 1000)

**KDF chains:**
- **Root KDF:** `HKDF-SHA256(root_key, dh_output, info=b"MyceliumRatchet")` → (new_root_key, chain_key)
- **Chain KDF:** `SHA-256(chain_key || 0x01)` → message_key; `SHA-256(chain_key || 0x02)` → next_chain_key
- **AEAD:** `HKDF-SHA256(message_key, info=b"MyceliumAEAD")` → AES-256-GCM key(32) + nonce(12)

### Session Management (`session.rs`)

Combines X3DH + Double Ratchet into a unified session interface:

```rust
pub struct SessionManager {
    sessions: HashMap<NodeId, Session>,  // One session per peer
}
```

- `initiate_session()` — Alice side: X3DH → init_alice → store session
- `accept_session()` — Bob side: X3DH respond → init_bob → store session
- `encrypt_for()` / `decrypt_from()` — Per-message ratchet operations
- `verify_session()` — Mark session as verified after safety number comparison

**Safety Numbers:** `SHA-256(b"MyceliumSafetyNumber" || min(key_a, key_b) || max(key_a, key_b))` → split into 16 groups of 4-digit numbers. Symmetric (same from both perspectives).

### Web of Trust (`wot.rs`)

```rust
pub struct TrustGraph {
    vouches: HashMap<NodeId, HashSet<NodeId>>,      // voucher → vouchees
    vouched_by: HashMap<NodeId, HashSet<NodeId>>,   // vouchee → vouchers
    max_hops: u8,                                    // default: 4
}
```

- **Vouching:** Ed25519-signed statement: `sign(key, b"mycelium-vouch-v1:" || voucher_id || vouchee_id || name || timestamp)`
- **Trust scoring:** BFS with exponential decay: 1 hop = 1.0, 2 hops = 0.5, 3 hops = 0.25, 4 hops = 0.125
- **Trust path:** BFS parent tracking returns shortest path between nodes

### Sender Key Groups (`group.rs`)

Simplified MLS for groups. Each member generates a sender key (32-byte chain key + iteration counter) and distributes it to other members via pairwise Double Ratchet sessions.

- **Encrypt:** Derive message key via `HKDF-SHA256(chain_key, iteration, info=b"MyceliumGroupMK")`, encrypt with `AES-256-GCM(key, nonce, plaintext, group_id_as_aad)`
- **Forward secrecy:** Chain key advanced via `SHA-256(chain_key || b"MyceliumGroupCK")` (one-way)
- **Member removal:** Triggers sender key rotation (new key generated, old key can't decrypt future messages)

### Info Strings (Domain Separation)

| String | Length | Usage |
|--------|--------|-------|
| `b"MyceliumX3DH"` | 12 | X3DH shared secret derivation |
| `b"MyceliumRatchet"` | 15 | Double Ratchet root KDF |
| `b"MyceliumAEAD"` | 12 | Per-message AEAD key derivation |
| `b"MyceliumSafetyNumber"` | 20 | Safety number generation |
| `b"MyceliumGroupMK"` | 15 | Group message key derivation |
| `b"MyceliumGroupCK"` | 15 | Group chain key advancement |
| `b"MyceliumGroupAEAD"` | 17 | Group AEAD key derivation |

**Tests:** ~35 tests covering identity, X3DH (with/without OTP), ratchet (basic, out-of-order, wrong AD), sessions, WoT (12 graph tests), and groups.

---

## 7. mycelium-core

**Purpose:** Transport abstraction layer, mesh routing, and DTN engine.

### Transport Trait (`transport/mod.rs`)

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    fn transport_type(&self) -> TransportType;
    async fn start(&self) -> Result<(), TransportError>;
    async fn stop(&self) -> Result<(), TransportError>;
    async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError>;
    fn events(&self) -> broadcast::Receiver<TransportEvent>;
    fn link_quality(&self, peer: &NodeId) -> Option<LinkQuality>;
    fn connected_peers(&self) -> Vec<NodeId>;
    fn mtu(&self) -> usize;
}
```

**TransportType:** Ble, WifiDirect, Mock

**TransportEvent:** `NeighborDiscovered`, `NeighborLost`, `DataReceived` (each carries peer, transport type, and optional data)

### TransportManager (`transport/manager.rs`)

Multiplexes multiple transports behind a single interface:

- `add_transport()` — Registers a transport, starts it if manager is already started, spawns event forwarder
- `send(peer, data)` — Sends via the first transport that has `peer` connected
- `known_peers()` — Union of all transports' connected peers
- Event forwarding: Each transport's event stream is forwarded to a unified broadcast channel

### BLE Transport (`transport/ble.rs`)

```rust
pub struct BleTransport {
    local_id: NodeId,
    tx: broadcast::Sender<TransportEvent>,
    connected_peers: Arc<RwLock<Vec<NodeId>>>,
    started: Arc<RwLock<bool>>,
    send_callback: Arc<RwLock<Option<BleSendCallback>>>,
    outbox: Arc<Mutex<VecDeque<(NodeId, Vec<u8>)>>>,  // std::sync::Mutex
}
```

- **send():** If send callback registered, invokes it directly. Otherwise pushes to outbox for Dart polling.
- **dequeue_send():** Called by Dart at 50ms intervals via FFI to retrieve pending packets.
- **on_peer_discovered/lost/data_received():** Called by platform code via FFI to inject BLE events.
- **MTU:** 512 bytes

### Wi-Fi Direct Transport (`transport/wifi_direct.rs`)

```rust
pub struct WifiDirectTransport {
    local_id: NodeId,
    tx: broadcast::Sender<TransportEvent>,
    connected_peers: Arc<RwLock<Vec<NodeId>>>,
    started: Arc<RwLock<bool>>,
    send_callback: Arc<RwLock<Option<WifiSendCallback>>>,
    outbox: Arc<Mutex<VecDeque<(NodeId, Vec<u8>)>>>,  // std::sync::Mutex
}
```

- **send():** If send callback registered, invokes it directly. Otherwise pushes to outbox for Dart polling.
- **dequeue_send():** Called by Dart at 50ms intervals via FFI to retrieve pending packets.
- **on_peer_connected/disconnected/data_received():** Called by platform code via FFI to inject Wi-Fi Direct events.
- **MTU:** 65535 bytes (TCP handles segmentation)
- **LinkQuality:** ~50 Mbps throughput, 10ms latency, -40 RSSI

**Platform integration (ADR-003):**
- `WifiDirectService.kt`: Android WifiP2pManager + Bonjour service discovery + TCP sockets on port 9740
- `WifiDirectManager.dart`: Dart bridge between Kotlin EventChannel/MethodChannel and Rust FFI
- TCP wire protocol: 1-byte type (Hello=0x01, MeshData=0x02) + 4-byte BE length + payload

### AODV Routing (`routing/aodv.rs`)

Reactive routing protocol (spec Section 4.1, Layer 1):

```rust
pub struct AodvRouter {
    local_id: NodeId,
    routing_table: HashMap<NodeId, RouteEntry>,  // destination → next_hop + metrics
    sequence_number: u32,                         // Per-node sequence counter
    request_id: u32,                              // RREQ counter
    seen_rreqs: HashMap<(NodeId, u32), Instant>,  // Deduplication
}
```

- **Route discovery:** `initiate_route_discovery(dest)` → floods RREQ to all neighbors
- **RREQ handling:** If destination is us → generate RREP; if we have route → forward RREP; else → rebroadcast RREQ
- **RREP handling:** Install route entry, propagate back toward source
- **Route expiry:** Entries expire after configurable lifetime (default 60s)
- **Link break:** Generate RERR, invalidate affected routes

**AodvAction** enum: `Forward(RREQ)`, `BroadcastRreq`, `UnicastRrep`, `RouteFound { destination, next_hop }`, `BroadcastRerr`, `None`

### DTN Spray-and-Wait (`dtn/spray_and_wait.rs`)

Store-carry-forward protocol (spec Section 4.1, Layer 2):

```rust
pub struct DtnEngine {
    config: DtnConfig,
    bundles: HashMap<MessageId, DtnBundle>,
    total_stored_bytes: usize,
    per_source_bytes: HashMap<NodeId, usize>,
    sprayed_to: HashMap<MessageId, Vec<NodeId>>,
}
```

**DtnConfig defaults (Phone):** `spray_copies=8, ttl=72h, max_storage=256MB, per_identity_quota=10MB`
**DtnConfig supernode:** `max_storage=2GB, per_identity_quota=50MB`

- **Spray phase:** When encountering a relay, give half remaining copies (binary spray). Track already-sprayed peers.
- **Wait phase:** Each copy waits until encountering the destination.
- **Eviction:** TTL expiry first, then oldest-first when storage is full.

### Routing Coordinator (`routing/coordinator.rs`)

Decides between AODV and DTN:

```rust
pub fn route_message(&self, destination: &NodeId) -> RoutingDecision {
    if *destination == self.local_id { return DeliverLocal; }
    if let Some(route) = self.aodv.find_route(destination) {
        return SendRealtime { next_hop: route.next_hop };
    }
    RoutingDecision::DiscoveryPending
}
```

**RoutingDecision:** `SendRealtime { next_hop }`, `DiscoveryPending`, `EnterDtn`, `DeliverLocal`

The node's event loop upgrades `DiscoveryPending` → `EnterDtn` after AODV discovery timeout (5s).

### Messaging Types (`messaging.rs`)

```rust
pub enum MessageStatus { Pending, Sent, DtnPending, Delivered, Read, Failed }

pub struct StoredMessage {
    pub message_id: MessageId,
    pub source: NodeId,
    pub destination: NodeId,
    pub content_type: ContentType,
    pub plaintext: Vec<u8>,
    pub lamport_clock: LamportClock,
    pub device_timestamp: u64,
    pub status: MessageStatus,
    pub is_incoming: bool,
}
```

**Tests:** AODV routing (discovery, RREP, link break), DTN (store, spray, deliver, quota, eviction), transport (mock, manager).

---

## 8. mycelium-storage

**Purpose:** SQLCipher-encrypted persistence layer. Thread-safe via `Mutex<Connection>`.

### Database Schema (9 tables)

| Table | Primary Key | Purpose |
|-------|-------------|---------|
| `schema_version` | `version INTEGER` | Migration tracking |
| `messages` | `message_id BLOB` | Decrypted message storage |
| `sessions` | `peer_id BLOB` | Serialized Double Ratchet state |
| `contacts` | `node_id BLOB` | Contact directory with trust scores |
| `vouches` | `(voucher_id, vouchee_id)` | Signed identity attestations |
| `prekey_cache` | `node_id BLOB` | Cached remote prekey bundles |
| `our_prekeys` | `prekey_id INTEGER` | Own X25519 prekeys (signed + one-time) |
| `dtn_store` | `message_id BLOB` | DTN bundle storage |
| `config` | `key TEXT` | Key-value store (prekey state, group blobs) |

### Initialization

```rust
pub fn open(path: &str, encryption_key: &[u8]) -> Result<Self, StorageError> {
    let conn = Connection::open(path)?;
    conn.execute_batch(&format!("PRAGMA key = x'{}';", hex(encryption_key)))?;
    conn.query_row("SELECT cipher_version();", [], |_| Ok(()))?;  // Verify key
    Self::run_migrations(&conn)?;
    Ok(Database { conn: Mutex::new(conn) })
}
```

Encryption key derived in `main.rs`: `SHA-256(b"mycelium-db-key:" || identity.to_bytes())`

### Key Operations

- **Messages:** insert, get, update_status, get_conversation (bidirectional, ordered by lamport_clock), list_conversations, mark_read, unread_count, delete_conversation
- **Sessions:** save, load, list, delete (serialized Double Ratchet blob)
- **Contacts:** save, get, list (ordered by display_name)
- **Vouches:** save, get_vouches_by, get_vouches_for, list_all, remove
- **Prekeys:** store, get_unused_one_time, mark_used, count_unused, cache/get/remove bundles, save/load_prekey_state_blob
- **DTN:** store, get_for_destination, remove, expire, list_all, update_copies, storage_used
- **Groups:** save/load/list/remove_group_blob (serialized in config table as `group:<hex_id>`)

**Design decisions:**
- All writes use INSERT OR REPLACE (idempotent upserts)
- Status stored as TEXT for extensibility
- Group/prekey state stored as opaque blobs (avoids complex schema)
- `Mutex<Connection>` makes Database `Send + Sync` for tokio

**Tests:** 5 integration tests using in-memory databases.

---

## 9. mycelium-node

**Purpose:** The node daemon. Contains the main event loop, message pipeline, and all protocol handlers. The largest crate (~4000 lines of code + ~1000 lines of tests).

### Node Struct (`node.rs`)

```rust
pub struct Node {
    pub node_id: NodeId,
    pub identity: Identity,
    pub db: Arc<Database>,
    pub transport_manager: Arc<TransportManager>,
    pub ble_transport: Arc<RwLock<Option<Arc<BleTransport>>>>,
    pub wifi_transport: Arc<RwLock<Option<Arc<WifiDirectTransport>>>>,
    routing: Arc<RwLock<RoutingCoordinator>>,
    session_manager: Arc<RwLock<SessionManager>>,
    prekey_state: Arc<RwLock<PrekeyState>>,
    trust_graph: Arc<RwLock<TrustGraph>>,
    groups: Arc<RwLock<HashMap<[u8; 32], SenderKeyGroup>>>,
    pending_messages: Arc<RwLock<HashMap<NodeId, Vec<PendingMessage>>>>,
    pending_routes: Arc<RwLock<HashMap<NodeId, Vec<PendingRouteEnvelope>>>>,
    lamport_clock: Arc<RwLock<LamportClock>>,
    battery: Arc<RwLock<BatteryManager>>,
    rate_limiter: Arc<RwLock<RateLimiter>>,
    cancel_token: CancellationToken,
    config: NodeConfig,
}
```

### Event Loop (`start()`)

Spawns concurrent tasks:

1. **Transport event listener** — Processes `NeighborDiscovered`, `NeighborLost`, `DataReceived`
2. **Beacon broadcaster** — Sends heartbeats every `config.beacon_interval_secs` (default 10s)
3. **Maintenance timer** — Every 30s: expire AODV routes, expire DTN bundles, cleanup rate limiter, rotate prekeys

### Message Sending Pipeline (`send_message()`)

```
send_message(destination, plaintext, content_type)
  ├─ Session exists?
  │   → encrypt with Double Ratchet
  │   → wrap in EncryptedPayload
  │   → wrap in Envelope
  │   → route_and_send_envelope()
  ├─ Prekey cached?
  │   → initiate_and_send_session()
  │     → X3DH initiate → init Double Ratchet → encrypt
  │     → wrap in SessionInitPayload → route
  └─ Neither?
      → queue in pending_messages
      → send PrekeyRequest → route
```

### Incoming Message Handlers

| Payload Type | Handler | Action |
|--------------|---------|--------|
| EncryptedMessage | `handle_encrypted_message()` | Decrypt → store → send delivery receipt |
| SessionInit | `handle_session_init()` | Accept X3DH → decrypt first msg → store |
| PrekeyRequest | `handle_prekey_request()` | Respond with our prekey bundle |
| PrekeyResponse | `handle_prekey_response()` | Cache bundle → flush pending_messages |
| AODV RREQ/RREP/RERR | `handle_aodv_*()` | Update routing table, broadcast/unicast |
| Beacon | `handle_beacon()` | Auto-create/update contact, merge lamport clock |
| Receipt | `handle_receipt()` | Update message status (Delivered/Read) |
| DtnRelay | `handle_dtn_relay()` | Deliver locally or store for relay |
| GroupMessage | `handle_group_message()` | Decrypt with sender key → store |
| SenderKeyDist | `handle_sender_key_dist()` | Install sender key for group member |

### NeighborDiscovered Handler

When a new neighbor is discovered:
1. Add direct AODV route via `routing.on_neighbor_encountered()`
2. Process DTN actions (deliver local bundles, spray copies)
3. Flush `pending_routes` for the discovered peer

### Beacon (`beacon.rs`)

```
Serialization format:
[4]  Magic: "MYCO"
[32] node_id
[1]  node_type byte
[1]  name_length (max 255)
[*]  display_name
[2]  protocol_version (u16 LE)
[1]  battery_level
[2]  neighbor_count (u16 LE)
[8]  lamport_clock (u64 LE)
```

Beacons are broadcast to all neighbors with TTL=1 (no forwarding) every 10 seconds.

### Rate Limiter (`rate_limiter.rs`)

Trust-based rate limiting per spec Section 11:

| Trust Hops | Messages/Hour | DTN Relay Quota |
|------------|---------------|-----------------|
| 0-1 (direct) | Unlimited | 50 MB |
| 2 | 500 | 10 MB |
| 3 | 100 | 2 MB |
| 4 | 20 | 500 KB |
| 5+ (unknown) | 5 | 100 KB |

Auto-blacklist after 10 violations per window (1 hour blacklist duration).

### Battery Management (`battery.rs`)

| Battery Level | Charging | Neighbors | PowerMode |
|---------------|----------|-----------|-----------|
| Unknown/wired | — | — | Full |
| Any | Yes | — | Full |
| 0-4% | No | — | Hibernate (disconnect) |
| 5-19% | No | — | Leaf (receive only) |
| 20-49% | No | — | Light (own connections, direct trust relay) |
| 50-100% | No | ≤2 | Full (critical for mesh) |
| 50-100% | No | >2 | Moderate (Wi-Fi relay only) |

### Configuration (`config.rs`)

```rust
pub struct NodeConfig {
    pub data_dir: String,           // "./mycelium-data"
    pub display_name: String,       // "Mycelium Node"
    pub node_type: NodeTypeConfig,  // Phone | Supernode
    pub dtn: DtnStorageConfig,      // 256MB/10MB/72h/8 copies
    pub beacon_interval_secs: u64,  // 10
    pub api: ApiConfig,             // REST/WS server bind + port
    pub group_seed: Option<String>, // Group discovery key (hex)
}
```

### CLI (`main.rs`)

```
mycelium-node [OPTIONS] [CONFIG_FILE]

Options:
  --supernode     Run as supernode (always-on, 2GB DTN, internet transport, API on 0.0.0.0)
  --data-dir DIR  Override data directory
  --port PORT     Override API server port
  --help          Print help
```

When `--supernode` is passed:
- Uses `NodeConfig::supernode()` as base (2GB DTN, 50MB per-identity quota)
- Enables internet tunnel transport automatically
- Binds API server to `0.0.0.0` for remote management
- Uses `BatteryManager::always_on()` (always `PowerMode::Full`)

**Tests:** 40+ tests across 4 test files covering lifecycle, message exchange, multi-hop routing, DTN fallback, persistence, receipts, beacons, and session management.

---

## 10. mycelium-api

**Purpose:** Local REST + WebSocket API server for interacting with a Mycelium node. Any app (including the Flutter chat app in the future) connects to this API instead of using direct FFI. See ADR-001.

### Architecture

```
Client Apps ──▶ REST (axum)     ──▶ Node methods / Database queries
             ──▶ WebSocket (axum) ──▶ Event broadcast + bidirectional messaging
```

### Technology Stack

- **HTTP/WS server:** `axum` 0.8 with built-in WebSocket support
- **Serialization:** `serde_json` (Phase 1). Protobuf via `prost` planned for Phase 2.
- **CORS:** `tower-http` CorsLayer (permissive for localhost)
- **Default bind:** `127.0.0.1:9735` (configured via `NodeConfig.api`)

### REST Endpoints

| Group | Endpoints | Description |
|-------|-----------|-------------|
| `/v1/node/` | `status`, `identity`, `trust` | Node ID, uptime, public key, trust graph stats |
| `/v1/messages/` | CRUD + mark-read | Send messages, get conversation, delete |
| `/v1/conversations/` | list, unread count | Conversation summaries with display names |
| `/v1/contacts/` | CRUD + trust + vouch + verify + safety-number | Add/list/delete contacts, trust scores, vouching |
| `/v1/groups/` | CRUD + members + messages | Create groups, manage members, send group messages |
| `/v1/channels/` | CRUD + subscribe + messages | Create/list channels, subscribe/unsubscribe, post/get messages |
| `/v1/prekeys/{node_id}` | GET | Retrieve cached prekey bundle for a peer |
| `/v1/emergency/` | broadcast, history | Send emergency alerts, view history |
| `/v1/network/` | status, routes, dtn, transports, peers, pending, events | Diagnostics: AODV table, DTN queue, per-transport status, unified peers, pending queues, event log |

### WebSocket API

Connect to `/v1/ws`. JSON-framed messages:

**Client → Server:**
- `subscribe` — Filter incoming messages by protocol IDs
- `send` — Send data to a destination node

**Server → Client:**
- `message` — Incoming message (filtered by subscription)
- `peer` — Neighbor discovered/lost events
- `network` — Periodic network status (broadcast every 5 seconds with neighbor count, connectivity, DTN queue size)
- `receipt` — Delivery receipt status changes
- `channel_message` — Channel message received
- `emergency` — Emergency broadcast received (source, level, message)

### Key Types

- `AppState` — Shared state: `Arc<Node>` + `broadcast::Sender<WsServerMessage>` + start time + event log ring buffer
- `WsServerMessage` — Enum of all server-pushed event types (Clone for broadcast)
- `ApiConfig` — Bind address, port, enabled flag (in `NodeConfig`)

### Integration Points

- `Node.send_message()` — Called by message POST and WebSocket send
- `Node.db.*` — Direct database queries for messages, contacts, conversations
- `Node.routing.read().aodv().routes()` — AODV routing table inspection
- `Node.routing.read().dtn().bundles()` — DTN bundle queue inspection
- `Node.pending_messages_count()` / `Node.pending_routes_count()` — Pending queue sizes

**Tests:** 11 integration tests covering all REST endpoints, error handling, contact CRUD, and 404s.

---

## 11. mycelium-ffi

**Purpose:** C FFI bridge between Rust and mobile platforms. Exposes 48 `extern "C"` functions.

### Architecture

```rust
static RUNTIME: OnceLock<Runtime> = OnceLock::new();  // Single global Tokio runtime

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime::new().expect("tokio runtime"))
}
```

All async operations use `runtime().block_on(async { ... })` to bridge sync C to async Rust.

### Thread-Local State

```rust
thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
    static MESSAGE_PLAINTEXTS: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::new());
}
```

- **Error reporting:** `mycelium_last_error()` retrieves last error, `mycelium_clear_error()` clears it
- **Plaintext lifetime:** `MessageInfo.plaintext` pointers valid only until next `mycelium_get_messages()` call on the same thread

### Function Groups (49 functions)

| Group | Functions | Description |
|-------|-----------|-------------|
| Error | `last_error`, `clear_error` | Thread-local error retrieval |
| Lifecycle | `node_new`, `node_start`, `node_stop`, `node_id`, `node_free` | Node creation/destruction |
| Messaging | `send_message`, `get_messages`, `set_message_callback` | Send/receive messages |
| Conversations | `get_conversations`, `delete_conversation`, `mark_read`, `unread_count`, `total_unread_count` | Conversation management |
| Contacts | `contact_count`, `get_contacts`, `set_display_name`, `get_display_name` | Contact CRUD |
| Groups | `create_group`, `add_group_member`, `remove_group_member`, `group_member_count`, `get_group_members`, `send_group_message` | Group management |
| Trust | `add_vouch`, `trust_score`, `verify_session`, `safety_number` | Web of Trust |
| Network | `network_status`, `update_battery` | Status and battery |
| Transport | `register_ble_transport`, `register_wifi_direct_transport` | Register transports |
| BLE Events | `ble_on_peer_discovered`, `ble_on_peer_lost`, `ble_on_data_received` | Platform → Rust |
| Wi-Fi Events | `wifi_on_peer_connected`, `wifi_on_peer_disconnected`, `wifi_on_data_received` | Platform → Rust |
| Outbox | `ble_dequeue_send`, `wifi_dequeue_send` | Rust → Platform polling |
| Callbacks | `ble_set_send_callback`, `wifi_set_send_callback` | Rust → Platform direct |

### Memory Management

- **Node handle:** `Box::into_raw()` on create, `Box::from_raw()` on free. Caller must call `mycelium_node_free()` exactly once.
- **Return convention:** 0 = success, -1 = invalid pointers, -2 = operation failed (check `last_error`)
- **Plaintext pointers:** Valid only until next `get_messages()` call (stored in thread-local Vec)

### C Header (`include/mycelium.h`)

Defines:
- `MyceliumNode` opaque struct
- FFI structs: `MessageInfo`, `ConversationInfo`, `ConversationSummary`, `NetworkStatus`, `ContactInfo`
- Callback types: `MessageCallback`, `TransportSendCallback`
- All 48 function declarations with C-compatible signatures

---

## 12. Flutter App

**Purpose:** Android mobile UI. Uses Flutter with Riverpod for state management, GoRouter for navigation, and dart:ffi for native library access.

### App Structure

```
main.dart → App (MaterialApp + GoRouter)
  ├─ /conversations → ConversationsScreen (conversation list)
  ├─ /contacts      → ContactsScreen (contact list + QR scan)
  ├─ /settings      → SettingsScreen (node ID + QR code display)
  ├─ /chat/:peerId  → ChatScreen (message view + send)
  └─ /qr-scanner    → QrScannerScreen (camera QR reader)
```

### Service Layer

**MyceliumService** (singleton via Riverpod):
- `initialize()` — Creates `MyceliumNode` via FFI, generates identity, opens DB
- `start()` — Starts node, registers BLE transport, creates BleManager, begins polling
- `_poll()` — 500ms timer checking for new messages and unread counts
- Wraps all FFI calls with error handling and type conversion

**BleManager** (platform channel bridge):
- `start(nodeId)` — Sends `start` via MethodChannel, listens to EventChannel
- `_pollOutbox()` — 50ms timer calling `mycelium_ble_dequeue_send()`, forwards to Kotlin `sendData()`
- Event handlers forward `peerDiscovered`/`peerLost`/`dataReceived` to Rust FFI

### Riverpod Providers

| Provider | Type | Refresh |
|----------|------|---------|
| `myceliumServiceProvider` | Singleton | Manual |
| `conversationListProvider` | Auto-dispose | 2 seconds |
| `chatMessagesProvider(peerId)` | Family, auto-dispose | 1 second |
| `contactListProvider` | Auto-dispose | Manual invalidation |
| `networkStatusProvider` | Auto-dispose | 5 seconds |
| `totalUnreadProvider` | Auto-dispose | 2 seconds |

### Models

- **Message:** message_id, source, destination, content_type, timestamp, status, is_incoming, plaintext
- **Contact:** node_id, display_name, trust_score, is_verified, last_seen
- **Conversation:** peer_id, last_message_time, message_count, has_unread
- **NetworkStatus:** neighbor_count, is_connected, battery_level, dtn_queue_size

### FFI Helpers (`ffi_helpers.dart`)

- `bytesToHex()` / `hexToBytes()` — Hex string conversion
- `arrayToBytes(Array<Uint8>, int)` — Convert C fixed-size arrays to Dart Uint8List
- `stringFromNative(Pointer<Uint8>, int)` — Null-terminated C string to Dart String

### Dependencies (`pubspec.yaml`)

```yaml
ffi: ^2.1.3                    # FFI bindings
path_provider: ^2.1.5          # App documents directory
flutter_riverpod: ^2.6.1       # State management
go_router: ^14.8.1             # Navigation
intl: ^0.19.0                  # Date/time formatting
permission_handler: ^11.3.1    # BLE/camera permissions
qr_flutter: ^4.1.0             # QR code generation
mobile_scanner: ^6.0.2         # QR code scanning
```

---

## 13. Android BLE Stack

**Purpose:** Full dual-role BLE implementation (GATT server + client) in Kotlin. Handles peer discovery, data exchange, fragmentation, and identity mapping.

### GATT Service Design

```
Service UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
├─ Node ID    (7891) Read       — 32-byte Ed25519 public key
├─ Data TX    (7892) Write      — Central writes data to peripheral
├─ Data RX    (7893) Notify     — Peripheral notifies central with data
└─ Identity   (7894) Write      — Client writes own node ID to server
```

### Dual-Role Architecture

Each device simultaneously runs:
- **Peripheral (GATT Server):** Advertises service, accepts connections, serves Node ID reads, handles Data TX writes, notifies Data RX
- **Central (GATT Client):** Scans for Mycelium service, connects, reads peer's Node ID, subscribes to RX notifications, writes to TX

### Identity Mapping (BLE RPA Solution)

BLE Random Private Addresses (RPA) cause different addresses per connection direction. Solution:

1. Client reads server's Node ID characteristic → maps server address to node ID
2. Client writes own node ID to server's Identity characteristic (UUID 7894)
3. Server receives identity write → maps client address to node ID
4. Both directions now have address ↔ node ID mapping

### Fragmentation Protocol

```
Byte 0: Flags
  0x01 = first fragment
  0x02 = last fragment
  0x03 = single packet (first + last)
  0x00 = middle fragment
Bytes 1+: payload chunk
```

Fragment size = `max(negotiated_MTU - 4, 20)` bytes. Reassembly buffers per-device address.

### Write Queue (Sequential Operations)

Android BLE allows only one outstanding GATT operation at a time. The write queue ensures sequential processing:

```kotlin
data class WriteOperation(
    val address: String,
    val fragments: List<ByteArray>,
    var currentIndex: Int,
    val isClientWrite: Boolean
)

private val writeQueue = ConcurrentLinkedQueue<WriteOperation>()
```

`processNextWrite()` sends one fragment, waits for `onCharacteristicWrite` or `onNotificationSent` callback, then sends next fragment or next operation.

### Connection Management

- **Scan:** Filtered by Mycelium service UUID, low latency mode
- **Connect:** Stagger 500-1500ms + jitter if already server-connected, prevent self-connections
- **Retry:** Exponential backoff (1s, 2.5s, 4s) with max 3 retries
- **MTU:** Request 512 bytes, store negotiated value per device (both client and server sides)

### Platform Channels

- **MethodChannel** `com.mycelium.ble`: `start(nodeId)`, `stop()`, `sendData(peerId, data)`
- **EventChannel** `com.mycelium.ble/events`: `peerDiscovered`, `peerLost`, `dataReceived`

### Android Permissions

```xml
<uses-permission android:name="android.permission.BLUETOOTH_SCAN"
    android:usesPermissionFlags="neverForLocation" />
<uses-permission android:name="android.permission.BLUETOOTH_ADVERTISE" />
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.CAMERA" />
```

---

## 14. Build System

### Workspace Build

```bash
# Host tests (all 133 pass)
export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
cargo test
```

### Android Cross-Compilation

`scripts/build-android.sh` handles:

1. Detects NDK location (`ANDROID_NDK_HOME` or common paths)
2. Generates `.cargo/config.toml` with per-target linker settings
3. Prepends rustup toolchain bin to PATH (overrides Homebrew rustc)
4. Sets `CC_*`, `AR_*`, `RANLIB_*` env vars per target for OpenSSL
5. Puts NDK toolchain bin on PATH for `llvm-ranlib` etc.
6. Builds `mycelium-ffi` for 3 targets:
   - `aarch64-linux-android` → `arm64-v8a`
   - `armv7-linux-androideabi` → `armeabi-v7a`
   - `x86_64-linux-android` → `x86_64`
7. Copies `.so` files to `android-libs/<abi>/`

### Flutter Build Integration

`flutter/android/app/build.gradle.kts`:
- Custom Gradle task `buildRustLibrary` runs `./scripts/build-android.sh`
- Hooks into `merge*JniLibFolders` to ensure Rust is built before linking
- JNI libs sourced from `../../../android-libs`
- NDK version pinned to `27.0.12077973`

### FFI Binding Generation

```bash
cd flutter && dart run ffigen --config ffigen.yaml
```

Reads `crates/mycelium-ffi/include/mycelium.h`, generates `lib/src/ffi/mycelium_bindings_generated.dart`.

---

## 15. Wire Format Reference

### Envelope Layout (106-byte header)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────────────────────────────────────────────────────────────┤
│                         source (32 bytes)                       │
├─────────────────────────────────────────────────────────────────┤
│                      destination (32 bytes)                     │
├─────────────────────────────────────────────────────────────────┤
│                      message_id (16 bytes)                      │
├────────┬────────┬──────────────┬────────────────────────────────┤
│  ttl   │hop_cnt │  flags (LE)  │      lamport_clock (LE)        │
│  (1)   │  (1)   │    (2)       │           (8)                  │
├────────┴────────┴──────────────┼────────────────────────────────┤
│      device_timestamp (LE)     │proto_ver│  payload_length (LE) │
│            (8)                 │  (2)    │       (4)            │
├────────────────────────────────┴─────────┴─────────────────────┤
│                        payload (variable)                       │
└─────────────────────────────────────────────────────────────────┘
```

### Typical Message Sizes

| Message Type | Envelope + Payload | Notes |
|--------------|-------------------|-------|
| Prekey Request | ~139 bytes | 106 header + 33 payload |
| Prekey Response | ~278 bytes | 106 header + ~172 payload |
| Encrypted Text | ~180-250 bytes | 106 header + 46 min + ciphertext |
| Session Init | ~250-350 bytes | 106 header + 69-73 min + encrypted msg |
| Beacon | ~100-160 bytes | 106 header + variable name |
| Receipt | ~124 bytes | 106 header + 18 payload |
| AODV RREQ | ~185 bytes | 106 header + 79 payload |

---

## 16. Cryptographic Architecture

### Key Hierarchy

```
Identity Generation:
  Ed25519 seed (32 bytes, from OsRng)
    ├─ Ed25519 SigningKey → VerifyingKey (signing/verification)
    ├─ SHA-512(seed)[0:32] clamped → X25519 StaticSecret → PublicKey (DH)
    └─ SHA-256(VerifyingKey) → NodeId (32 bytes, identity)

Session Establishment (X3DH):
  HKDF-SHA256(DH1||DH2||DH3[||DH4], info="MyceliumX3DH") → shared_secret (32)
    └─ Double Ratchet root key

Per-Message Encryption (Double Ratchet):
  Root Key ──HKDF("MyceliumRatchet")──→ new Root Key + Chain Key
  Chain Key ──SHA256(||0x01)──→ Message Key
            ──SHA256(||0x02)──→ next Chain Key
  Message Key ──HKDF("MyceliumAEAD")──→ AES-256 Key (32) + Nonce (12)
    └─ AES-256-GCM(key, nonce, plaintext, AD=source||destination)

Group Messaging (Sender Keys):
  Chain Key ──HKDF("MyceliumGroupMK")──→ Message Key
            ──SHA256(||"MyceliumGroupCK")──→ next Chain Key
  Message Key ──HKDF("MyceliumGroupAEAD")──→ AES-256 Key (32) + Nonce (12)
    └─ AES-256-GCM(key, nonce, plaintext, AD=group_id)
```

### Security Properties

| Property | Mechanism |
|----------|-----------|
| Forward secrecy | DH ratchet generates new keys on direction change |
| Post-compromise security | DH ratchet + ephemeral keys |
| Authenticated encryption | AES-256-GCM with associated data |
| Identity authentication | Ed25519 signatures on prekey bundles |
| Out-of-order tolerance | Skipped message keys stored (max 1000 gap) |
| Group forward secrecy | Sender key rotation on member removal |
| Metadata privacy | Routing headers visible; payload always encrypted |

---

## 17. Routing Architecture

### Decision Flow

```
Node.send_message(destination, data)
  │
  ▼
RoutingCoordinator.route_message(destination)
  │
  ├── DeliverLocal (destination == self) → error
  │
  ├── SendRealtime { next_hop }
  │     └── AODV table has route → transport_manager.send(next_hop, envelope)
  │
  ├── DiscoveryPending
  │     ├── Initiate AODV RREQ broadcast
  │     ├── Queue envelope in pending_routes[destination]
  │     └── After timeout (5s): EnterDtn
  │
  └── EnterDtn
        └── DtnEngine.store_outgoing(msg_id, dest, src, payload)
              └── spray_copies=8, ttl=72h
```

### Neighbor Discovery Flow

```
BLE scan finds device with Mycelium service UUID
  → GATT connect → read Node ID characteristic
    → EventChannel peerDiscovered → FFI ble_on_peer_discovered()
      → BleTransport.on_peer_discovered(peer)
        → TransportEvent::NeighborDiscovered broadcast
          → Node event loop:
            1. routing.on_neighbor_encountered(peer)
               ├── Add direct AODV route
               └── Check DTN bundles for this peer
            2. Flush pending_routes[peer]
            3. Process DTN actions (spray/deliver)
```

---

## 18. Test Coverage

### By Crate

| Crate | Test Files | Tests | Coverage Areas |
|-------|------------|-------|----------------|
| mycelium-protocol | 3 modules | 26 | Type display, lamport ops, envelope roundtrips, all payload roundtrips |
| mycelium-crypto | 6 modules | ~35 | Identity gen/serde, X3DH ±OTP, ratchet basic/OOO/wrong-AD, sessions, WoT graph (12), groups |
| mycelium-core | 3 modules | ~20 | AODV routing, DTN spray/deliver/quota/eviction, transport mock/manager |
| mycelium-storage | 2 modules | 5 | Message CRUD, mark-read/unread, conversation queries, vouch CRUD |
| mycelium-node | 4 test files | ~40 | Lifecycle, 2-node exchange, multi-hop, DTN fallback, receipts, beacons, persistence (12), session/prekey roundtrips |
| mycelium-api | 1 test file | 11 | REST endpoints, JSON responses, error handling, contact CRUD |
| mycelium-ffi | — | 0 | No unit tests (integration via Flutter) |
| **Total** | | **~144** | |

### Integration Test Highlights

- **`test_two_nodes_exchange_messages`** — Full pipeline: prekey request → response → session → encrypt → send → receive → decrypt → store (500ms)
- **`test_three_node_multihop`** — Alice → Bob → Carol multi-hop AODV routing
- **`test_partition_triggers_dtn_fallback`** — AODV timeout → DTN store-and-forward (65s test)
- **`test_delivery_receipts`** — Delivery receipt updates message status
- **`test_vouch_persistence_and_trust`** — Trust graph rebuild from persisted vouches

---

## 19. Spec Compliance Matrix

| Spec Section | Feature | Status | Notes |
|-------------|---------|--------|-------|
| §2 Architecture | Rust core + mobile UI | **Implemented** | Flutter instead of Jetpack Compose |
| §3.1 Wi-Fi Direct | Transport | **Implemented** | Rust outbox + Android WifiP2pManager + Dart bridge (ADR-003) |
| §3.1 BLE | Transport | **Implemented** | Full dual-role GATT, fragmentation, write queue |
| §3.1 BT Classic | Transport | **Not started** | Deferred to v0.4 |
| §3.1 LoRa | Transport | **Not started** | Deferred to v0.4 |
| §3.1 Internet Tunnel | Transport | **Not started** | Deferred to v0.2 |
| §3.2 Transport Handoff | Seamless migration | **Partial** | TransportManager sends via first available, no session migration |
| §3.3 iOS Strategy | BLE relay | **Not started** | Deferred to v0.2 |
| §4.1 AODV Routing | Reactive routing | **Implemented** | RREQ/RREP/RERR, route table, expiry |
| §4.1 DTN Spray-and-Wait | Store-and-forward | **Implemented** | Binary spray, per-identity quotas, eviction |
| §4.2 Geographic Hash | Overlay routing | **Not started** | Deferred to v0.4 |
| §5.1 Ed25519 Identity | Keypair identity | **Implemented** | Device-bound, no external identifiers |
| §5.2 Web of Trust | Transitive trust | **Implemented** | BFS scoring with decay, vouch signing |
| §5.3 Sybil Defense | Rate limiting | **Implemented** | Trust-based rate limits + blacklisting |
| §5.4 Threshold Revocation | Key revocation | **Not started** | Deferred to v0.4 |
| §6.1 X3DH | Key exchange | **Implemented** | SPK + OTP, signature verification |
| §6.1 Double Ratchet | Forward-secret msgs | **Implemented** | DH ratchet, chain keys, out-of-order support |
| §6.2 Group MLS | Group encryption | **Implemented** | Simplified sender keys (not full MLS tree) |
| §6.3 DTN Relay Storage | Encrypted blobs | **Implemented** | SQLCipher, per-identity quotas |
| §7 Multi-Device | Linked devices | **Not started** | Deferred to v0.3 |
| §8.1 Content Types | Message types | **Implemented** | Text, Image, File, GpsPin, VoiceNote, Receipt, System |
| §8.2 Lamport Clocks | Message ordering | **Implemented** | Tick on send, merge on receive |
| §8.3 Receipts | Delivery/Read | **Implemented** | Auto-send on receive, update status |
| §8.4 Public Channels | Broadcast boards | **Not started** | Deferred to v0.2 |
| §9 Emergency Broadcast | Tiered emergencies | **Complete** | Wire types, trust-gated handler, REST API, Flutter UI |
| §10 OpenWRT Supernode | Router package | **Partial** | CLI `--supernode`, auto-config, route preference, prekey cache API |
| §11 Rate Limiting | Trust + rate hybrid | **Implemented** | Per-tier limits, auto-blacklist |
| §12 Internet Tunnel | Opportunistic tunnel | **Not started** | Deferred to v0.2 |
| §13 Protocol Versioning | Backwards compat | **Partial** | Version field in envelope, no negotiation yet |
| §14 Plugin System | Transport plugins | **Not started** | Deferred to v0.3 |
| §15 Onboarding | Seed phrase groups | **Not started** | QR code sharing implemented instead |
| §16 Battery Management | Adaptive power | **Implemented** | 5 power modes, platform battery injection |
| §17 UI | Core screens | **Implemented** | Chat, Contacts, Settings, QR Scanner |
| §18 Docker Testbed | CI/CD testing | **Not started** | Unit/integration tests only |

### Deviations from Spec

1. **UI Framework:** Flutter/Dart instead of Jetpack Compose (spec §2.3)
2. **Wire Format:** Custom binary codec instead of Cap'n Proto (spec §2.3). Schemas kept as documentation.
3. **Group Crypto:** Simplified sender keys instead of full MLS tree ratchet (spec §6.2). Adequate for groups <20 members.
4. **Onboarding:** QR code scanning instead of seed phrase groups (spec §15). Simpler UX.
5. **Transport:** BLE and Wi-Fi Direct both implemented. Wi-Fi Direct uses TCP sockets over WifiP2pManager groups (ADR-003).

---

*This document reflects the codebase as of 2026-03-10. Update when significant architectural changes are made.*
