# Mycelium

**Infrastructure-independent mesh communications platform**

Mycelium creates ad-hoc mesh networks using standard smartphone radios (BLE, Wi-Fi Direct) with end-to-end encryption, multi-hop routing, and delay-tolerant networking. No internet, no cell towers, no servers. Messages route through nearby devices and store-carry-forward across network partitions.

## How It Works

```
Phone A ←──BLE──→ Phone B ←──WiFi Direct──→ Phone C
   │                 │                          │
   └── Messages route through intermediate ─────┘
       nodes via AODV reactive routing.
       When no route exists, DTN spray-and-wait
       stores messages for later delivery.
```

Every message is end-to-end encrypted using the Signal Protocol (X3DH key exchange + Double Ratchet). Identity is a device-bound Ed25519 keypair — no phone numbers, no email, no accounts. Trust is established through a Web of Trust with signed vouches.

## Features

**Messaging**
- 1-on-1 encrypted chat (Signal Protocol: X3DH + Double Ratchet)
- Group messaging (Sender Key encryption)
- Public channels (broadcast boards with moderation)
- Delivery and read receipts with real-time WebSocket push
- 7 content types: text, image, file, GPS pin, voice note, receipt, system

**Networking**
- BLE mesh transport (dual-role GATT, fragmentation, 512-byte MTU)
- Wi-Fi Direct transport (P2P groups, TCP sockets, 65KB MTU)
- AODV reactive routing for multi-hop message delivery
- DTN spray-and-wait for delay-tolerant delivery (72h TTL, L=8 copies)
- Supernode mode for always-on backbone nodes (`--supernode`)
- Transport plugin system for third-party radio hardware

**Security**
- Ed25519 identity keys (device-bound, no external identifiers)
- X25519 Diffie-Hellman key exchange
- AES-256-GCM authenticated encryption
- Forward secrecy via DH ratchet
- Web of Trust with signed vouches and BFS trust scoring
- Trust-based rate limiting and auto-blacklisting
- SQLCipher encrypted database

**Platform**
- Rust core (7 crates, 186 tests)
- Local REST API (47 endpoints) + WebSocket server
- Flutter/Android mobile app (14 screens)
- Onboarding with seed phrase groups or QR code scanning
- Emergency broadcast system (3 trust-gated tiers)
- Battery-adaptive power modes (5 levels)

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                    Flutter UI (Dart)                           │
│  14 screens, Riverpod state, GoRouter navigation              │
├───────────────────────────────────────────────────────────────┤
│               Service Layer (Dart + Kotlin)                   │
│  REST API Client ←→ WebSocket Events ←→ BLE/WiFi Managers    │
├───────────────────────────────────────────────────────────────┤
│              C FFI Boundary (libmycelium_ffi.so)              │
├───────────────────────────────────────────────────────────────┤
│  mycelium-api     │ REST + WebSocket server (axum, JSON)      │
│  mycelium-node    │ Event loop, message pipeline, beacons     │
│  mycelium-core    │ Transports, AODV routing, DTN, DHT        │
│  mycelium-crypto  │ X3DH, Double Ratchet, WoT, Groups        │
│  mycelium-storage │ SQLCipher encrypted database              │
│  mycelium-protocol│ Wire format, binary codec                 │
└───────────────────────────────────────────────────────────────┘
```

The Rust daemon exposes a local API on `127.0.0.1:9735`. The Flutter app (and any future client) communicates exclusively through this API. FFI is retained only for transport bridging (BLE/Wi-Fi Direct hardware access).

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) (stable, via rustup — not Homebrew)
- [Flutter](https://flutter.dev/docs/get-started/install) 3.29+
- Android SDK with NDK `27.0.12077973`

### Build and Test

```bash
# Rust workspace
make build    # Debug build
make test     # Run all 186 tests
make lint     # cargo fmt --check + cargo clippy

# Flutter app
make flutter-get      # Install dependencies
make flutter-analyze  # Static analysis
make flutter-apk      # Build debug APK (triggers Rust cross-compile)

# Full check
make check    # lint + test + flutter-analyze
```

### Run the Node Daemon

```bash
# Phone mode (default)
cargo run -p mycelium-node

# Supernode mode (always-on, 2GB DTN, internet transport, API on 0.0.0.0)
cargo run -p mycelium-node -- --supernode

# With custom settings
cargo run -p mycelium-node -- --data-dir /path/to/data --port 9800
```

### Run on Android

```bash
cd flutter && flutter run
```

Both phones need Bluetooth and Location enabled. Grant all permissions when prompted. Messages flow automatically once devices discover each other via BLE or Wi-Fi Direct.

## API

The node exposes a local REST + WebSocket API for all operations.

### REST Endpoints (47 total)

| Group | Endpoints | Description |
|-------|-----------|-------------|
| `/v1/node/` | `status`, `identity`, `trust` | Node info and trust stats |
| `/v1/messages/` | CRUD + mark-read | Send/receive messages |
| `/v1/conversations/` | list, unread count | Conversation summaries |
| `/v1/contacts/` | CRUD + trust + vouch + verify | Contact management |
| `/v1/groups/` | CRUD + members + messages | Group messaging |
| `/v1/channels/` | CRUD + subscribe + messages | Public channels |
| `/v1/prekeys/{id}` | GET | Cached prekey bundles |
| `/v1/emergency/` | broadcast, history | Emergency alerts |
| `/v1/network/` | status, routes, dtn, transports, peers, pending, events | Diagnostics |

### WebSocket

Connect to `ws://127.0.0.1:9735/v1/ws` for real-time events:

- `message` — Incoming messages
- `receipt` — Delivery/read status changes
- `peer` — Neighbor discovered/lost
- `network` — Periodic status (every 5s)
- `channel_message` — Channel broadcasts
- `emergency` — Emergency alerts

## Project Structure

```
mycelium/
├── crates/
│   ├── mycelium-protocol/    # Wire format types + binary codec (29 tests)
│   ├── mycelium-crypto/      # X3DH, Double Ratchet, WoT, Groups (43 tests)
│   ├── mycelium-core/        # Transports, AODV, DTN, DHT (51 tests)
│   ├── mycelium-storage/     # SQLCipher database (9 tests)
│   ├── mycelium-node/        # Node daemon + CLI (43 tests)
│   ├── mycelium-api/         # REST + WebSocket API server (11 tests)
│   └── mycelium-ffi/         # C FFI for mobile (64 functions)
├── flutter/                  # Flutter Android app (47 Dart files)
├── scripts/                  # Build scripts
├── docs/adr/                 # Architecture Decision Records
├── ARCHITECTURE.md           # Comprehensive codebase documentation
├── MYCELIUM_SPEC.md          # Protocol specification
├── CONTRIBUTING.md           # Build setup and conventions
└── REMAINING_WORK.md         # Task tracking (85% complete)
```

## Wire Format

106-byte envelope header + variable payload. 17 payload types:

| Category | Types |
|----------|-------|
| Messaging | EncryptedMessage, SessionInit |
| Key Exchange | PrekeyRequest, PrekeyResponse |
| Routing | AODV RREQ, RREP, RERR |
| DTN | DtnRelay |
| Discovery | Beacon |
| Receipts | Receipt |
| Groups | GroupMessage, SenderKeyDist |
| Channels | ChannelMessage, ChannelSubscribe, ChannelUnsubscribe, ChannelModeration |
| Emergency | EmergencyBroadcast |

All multi-byte integers use little-endian encoding. Custom binary codec (no protobuf dependency).

## Cryptographic Design

```
Identity:  Ed25519 seed → signing key + X25519 DH key + NodeId
Sessions:  X3DH → shared secret → Double Ratchet (per-message forward secrecy)
Messages:  AES-256-GCM with AD = source || destination
Groups:    Sender Key chains with HKDF-derived message keys
Trust:     BFS with exponential decay (1.0, 0.5, 0.25, 0.125 over 4 hops)
```

8 HKDF info strings for domain separation. See `ARCHITECTURE.md` Section 16 for full details.

## Transport Layer

| Transport | MTU | Throughput | Range | Status |
|-----------|-----|------------|-------|--------|
| BLE | 512 B | ~100 kbps | 10-30m | Full (Android + iOS) |
| Wi-Fi Direct | 65 KB | ~50 Mbps | 50-200m | Full (Android only) |
| LoRa | 51-222 B | ~1-37 kbps | 1-15 km | Rust + BLE bridge (Android + iOS) |
| BT Classic | 16 KB | ~2 Mbps | 10-100m | Rust only |
| Internet | 65 KB | varies | global | Rust + FFI |

The `TransportPlugin` trait allows third-party transports (e.g., Meshtastic, Reticulum) to integrate as plugins.

## Documentation

| Document | Purpose |
|----------|---------|
| `MYCELIUM_SPEC.md` | Protocol specification |
| `ARCHITECTURE.md` | Codebase documentation (all modules, all types) |
| `IMPLEMENTATION_SPEC.md` | Roadmap and design decisions |
| `CONTRIBUTING.md` | Build setup, test commands, conventions |
| `REMAINING_WORK.md` | Task tracking with completion status |
| `CLAUDE.md` | AI assistant instructions |
| `docs/adr/` | Architecture Decision Records |

## Status

**85% complete** (124/146 tasks). Phases 1-13 done. Remaining:

- External radio platform bridges (LoRa BLE GATT, USB serial, BT Classic Kotlin/Dart)
- OpenWRT cross-compilation and LuCI web plugin
- Protocol adapter crates (Meshtastic, Reticulum)
- Plugin API documentation

See `REMAINING_WORK.md` for the detailed task list.

## License

GPLv3. See `LICENSE` for details.
