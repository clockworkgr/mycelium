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
- Rust core (10 crates, 460 tests)
- Local REST API (38 endpoints) + WebSocket server, bearer-token authenticated (ADR-006)
- Flutter mobile app for Android and iOS (14 screens, 49 Dart files)
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
make test     # Run all 460 tests
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
cargo run -p mycelium-daemon

# Supernode mode (always-on, 2GB DTN, internet transport, API on 0.0.0.0)
cargo run -p mycelium-daemon -- --supernode

# With custom settings
cargo run -p mycelium-daemon -- --data-dir /path/to/data --port 9800

# Same via environment (flags win over env; used by the Docker testbed)
MYCELIUM_DATA_DIR=/path/to/data MYCELIUM_DISPLAY_NAME=alice cargo run -p mycelium-daemon
```

### Run on Android

```bash
cd flutter && flutter run
```

Both phones need Bluetooth and Location enabled. Grant all permissions when prompted. Messages flow automatically once devices discover each other via BLE or Wi-Fi Direct.

## API

The node exposes a local REST + WebSocket API for all operations. Every
request needs the node's bearer token, generated on first start at
`<data_dir>/api.token` (ADR-006):

```bash
TOKEN=$(cat ./mycelium-data/api.token)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9735/v1/node/status
# WebSocket clients may pass it as ?token=$TOKEN
```

### REST Endpoints (38 total, 31 unique paths)

| Group | Endpoints | Description |
|-------|-----------|-------------|
| `/v1/node/` | `status`, `identity`, `trust` | Node info and trust stats |
| `/v1/messages/` | CRUD + mark-read | Send/receive messages |
| `/v1/conversations/` | list, unread count | Conversation summaries |
| `/v1/contacts/` | CRUD + trust + vouch + verify + safety-number | Contact management |
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
- `send_result` — Reply to your `send` frame (message id or error)

## Project Structure

```
mycelium/
├── crates/
│   ├── mycelium-protocol/    # Wire format types + binary codec (39 tests)
│   ├── mycelium-crypto/      # X3DH, Double Ratchet, WoT, Groups (53 tests)
│   ├── mycelium-core/        # Transports, AODV, DTN, DHT (77 tests)
│   ├── mycelium-storage/     # SQLCipher database (10 tests)
│   ├── mycelium-node/        # Node library: event loop, message pipeline, groups (45 tests)
│   ├── mycelium-api/         # REST + WebSocket API server, bearer auth (19 tests)
│   ├── mycelium-daemon/      # `mycelium-node` binary: node + API server (ADR-004)
│   ├── mycelium-ffi/         # C FFI for mobile (64 functions)
│   ├── mycelium-meshtastic/  # Meshtastic adapter (16 tests; not yet interoperable)
│   └── mycelium-reticulum/   # Reticulum adapter (21 tests; not yet interoperable)
├── flutter/                  # Flutter app, Android + iOS (49 Dart files)
├── openwrt/                  # .ipk package files + LuCI app
├── testbed/                  # Docker mesh testbed (Dockerfile, compose, scenarios)
├── scripts/                  # Build scripts (Android, iOS, OpenWRT)
├── docs/adr/                 # Architecture Decision Records
├── docs/plugin-api.md        # Transport plugin development guide
├── MYCELIUM_SPEC.md          # Protocol + architecture specification
├── ROADMAP.md                # Open work
└── CONTRIBUTING.md           # Build setup and conventions
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

8 HKDF info strings for domain separation. See `MYCELIUM_SPEC.md` §5 for the full key hierarchy.

## Transport Layer

| Transport | MTU | Throughput | Range | Status |
|-----------|-----|------------|-------|--------|
| BLE | 512 B | ~100 kbps | 10-30 m | Working on Android + iOS |
| Wi-Fi Direct | 65 KB | ~50 Mbps | 50-200 m | Working on Android (iOS does not expose it) |
| LoRa | 2 KB msgs (51-222 B frames) | 0.25-37 kbps | 1-15 km | Complete in software; **untested on hardware** |
| BT Classic | 16 KB | ~2 Mbps | 10-100 m | Complete in software, Android only; **untested on hardware** |
| Internet | 65 KB | varies | global | Partial — peer identity is not yet authenticated |

The `TransportPlugin` trait allows third-party transports to integrate as plugins. The `mycelium-meshtastic` and `mycelium-reticulum` crates implement it but are not yet wired into the node or interoperable with the real protocols.

## Documentation

| Document | Purpose |
|----------|---------|
| [`MYCELIUM_SPEC.md`](MYCELIUM_SPEC.md) | The spec: wire protocol, cryptography, architecture as built, compliance matrix |
| [`ROADMAP.md`](ROADMAP.md) | The plan: everything still open, prioritised, with acceptance criteria |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Build setup, test commands, conventions |
| [`docs/adr/`](docs/adr/) | Architecture Decision Records (ADR-001 … ADR-011) |
| [`docs/plugin-api.md`](docs/plugin-api.md) | Transport plugin development guide |
| `CLAUDE.md` | AI assistant instructions |

Two documents, by design. The spec says what Mycelium is and what is built; the
roadmap says what is not. Anything else drifts.

## Status

**v0.1, pre-release.** Everything in the v0.1 scope is implemented: 1:1 and
group messaging, channels, emergency broadcast, AODV multi-hop, DTN
store-and-forward, Web of Trust, onboarding, battery adaptation, the local API,
and the Android + iOS apps. `cargo test`, `clippy -D warnings`, `cargo fmt` and
`flutter analyze` are all green.

What stands between here and a release (see [`ROADMAP.md`](ROADMAP.md) for the
full list with acceptance criteria):

- **Hardening of shipped features** — FFI panic guards, ratchet
  persist-before-send, identity key in the platform keystore, emergency
  co-signer signature verification, internet-transport peer authentication,
  group-discovery proof of possession.
- **Validation** — LoRa, BT Classic and OpenWRT work in software but have never
  run against real hardware. There is no CI, and the Docker testbed has no
  scenario runner.
- **v0.2 features** — Meshtastic and Reticulum interoperability, plugin
  instantiation, per-app API tokens, protocol capability negotiation.

Deferred to v0.3+: multi-device sync, geographic overlay, threshold key
revocation, Wi-Fi Aware.

## License

GPLv3. See `LICENSE` for details.
