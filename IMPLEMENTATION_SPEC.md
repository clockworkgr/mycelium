# Mycelium: Continuing Implementation Specification

**Last Updated:** 2026-03-11

## 1. Vision

Mycelium evolves from a mesh messenger into a **general-purpose mesh transport platform**. The Mycelium daemon runs as a standalone process on the device, exposing a local API (REST + WebSocket) that any application can connect to. The chat app becomes the first client, proving the API by dogfooding it.

**Current state:** Phases 1-13 are complete. The local API server (47 REST endpoints + WebSocket) is operational. The Flutter app uses the REST API as its primary data interface with WebSocket for real-time events. BLE and Wi-Fi Direct transports work on Android. 186 tests pass across 7 Rust crates.

**Long-term architecture:**
```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Chat App   │  │  Game App   │  │  File Sync  │
│  (Flutter)  │  │  (any lang) │  │  (any lang) │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │ WS/REST        │ WS/REST        │ WS/REST
       └────────────────┼────────────────┘
                        │
              ┌─────────▼─────────┐
              │  Mycelium Daemon  │
              │  (Rust binary)    │
              │                   │
              │  ┌─────────────┐  │
              │  │ Local API   │  │  ← axum REST + WebSocket
              │  │ (JSON)      │  │    serde_json serialization
              │  └─────────────┘  │
              │  ┌─────────────┐  │
              │  │ Protocol    │  │  ← String-based protocol IDs
              │  │ Router      │  │    per-app E2E encryption
              │  └─────────────┘  │
              │  ┌─────────────┐  │
              │  │ Transports  │  │  ← BLE, Wi-Fi Direct, LoRa, BT Classic, Internet
              │  └─────────────┘  │
              └───────────────────┘
```

---

## 2. Phases (Build Order)

### Phase 1: WebSocket + REST API & Debug Panel — COMPLETE

Built the local API server in Rust (axum, 47 endpoints) and debug panel in Flutter. JSON serialization (not protobuf as originally planned). See ADR-001.

### Phase 2: Receipt Fix & 2-Phone Reliability — COMPLETE

Delivery receipts working end-to-end. WebSocket push for real-time status updates.

### Phase 3: Multi-Hop Forwarding — COMPLETE

AODV forwarding verified with 3-node and 4-node mock transport tests. DTN fallback after AODV timeout.

### Phase 4: Group Chat UI — COMPLETE

Sender Key groups wired through REST API. Groups screen in Flutter. Create, add/remove members, send messages.

### Phase 5: Contact Verification — COMPLETE

Safety number comparison flow. Verify screen with 60-digit display. QR-based verification.

### Phase 6: Chat App Migration to WebSocket — COMPLETE

Flutter app uses REST API (via ApiClient) + WebSocket (WsService) for real-time events. FFI retained for transport bridging only.

### Phase 7: Internet Overlay (DHT) — PARTIAL

Kademlia DHT module implemented in `mycelium-core/src/dht/` (routing table, RPC, message serialization, 16 tests). TCP networking not yet wired.

### Phase 8: Full Daemon Extraction — COMPLETE

Node runs as standalone process. Flutter reconnects to surviving daemon after app kill.

---

## 3. Local API Server Design

### 3.1 Technology Stack

- **HTTP/REST**: `axum` 0.8 (Tower-based, async, Tokio-native)
- **WebSocket**: `axum` built-in WebSocket support (uses `tokio-tungstenite` internally)
- **Serialization**: `serde_json` for all request/response bodies (originally planned protobuf, chose JSON for simplicity)
- **CORS**: `tower-http` CorsLayer (permissive for localhost)
- **Hex encoding**: `hex` crate for NodeId/MessageId serialization

### 3.2 Server Configuration

- **Default bind**: `127.0.0.1:9735` (localhost only)
- **Authentication**: Configurable
  - Default: No auth (localhost-only is sufficient)
  - Optional: API key in `Authorization: Bearer <key>` header
  - Optional: Per-app tokens (apps register and receive unique tokens)
- **Config file**: Extend `NodeConfig` with API server settings

### 3.3 REST API (Full CRUD) — IMPLEMENTED

All request/response bodies are JSON-encoded (`Content-Type: application/json`). 47 endpoints across 9 route modules.

#### Node
| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/node/status` | Node ID, uptime, version |
| GET | `/v1/node/identity` | Public key, node ID |

#### Messages
| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/messages` | Send a message (destination, data, content_type, protocol_id) |
| GET | `/v1/messages/{peer_id}` | Get messages with a peer (query: limit, offset) |
| DELETE | `/v1/messages/{peer_id}` | Delete conversation |
| POST | `/v1/messages/{peer_id}/read` | Mark messages as read |

#### Conversations
| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/conversations` | List all conversations with summaries |
| GET | `/v1/conversations/unread` | Total unread count |

#### Contacts
| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/contacts` | List all contacts |
| POST | `/v1/contacts` | Add/update contact (node_id, display_name) |
| DELETE | `/v1/contacts/{node_id}` | Remove contact |
| GET | `/v1/contacts/{node_id}/trust` | Get trust score |
| POST | `/v1/contacts/{node_id}/vouch` | Add trust vouch |
| POST | `/v1/contacts/{node_id}/verify` | Verify session (safety number confirmed) |
| GET | `/v1/contacts/{node_id}/safety-number` | Get safety number string |

#### Groups
| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/groups` | Create group, returns group_id |
| GET | `/v1/groups` | List groups |
| GET | `/v1/groups/{group_id}/members` | List members |
| POST | `/v1/groups/{group_id}/members` | Add member |
| DELETE | `/v1/groups/{group_id}/members/{node_id}` | Remove member |
| POST | `/v1/groups/{group_id}/messages` | Send group message |

#### Network (Diagnostics)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/network/status` | Neighbor count, connection state, battery, DTN queue |
| GET | `/v1/network/peers` | Connected BLE/WiFi peers with transport type, MTU, signal |
| GET | `/v1/network/routes` | AODV routing table (destination, next_hop, hop_count, expiry, valid) |
| GET | `/v1/network/dtn` | DTN bundle queue (message_id, destination, copies_remaining, expires) |
| GET | `/v1/network/pending` | Pending messages and route discoveries |

### 3.4 WebSocket API — IMPLEMENTED

#### Connection

Connect to `ws://127.0.0.1:9735/v1/ws`

Optional query parameter: `?protocols=mycelium.chat.v1,com.example.game`

Apps declare which protocol IDs they want to receive data for. If no protocols specified, the connection receives all events.

#### Frame Format

All WebSocket frames are JSON text. The actual implementation uses `serde_json` instead of the originally planned protobuf. The schema below shows the logical structure:

```protobuf
message WsMessage {
  oneof payload {
    // Client → Server
    Subscribe subscribe = 1;
    SendData send_data = 2;

    // Server → Client
    IncomingMessage incoming_message = 10;
    PeerEvent peer_event = 11;
    NetworkEvent network_event = 12;
    DeliveryReceipt delivery_receipt = 13;
  }
}

message Subscribe {
  repeated string protocol_ids = 1;  // Protocol IDs to listen for
}

message SendData {
  bytes destination = 1;       // 32-byte node ID
  bytes data = 2;              // Arbitrary binary payload
  string protocol_id = 3;     // e.g. "mycelium.chat.v1"
  uint32 content_type = 4;    // Application-defined content type
}

message IncomingMessage {
  bytes source = 1;            // 32-byte sender node ID
  bytes message_id = 2;       // 16-byte message ID
  bytes data = 3;             // Decrypted payload
  string protocol_id = 4;
  uint32 content_type = 5;
  uint64 timestamp = 6;
}

message PeerEvent {
  enum Type {
    DISCOVERED = 0;
    LOST = 1;
  }
  Type type = 1;
  bytes peer_id = 2;          // 32-byte node ID
  string transport = 3;       // "ble", "wifi_direct", "internet"
}

message NetworkEvent {
  uint32 neighbor_count = 1;
  bool is_connected = 2;
  uint32 dtn_queue_size = 3;
}

message DeliveryReceipt {
  bytes message_id = 1;
  uint32 status = 2;          // sent=1, delivered=2, read=3, failed=4
}
```

#### Event Streaming

When connected, the WebSocket pushes events in real-time:
- **IncomingMessage**: New message received (filtered by subscribed protocol IDs)
- **PeerEvent**: Neighbor discovered/lost
- **NetworkEvent**: Periodic network status updates (every 5s)
- **DeliveryReceipt**: Message status changes

---

## 4. Protocol ID System

### Design

- **Format**: Simple string, recommended reverse-DNS style (e.g., `mycelium.chat.v1`, `com.example.game`)
- **Registration**: Apps declare protocol IDs when connecting via WebSocket `Subscribe` message
- **Wire format**: Protocol ID included in the mesh envelope payload alongside the encrypted data
- **Discovery**: Supported protocols exchanged post-BLE-connection (not in advertisement data), included in beacon messages
- **Encryption**: All data is E2E encrypted by Mycelium using the existing Double Ratchet session. Apps get encryption for free.

### Built-in Protocols

| Protocol ID | Purpose |
|-------------|---------|
| `mycelium.chat.v1` | Text/media messaging |
| `mycelium.groups.v1` | Group messaging |
| `mycelium.system.v1` | Internal control messages |

---

## 5. Debug Panel Specification

### Access

- Settings screen contains a toggle: "Developer Mode"
- When enabled, a 4th tab "Debug" appears in the bottom navigation
- Debug data is fetched via the REST API (`/v1/network/*` endpoints)

### Sections

#### 5.1 BLE Connections
- Table of connected peers: BLE address, Node ID (short hex), role (client/server/both), negotiated MTU, connection duration, signal strength (if available)
- Connection status indicators (green/yellow/red)

#### 5.2 Routing Table
- AODV routes: destination (short hex), next_hop (short hex), hop_count, sequence_number, is_valid, time until expiry
- Color-coded: green=valid, red=expired, yellow=expiring soon

#### 5.3 Message Pipeline
- Pending messages count (waiting for session establishment)
- Pending route discoveries (waiting for AODV RREP)
- DTN queue depth with total storage used
- BLE outbox depth
- Recent events log (last 50 send/receive/forward events with timestamps)

#### 5.4 Node Info
- Node ID, uptime, protocol version
- Prekey state: SPK ID, OTP count remaining
- Session count, group count
- Trust graph stats: total vouches, contacts

---

## 6. Receipt Flow Fix

### Current State
- Rust sends delivery receipts (`send_delivery_receipt` in node.rs)
- Rust handles incoming receipts (`handle_receipt` in node.rs)
- Receipt updates message status in database
- Flutter polls messages every 1 second

### Investigation Steps
1. Add logging to `handle_receipt()` to confirm receipts are being processed
2. Verify receipt envelope is being sent back via BLE (check outbox)
3. Verify receipt is received and deserialized on the other side
4. Verify database status update is happening
5. Verify Flutter polling picks up the status change
6. Check if `status_to_u8()` and `status_from_u8()` mappings match between Rust FFI and Dart

### Expected Fix
Once the WebSocket API is in place, delivery receipts will be pushed via `DeliveryReceipt` WebSocket events in real-time instead of relying on polling.

---

## 7. Multi-Hop Forwarding

### Current State
- AODV routing is fully implemented in Rust (RREQ/RREP/RERR)
- Event loop handles forwarding (node.rs:1694-1737)
- TransportManager can send to any connected peer
- **Gap**: Never tested with 3+ devices. BLE broadcast to all peers needs verification.

### Implementation Tasks
1. Verify `TransportManager.send()` correctly selects transport for forwarding
2. Verify RREQ is broadcast to ALL connected BLE peers (not just one)
3. Add integration tests with 3+ MockTransport nodes:
   - Linear relay: A→B→C
   - Dynamic mesh: A→B, B→C, B→D, route discovery from A to D
   - Route failure and RERR propagation
4. Test DTN spray-and-wait across 3 nodes
5. Add forwarding metrics to debug panel (messages forwarded count, routes learned from forwarding)

### Test Strategy (2 phones)
- Use MockTransport tests to verify multi-hop logic
- Test forwarding code paths with unit/integration tests
- Defer live multi-phone testing until more devices available

---

## 8. Group Chat

### Membership Model
- **Any member can add** new members to the group
- **Only admin (creator) can remove** members
- On member removal, sender key is rotated and redistributed to remaining members
- Group metadata (name, members) stored locally; no central server

### UI Design
- Group chat screen similar to 1:1 chat
- Group info screen showing members, with "Add Member" button for all members
- "Remove Member" only visible to admin
- Group creation wizard: name → add members → create

### Wire Protocol
- `SenderKeyDistribution` message distributes keys to new members
- `GroupMessage` payload carries group_id + encrypted data
- Both already implemented in Rust (`handle_group_message`, `handle_sender_key_distribution`)

---

## 9. Contact Verification

### Flow
1. QR scan adds contact (existing flow)
2. Contact detail screen has "Verify" button
3. Tap "Verify" → shows safety number (60 digits in groups of 4)
4. Both users compare numbers (in person or via separate channel)
5. If match → tap "Mark as Verified" → calls `mycelium_verify_session`
6. Verified badge appears on contact

### QR Verification (Alternative)
1. Contact detail → "Verify via QR"
2. Shows QR containing safety number hash
3. Other user scans → app compares automatically
4. If match → auto-verify

---

## 10. Internet Overlay (Future)

### Discovery: Kademlia DHT
- DHT key: derived from mesh identity (hash of Ed25519 public key, not the key itself)
- Prevents reverse-mapping DHT key → mesh identity
- Bootstrap via well-known nodes (configurable list)
- Nodes with internet access join DHT and publish their endpoint (IP:port)

### Relay Protocol
- Internet-connected nodes can relay mesh traffic over TCP/QUIC
- End-to-end encryption is already handled by Double Ratchet
- Relay sees only encrypted blobs, cannot read content
- P2P connections: nodes connect directly to each other when both have internet

### Transport Integration
- New `InternetTransport` implementing the `Transport` trait
- TransportManager selects between BLE, WiFi Direct, and Internet based on link quality
- Seamless fallback: try local mesh first, then internet relay

---

## 11. Daemon Architecture (Future)

### Android Daemon
- Mycelium node runs as a **separate process** on Android
- Started at boot via Android `JobScheduler` or `WorkManager`
- Exposes local WebSocket + REST API on `127.0.0.1:9735`
- Manages BLE and WiFi Direct transports independently of any app
- Survives app kills — the mesh node stays connected

### Flutter App Becomes Pure UI Client
- No more direct FFI calls
- All communication via WebSocket + REST API
- App is just a client of the `mycelium.chat.v1` protocol
- Can be replaced by any other UI (web, native, CLI)

### Desktop Support
- Same Rust daemon binary runs on Linux/macOS/Windows
- Transports: Internet overlay, Bluetooth (platform-specific), local network discovery
- CLI client for headless operation

---

## 12. File Summary — CURRENT STATE

### Crate: `mycelium-api` (implemented)
- Local HTTP/WebSocket server using axum 0.8
- JSON serialization via serde_json (no protobuf)
- 9 route modules: node, messages, conversations, contacts, groups, channels, prekeys, emergency, network
- WebSocket handler with 6 server event types
- 30+ request/response types in `types.rs`
- 11 integration tests

### Crate: `mycelium-core` additions (implemented)
- 8 transport modules: ble, wifi_direct, lora, bt_classic, internet, plugin, mock, manager
- DHT module: Kademlia routing table, RPC, message serialization (16 tests)
- AODV supernode route preference

### Crate: `mycelium-node` additions (implemented)
- CLI entry point with `--supernode`, `--data-dir`, `--port` flags
- Supernode auto-configuration (2GB DTN, 0.0.0.0 bind, always-on battery)
- Prekey cache REST API and opportunistic caching during relay
- Beacon with group_discovery_hash for auto-trust

### Crate: `mycelium-crypto` additions (implemented)
- `discovery.rs`: Group discovery key derivation (HKDF, "MyceliumGroupDiscovery")

### Crate: `mycelium-storage` additions (implemented)
- `channels.rs`: Channel storage, subscriptions, messages (5 tests)

### Flutter App (47 Dart files, implemented)
- 14 screens: conversations, chat, contacts, groups, channels, channel_chat, settings, debug, welcome, name_setup, join_method, seed_phrase, qr_scanner, verify
- 8 services: mycelium_service, api_client, ws_service, notification_service, ble_manager, wifi_direct_manager, ffi_helpers, mycelium_exception
- 8 Riverpod providers with async/stream support
- 7 data models with enum types
- 6 reusable widgets
- GoRouter with 6-tab shell + onboarding redirect
