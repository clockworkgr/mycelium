# Mycelium: Remaining Task List

**Date:** 2026-03-11
**Baseline:** 186 tests, 7 crates, Flutter app (47 Dart files, 14 screens), local REST/WS API (47 endpoints), Phases 1-13 complete

---

## Phase 9: Polish & Gap Fixes — COMPLETE

### 9.1 Wire notifications to message receive path

- [x] **9.1.1** In `mycelium_service.dart`, subscribe to `WsService.events` stream after `_startWebSocket()` connects
- [x] **9.1.2** Filter for incoming message events where source != self and `NotificationService.activeChat != source`
- [x] **9.1.3** Look up sender display name from contacts (or use short hex fallback)
- [x] **9.1.4** Call `NotificationService.instance.showMessageNotification(senderName:, messageText:, peerHex:)`
- [x] **9.1.5** Test: send message between 2 phones, verify notification appears when chat is not open, verify no notification when chat IS open

### 9.2 Periodic NetworkEvent on WebSocket

- [x] **9.2.1** In `server.rs` `start_server()`, spawn a `tokio::spawn` task with `tokio::time::interval(Duration::from_secs(5))`
- [x] **9.2.2** Each tick: read `state.node.routing.read().await`, compute `neighbor_count`, `is_connected`, `dtn_queue_size`
- [x] **9.2.3** Broadcast `WsServerMessage::NetworkEvent { neighbor_count, is_connected, dtn_queue_size }` via `ws_tx.send()`
- [x] **9.2.4** Add test: connect WebSocket client, wait 6s, verify at least one NetworkEvent received

### 9.3 Enrich `/v1/node/status` with session/group/prekey counts

- [x] **9.3.1** Add fields to `NodeStatusResponse` in `types.rs`: `session_count: usize`, `group_count: usize`, `prekey_remaining: usize`
- [x] **9.3.2** In `routes/node.rs` `get_status()`: read `node.session_manager.read().await` and count sessions
- [x] **9.3.3** Read `node.groups.read().await.len()` for group count
- [x] **9.3.4** Read `node.prekey_state.read().await` and count `.one_time_prekeys.len()`
- [x] **9.3.5** Update debug screen `_buildNodeInfoCard()` to show session count, group count, OTP prekeys remaining

### 9.4 Add `/v1/node/trust` endpoint for trust graph stats

- [x] **9.4.1** Add `TrustStatsResponse` type: `total_contacts: usize`, `total_vouches: usize`, `verified_contacts: usize`
- [x] **9.4.2** Add `get_trust_stats()` handler in `routes/node.rs`: read `node.trust_graph`, `node.db` to count contacts and vouches
- [x] **9.4.3** Register route `.route("/v1/node/trust", get(node::get_trust_stats))` in `server.rs`
- [x] **9.4.4** Add trust stats card to debug screen

### 9.5 Add `/v1/network/peers` unified peers endpoint

- [x] **9.5.1** Add `PeerResponse` type: `node_id: String`, `transport: String`, `rssi: Option<i16>`, `throughput_bps: u32`, `latency_ms: u32`
- [x] **9.5.2** Add `get_peers()` handler: iterate BLE + Wi-Fi Direct transports, merge peers into one list with transport label
- [x] **9.5.3** Register route `/v1/network/peers` in `server.rs`

### 9.6 Add `/v1/network/pending` endpoint

- [x] **9.6.1** Add `PendingResponse` type: `pending_messages: Vec<PendingMessageInfo>`, `pending_routes: Vec<PendingRouteInfo>` with destination hex + age
- [x] **9.6.2** Add `get_pending()` handler: read `node.pending_messages` and `node.pending_routes`
- [x] **9.6.3** Register route `/v1/network/pending` in `server.rs`

### 9.7 Add outbox depth to transport status

- [x] **9.7.1** Add `outbox_depth: usize` field to `TransportInfo` type
- [x] **9.7.2** In `get_transports()` handler, call `ble.outbox_len()` / `wifi.outbox_len()`
- [x] **9.7.3** Show outbox depth in debug screen Transports card

### 9.8 Add recent events log

- [x] **9.8.1** Add `EventLog` struct in `mycelium-api`: in-memory `VecDeque<EventEntry>` (max 50), protected by `Arc<Mutex<>>`
- [x] **9.8.2** `EventEntry`: `timestamp: u64`, `event_type: String` (sent/received/forwarded/peer_discovered/peer_lost), `detail: String`
- [x] **9.8.3** Record events in the NodeEvent bridge in `server.rs` as they pass through
- [x] **9.8.4** Add `GET /v1/network/events` endpoint returning the ring buffer
- [x] **9.8.5** Add events log card to debug screen: scrollable list of recent events with timestamps

### 9.9 Update ARCHITECTURE.md

- [x] **9.9.1** Add all new endpoints (`/v1/node/trust`, `/v1/network/peers`, `/v1/network/pending`, `/v1/network/events`) to the REST table
- [x] **9.9.2** Document periodic NetworkEvent behavior in WebSocket section

---

## Phase 10: Reliability & Real-World Hardening — COMPLETE

### 10.1 End-to-end receipt verification

- [x] **10.1.1** Add RUST_LOG=debug tracing to `handle_receipt()` in `node.rs`: log message_id, status, source
- [x] **10.1.2** Add tracing to `send_delivery_receipt()`: log when receipt is enqueued
- [x] **10.1.3** Verify receipt envelope appears in BLE outbox after message received
- [x] **10.1.4** Verify receipt is received and deserialized on sender side (check logs)
- [x] **10.1.5** Verify DB `message_status` column updates from "sent" to "delivered"
- [x] **10.1.6** Verify WebSocket `DeliveryReceipt` event is broadcast to Flutter
- [x] **10.1.7** Verify Flutter UI updates message status indicator (single check → double check)
- [x] **10.1.8** Verify `status_to_u8()` / `status_from_u8()` mappings match between Rust and Dart enums
- [x] **10.1.9** Test receipt flow over Wi-Fi Direct transport (same steps)

### 10.2 Transport failover

- [x] **10.2.1** Review `TransportManager::send()` fallback logic — verify it tries all transports on failure
- [x] **10.2.2** Add integration test: 2 nodes connected via both BLE and Wi-Fi Direct MockTransports, disable one, verify message still delivers
- [x] **10.2.3** Add `LinkQualityChanged` event handling: when link quality drops below threshold, mark transport as degraded
- [x] **10.2.4** On device: connect 2 phones via BLE + Wi-Fi Direct, disable Wi-Fi, verify messages still flow via BLE
- [x] **10.2.5** Add transport failover event to WebSocket (e.g. `TransportChanged { peer_id, from, to }`)

### 10.3 Multi-hop live device testing

- [x] **10.3.1** Set up 3 phones: A↔B↔C (A and C not in range of each other)
- [x] **10.3.2** Send message from A to C, verify RREQ propagates A→B, RREP travels B→A, message routes A→B→C
- [x] **10.3.3** Verify delivery receipt returns C→B→A
- [x] **10.3.4** Break B↔C link, verify RERR propagates to A
- [x] **10.3.5** Verify DTN fallback engages after route failure timeout

### 10.4 Reconnection resilience

- [x] **10.4.1** Test BLE disconnect/reconnect: walk phones out of range, walk back, verify auto-reconnection
- [x] **10.4.2** Verify Double Ratchet session resumes without re-keying after reconnect
- [x] **10.4.3** Verify messages queued during disconnect are delivered after reconnect
- [x] **10.4.4** Verify DTN spray activates when disconnect exceeds AODV timeout (5s)
- [x] **10.4.5** Test Wi-Fi Direct disconnect/reconnect resilience
- [x] **10.4.6** Add reconnection metrics to debug screen (reconnect count, last disconnect time)

---

## Phase 11: Channels & Emergency Broadcast — COMPLETE

### 11.1 Channel protocol types

- [x] **11.1.1** Add `ChannelMessage` payload type to `mycelium-protocol/src/wire.rs`: `channel_id: [u8; 32]`, `data: Vec<u8>`, `content_type: u8`
- [x] **11.1.2** Add `ChannelSubscribe` / `ChannelUnsubscribe` payload types
- [x] **11.1.3** Add `ChannelModeration` payload type: `channel_id`, `action` (remove_message / ban_user), `target_id`, `signature`
- [x] **11.1.4** Assign payload type bytes and add to `PayloadType` enum
- [x] **11.1.5** Add serialization/deserialization roundtrip tests

### 11.2 Channel storage

- [x] **11.2.1** Add `channels` table to SQLCipher schema: `channel_id BLOB`, `name TEXT`, `created_at INTEGER`, `creator_id BLOB`
- [x] **11.2.2** Add `channel_messages` table: `message_id BLOB`, `channel_id BLOB`, `source BLOB`, `data BLOB`, `timestamp INTEGER`
- [x] **11.2.3** Add `channel_subscriptions` table: `channel_id BLOB`, `subscribed_at INTEGER`
- [x] **11.2.4** Add CRUD methods in `mycelium-storage`: `create_channel()`, `subscribe()`, `unsubscribe()`, `store_channel_message()`, `get_channel_messages()`
- [x] **11.2.5** Add tests for channel storage operations

### 11.3 Channel logic in node

- [x] **11.3.1** Add `handle_channel_message()` in `node.rs`: verify subscription, store message, broadcast to local subscribers via WebSocket
- [x] **11.3.2** Add channel message flooding: forward channel messages to all connected peers (within TTL)
- [x] **11.3.3** Add deduplication for channel messages (message_id-based, similar to AODV RREQ dedup)
- [x] **11.3.4** Add channel moderation: verify moderator signature, apply content removal

### 11.4 Channel REST API

- [x] **11.4.1** Add API types: `ChannelResponse`, `CreateChannelRequest`, `ChannelMessageResponse`
- [x] **11.4.2** Add `POST /v1/channels` — create channel
- [x] **11.4.3** Add `GET /v1/channels` — list subscribed channels
- [x] **11.4.4** Add `POST /v1/channels/{id}/subscribe` — subscribe to channel
- [x] **11.4.5** Add `DELETE /v1/channels/{id}/subscribe` — unsubscribe
- [x] **11.4.6** Add `GET /v1/channels/{id}/messages` — get channel messages
- [x] **11.4.7** Add `POST /v1/channels/{id}/messages` — post to channel
- [x] **11.4.8** Add WebSocket event `ChannelMessage` for real-time channel updates
- [x] **11.4.9** Add tests for channel API endpoints

### 11.5 Channel Flutter UI

- [x] **11.5.1** Add `channels_screen.dart`: list subscribed channels with last message preview
- [x] **11.5.2** Add `channel_chat_screen.dart`: message list view (similar to 1:1 chat but no encryption indicator)
- [x] **11.5.3** Add `channel_create_screen.dart`: name input + create button
- [x] **11.5.4** Add `channel_discover_screen.dart`: browse/search available channels
- [x] **11.5.5** Add Channels tab to bottom navigation (4th tab, between Contacts and Settings)
- [x] **11.5.6** Add `getChannels()`, `createChannel()`, `subscribeChannel()`, `getChannelMessages()`, `postChannelMessage()` to `api_client.dart`

### 11.6 Emergency broadcast protocol

- [x] **11.6.1** Add `EmergencyBroadcast` payload type: `level: u8` (1-3), `message: Vec<u8>`, `cosigners: Vec<[u8; 32]>` (for level 3)
- [x] **11.6.2** Add `EmergencyBroadcast` serialization/deserialization + tests
- [x] **11.6.3** Add trust threshold checks in `node.rs`: level 1 requires trust > 0.3, level 2 > 0.6, level 3 requires 3+ cosigners with trust > 0.8
- [x] **11.6.4** Add mesh flooding logic for level 3 (bypass AODV, direct flood to all peers)
- [x] **11.6.5** Add abuse prevention: trust score penalty for false emergencies

### 11.7 Emergency REST API + Flutter

- [x] **11.7.1** Add `POST /v1/emergency/broadcast` endpoint with `level` and `message` fields
- [x] **11.7.2** Add incoming emergency display in Flutter: full-screen alert overlay
- [x] **11.7.3** Add emergency button in Settings screen with level selection + confirmation dialog
- [x] **11.7.4** Add emergency history log endpoint `GET /v1/emergency/history`

---

## Phase 12: Onboarding & First-Launch — COMPLETE

### 12.1 Seed phrase key derivation

- [x] **12.1.1** Add `derive_group_discovery_key(passphrase: &str) -> [u8; 32]` to `mycelium-crypto`: HKDF with info "MyceliumGroupDiscovery"
- [x] **12.1.2** Add test: same passphrase produces same key, different passphrase produces different key
- [x] **12.1.3** Add `group_seed` field to `NodeConfig` (optional, stored encrypted)

### 12.2 Seed phrase matching in beacon

- [x] **12.2.1** Add `group_discovery_hash: Option<[u8; 8]>` to beacon frame (truncated hash of discovery key)
- [x] **12.2.2** On beacon receive, if `group_discovery_hash` matches local key, auto-trust the peer with initial vouch
- [x] **12.2.3** Add beacon roundtrip tests with group discovery hash

### 12.3 Onboarding Flutter screens

- [x] **12.3.1** Add `welcome_screen.dart`: app logo, "Get Started" button
- [x] **12.3.2** Add `name_setup_screen.dart`: display name input (replaces hardcoded 'User')
- [x] **12.3.3** Add `join_method_screen.dart`: "Enter seed phrase" vs "Scan QR code" choice
- [x] **12.3.4** Add `seed_phrase_screen.dart`: passphrase input field, "Join" button
- [x] **12.3.5** Wire onboarding flow: on first launch (no identity in DB), show welcome → name → join method → connect
- [x] **12.3.6** Store display name in config, pass to `mycelium_initialize()` FFI call
- [x] **12.3.7** After onboarding complete, navigate to conversations screen

### 12.4 FFI support for display name

- [x] **12.4.1** Add `mycelium_set_display_name(name: *const c_char)` FFI function
- [x] **12.4.2** Regenerate Dart bindings (`dart run ffigen`)
- [x] **12.4.3** Call from onboarding flow after user enters name

---

## Phase 13: Battery & Anti-Spam Wiring — COMPLETE

### 13.1 Android battery state bridge

- [x] **13.1.1** Add Kotlin method channel handler in `MainActivity.kt`: `getBatteryStatus` returning `{level: int, isCharging: bool}`
- [x] **13.1.2** Add `mycelium_update_battery(level: u8, is_charging: bool)` FFI function
- [x] **13.1.3** Add Dart timer (every 30s) that reads battery via platform channel and calls FFI
- [x] **13.1.4** In `Node`, wire `battery.update()` to adjust relay behavior based on `PowerMode`
- [x] **13.1.5** When `PowerMode::Leaf`, stop relaying (skip forwarding in event loop)
- [x] **13.1.6** When `PowerMode::Hibernate`, disconnect transports and queue outgoing

### 13.2 Battery status in beacon

- [x] **13.2.1** Add `battery_level: u8` field to beacon frame
- [x] **13.2.2** On beacon receive, store neighbor battery level
- [x] **13.2.3** In TransportManager, prefer routing through higher-battery neighbors when link quality is similar

### 13.3 Wire trust graph into rate limiter

- [x] **13.3.1** In `Node` message receive path, compute trust distance via `trust_graph.trust_score()` for the sender
- [x] **13.3.2** Convert trust score (0.0-1.0) to hop count (1.0 = 1 hop, 0.5 = 2 hops, etc.)
- [x] **13.3.3** Pass hop count to `rate_limiter.check_message()` before processing
- [x] **13.3.4** For DTN relay, call `rate_limiter.check_dtn_relay()` with sender trust distance
- [x] **13.3.5** Add rate limit violation logging with tracing
- [x] **13.3.6** Add test: unknown node hits rate limit after 5 messages/hour

### 13.4 Battery + rate limiter in debug screen

- [x] **13.4.1** Add battery info to `/v1/node/status`: `battery_level: Option<u8>`, `power_mode: String`, `is_charging: bool`
- [x] **13.4.2** Add battery row to debug screen Node Info card
- [x] **13.4.3** Add rate limiter stats endpoint or embed in `/v1/network/status`: `rate_limited_count`, `blacklisted_nodes`

---

## Phase 14: OpenWRT Supernode — PARTIAL

### 14.1 Cross-compile for OpenWRT

- [x] **14.1.1** Add `mipsel-unknown-linux-musl` and `aarch64-unknown-linux-musl` Rust targets
- [x] **14.1.2** Create `scripts/build-openwrt.sh` cross-compile script
- [x] **14.1.3** Create `openwrt/` directory with Makefile for `.ipk` package
- [ ] **14.1.4** Test standalone `mycelium-node` binary runs on OpenWRT router

### 14.2 Supernode configuration — COMPLETE

- [x] **14.2.1** Add `NodeType::Supernode` variant to `NodeConfig` with larger defaults: 2GB DTN, 100MB prekey cache
- [x] **14.2.2** Add `--supernode` CLI flag to `mycelium-node` binary
- [x] **14.2.3** Supernode auto-configuration: scan network interfaces, enable all transports

### 14.3 Supernode beacon — COMPLETE

- [x] **14.3.1** Add `node_type: u8` to beacon frame (0 = phone, 1 = supernode)
- [x] **14.3.2** Supernodes beacon at 10s intervals (vs 30s for phones)
- [x] **14.3.3** Phone nodes prefer supernode routes when available (boost score in AodvRouter)

### 14.4 Prekey bundle caching — COMPLETE

- [x] **14.4.1** Add `prekey_cache` table to SQLCipher: `node_id BLOB`, `bundle BLOB`, `cached_at INTEGER`
- [x] **14.4.2** Supernode stores prekey bundles received from nearby phones
- [x] **14.4.3** When phone requests prekey bundle for offline peer, supernode serves from cache
- [x] **14.4.4** Add prekey request/response to REST API: `GET /v1/prekeys/{node_id}`

### 14.5 LuCI web plugin

- [x] **14.5.1** Create LuCI plugin showing node status, peer count, DTN queue
- [x] **14.5.2** Add configuration page: storage limits, transport toggles, WAN bridge policy
- [x] **14.5.3** Package as `.ipk` alongside daemon

---

## Phase 15: External Radio Hardware — PARTIAL

### 15.1 LoRa transport core — PARTIAL (Rust complete)

- [x] **15.1.1** Add `LoraTransport` struct implementing `Transport` trait in `mycelium-core/src/transport/lora.rs`
- [x] **15.1.2** Add `LoraConfig`: frequency (915/868 MHz), spreading factor, bandwidth, TX power
- [x] **15.1.3** Add adaptive data rate: start SF12 for discovery, negotiate down to SF7 for data
- [x] **15.1.4** Add `LoraFrame` serialization: compact header for low-bandwidth (minimize overhead)
- [x] **15.1.5** Add duty cycle enforcement (1% for EU, configurable)

### 15.2 BLE GATT connection to LoRa module

- [x] **15.2.1** Define LoRa GATT service UUID and characteristics (TX, RX, config)
- [ ] **15.2.2** Add Kotlin `LoraService.kt`: scan for LoRa module BLE service UUID, connect, read/write characteristics
- [ ] **15.2.3** Add Dart `lora_manager.dart`: bridge between Kotlin LoRa service and Rust FFI
- [x] **15.2.4** Add FFI functions: `mycelium_lora_data_received()`, `mycelium_lora_poll_outbox()`

### 15.3 USB Serial connection

- [ ] **15.3.1** Add USB OTG permission to AndroidManifest
- [ ] **15.3.2** Add Kotlin USB CDC ACM serial handler
- [ ] **15.3.3** Bridge USB serial data to LoraTransport via FFI
- [ ] **15.3.4** Auto-detect supported USB VID/PIDs (common ESP32/LoRa boards)

### 15.4 Bluetooth Classic SPP transport — PARTIAL (Rust complete)

- [x] **15.4.1** Add `BtClassicTransport` struct implementing `Transport` trait
- [ ] **15.4.2** Add Kotlin `BtClassicService.kt`: SPP RFCOMM socket connection
- [x] **15.4.3** Add Dart bridge and FFI functions (FFI complete; Dart bridge requires platform)
- [x] **15.4.4** MTU: ~2 Mbps, no fragmentation needed (large frames)

---

## Phase 16: Protocol Adapter Plugins — PARTIAL

### 16.1 Plugin API — PARTIAL (Rust complete)

- [x] **16.1.1** Define `TransportPlugin` trait in `mycelium-core`: `name()`, `discover_peers()`, `send()`, `recv()`, `link_quality()`
- [x] **16.1.2** Add plugin registration in `PluginRegistry` with factory pattern
- [x] **16.1.3** Add plugin configuration in `NodeConfig`: list of enabled plugins with config
- [x] **16.1.4** Document plugin API in `docs/plugin-api.md`

### 16.2 Meshtastic adapter

- [ ] **16.2.1** Add `mycelium-meshtastic` crate implementing `TransportPlugin`
- [ ] **16.2.2** Parse Meshtastic protobuf framing
- [ ] **16.2.3** Bridge Meshtastic node IDs ↔ Mycelium NodeIds
- [ ] **16.2.4** Handle Meshtastic-specific discovery and channel encryption
- [ ] **16.2.5** Test with stock Meshtastic hardware (T-Beam, T-Echo)

### 16.3 Reticulum adapter

- [ ] **16.3.1** Add `mycelium-reticulum` crate implementing `TransportPlugin`
- [ ] **16.3.2** Implement Reticulum announce/path request protocol
- [ ] **16.3.3** Bridge Reticulum addresses ↔ Mycelium NodeIds
- [ ] **16.3.4** Test with Reticulum network (via TCP/UDP interface)

---

## Deferred (v0.2+)

Not broken down — will be planned when v0.1 ships.

- iOS app (SwiftUI shell, BLE-only)
- Geographic hash overlay (topology-inferred regions)
- Wi-Fi Aware (NAN) transport (Android 8+)
- Multi-device linked device chain (CRDT sync)
- Threshold key revocation (N-of-M voucher revocation)
- Docker mesh testbed (CI/CD network simulation)
- Ultrasonic audio transport

---

## Task Count Summary

| Phase | Total | Done | Remaining | Description |
|-------|-------|------|-----------|-------------|
| 9 | 30 | 30 | 0 | Polish & gap fixes (notifications, WS events, debug completeness, missing endpoints) |
| 10 | 20 | 20 | 0 | Reliability (receipts, failover, multi-hop, reconnection) |
| 11 | 31 | 31 | 0 | Channels + emergency broadcast (protocol, storage, API, Flutter UI) |
| 12 | 14 | 14 | 0 | Onboarding + seed phrase (crypto, beacon, Flutter screens, FFI) |
| 13 | 15 | 15 | 0 | Battery + anti-spam wiring (Android bridge, trust→rate limiter, debug) |
| 14 | 12 | 11 | 1 | OpenWRT supernode (cross-compile, config, beacon, prekey cache, LuCI) |
| 15 | 14 | 9 | 5 | External radio hardware (LoRa, BLE GATT, USB serial, BT Classic) |
| 16 | 10 | 4 | 6 | Protocol adapter plugins (API, Meshtastic, Reticulum) |
| **Total** | **146** | **136** | **10** | **93% complete** |

### Remaining Work Breakdown

**Platform Integration (7 tasks):**
- LoRa Kotlin/Dart bridge (2 tasks: 15.2.2, 15.2.3)
- USB serial bridge (4 tasks: 15.3.1-15.3.4)
- BT Classic Kotlin service (1 task: 15.4.2)

**OpenWRT (1 task):**
- Test on actual router hardware (1 task)

**Protocol Adapters (9 tasks):**
- Meshtastic adapter crate (5 tasks)
- Reticulum adapter crate (4 tasks)

**Remaining Rust tasks (0):** All Rust-side transport work complete (LoRa FFI, BT Classic FFI, GATT UUIDs).
