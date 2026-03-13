# Mycelium Transport Plugin API

This document describes how to extend Mycelium with custom transport plugins for external radio hardware or protocol adapters.

## Overview

Mycelium's transport layer is pluggable. Built-in transports (BLE, Wi-Fi Direct, LoRa, BT Classic, Internet Tunnel) implement the `Transport` trait. External transports implement the `TransportPlugin` trait, which extends `Transport` with configuration and metadata, and register themselves via a `PluginFactory`.

Plugins participate in the mesh identically to built-in transports — they receive routed envelopes, forward AODV messages, and relay DTN bundles.

## Architecture

```
┌────────────────────────────────────────────┐
│              TransportManager              │
│  Owns all transports (built-in + plugins)  │
├────────────┬───────────┬───────────────────┤
│ BLE        │ Wi-Fi     │ Plugin: meshtastic│
│ Transport  │ Direct    │ (TransportPlugin) │
├────────────┴───────────┴───────────────────┤
│              Transport trait                │
│  start / stop / send / events / mtu / ...  │
└────────────────────────────────────────────┘
```

The `TransportManager` calls `add_transport()` for each plugin instance, after which the plugin is indistinguishable from a built-in transport.

## Trait Reference

### `Transport` (base trait)

All transports (built-in and plugin) implement this async trait:

```rust
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Transport type identifier.
    fn transport_type(&self) -> TransportType;

    /// Start discovery and accept connections.
    async fn start(&self) -> Result<(), TransportError>;

    /// Stop the transport and disconnect all peers.
    async fn stop(&self) -> Result<(), TransportError>;

    /// Send data to a specific peer.
    async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError>;

    /// Subscribe to transport events (neighbor discovered/lost, data received).
    fn events(&self) -> broadcast::Receiver<TransportEvent>;

    /// Current link quality for a peer (RSSI, throughput, latency, packet loss).
    fn link_quality(&self, peer: &NodeId) -> Option<LinkQuality>;

    /// List of currently connected peers.
    fn connected_peers(&self) -> Vec<NodeId>;

    /// Maximum transmission unit in bytes.
    fn mtu(&self) -> usize;
}
```

### `TransportPlugin` (extension trait)

Plugins additionally implement:

```rust
pub trait TransportPlugin: Transport {
    /// Unique plugin name (e.g., "meshtastic", "reticulum", "lora-sx1276").
    fn plugin_name(&self) -> &str;

    /// Semantic version string (e.g., "0.1.0").
    fn plugin_version(&self) -> &str;

    /// Human-readable description.
    fn plugin_description(&self) -> &str;

    /// Apply configuration. Called once before start().
    fn configure(&mut self, config: &PluginConfig) -> Result<(), TransportError>;

    /// Whether this plugin needs platform FFI callbacks (e.g., BLE/Wi-Fi bridge).
    /// Default: false. Plugins using USB serial or direct hardware return false.
    fn requires_platform_bridge(&self) -> bool { false }
}
```

### `PluginFactory`

Factories create plugin instances from config:

```rust
pub trait PluginFactory: Send + Sync {
    fn create(&self, config: &PluginConfig) -> Result<Box<dyn TransportPlugin>, TransportError>;
}
```

### `PluginConfig`

Configuration passed to the factory and `configure()`:

```rust
pub struct PluginConfig {
    /// Must match plugin_name().
    pub name: String,
    /// Whether this plugin is enabled.
    pub enabled: bool,
    /// Plugin-specific key-value settings.
    pub settings: HashMap<String, String>,
}
```

## Registration

Plugins register with the `PluginRegistry` at startup:

```rust
use mycelium_core::transport::plugin::{PluginRegistry, PluginFactory, PluginConfig};

struct MeshtasticFactory;

impl PluginFactory for MeshtasticFactory {
    fn create(&self, config: &PluginConfig) -> Result<Box<dyn TransportPlugin>, TransportError> {
        let mut plugin = MeshtasticPlugin::new();
        plugin.configure(config)?;
        Ok(Box::new(plugin))
    }
}

// At startup:
let mut registry = PluginRegistry::new();
registry.register("meshtastic", Box::new(MeshtasticFactory));
```

The node reads plugin config from `NodeConfig.plugins` and calls `registry.create_plugin()` for each enabled entry.

## Configuration (TOML)

Plugins are configured in the node's TOML config file:

```toml
[[plugins]]
name = "meshtastic"
enabled = true

[plugins.settings]
serial_port = "/dev/ttyUSB0"
baud_rate = "115200"
channel = "0"
```

Each `[[plugins]]` entry maps to a `PluginConfigEntry`:

```rust
pub struct PluginConfigEntry {
    pub name: String,
    pub enabled: bool,
    pub settings: HashMap<String, String>,
}
```

## Transport Events

Plugins emit events through a `broadcast::Sender<TransportEvent>`:

| Event | Description |
|-------|-------------|
| `NeighborDiscovered { peer, transport }` | New peer found on this transport |
| `NeighborLost { peer, transport }` | Peer disconnected or timed out |
| `DataReceived { peer, data, transport }` | Raw bytes received from a peer |
| `LinkQualityChanged { peer, quality, transport }` | RSSI/throughput/latency changed |

The `TransportManager` merges events from all transports and feeds them to the routing layer.

## Transport Errors

```rust
pub enum TransportError {
    PeerNotConnected(NodeId),
    NotStarted,
    AlreadyStarted,
    SendFailed(String),
    ExceedsMtu { size: usize, mtu: usize },
    Other(String),
}
```

## Writing a Plugin: Step by Step

### 1. Create a new crate

```
cargo new --lib mycelium-meshtastic
```

Add dependencies:

```toml
[dependencies]
mycelium-core = { path = "../mycelium-core" }
mycelium-protocol = { path = "../mycelium-protocol" }
async-trait = "0.1"
tokio = { version = "1", features = ["sync"] }
```

### 2. Implement Transport + TransportPlugin

```rust
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use mycelium_core::transport::*;
use mycelium_core::transport::plugin::*;
use mycelium_protocol::types::{LinkQuality, NodeId};

pub struct MeshtasticPlugin {
    tx: broadcast::Sender<TransportEvent>,
    peers: Arc<RwLock<Vec<NodeId>>>,
    started: Arc<RwLock<bool>>,
    serial_port: String,
}

impl MeshtasticPlugin {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(128);
        Self {
            tx,
            peers: Arc::new(RwLock::new(Vec::new())),
            started: Arc::new(RwLock::new(false)),
            serial_port: String::new(),
        }
    }
}

#[async_trait::async_trait]
impl Transport for MeshtasticPlugin {
    fn transport_type(&self) -> TransportType { TransportType::Lora }
    async fn start(&self) -> Result<(), TransportError> { /* open serial */ Ok(()) }
    async fn stop(&self) -> Result<(), TransportError> { /* close serial */ Ok(()) }
    async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError> {
        // Frame data and write to serial port
        Ok(())
    }
    fn events(&self) -> broadcast::Receiver<TransportEvent> { self.tx.subscribe() }
    fn link_quality(&self, _peer: &NodeId) -> Option<LinkQuality> { None }
    fn connected_peers(&self) -> Vec<NodeId> {
        self.peers.try_read().map(|p| p.clone()).unwrap_or_default()
    }
    fn mtu(&self) -> usize { 237 } // Meshtastic max payload
}

impl TransportPlugin for MeshtasticPlugin {
    fn plugin_name(&self) -> &str { "meshtastic" }
    fn plugin_version(&self) -> &str { "0.1.0" }
    fn plugin_description(&self) -> &str { "Meshtastic LoRa mesh bridge" }
    fn configure(&mut self, config: &PluginConfig) -> Result<(), TransportError> {
        self.serial_port = config.settings
            .get("serial_port")
            .cloned()
            .unwrap_or_else(|| "/dev/ttyUSB0".to_string());
        Ok(())
    }
}
```

### 3. Implement PluginFactory

```rust
pub struct MeshtasticFactory;

impl PluginFactory for MeshtasticFactory {
    fn create(&self, config: &PluginConfig) -> Result<Box<dyn TransportPlugin>, TransportError> {
        let mut plugin = MeshtasticPlugin::new();
        plugin.configure(config)?;
        Ok(Box::new(plugin))
    }
}
```

### 4. Register in the node

In `mycelium-node/src/main.rs` or at initialization:

```rust
registry.register("meshtastic", Box::new(MeshtasticFactory));
```

## Node ID Bridging

External protocols (Meshtastic, Reticulum) have their own addressing schemes. Plugins must bridge external addresses to Mycelium's 32-byte `NodeId`:

- **Option A: Hash mapping** — SHA-256 hash of the external address (deterministic, no state)
- **Option B: Discovery mapping** — Maintain a bidirectional map populated during discovery

The plugin is responsible for translating between address formats in `send()` and when emitting `DataReceived` events.

## Platform Bridge Plugins

Some plugins need platform-specific APIs (Android BLE, iOS CoreBluetooth). These plugins:

1. Return `true` from `requires_platform_bridge()`
2. Use the outbox polling pattern: queue sends in an `Arc<Mutex<VecDeque>>` and let Dart poll via FFI
3. Receive data via a callback function injected from the platform side

See `BleTransport` and `WifiDirectTransport` for examples of this pattern.

## Built-in Transports Reference

| Transport | MTU | Range | Throughput | Use Case |
|-----------|-----|-------|------------|----------|
| BLE | 512 B | 10-100m | ~1 Mbps | Discovery, small messages |
| Wi-Fi Direct | 64 KB | 50-200m | ~50 Mbps | Bulk data, file sharing |
| BT Classic | 16 KB | 10-100m | ~2 Mbps | Medium data, voice notes |
| LoRa | 51-222 B | 1-15+ km | 0.25-5.5 kbps | Long-range relay, emergency |
| Internet Tunnel | 64 KB | Global | Variable | WAN bridge, supernodes |

## Files

| File | Description |
|------|-------------|
| `crates/mycelium-core/src/transport/mod.rs` | `Transport` trait, `TransportType`, `TransportEvent`, `TransportError` |
| `crates/mycelium-core/src/transport/plugin.rs` | `TransportPlugin`, `PluginFactory`, `PluginRegistry`, `PluginConfig` |
| `crates/mycelium-core/src/transport/manager.rs` | `TransportManager` — owns and dispatches across all transports |
| `crates/mycelium-node/src/config.rs` | `PluginConfigEntry` — TOML config for plugins |
