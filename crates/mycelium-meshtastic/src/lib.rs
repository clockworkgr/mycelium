//! Meshtastic protocol adapter for Mycelium.
//!
//! Bridges Meshtastic LoRa mesh devices (T-Beam, T-Echo, etc.) into the
//! Mycelium network. Meshtastic nodes appear as Mycelium peers, and their
//! messages are translated between protocols.
//!
//! # Protocol Differences
//!
//! | Feature       | Meshtastic              | Mycelium                  |
//! |---------------|-------------------------|---------------------------|
//! | Node ID       | 4-byte node number      | 32-byte Ed25519 pubkey    |
//! | Encryption    | AES-256-CTR with PSK    | X3DH + Double Ratchet     |
//! | Routing       | Flooding with hop limit | AODV reactive routing     |
//! | Frame format  | Protobuf                | Custom binary codec       |
//!
//! # Architecture
//!
//! The adapter connects to a Meshtastic device via serial (USB/BLE) and:
//! 1. Receives Meshtastic packets, extracts payloads, bridges to Mycelium
//! 2. Receives Mycelium messages, wraps in Meshtastic framing, sends to device
//! 3. Maintains a mapping between Meshtastic node numbers and Mycelium NodeIds

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info};

use mycelium_core::transport::plugin::{PluginConfig, TransportPlugin};
use mycelium_core::transport::{Transport, TransportError, TransportEvent, TransportType};
use mycelium_protocol::types::{LinkQuality, NodeId};

// --- Meshtastic Protocol Types ---

/// Meshtastic packet header (simplified binary representation).
///
/// Real Meshtastic uses protobuf, but we parse a simplified binary format
/// for the serial interface. The actual protobuf framing is handled by the
/// `MeshtasticFrame` serialization below.
#[derive(Debug, Clone)]
pub struct MeshtasticPacket {
    /// Source node number (4 bytes).
    pub from: u32,
    /// Destination node number (4 bytes, 0xFFFFFFFF = broadcast).
    pub to: u32,
    /// Packet ID.
    pub id: u32,
    /// Remaining hop count.
    pub hop_limit: u8,
    /// Whether ACK is requested.
    pub want_ack: bool,
    /// Channel index (0-7).
    pub channel: u8,
    /// Payload data.
    pub payload: Vec<u8>,
}

/// Meshtastic broadcast address.
pub const MESHTASTIC_BROADCAST: u32 = 0xFFFFFFFF;

/// Start bytes of the Meshtastic serial "stream" protocol (START1, START2).
/// A frame is `[0x94][0xC3][len MSB][len LSB][body]`.
const SERIAL_MAGIC: [u8; 2] = [0x94, 0xC3];

/// Serial frame prefix length: 2 magic bytes + 2 length bytes.
const SERIAL_PREFIX_LEN: usize = 4;

/// Maximum body length the Meshtastic firmware accepts on the serial link
/// (MAX_TO_FROM_RADIO_SIZE).
const SERIAL_MAX_BODY_LEN: usize = 512;

/// Fixed header length inside the frame body.
const PACKET_HEADER_LEN: usize = 15; // 4+4+4+1+1+1

impl MeshtasticPacket {
    /// Serialize to a serial-stream frame.
    ///
    /// Frame format: [2B magic][2B length BE][header][payload]
    /// Header: [4B from][4B to][4B id][1B hop_limit][1B flags][1B channel]
    ///
    /// NOTE: the body layout is a Mycelium-specific simplification; real
    /// Meshtastic firmware carries protobuf `ToRadio`/`FromRadio` messages
    /// in the body. Only the stream framing (magic + length) matches upstream.
    pub fn serialize(&self) -> Vec<u8> {
        let frame_len = PACKET_HEADER_LEN + self.payload.len();
        let mut buf = Vec::with_capacity(SERIAL_PREFIX_LEN + frame_len);

        // Magic
        buf.extend_from_slice(&SERIAL_MAGIC);
        // Length (2B big-endian)
        buf.push((frame_len >> 8) as u8);
        buf.push((frame_len & 0xFF) as u8);
        // Header
        buf.extend_from_slice(&self.from.to_le_bytes());
        buf.extend_from_slice(&self.to.to_le_bytes());
        buf.extend_from_slice(&self.id.to_le_bytes());
        buf.push(self.hop_limit);
        buf.push(if self.want_ack { 1 } else { 0 });
        buf.push(self.channel);
        // Payload
        buf.extend_from_slice(&self.payload);

        buf
    }

    /// Deserialize from a serial-stream frame.
    pub fn deserialize(data: &[u8]) -> Result<Self, TransportError> {
        if data.len() < SERIAL_PREFIX_LEN {
            return Err(TransportError::Other("packet too short".into()));
        }

        // Check magic
        if data[0..2] != SERIAL_MAGIC {
            return Err(TransportError::Other("invalid magic".into()));
        }

        let frame_len = ((data[2] as usize) << 8) | (data[3] as usize);
        if frame_len > SERIAL_MAX_BODY_LEN {
            return Err(TransportError::Other("frame length exceeds 512".into()));
        }
        if data.len() < SERIAL_PREFIX_LEN + frame_len || frame_len < PACKET_HEADER_LEN {
            return Err(TransportError::Other("incomplete frame".into()));
        }

        let header = &data[SERIAL_PREFIX_LEN..SERIAL_PREFIX_LEN + frame_len];
        let from = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let to = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let id = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        let hop_limit = header[12];
        let want_ack = header[13] != 0;
        let channel = header[14];
        let payload = header[15..frame_len].to_vec();

        Ok(MeshtasticPacket {
            from,
            to,
            id,
            hop_limit,
            want_ack,
            channel,
            payload,
        })
    }
}

// --- Node ID Bridging ---

/// Maps Meshtastic 4-byte node numbers to Mycelium 32-byte NodeIds.
///
/// The mapping is deterministic: `NodeId = SHA-256("meshtastic:" || node_num_le_bytes)`.
/// This ensures the same Meshtastic node always maps to the same Mycelium NodeId.
#[derive(Debug, Default)]
pub struct NodeIdBridge {
    /// Meshtastic node_num → Mycelium NodeId
    meshtastic_to_mycelium: HashMap<u32, NodeId>,
    /// Mycelium NodeId → Meshtastic node_num
    mycelium_to_meshtastic: HashMap<NodeId, u32>,
}

impl NodeIdBridge {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create the Mycelium NodeId for a Meshtastic node number.
    pub fn to_mycelium(&mut self, node_num: u32) -> NodeId {
        *self
            .meshtastic_to_mycelium
            .entry(node_num)
            .or_insert_with(|| {
                let node_id = Self::derive_node_id(node_num);
                self.mycelium_to_meshtastic.insert(node_id, node_num);
                node_id
            })
    }

    /// Look up the Meshtastic node number for a Mycelium NodeId.
    pub fn to_meshtastic(&self, node_id: &NodeId) -> Option<u32> {
        self.mycelium_to_meshtastic.get(node_id).copied()
    }

    /// Deterministic derivation: SHA-256("meshtastic:" || node_num_le_bytes).
    fn derive_node_id(node_num: u32) -> NodeId {
        let mut hasher = Sha256::new();
        hasher.update(b"meshtastic:");
        hasher.update(node_num.to_le_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        NodeId(bytes)
    }
}

// --- Channel Encryption ---

/// Meshtastic channel key placeholder.
///
/// NOTE: this is NOT how Meshtastic derives channel keys. Real Meshtastic
/// channels carry an independent PSK (0/1/16/32 bytes; the default "LongFast"
/// channel uses a well-known 16-byte AES-128 key) and a one-byte channel hash
/// of `xor_fold(name) ^ xor_fold(psk)`; payloads are AES-CTR encrypted with a
/// nonce of `packet_id (u64 LE) || from_node (u32 LE) || 0u32`. None of that is
/// implemented yet (see ROADMAP.md T-16); this type only gives
/// the adapter a stable per-channel identifier until real PSK support lands.
#[derive(Debug, Clone)]
pub struct ChannelKey {
    pub name: String,
    pub key: [u8; 32],
}

impl ChannelKey {
    /// Derive a placeholder 32-byte identifier from the channel name
    /// (SHA-256 of the name). Not interoperable with Meshtastic PSKs.
    pub fn from_passphrase(name: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        Self {
            name: name.to_string(),
            key,
        }
    }

    /// Placeholder for the default "LongFast" channel.
    pub fn default_channel() -> Self {
        Self::from_passphrase("LongFast")
    }
}

// --- Meshtastic Transport ---

/// Meshtastic protocol adapter transport.
///
/// Implements `TransportPlugin` to bridge Meshtastic devices into the
/// Mycelium mesh. The transport connects to a Meshtastic node via serial
/// (USB or BLE GATT) and translates between protocols.
pub struct MeshtasticTransport {
    config: MeshtasticConfig,
    tx: broadcast::Sender<TransportEvent>,
    connected_peers: Arc<RwLock<Vec<NodeId>>>,
    started: Arc<RwLock<bool>>,
    #[allow(clippy::type_complexity)]
    outbox: Arc<Mutex<VecDeque<(NodeId, Vec<u8>)>>>,
    bridge: Arc<Mutex<NodeIdBridge>>,
    #[allow(dead_code)] // Used when encryption support is activated
    channels: Arc<RwLock<Vec<ChannelKey>>>,
}

/// Configuration for the Meshtastic adapter.
#[derive(Debug, Clone)]
pub struct MeshtasticConfig {
    /// Channel passphrase (default: "LongFast").
    pub channel: String,
    /// Local Meshtastic node number (set after connection).
    pub local_node_num: Option<u32>,
    /// Maximum hop limit for outgoing packets.
    pub hop_limit: u8,
}

impl Default for MeshtasticConfig {
    fn default() -> Self {
        Self {
            channel: "LongFast".to_string(),
            local_node_num: None,
            hop_limit: 3,
        }
    }
}

impl MeshtasticTransport {
    pub fn new(config: MeshtasticConfig) -> Self {
        let (tx, _) = broadcast::channel(64);
        Self {
            config,
            tx,
            connected_peers: Arc::new(RwLock::new(Vec::new())),
            started: Arc::new(RwLock::new(false)),
            outbox: Arc::new(Mutex::new(VecDeque::new())),
            bridge: Arc::new(Mutex::new(NodeIdBridge::new())),
            channels: Arc::new(RwLock::new(vec![ChannelKey::default_channel()])),
        }
    }

    /// Number of packets waiting in the outbox.
    pub fn outbox_len(&self) -> usize {
        self.outbox.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// Dequeue a pending send from the outbox.
    pub fn dequeue_send(&self) -> Option<(NodeId, Vec<u8>)> {
        self.outbox.lock().ok()?.pop_front()
    }

    /// Called by platform when a Meshtastic packet is received from the serial link.
    pub fn on_packet_received(&self, packet: MeshtasticPacket) {
        let peer_id = {
            let mut bridge = match self.bridge.lock() {
                Ok(b) => b,
                Err(_) => return,
            };
            bridge.to_mycelium(packet.from)
        };

        // Add peer if not already known
        if let Ok(mut peers) = self.connected_peers.try_write() {
            if !peers.contains(&peer_id) {
                info!("Meshtastic peer discovered: node_num={:#010x}", packet.from);
                peers.push(peer_id);
                let _ = self.tx.send(TransportEvent::NeighborDiscovered {
                    peer: peer_id,
                    transport: TransportType::Meshtastic,
                });
            }
        }

        // Forward payload as Mycelium data
        if !packet.payload.is_empty() {
            debug!(
                "Meshtastic data: {} bytes from node {:#010x}",
                packet.payload.len(),
                packet.from
            );
            let _ = self.tx.send(TransportEvent::DataReceived {
                peer: peer_id,
                data: packet.payload,
                transport: TransportType::Meshtastic,
            });
        }
    }

    /// Called by platform when raw serial data is received.
    pub fn on_serial_data(&self, data: &[u8]) {
        match MeshtasticPacket::deserialize(data) {
            Ok(packet) => self.on_packet_received(packet),
            Err(e) => debug!("Meshtastic: failed to parse packet: {}", e),
        }
    }

    /// Get the node ID bridge for external access.
    pub fn bridge(&self) -> &Arc<Mutex<NodeIdBridge>> {
        &self.bridge
    }
}

#[async_trait::async_trait]
impl Transport for MeshtasticTransport {
    fn transport_type(&self) -> TransportType {
        // A Meshtastic bridge, not a native Mycelium LoRa radio: the
        // framing and channel crypto are the foreign protocol's.
        TransportType::Meshtastic
    }

    async fn start(&self) -> Result<(), TransportError> {
        let mut started = self.started.write().await;
        if *started {
            return Err(TransportError::AlreadyStarted);
        }
        *started = true;
        info!(
            "Meshtastic adapter started (channel: {})",
            self.config.channel
        );
        Ok(())
    }

    async fn stop(&self) -> Result<(), TransportError> {
        let mut started = self.started.write().await;
        if !*started {
            return Err(TransportError::NotStarted);
        }
        *started = false;
        let mut peers = self.connected_peers.write().await;
        peers.clear();
        if let Ok(mut outbox) = self.outbox.lock() {
            outbox.clear();
        }
        Ok(())
    }

    async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError> {
        let started = self.started.read().await;
        if !*started {
            return Err(TransportError::NotStarted);
        }

        if data.len() > self.mtu() {
            return Err(TransportError::ExceedsMtu {
                size: data.len(),
                mtu: self.mtu(),
            });
        }

        // Look up Meshtastic node number. An unknown peer must fail loudly:
        // TransportManager treats Ok(()) as delivered, so silently
        // broadcasting would mask undeliverable unicasts.
        let dest_node_num = {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| TransportError::Other("bridge lock failed".into()))?;
            bridge
                .to_meshtastic(peer)
                .ok_or(TransportError::PeerNotConnected(*peer))?
        };

        // Wrap in Meshtastic packet
        let packet = MeshtasticPacket {
            from: self.config.local_node_num.unwrap_or(0),
            to: dest_node_num,
            id: rand::random(),
            hop_limit: self.config.hop_limit,
            want_ack: false,
            channel: 0,
            payload: data.to_vec(),
        };

        let serialized = packet.serialize();
        debug!(
            "Meshtastic send: {} bytes to node {:#010x}",
            data.len(),
            dest_node_num
        );

        if let Ok(mut outbox) = self.outbox.lock() {
            outbox.push_back((*peer, serialized));
        }

        Ok(())
    }

    fn events(&self) -> broadcast::Receiver<TransportEvent> {
        self.tx.subscribe()
    }

    fn link_quality(&self, peer: &NodeId) -> Option<LinkQuality> {
        let peers = self.connected_peers.try_read().ok()?;
        if peers.contains(peer) {
            Some(LinkQuality {
                rssi: Some(-100),
                packet_loss: 0.1,
                latency_ms: 1000,    // Meshtastic is slow
                throughput_bps: 250, // Typical SF12 LoRa rate
            })
        } else {
            None
        }
    }

    fn connected_peers(&self) -> Vec<NodeId> {
        self.connected_peers
            .try_read()
            .map(|p| p.clone())
            .unwrap_or_default()
    }

    fn mtu(&self) -> usize {
        237 // Meshtastic max payload
    }
}

impl TransportPlugin for MeshtasticTransport {
    fn plugin_name(&self) -> &str {
        "meshtastic"
    }

    fn plugin_version(&self) -> &str {
        "0.1.0"
    }

    fn plugin_description(&self) -> &str {
        "Meshtastic LoRa mesh protocol adapter"
    }

    fn configure(&mut self, config: &PluginConfig) -> Result<(), TransportError> {
        if let Some(channel) = config.settings.get("channel") {
            self.config.channel = channel.clone();
        }
        if let Some(hop_limit) = config.settings.get("hop_limit") {
            self.config.hop_limit = hop_limit
                .parse()
                .map_err(|_| TransportError::Other("invalid hop_limit".into()))?;
        }
        Ok(())
    }

    fn requires_platform_bridge(&self) -> bool {
        true // Connects to Meshtastic device via serial
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_roundtrip() {
        let packet = MeshtasticPacket {
            from: 0xDEADBEEF,
            to: MESHTASTIC_BROADCAST,
            id: 42,
            hop_limit: 3,
            want_ack: true,
            channel: 0,
            payload: b"Hello Meshtastic!".to_vec(),
        };

        let serialized = packet.serialize();
        let deserialized = MeshtasticPacket::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.from, 0xDEADBEEF);
        assert_eq!(deserialized.to, MESHTASTIC_BROADCAST);
        assert_eq!(deserialized.id, 42);
        assert_eq!(deserialized.hop_limit, 3);
        assert!(deserialized.want_ack);
        assert_eq!(deserialized.channel, 0);
        assert_eq!(deserialized.payload, b"Hello Meshtastic!");
    }

    #[test]
    fn test_packet_too_short() {
        let result = MeshtasticPacket::deserialize(&[0, 1, 2]);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_bad_magic() {
        let mut bad = [0u8; 19];
        bad[3] = 15; // frame_len = 15 but magic is wrong
        let result = MeshtasticPacket::deserialize(&bad);
        assert!(result.is_err());
    }

    /// The stream framing must match the Meshtastic serial protocol:
    /// START1=0x94, START2=0xC3, then a big-endian u16 body length.
    #[test]
    fn test_serial_frame_layout() {
        let packet = MeshtasticPacket {
            from: 1,
            to: 2,
            id: 3,
            hop_limit: 3,
            want_ack: false,
            channel: 0,
            payload: vec![0xAA; 5],
        };
        let bytes = packet.serialize();
        assert_eq!(&bytes[0..2], &[0x94, 0xC3]);
        let body_len = PACKET_HEADER_LEN + 5;
        assert_eq!(bytes[2], (body_len >> 8) as u8);
        assert_eq!(bytes[3], (body_len & 0xFF) as u8);
        assert_eq!(bytes.len(), SERIAL_PREFIX_LEN + body_len);
    }

    #[test]
    fn test_frame_length_over_512_rejected() {
        let mut bad = vec![0x94, 0xC3, 0x02, 0x01]; // length 513
        bad.extend(vec![0u8; 513]);
        assert!(MeshtasticPacket::deserialize(&bad).is_err());
    }

    #[test]
    fn test_node_id_bridge_deterministic() {
        let mut bridge = NodeIdBridge::new();
        let id1 = bridge.to_mycelium(0xDEADBEEF);
        let id2 = bridge.to_mycelium(0xDEADBEEF);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_node_id_bridge_different_nodes() {
        let mut bridge = NodeIdBridge::new();
        let id1 = bridge.to_mycelium(0x00000001);
        let id2 = bridge.to_mycelium(0x00000002);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_node_id_bridge_reverse_lookup() {
        let mut bridge = NodeIdBridge::new();
        let node_id = bridge.to_mycelium(0xCAFEBABE);
        let node_num = bridge.to_meshtastic(&node_id);
        assert_eq!(node_num, Some(0xCAFEBABE));
    }

    #[test]
    fn test_channel_key_derivation() {
        let key1 = ChannelKey::from_passphrase("LongFast");
        let key2 = ChannelKey::from_passphrase("LongFast");
        assert_eq!(key1.key, key2.key);

        let key3 = ChannelKey::from_passphrase("Different");
        assert_ne!(key1.key, key3.key);
    }

    #[test]
    fn test_default_channel() {
        let key = ChannelKey::default_channel();
        assert_eq!(key.name, "LongFast");
    }

    #[tokio::test]
    async fn test_meshtastic_transport_lifecycle() {
        let transport = MeshtasticTransport::new(MeshtasticConfig::default());
        assert_eq!(transport.transport_type(), TransportType::Meshtastic);
        assert_eq!(transport.mtu(), 237);

        transport.start().await.unwrap();

        // Receive a packet
        let packet = MeshtasticPacket {
            from: 0x12345678,
            to: MESHTASTIC_BROADCAST,
            id: 1,
            hop_limit: 3,
            want_ack: false,
            channel: 0,
            payload: b"test".to_vec(),
        };
        transport.on_packet_received(packet);

        // Peer should be discovered
        let peers = transport.connected_peers();
        assert_eq!(peers.len(), 1);

        // Link quality should be available
        assert!(transport.link_quality(&peers[0]).is_some());

        transport.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_meshtastic_send() {
        let transport = MeshtasticTransport::new(MeshtasticConfig {
            local_node_num: Some(0xAABBCCDD),
            ..Default::default()
        });
        transport.start().await.unwrap();

        // Discover a peer first
        let packet = MeshtasticPacket {
            from: 0x11223344,
            to: MESHTASTIC_BROADCAST,
            id: 1,
            hop_limit: 3,
            want_ack: false,
            channel: 0,
            payload: b"hello".to_vec(),
        };
        transport.on_packet_received(packet);

        let peers = transport.connected_peers();
        assert_eq!(peers.len(), 1);

        // Send to the peer
        let result = transport.send(&peers[0], b"response").await;
        assert!(result.is_ok());
        assert_eq!(transport.outbox_len(), 1);

        // Dequeue and verify
        let (_, serialized) = transport.dequeue_send().unwrap();
        let outgoing = MeshtasticPacket::deserialize(&serialized).unwrap();
        assert_eq!(outgoing.from, 0xAABBCCDD);
        assert_eq!(outgoing.to, 0x11223344);
        assert_eq!(outgoing.payload, b"response");
    }

    #[tokio::test]
    async fn test_send_unknown_peer_fails() {
        let transport = MeshtasticTransport::new(MeshtasticConfig::default());
        transport.start().await.unwrap();
        let peer = NodeId([0x42; 32]);
        let result = transport.send(&peer, b"hi").await;
        assert!(matches!(result, Err(TransportError::PeerNotConnected(_))));
        assert_eq!(transport.outbox_len(), 0);
    }

    #[tokio::test]
    async fn test_send_exceeds_mtu() {
        let transport = MeshtasticTransport::new(MeshtasticConfig::default());
        transport.start().await.unwrap();
        let peer = NodeId([0x42; 32]);
        let too_large = vec![0u8; transport.mtu() + 1];
        let result = transport.send(&peer, &too_large).await;
        assert!(matches!(result, Err(TransportError::ExceedsMtu { .. })));
    }

    #[test]
    fn test_plugin_interface() {
        let mut transport = MeshtasticTransport::new(MeshtasticConfig::default());
        assert_eq!(transport.plugin_name(), "meshtastic");
        assert_eq!(transport.plugin_version(), "0.1.0");
        assert!(transport.requires_platform_bridge());

        let mut config = PluginConfig::default();
        config
            .settings
            .insert("channel".to_string(), "MyChannel".to_string());
        config
            .settings
            .insert("hop_limit".to_string(), "5".to_string());
        transport.configure(&config).unwrap();
        assert_eq!(transport.config.channel, "MyChannel");
        assert_eq!(transport.config.hop_limit, 5);
    }

    #[test]
    fn test_serial_data_parsing() {
        let packet = MeshtasticPacket {
            from: 0xDEADBEEF,
            to: MESHTASTIC_BROADCAST,
            id: 99,
            hop_limit: 7,
            want_ack: false,
            channel: 2,
            payload: vec![1, 2, 3, 4, 5],
        };
        let serialized = packet.serialize();

        let transport = MeshtasticTransport::new(MeshtasticConfig::default());
        transport.on_serial_data(&serialized);

        // Should have discovered the peer
        let peers = transport.connected_peers();
        assert_eq!(peers.len(), 1);
    }
}
