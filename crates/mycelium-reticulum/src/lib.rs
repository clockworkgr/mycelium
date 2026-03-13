//! Reticulum protocol adapter for Mycelium.
//!
//! Bridges Reticulum network nodes into the Mycelium mesh. Reticulum
//! destinations appear as Mycelium peers, and messages are translated
//! between protocols.
//!
//! # Protocol Differences
//!
//! | Feature       | Reticulum                 | Mycelium                  |
//! |---------------|---------------------------|---------------------------|
//! | Address       | 16-byte destination hash  | 32-byte Ed25519 pubkey    |
//! | Encryption    | X25519+AES-256-CBC+HMAC   | X3DH + Double Ratchet     |
//! | Routing       | Announce/path request     | AODV reactive routing     |
//! | Frame format  | 2B header + addresses     | Custom binary codec       |
//! | MTU           | 500 bytes (465 MDU)       | Transport-dependent       |
//!
//! # Architecture
//!
//! The adapter connects to a Reticulum instance via TCP or UDP and:
//! 1. Receives Reticulum packets, extracts payloads, bridges to Mycelium
//! 2. Receives Mycelium messages, wraps in Reticulum framing, sends out
//! 3. Maintains a mapping between Reticulum destination hashes and Mycelium NodeIds
//! 4. Translates announce packets into Mycelium peer discovery events

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info};

use mycelium_core::transport::plugin::{PluginConfig, TransportPlugin};
use mycelium_core::transport::{Transport, TransportError, TransportEvent, TransportType};
use mycelium_protocol::types::{LinkQuality, NodeId};

// --- Reticulum Protocol Constants ---

/// Reticulum MTU (physical layer maximum).
pub const RETICULUM_MTU: usize = 500;
/// Reticulum MDU (maximum data unit after header).
pub const RETICULUM_MDU: usize = 465;
/// Maximum hop count for Reticulum packets.
pub const MAX_HOPS: u8 = 128;
/// Reticulum address length (truncated SHA-256).
pub const ADDRESS_LENGTH: usize = 16;
/// Reticulum name hash length.
pub const NAME_HASH_LENGTH: usize = 10;

// --- Header Flag Bits ---

/// Header type: single address (HEADER_1).
pub const HEADER_1: u8 = 0x00;
/// Header type: two addresses (HEADER_2).
pub const HEADER_2: u8 = 0x01;

/// Propagation type: broadcast/flood.
pub const PROPAGATION_BROADCAST: u8 = 0x00;
/// Propagation type: routed via transport nodes.
pub const PROPAGATION_TRANSPORT: u8 = 0x01;

/// Destination type: single (asymmetric encryption).
pub const DEST_SINGLE: u8 = 0x00;
/// Destination type: group (symmetric encryption).
pub const DEST_GROUP: u8 = 0x01;
/// Destination type: plain (unencrypted).
pub const DEST_PLAIN: u8 = 0x02;
/// Destination type: link (bidirectional ECDH channel).
pub const DEST_LINK: u8 = 0x03;

/// Packet type: data.
pub const PACKET_DATA: u8 = 0x00;
/// Packet type: announce.
pub const PACKET_ANNOUNCE: u8 = 0x01;
/// Packet type: link request.
pub const PACKET_LINKREQUEST: u8 = 0x02;
/// Packet type: proof.
pub const PACKET_PROOF: u8 = 0x03;

// --- Context Types ---

/// No context.
pub const CONTEXT_NONE: u8 = 0x00;
/// Path response context.
pub const CONTEXT_PATH_RESPONSE: u8 = 0x0B;

// --- Reticulum Packet Types ---

/// Header flags for a Reticulum packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderFlags {
    /// 0 = HEADER_1 (one address), 1 = HEADER_2 (two addresses).
    pub header_type: u8,
    /// Context flag.
    pub context_flag: bool,
    /// 0 = broadcast, 1 = transport.
    pub propagation_type: u8,
    /// 0 = single, 1 = group, 2 = plain, 3 = link.
    pub destination_type: u8,
    /// 0 = data, 1 = announce, 2 = linkrequest, 3 = proof.
    pub packet_type: u8,
}

impl HeaderFlags {
    /// Encode flags into a single byte.
    pub fn encode(&self) -> u8 {
        (self.header_type << 6)
            | (u8::from(self.context_flag) << 5)
            | (self.propagation_type << 4)
            | (self.destination_type << 2)
            | self.packet_type
    }

    /// Decode flags from a single byte.
    pub fn decode(byte: u8) -> Self {
        Self {
            header_type: (byte >> 6) & 0x01,
            context_flag: (byte >> 5) & 0x01 != 0,
            propagation_type: (byte >> 4) & 0x01,
            destination_type: (byte >> 2) & 0x03,
            packet_type: byte & 0x03,
        }
    }
}

/// A Reticulum packet parsed from the wire.
#[derive(Debug, Clone)]
pub struct ReticulumPacket {
    /// Header flags.
    pub flags: HeaderFlags,
    /// Hop count.
    pub hops: u8,
    /// Transport ID (only present in HEADER_2 packets).
    pub transport_id: Option<[u8; ADDRESS_LENGTH]>,
    /// Destination hash (16 bytes).
    pub destination: [u8; ADDRESS_LENGTH],
    /// Context byte.
    pub context: u8,
    /// Payload data.
    pub data: Vec<u8>,
}

impl ReticulumPacket {
    /// Serialize to wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let has_transport = self.transport_id.is_some();
        let header_size = if has_transport { 35 } else { 19 };
        let mut buf = Vec::with_capacity(header_size + self.data.len());

        // Header byte 0: flags
        buf.push(self.flags.encode());
        // Header byte 1: hop count
        buf.push(self.hops);

        // Addresses
        if let Some(tid) = &self.transport_id {
            buf.extend_from_slice(tid);
        }
        buf.extend_from_slice(&self.destination);

        // Context
        buf.push(self.context);

        // Data
        buf.extend_from_slice(&self.data);

        buf
    }

    /// Deserialize from wire format.
    pub fn deserialize(data: &[u8]) -> Result<Self, TransportError> {
        if data.len() < 19 {
            return Err(TransportError::Other("packet too short".into()));
        }

        let flags = HeaderFlags::decode(data[0]);
        let hops = data[1];

        let (transport_id, dest_offset) = if flags.header_type == HEADER_2 {
            if data.len() < 35 {
                return Err(TransportError::Other(
                    "HEADER_2 packet too short for two addresses".into(),
                ));
            }
            let mut tid = [0u8; ADDRESS_LENGTH];
            tid.copy_from_slice(&data[2..18]);
            (Some(tid), 18)
        } else {
            (None, 2)
        };

        let mut destination = [0u8; ADDRESS_LENGTH];
        destination.copy_from_slice(&data[dest_offset..dest_offset + ADDRESS_LENGTH]);

        let context_offset = dest_offset + ADDRESS_LENGTH;
        let context = data[context_offset];

        let payload = data[context_offset + 1..].to_vec();

        Ok(ReticulumPacket {
            flags,
            hops,
            transport_id,
            destination,
            context,
            data: payload,
        })
    }

    /// Create a simple data packet (HEADER_1, broadcast, single destination).
    pub fn data_packet(destination: [u8; ADDRESS_LENGTH], data: Vec<u8>) -> Self {
        Self {
            flags: HeaderFlags {
                header_type: HEADER_1,
                context_flag: false,
                propagation_type: PROPAGATION_BROADCAST,
                destination_type: DEST_SINGLE,
                packet_type: PACKET_DATA,
            },
            hops: 0,
            transport_id: None,
            destination,
            context: CONTEXT_NONE,
            data,
        }
    }
}

// --- Address Bridging ---

/// Maps Reticulum 16-byte destination hashes to Mycelium 32-byte NodeIds.
///
/// The mapping is deterministic: `NodeId = SHA-256("reticulum:" || dest_hash)`.
#[derive(Debug, Default)]
pub struct AddressBridge {
    /// Reticulum dest hash → Mycelium NodeId
    reticulum_to_mycelium: HashMap<[u8; ADDRESS_LENGTH], NodeId>,
    /// Mycelium NodeId → Reticulum dest hash
    mycelium_to_reticulum: HashMap<NodeId, [u8; ADDRESS_LENGTH]>,
}

impl AddressBridge {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create the Mycelium NodeId for a Reticulum destination hash.
    pub fn to_mycelium(&mut self, dest_hash: &[u8; ADDRESS_LENGTH]) -> NodeId {
        *self
            .reticulum_to_mycelium
            .entry(*dest_hash)
            .or_insert_with(|| {
                let node_id = Self::derive_node_id(dest_hash);
                self.mycelium_to_reticulum.insert(node_id, *dest_hash);
                node_id
            })
    }

    /// Look up the Reticulum destination hash for a Mycelium NodeId.
    pub fn to_reticulum(&self, node_id: &NodeId) -> Option<[u8; ADDRESS_LENGTH]> {
        self.mycelium_to_reticulum.get(node_id).copied()
    }

    /// Deterministic derivation: SHA-256("reticulum:" || dest_hash).
    fn derive_node_id(dest_hash: &[u8; ADDRESS_LENGTH]) -> NodeId {
        let mut hasher = Sha256::new();
        hasher.update(b"reticulum:");
        hasher.update(dest_hash);
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        NodeId(bytes)
    }
}

// --- Announce Parsing ---

/// Parsed Reticulum announce data.
#[derive(Debug, Clone)]
pub struct AnnounceData {
    /// Ed25519 + X25519 public keys (64 bytes total).
    pub public_key: [u8; 64],
    /// Name hash (10 bytes).
    pub name_hash: [u8; NAME_HASH_LENGTH],
    /// Random hash (10 bytes: 5 random + 5 timestamp).
    pub random_hash: [u8; 10],
    /// Optional app data.
    pub app_data: Vec<u8>,
}

impl AnnounceData {
    /// Minimum announce data size: 64 (pubkey) + 10 (name_hash) + 10 (random_hash) + 64 (signature) = 148.
    const MIN_SIZE: usize = 148;

    /// Parse announce data from a packet payload.
    pub fn parse(data: &[u8]) -> Result<Self, TransportError> {
        if data.len() < Self::MIN_SIZE {
            return Err(TransportError::Other("announce data too short".into()));
        }

        let mut public_key = [0u8; 64];
        public_key.copy_from_slice(&data[..64]);

        let mut name_hash = [0u8; NAME_HASH_LENGTH];
        name_hash.copy_from_slice(&data[64..74]);

        let mut random_hash = [0u8; 10];
        random_hash.copy_from_slice(&data[74..84]);

        // Bytes 84..148 are the signature (64 bytes) — we store but don't verify here
        // Bytes 148.. are optional app_data
        let app_data = if data.len() > Self::MIN_SIZE {
            data[Self::MIN_SIZE..].to_vec()
        } else {
            Vec::new()
        };

        Ok(AnnounceData {
            public_key,
            name_hash,
            random_hash,
            app_data,
        })
    }
}

// --- HDLC Framing ---

/// HDLC framing for serial interfaces.
pub struct HdlcFraming;

const HDLC_FLAG: u8 = 0x7E;
const HDLC_ESC: u8 = 0x7D;
const HDLC_ESC_MASK: u8 = 0x20;

impl HdlcFraming {
    /// Encode a packet with HDLC framing (flag + escaped data + flag).
    pub fn encode(data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(data.len() + 4);
        buf.push(HDLC_FLAG);
        for &byte in data {
            if byte == HDLC_FLAG || byte == HDLC_ESC {
                buf.push(HDLC_ESC);
                buf.push(byte ^ HDLC_ESC_MASK);
            } else {
                buf.push(byte);
            }
        }
        buf.push(HDLC_FLAG);
        buf
    }

    /// Decode HDLC-framed data. Returns the unescaped payload.
    pub fn decode(data: &[u8]) -> Result<Vec<u8>, TransportError> {
        if data.len() < 2 || data[0] != HDLC_FLAG || data[data.len() - 1] != HDLC_FLAG {
            return Err(TransportError::Other("invalid HDLC framing".into()));
        }

        let inner = &data[1..data.len() - 1];
        let mut result = Vec::with_capacity(inner.len());
        let mut escaped = false;

        for &byte in inner {
            if escaped {
                result.push(byte ^ HDLC_ESC_MASK);
                escaped = false;
            } else if byte == HDLC_ESC {
                escaped = true;
            } else if byte == HDLC_FLAG {
                return Err(TransportError::Other("unexpected flag in HDLC data".into()));
            } else {
                result.push(byte);
            }
        }

        if escaped {
            return Err(TransportError::Other("truncated HDLC escape".into()));
        }

        Ok(result)
    }
}

// --- Reticulum Transport ---

/// Reticulum protocol adapter transport.
///
/// Implements `TransportPlugin` to bridge Reticulum nodes into the
/// Mycelium mesh. Connects to a Reticulum instance via TCP or UDP.
pub struct ReticulumTransport {
    config: ReticulumConfig,
    tx: broadcast::Sender<TransportEvent>,
    connected_peers: Arc<RwLock<Vec<NodeId>>>,
    started: Arc<RwLock<bool>>,
    #[allow(clippy::type_complexity)]
    outbox: Arc<Mutex<VecDeque<(NodeId, Vec<u8>)>>>,
    bridge: Arc<Mutex<AddressBridge>>,
}

/// Configuration for the Reticulum adapter.
#[derive(Debug, Clone)]
pub struct ReticulumConfig {
    /// Interface type: "tcp", "udp", or "serial".
    pub interface_type: String,
    /// Host address for TCP/UDP (e.g., "127.0.0.1:4242").
    pub host: String,
    /// Application name for destination registration.
    pub app_name: String,
}

impl Default for ReticulumConfig {
    fn default() -> Self {
        Self {
            interface_type: "tcp".to_string(),
            host: "127.0.0.1:4242".to_string(),
            app_name: "mycelium".to_string(),
        }
    }
}

impl ReticulumTransport {
    pub fn new(config: ReticulumConfig) -> Self {
        let (tx, _) = broadcast::channel(64);
        Self {
            config,
            tx,
            connected_peers: Arc::new(RwLock::new(Vec::new())),
            started: Arc::new(RwLock::new(false)),
            outbox: Arc::new(Mutex::new(VecDeque::new())),
            bridge: Arc::new(Mutex::new(AddressBridge::new())),
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

    /// Called when a Reticulum packet is received from the network interface.
    pub fn on_packet_received(&self, packet: ReticulumPacket) {
        match packet.flags.packet_type {
            PACKET_ANNOUNCE => self.handle_announce(&packet),
            PACKET_DATA => self.handle_data(&packet),
            _ => {
                debug!(
                    "Reticulum: ignoring packet type {}",
                    packet.flags.packet_type
                );
            }
        }
    }

    fn handle_announce(&self, packet: &ReticulumPacket) {
        let peer_id = {
            let mut bridge = match self.bridge.lock() {
                Ok(b) => b,
                Err(_) => return,
            };
            bridge.to_mycelium(&packet.destination)
        };

        if let Ok(mut peers) = self.connected_peers.try_write() {
            if !peers.contains(&peer_id) {
                info!(
                    "Reticulum peer announced: dest={}",
                    hex_short(&packet.destination)
                );
                peers.push(peer_id);
                let _ = self.tx.send(TransportEvent::NeighborDiscovered {
                    peer: peer_id,
                    transport: TransportType::InternetTunnel,
                });
            }
        }
    }

    fn handle_data(&self, packet: &ReticulumPacket) {
        let peer_id = {
            let mut bridge = match self.bridge.lock() {
                Ok(b) => b,
                Err(_) => return,
            };
            bridge.to_mycelium(&packet.destination)
        };

        // Ensure peer is known
        if let Ok(mut peers) = self.connected_peers.try_write() {
            if !peers.contains(&peer_id) {
                peers.push(peer_id);
                let _ = self.tx.send(TransportEvent::NeighborDiscovered {
                    peer: peer_id,
                    transport: TransportType::InternetTunnel,
                });
            }
        }

        if !packet.data.is_empty() {
            debug!(
                "Reticulum data: {} bytes from dest {}",
                packet.data.len(),
                hex_short(&packet.destination)
            );
            let _ = self.tx.send(TransportEvent::DataReceived {
                peer: peer_id,
                data: packet.data.clone(),
                transport: TransportType::InternetTunnel,
            });
        }
    }

    /// Called when raw data is received from a network interface.
    pub fn on_raw_data(&self, data: &[u8]) {
        match ReticulumPacket::deserialize(data) {
            Ok(packet) => self.on_packet_received(packet),
            Err(e) => debug!("Reticulum: failed to parse packet: {}", e),
        }
    }

    /// Get the address bridge for external access.
    pub fn bridge(&self) -> &Arc<Mutex<AddressBridge>> {
        &self.bridge
    }
}

#[async_trait::async_trait]
impl Transport for ReticulumTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::InternetTunnel // Reticulum typically runs over IP
    }

    async fn start(&self) -> Result<(), TransportError> {
        let mut started = self.started.write().await;
        if *started {
            return Err(TransportError::AlreadyStarted);
        }
        *started = true;
        info!(
            "Reticulum adapter started (interface: {}, host: {})",
            self.config.interface_type, self.config.host
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
        Ok(())
    }

    async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError> {
        let started = self.started.read().await;
        if !*started {
            return Err(TransportError::NotStarted);
        }

        if data.len() > RETICULUM_MDU {
            return Err(TransportError::ExceedsMtu {
                size: data.len(),
                mtu: RETICULUM_MDU,
            });
        }

        // Look up Reticulum destination hash
        let dest_hash = {
            let bridge = self
                .bridge
                .lock()
                .map_err(|_| TransportError::Other("bridge lock failed".into()))?;
            bridge.to_reticulum(peer)
        };

        let packet = match dest_hash {
            Some(dest) => ReticulumPacket::data_packet(dest, data.to_vec()),
            None => {
                // Unknown destination — use zero hash (will be handled by Reticulum routing)
                ReticulumPacket::data_packet([0u8; ADDRESS_LENGTH], data.to_vec())
            }
        };

        let serialized = packet.serialize();
        debug!(
            "Reticulum send: {} bytes to dest {}",
            data.len(),
            dest_hash.map_or_else(|| "unknown".to_string(), |d| hex_short(&d))
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
                rssi: None, // IP-based, no RSSI
                packet_loss: 0.01,
                latency_ms: 50,          // Typical LAN/internet latency
                throughput_bps: 100_000, // Typical TCP throughput
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
        RETICULUM_MDU
    }
}

impl TransportPlugin for ReticulumTransport {
    fn plugin_name(&self) -> &str {
        "reticulum"
    }

    fn plugin_version(&self) -> &str {
        "0.1.0"
    }

    fn plugin_description(&self) -> &str {
        "Reticulum mesh protocol adapter"
    }

    fn configure(&mut self, config: &PluginConfig) -> Result<(), TransportError> {
        if let Some(iface) = config.settings.get("interface_type") {
            self.config.interface_type = iface.clone();
        }
        if let Some(host) = config.settings.get("host") {
            self.config.host = host.clone();
        }
        if let Some(app) = config.settings.get("app_name") {
            self.config.app_name = app.clone();
        }
        Ok(())
    }

    fn requires_platform_bridge(&self) -> bool {
        false // Connects via TCP/UDP directly
    }
}

/// Format first 8 bytes of an address as hex for logging.
fn hex_short(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_flags_roundtrip() {
        let flags = HeaderFlags {
            header_type: HEADER_1,
            context_flag: true,
            propagation_type: PROPAGATION_TRANSPORT,
            destination_type: DEST_SINGLE,
            packet_type: PACKET_DATA,
        };
        let byte = flags.encode();
        let decoded = HeaderFlags::decode(byte);
        assert_eq!(decoded.header_type, HEADER_1);
        assert!(decoded.context_flag);
        assert_eq!(decoded.propagation_type, PROPAGATION_TRANSPORT);
        assert_eq!(decoded.destination_type, DEST_SINGLE);
        assert_eq!(decoded.packet_type, PACKET_DATA);
    }

    #[test]
    fn test_header_flags_all_types() {
        let flags = HeaderFlags {
            header_type: HEADER_2,
            context_flag: false,
            propagation_type: PROPAGATION_BROADCAST,
            destination_type: DEST_LINK,
            packet_type: PACKET_PROOF,
        };
        let byte = flags.encode();
        assert_eq!(byte, 0b01001111);
        let decoded = HeaderFlags::decode(byte);
        assert_eq!(decoded, flags);
    }

    #[test]
    fn test_packet_header1_roundtrip() {
        let dest = [0xAA; ADDRESS_LENGTH];
        let packet = ReticulumPacket::data_packet(dest, b"Hello Reticulum!".to_vec());

        let serialized = packet.serialize();
        assert_eq!(serialized.len(), 19 + 16); // header + payload

        let deserialized = ReticulumPacket::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.destination, dest);
        assert_eq!(deserialized.data, b"Hello Reticulum!");
        assert_eq!(deserialized.hops, 0);
        assert!(deserialized.transport_id.is_none());
    }

    #[test]
    fn test_packet_header2_roundtrip() {
        let tid = [0xBB; ADDRESS_LENGTH];
        let dest = [0xCC; ADDRESS_LENGTH];
        let packet = ReticulumPacket {
            flags: HeaderFlags {
                header_type: HEADER_2,
                context_flag: false,
                propagation_type: PROPAGATION_TRANSPORT,
                destination_type: DEST_SINGLE,
                packet_type: PACKET_DATA,
            },
            hops: 5,
            transport_id: Some(tid),
            destination: dest,
            context: CONTEXT_NONE,
            data: vec![1, 2, 3],
        };

        let serialized = packet.serialize();
        assert_eq!(serialized.len(), 35 + 3); // header2 + payload

        let deserialized = ReticulumPacket::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.transport_id, Some(tid));
        assert_eq!(deserialized.destination, dest);
        assert_eq!(deserialized.hops, 5);
        assert_eq!(deserialized.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_packet_too_short() {
        assert!(ReticulumPacket::deserialize(&[0; 10]).is_err());
    }

    #[test]
    fn test_address_bridge_deterministic() {
        let mut bridge = AddressBridge::new();
        let dest = [0xDE; ADDRESS_LENGTH];
        let id1 = bridge.to_mycelium(&dest);
        let id2 = bridge.to_mycelium(&dest);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_address_bridge_different_dests() {
        let mut bridge = AddressBridge::new();
        let dest1 = [0x01; ADDRESS_LENGTH];
        let dest2 = [0x02; ADDRESS_LENGTH];
        let id1 = bridge.to_mycelium(&dest1);
        let id2 = bridge.to_mycelium(&dest2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_address_bridge_reverse_lookup() {
        let mut bridge = AddressBridge::new();
        let dest = [0xCA; ADDRESS_LENGTH];
        let node_id = bridge.to_mycelium(&dest);
        let recovered = bridge.to_reticulum(&node_id);
        assert_eq!(recovered, Some(dest));
    }

    #[test]
    fn test_hdlc_roundtrip() {
        let data = vec![0x7E, 0x7D, 0x00, 0xFF, 0x7E];
        let encoded = HdlcFraming::encode(&data);
        let decoded = HdlcFraming::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hdlc_no_escapes() {
        let data = vec![0x01, 0x02, 0x03];
        let encoded = HdlcFraming::encode(&data);
        // flag + data + flag
        assert_eq!(encoded.len(), 5);
        let decoded = HdlcFraming::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hdlc_invalid_framing() {
        assert!(HdlcFraming::decode(&[0x00, 0x01, 0x7E]).is_err());
        assert!(HdlcFraming::decode(&[0x7E]).is_err());
    }

    #[test]
    fn test_announce_parse() {
        let mut data = vec![0u8; 148];
        // Fill public key region
        data[..64].fill(0xAA);
        // Name hash
        data[64..74].fill(0xBB);
        // Random hash
        data[74..84].fill(0xCC);
        // Signature
        data[84..148].fill(0xDD);

        let announce = AnnounceData::parse(&data).unwrap();
        assert_eq!(announce.public_key[0], 0xAA);
        assert_eq!(announce.name_hash[0], 0xBB);
        assert_eq!(announce.random_hash[0], 0xCC);
        assert!(announce.app_data.is_empty());
    }

    #[test]
    fn test_announce_with_app_data() {
        let mut data = vec![0u8; 148 + 5];
        data[148..].copy_from_slice(b"hello");
        let announce = AnnounceData::parse(&data).unwrap();
        assert_eq!(announce.app_data, b"hello");
    }

    #[test]
    fn test_announce_too_short() {
        assert!(AnnounceData::parse(&[0u8; 100]).is_err());
    }

    #[tokio::test]
    async fn test_reticulum_transport_lifecycle() {
        let transport = ReticulumTransport::new(ReticulumConfig::default());
        assert_eq!(transport.transport_type(), TransportType::InternetTunnel);
        assert_eq!(transport.mtu(), RETICULUM_MDU);

        transport.start().await.unwrap();

        // Simulate receiving an announce
        let dest = [0x12; ADDRESS_LENGTH];
        let announce_packet = ReticulumPacket {
            flags: HeaderFlags {
                header_type: HEADER_1,
                context_flag: false,
                propagation_type: PROPAGATION_BROADCAST,
                destination_type: DEST_SINGLE,
                packet_type: PACKET_ANNOUNCE,
            },
            hops: 2,
            transport_id: None,
            destination: dest,
            context: CONTEXT_NONE,
            data: vec![0u8; 148], // minimal announce data
        };
        transport.on_packet_received(announce_packet);

        let peers = transport.connected_peers();
        assert_eq!(peers.len(), 1);
        assert!(transport.link_quality(&peers[0]).is_some());

        transport.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_reticulum_send() {
        let transport = ReticulumTransport::new(ReticulumConfig::default());
        transport.start().await.unwrap();

        // Discover a peer via data packet
        let dest = [0x34; ADDRESS_LENGTH];
        let data_packet = ReticulumPacket::data_packet(dest, b"hello".to_vec());
        transport.on_packet_received(data_packet);

        let peers = transport.connected_peers();
        assert_eq!(peers.len(), 1);

        // Send to the peer
        let result = transport.send(&peers[0], b"response").await;
        assert!(result.is_ok());
        assert_eq!(transport.outbox_len(), 1);

        // Dequeue and verify
        let (_, serialized) = transport.dequeue_send().unwrap();
        let outgoing = ReticulumPacket::deserialize(&serialized).unwrap();
        assert_eq!(outgoing.destination, dest);
        assert_eq!(outgoing.data, b"response");
    }

    #[tokio::test]
    async fn test_reticulum_mdu_enforcement() {
        let transport = ReticulumTransport::new(ReticulumConfig::default());
        transport.start().await.unwrap();

        let too_large = vec![0u8; RETICULUM_MDU + 1];
        let peer = NodeId([0x99; 32]);
        let result = transport.send(&peer, &too_large).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_plugin_interface() {
        let mut transport = ReticulumTransport::new(ReticulumConfig::default());
        assert_eq!(transport.plugin_name(), "reticulum");
        assert_eq!(transport.plugin_version(), "0.1.0");
        assert!(!transport.requires_platform_bridge());

        let mut config = PluginConfig::default();
        config
            .settings
            .insert("interface_type".to_string(), "udp".to_string());
        config
            .settings
            .insert("host".to_string(), "10.0.0.1:5555".to_string());
        transport.configure(&config).unwrap();
        assert_eq!(transport.config.interface_type, "udp");
        assert_eq!(transport.config.host, "10.0.0.1:5555");
    }

    #[test]
    fn test_raw_data_parsing() {
        let dest = [0x56; ADDRESS_LENGTH];
        let packet = ReticulumPacket::data_packet(dest, vec![10, 20, 30]);
        let serialized = packet.serialize();

        let transport = ReticulumTransport::new(ReticulumConfig::default());
        transport.on_raw_data(&serialized);

        let peers = transport.connected_peers();
        assert_eq!(peers.len(), 1);
    }
}
