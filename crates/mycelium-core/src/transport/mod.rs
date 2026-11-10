pub mod ble;
pub mod bt_classic;
pub mod internet;
pub mod lora;
pub mod manager;
pub mod mock;
pub mod plugin;
pub mod wifi_direct;

use std::fmt;

use mycelium_protocol::types::{LinkQuality, NodeId};

/// Transport type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TransportType {
    WifiDirect,
    Ble,
    Lora,
    InternetTunnel,
    BtClassic,
    WifiAware,
    /// Meshtastic LoRa mesh, bridged by the `mycelium-meshtastic` adapter.
    /// Distinct from `Lora` so per-transport accounting, the manager's
    /// priority ordering and the diagnostics API can tell a native radio from
    /// a foreign-protocol bridge (ROADMAP T-11).
    Meshtastic,
    /// Reticulum network, bridged by the `mycelium-reticulum` adapter.
    Reticulum,
    Mock,
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WifiDirect => write!(f, "Wi-Fi Direct"),
            Self::Ble => write!(f, "BLE"),
            Self::Lora => write!(f, "LoRa"),
            Self::InternetTunnel => write!(f, "Internet Tunnel"),
            Self::BtClassic => write!(f, "BT Classic"),
            Self::WifiAware => write!(f, "Wi-Fi Aware"),
            Self::Meshtastic => write!(f, "Meshtastic"),
            Self::Reticulum => write!(f, "Reticulum"),
            Self::Mock => write!(f, "Mock"),
        }
    }
}

/// Events emitted by a transport.
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// A new neighbor was discovered on this transport.
    NeighborDiscovered {
        peer: NodeId,
        transport: TransportType,
    },
    /// A previously known neighbor is no longer reachable.
    NeighborLost {
        peer: NodeId,
        transport: TransportType,
    },
    /// Data received from a peer.
    DataReceived {
        peer: NodeId,
        data: Vec<u8>,
        transport: TransportType,
    },
    /// Link quality changed for a peer.
    LinkQualityChanged {
        peer: NodeId,
        quality: LinkQuality,
        transport: TransportType,
    },
}

/// Error type for transport operations.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("peer not connected: {0}")]
    PeerNotConnected(NodeId),
    #[error("transport not started")]
    NotStarted,
    #[error("transport already started")]
    AlreadyStarted,
    #[error("send failed: {0}")]
    SendFailed(String),
    #[error("data exceeds MTU ({size} > {mtu})")]
    ExceedsMtu { size: usize, mtu: usize },
    #[error("transport error: {0}")]
    Other(String),
}

/// Async transport trait abstracting over different radio/link types.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Get the transport type.
    fn transport_type(&self) -> TransportType;

    /// Start the transport (begin discovery and accepting connections).
    async fn start(&self) -> Result<(), TransportError>;

    /// Stop the transport.
    async fn stop(&self) -> Result<(), TransportError>;

    /// Send data to a specific peer.
    async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError>;

    /// Subscribe to transport events.
    fn events(&self) -> tokio::sync::broadcast::Receiver<TransportEvent>;

    /// Get current link quality for a peer.
    fn link_quality(&self, peer: &NodeId) -> Option<LinkQuality>;

    /// Get list of currently connected peers.
    fn connected_peers(&self) -> Vec<NodeId>;

    /// Get the maximum transmission unit for this transport.
    fn mtu(&self) -> usize;

    /// Whether `send(&NodeId::ZERO, ..)` reaches every node in range (a
    /// broadcast medium such as LoRa). Used to announce beacons before any
    /// peer is known. Default: no.
    fn supports_broadcast(&self) -> bool {
        false
    }
}
