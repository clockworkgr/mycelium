pub mod ble;
pub mod bt_classic;
pub mod fragment;
pub mod internet;
pub mod lora;
pub mod manager;
pub mod mock;
pub mod plugin;
pub mod wifi_direct;

use std::collections::VecDeque;
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

/// How urgently a frame should leave.
///
/// Every transport queues outbound frames — a platform outbox polled by the
/// app, or a channel drained by a writer task — and that queue is the only
/// place ordering can happen: the relay path sends as it decides, and an
/// emergency never enters the DTN store. Spec §9.5 gives level-1 alerts
/// "boosted priority in relay queues", and these are the queues it means
/// (ADR-014).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SendPriority {
    /// Ordinary traffic: queued behind whatever is already waiting.
    #[default]
    Normal,
    /// An emergency broadcast: queued ahead of ordinary traffic, and kept in
    /// preference to it when the queue is full.
    Alert,
}

/// A bounded outbox that keeps alerts ahead of ordinary traffic.
///
/// Every platform transport queues frames the app or radio has not collected
/// yet, and that queue is where an emergency's priority is honoured (spec
/// §9.5, ADR-014). Two deques rather than one, because the rules are about
/// which *class* a frame belongs to:
///
/// - an alert is queued after the alerts already waiting and before all
///   ordinary traffic, so alerts keep their own order;
/// - a full outbox makes room for an alert by dropping the **oldest ordinary**
///   frame, and only sacrifices the oldest alert when there is no ordinary
///   traffic left to give;
/// - a full outbox refuses *ordinary* traffic rather than evicting an alert to
///   fit it.
///
/// Getting that last rule wrong is easy and silent: a single deque with
/// alerts pushed to the front and the oldest entry evicted drops the alert
/// first, which is the opposite of the intent.
pub struct PriorityOutbox {
    alerts: VecDeque<(NodeId, Vec<u8>)>,
    normal: VecDeque<(NodeId, Vec<u8>)>,
    capacity: usize,
}

/// The outbox is full of alerts, so ordinary traffic cannot be queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxFull;

impl PriorityOutbox {
    pub fn new(capacity: usize) -> Self {
        Self {
            alerts: VecDeque::new(),
            normal: VecDeque::new(),
            capacity,
        }
    }

    pub fn len(&self) -> usize {
        self.alerts.len() + self.normal.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Queue a frame, evicting as described on the type.
    pub fn push(
        &mut self,
        peer: NodeId,
        data: Vec<u8>,
        priority: SendPriority,
    ) -> Result<(), OutboxFull> {
        self.push_batch(peer, vec![data], priority)
    }

    /// Queue the fragments of one message, **all or none**.
    ///
    /// A message split into frames is useless without every frame, so
    /// admitting some and evicting others — including, once the queue is
    /// nearly full, the batch's own earlier fragments — delivers nothing while
    /// reporting success. Feasibility is decided before anything is evicted or
    /// queued, so a refusal leaves the outbox exactly as it was and the caller
    /// can try another transport.
    pub fn push_batch(
        &mut self,
        peer: NodeId,
        frames: Vec<Vec<u8>>,
        priority: SendPriority,
    ) -> Result<(), OutboxFull> {
        if frames.is_empty() {
            return Ok(());
        }
        if frames.len() > self.capacity {
            // Nothing could carry this, whatever is evicted.
            return Err(OutboxFull);
        }

        let room = self.capacity.saturating_sub(self.len());
        let needed = frames.len().saturating_sub(room);
        if needed > 0 {
            // Ordinary traffic is what gets dropped; an alert batch may also
            // displace the oldest alerts, but only once nothing ordinary is
            // left.
            let available = match priority {
                SendPriority::Alert => self.normal.len() + self.alerts.len(),
                SendPriority::Normal => self.normal.len(),
            };
            if available < needed {
                return Err(OutboxFull);
            }
            let from_normal = needed.min(self.normal.len());
            for _ in 0..from_normal {
                self.normal.pop_front();
            }
            for _ in 0..(needed - from_normal) {
                self.alerts.pop_front();
            }
        }

        for data in frames {
            match priority {
                SendPriority::Alert => self.alerts.push_back((peer, data)),
                SendPriority::Normal => self.normal.push_back((peer, data)),
            }
        }
        Ok(())
    }

    /// Take the next frame: alerts first, each class in its own order.
    pub fn pop(&mut self) -> Option<(NodeId, Vec<u8>)> {
        self.alerts.pop_front().or_else(|| self.normal.pop_front())
    }
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

    /// Send data with a priority.
    ///
    /// Defaults to `send`, so a transport with no queue of its own — and any
    /// plugin written before this existed — keeps working unchanged. A
    /// transport that queues should order `Alert` ahead of `Normal` and, when
    /// its queue is full, drop ordinary traffic rather than an alert.
    async fn send_with_priority(
        &self,
        peer: &NodeId,
        data: &[u8],
        _priority: SendPriority,
    ) -> Result<(), TransportError> {
        self.send(peer, data).await
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(n: u8) -> (NodeId, Vec<u8>) {
        (NodeId([n; 32]), vec![n])
    }

    #[test]
    fn test_an_alert_is_queued_ahead_of_ordinary_traffic() {
        let mut outbox = PriorityOutbox::new(8);
        let (p, d) = frame(1);
        outbox.push(p, d, SendPriority::Normal).unwrap();
        let (p, d) = frame(2);
        outbox.push(p, d, SendPriority::Alert).unwrap();
        let (p, d) = frame(3);
        outbox.push(p, d, SendPriority::Alert).unwrap();

        assert_eq!(
            outbox.pop().unwrap().1,
            vec![2],
            "alerts in their own order"
        );
        assert_eq!(outbox.pop().unwrap().1, vec![3]);
        assert_eq!(outbox.pop().unwrap().1, vec![1], "then ordinary traffic");
        assert!(outbox.pop().is_none());
    }

    /// A full outbox makes room for an alert by dropping the **oldest
    /// ordinary** frame. A single deque with alerts at the front would drop
    /// the newest ordinary frame — or, worse, the alert.
    #[test]
    fn test_a_full_outbox_drops_the_oldest_ordinary_frame_for_an_alert() {
        let mut outbox = PriorityOutbox::new(3);
        for n in 1..=3 {
            let (p, d) = frame(n);
            outbox.push(p, d, SendPriority::Normal).unwrap();
        }
        let (p, d) = frame(9);
        outbox.push(p, d, SendPriority::Alert).unwrap();

        assert_eq!(outbox.len(), 3, "still bounded");
        assert_eq!(outbox.pop().unwrap().1, vec![9], "the alert is first");
        assert_eq!(
            outbox.pop().unwrap().1,
            vec![2],
            "frame 1 was the oldest ordinary and is the one that went"
        );
        assert_eq!(outbox.pop().unwrap().1, vec![3]);
    }

    /// Ordinary traffic must never evict an alert to fit: when the outbox
    /// holds nothing but alerts, the ordinary frame is refused.
    #[test]
    fn test_ordinary_traffic_is_refused_rather_than_evicting_an_alert() {
        let mut outbox = PriorityOutbox::new(2);
        for n in 1..=2 {
            let (p, d) = frame(n);
            outbox.push(p, d, SendPriority::Alert).unwrap();
        }
        let (p, d) = frame(3);
        assert_eq!(
            outbox.push(p, d, SendPriority::Normal),
            Err(OutboxFull),
            "an alert is not displaced by ordinary traffic"
        );
        assert_eq!(outbox.len(), 2);
        assert_eq!(outbox.pop().unwrap().1, vec![1]);
    }

    /// A fragmented message is useless without every fragment, so a batch is
    /// admitted whole or not at all — and a refusal must leave the outbox
    /// untouched, or the caller cannot fall back to another transport.
    #[test]
    fn test_a_batch_is_admitted_whole_or_not_at_all() {
        let mut outbox = PriorityOutbox::new(4);
        for n in 1..=4 {
            let (p, d) = frame(n);
            outbox.push(p, d, SendPriority::Alert).unwrap();
        }

        let refused = outbox.push_batch(
            NodeId([9u8; 32]),
            vec![vec![7], vec![8], vec![9]],
            SendPriority::Normal,
        );
        assert_eq!(refused, Err(OutboxFull));
        assert_eq!(outbox.len(), 4, "a refusal evicts nothing");
        for n in 1..=4 {
            assert_eq!(outbox.pop().unwrap().1, vec![n], "the alerts are intact");
        }
    }

    /// An ordinary batch may displace other ordinary traffic to fit, but never
    /// its own fragments: all three arrive or none do.
    #[test]
    fn test_a_batch_does_not_evict_its_own_fragments() {
        let mut outbox = PriorityOutbox::new(4);
        for n in 1..=4 {
            let (p, d) = frame(n);
            outbox.push(p, d, SendPriority::Normal).unwrap();
        }

        outbox
            .push_batch(
                NodeId([9u8; 32]),
                vec![vec![7], vec![8], vec![9]],
                SendPriority::Normal,
            )
            .expect("three ordinary frames can displace three older ones");
        assert_eq!(outbox.len(), 4);
        assert_eq!(outbox.pop().unwrap().1, vec![4], "the newest survivor");
        assert_eq!(outbox.pop().unwrap().1, vec![7], "then the batch, in order");
        assert_eq!(outbox.pop().unwrap().1, vec![8]);
        assert_eq!(outbox.pop().unwrap().1, vec![9]);
    }

    /// A batch larger than the whole outbox is refused rather than evicting
    /// everything to make room it still cannot fill.
    #[test]
    fn test_a_batch_larger_than_the_outbox_is_refused() {
        let mut outbox = PriorityOutbox::new(2);
        let (p, d) = frame(1);
        outbox.push(p, d, SendPriority::Normal).unwrap();
        assert_eq!(
            outbox.push_batch(
                NodeId([9u8; 32]),
                vec![vec![7], vec![8], vec![9]],
                SendPriority::Alert
            ),
            Err(OutboxFull)
        );
        assert_eq!(outbox.len(), 1, "and nothing was evicted trying");
    }

    /// Only when there is no ordinary traffic left does an alert displace the
    /// oldest alert.
    #[test]
    fn test_an_alert_displaces_the_oldest_alert_as_a_last_resort() {
        let mut outbox = PriorityOutbox::new(2);
        for n in 1..=2 {
            let (p, d) = frame(n);
            outbox.push(p, d, SendPriority::Alert).unwrap();
        }
        let (p, d) = frame(3);
        outbox.push(p, d, SendPriority::Alert).unwrap();

        assert_eq!(outbox.len(), 2);
        assert_eq!(outbox.pop().unwrap().1, vec![2], "the oldest alert went");
        assert_eq!(outbox.pop().unwrap().1, vec![3]);
    }
}
