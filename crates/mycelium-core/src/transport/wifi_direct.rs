//! Wi-Fi Direct transport (ADR-003), driven by a platform bridge.
//!
//! Android forms the group and runs the TCP sockets; the Rust side owns the
//! authenticated link layer ([`super::link`]) and the frame queue. The
//! bridge's own `Hello` — a bare 32-byte NodeId either end could claim — is
//! gone: it was the same defect BLE had, and leaving it would have left a
//! second, weaker path into the routing table (ADR-021, ROADMAP T-34). A
//! link is named by its socket endpoint and carries the same proof the
//! internet transport and BLE use.

use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

use mycelium_crypto::identity::Identity;
use mycelium_protocol::types::{LinkQuality, NodeId};

use super::link::{AuthenticatedLinks, LinkAddr, LinkConfig, LinkDirective};
use super::{SendPriority, Transport, TransportError, TransportEvent, TransportType};

/// Messages queued per transport while the platform is not collecting them.
const MAX_OUTBOX: usize = 64;

/// Links held at once. A Wi-Fi Direct group is one group owner and a handful
/// of clients; this is room for the churn of forming one.
const MAX_LINKS: usize = 16;

/// Bytes one frame carries, fragment header included.
///
/// TCP would carry more in one go, but the bridge's own framing declares a
/// 4-byte length and refuses anything over 65535, so a fragment is kept well
/// inside that rather than sitting on the boundary.
const WIFI_FRAME_MTU: usize = 16_384;

/// Largest sealed frame reassembled from fragments.
pub const WIFI_MAX_MESSAGE: usize = 65_535;

fn link_config() -> LinkConfig {
    LinkConfig {
        transport: TransportType::WifiDirect,
        label: "Wi-Fi Direct",
        frame_mtu: WIFI_FRAME_MTU,
        max_frame: WIFI_MAX_MESSAGE,
        max_links: MAX_LINKS,
        outbox_capacity: MAX_OUTBOX,
    }
}

/// Wi-Fi Direct transport for high-bandwidth mesh communication.
///
/// Characteristics:
/// - Range: ~50-200m depending on environment
/// - MTU: 64 KB messages (TCP underneath, so one frame per message)
/// - Power: Medium-High (Wi-Fi radio)
pub struct WifiDirectTransport {
    tx: broadcast::Sender<TransportEvent>,
    links: AuthenticatedLinks,
    started: Arc<RwLock<bool>>,
}

impl WifiDirectTransport {
    /// The identity is needed, not just the NodeId: this transport signs its
    /// own handshakes now.
    pub fn new(identity: Arc<Identity>) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            links: AuthenticatedLinks::new(identity, link_config(), tx.clone()),
            tx,
            started: Arc::new(RwLock::new(false)),
        }
    }

    /// Number of frames and messages waiting for the platform layer.
    pub fn outbox_len(&self) -> usize {
        self.links.outbox_len()
    }

    /// Links held, in any stage.
    pub fn link_count(&self) -> usize {
        self.links.link_count()
    }

    /// Whether a peer has proved its identity on some live link.
    pub fn is_connected(&self, peer: &NodeId) -> bool {
        self.links.is_connected(peer)
    }

    /// Dequeue a pending send, with the link to write it on.
    /// The third element says whether the fragment belongs to a handshake
    /// frame: the platform layer must not delay or evict one, and cannot
    /// tell for itself, because a link counts as established here as soon as
    /// the peer's confirmation arrives — which can be before our own has
    /// left.
    pub fn dequeue_send(&self) -> Option<(LinkAddr, Vec<u8>, bool)> {
        let result = self.links.dequeue_send();
        if let Some((ref addr, ref data, _)) = result {
            debug!(
                "Wi-Fi Direct outbox dequeue: {} bytes for {}",
                data.len(),
                addr
            );
        }
        result
    }

    /// Take the next thing the platform layer must do with a link.
    pub fn next_directive(&self) -> Option<(LinkAddr, LinkDirective)> {
        self.links.next_directive()
    }

    /// The platform layer accepted or opened a socket.
    pub fn on_link_up(&self, addr: &str) {
        info!("Wi-Fi Direct link up: {}", addr);
        self.links.link_up(addr);
    }

    /// The platform layer lost a socket.
    pub fn on_link_down(&self, addr: &str) {
        debug!("Wi-Fi Direct link down: {}", addr);
        self.links.link_down(addr);
    }

    /// One frame arrived on a link.
    pub fn on_link_data(&self, addr: &str, data: &[u8]) {
        debug!(
            "Wi-Fi Direct frame received: {} bytes on {}",
            data.len(),
            addr
        );
        self.links.link_data(addr, data);
    }
}

#[async_trait::async_trait]
impl Transport for WifiDirectTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::WifiDirect
    }

    async fn start(&self) -> Result<(), TransportError> {
        let mut started = self.started.write().await;
        if *started {
            return Err(TransportError::AlreadyStarted);
        }
        *started = true;
        // Links are taken only while started, so a bridge that is still
        // delivering frames cannot install a peer on a stopped transport.
        self.links.open();
        warn!("Wi-Fi Direct transport started (the radio is the platform bridge's)");
        Ok(())
    }

    async fn stop(&self) -> Result<(), TransportError> {
        let mut started = self.started.write().await;
        if !*started {
            return Err(TransportError::NotStarted);
        }
        *started = false;
        self.links.clear();
        Ok(())
    }

    async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError> {
        self.send_with_priority(peer, data, SendPriority::Normal)
            .await
    }

    /// An `Alert` frame is queued ahead of ordinary traffic, and kept in
    /// preference to it when the outbox is full: this outbox is where spec
    /// §9.5's "boosted priority in relay queues" actually happens (ADR-014).
    async fn send_with_priority(
        &self,
        peer: &NodeId,
        data: &[u8],
        priority: SendPriority,
    ) -> Result<(), TransportError> {
        let started = self.started.read().await;
        if !*started {
            return Err(TransportError::NotStarted);
        }
        self.links.send(peer, data, priority)
    }

    fn events(&self) -> broadcast::Receiver<TransportEvent> {
        self.tx.subscribe()
    }

    fn link_quality(&self, peer: &NodeId) -> Option<LinkQuality> {
        if self.links.is_connected(peer) {
            Some(LinkQuality {
                rssi: Some(-40),
                packet_loss: 0.0,
                latency_ms: 10,
                throughput_bps: 6_250_000, // ~50 Mbps Wi-Fi Direct
            })
        } else {
            None
        }
    }

    fn connected_peers(&self) -> Vec<NodeId> {
        self.links.connected_peers()
    }

    fn mtu(&self) -> usize {
        self.links.mtu()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::link::SEALED_FRAME_OVERHEAD;

    /// Each end names the link by the socket it holds, so the two names
    /// differ exactly as the endpoints do.
    const A_TO_B: &str = "192.168.49.1:9740";
    const B_TO_A: &str = "192.168.49.42:51314";

    async fn started() -> (Arc<Identity>, WifiDirectTransport) {
        let identity = Arc::new(Identity::generate());
        let transport = WifiDirectTransport::new(identity.clone());
        transport.start().await.expect("start");
        (identity, transport)
    }

    fn pump(a: &WifiDirectTransport, b: &WifiDirectTransport) {
        loop {
            let mut progress = false;
            while let Some((_, frame, _)) = a.dequeue_send() {
                b.on_link_data(B_TO_A, &frame);
                progress = true;
            }
            while let Some((_, frame, _)) = b.dequeue_send() {
                a.on_link_data(A_TO_B, &frame);
                progress = true;
            }
            if !progress {
                return;
            }
        }
    }

    fn next_data(events: &mut broadcast::Receiver<TransportEvent>) -> Option<(NodeId, Vec<u8>)> {
        while let Ok(event) = events.try_recv() {
            if let TransportEvent::DataReceived { peer, data, .. } = event {
                return Some((peer, data));
            }
        }
        None
    }

    #[tokio::test]
    async fn test_transport_type_and_mtu() {
        let (_, t) = started().await;
        assert_eq!(t.transport_type(), TransportType::WifiDirect);
        assert_eq!(t.mtu(), WIFI_MAX_MESSAGE - SEALED_FRAME_OVERHEAD);
    }

    /// The `Hello` that used to carry a bare NodeId is gone; what replaces it
    /// proves the key the NodeId is derived from.
    #[tokio::test]
    async fn test_two_sockets_authenticate_and_exchange_data() {
        let (a_id, a) = started().await;
        let (b_id, b) = started().await;
        let mut b_events = b.events();

        a.on_link_up(A_TO_B);
        b.on_link_up(B_TO_A);
        assert!(a.connected_peers().is_empty(), "nothing proved yet");
        pump(&a, &b);

        assert_eq!(a.connected_peers(), vec![b_id.node_id()]);
        assert_eq!(b.connected_peers(), vec![a_id.node_id()]);

        a.send(&b_id.node_id(), b"bulk traffic")
            .await
            .expect("queued");
        pump(&a, &b);
        assert_eq!(
            next_data(&mut b_events),
            Some((a_id.node_id(), b"bulk traffic".to_vec()))
        );
    }

    /// ROADMAP T-34's acceptance test, on the other local transport.
    #[tokio::test]
    async fn test_a_replayed_identity_exchange_installs_no_peer_and_no_route() {
        let (a_id, a) = started().await;
        let (_, b) = started().await;

        let mut captured: Vec<Vec<u8>> = Vec::new();
        a.on_link_up(A_TO_B);
        b.on_link_up(B_TO_A);
        loop {
            let mut progress = false;
            while let Some((_, frame, _)) = a.dequeue_send() {
                captured.push(frame.clone());
                b.on_link_data(B_TO_A, &frame);
                progress = true;
            }
            while let Some((_, frame, _)) = b.dequeue_send() {
                a.on_link_data(A_TO_B, &frame);
                progress = true;
            }
            if !progress {
                break;
            }
        }
        assert!(b.is_connected(&a_id.node_id()), "the honest link completed");

        let (_, victim) = started().await;
        let mut victim_events = victim.events();
        victim.on_link_up("192.168.49.77:40000");
        let _ = victim.dequeue_send();
        for frame in &captured {
            victim.on_link_data("192.168.49.77:40000", frame);
        }

        assert!(
            victim.connected_peers().is_empty(),
            "a replayed exchange installs no peer"
        );
        assert!(victim_events.try_recv().is_err(), "and no route follows");
        assert_eq!(victim.link_count(), 0);
    }

    #[tokio::test]
    async fn test_a_send_to_an_unproved_peer_is_refused() {
        let (_, a) = started().await;
        assert!(matches!(
            a.send(&NodeId([3u8; 32]), b"data").await,
            Err(TransportError::PeerNotConnected(_))
        ));
    }

    #[tokio::test]
    async fn test_a_send_before_start_is_refused() {
        let identity = Arc::new(Identity::generate());
        let t = WifiDirectTransport::new(identity);
        assert!(matches!(
            t.send(&NodeId([2u8; 32]), b"data").await,
            Err(TransportError::NotStarted)
        ));
    }
}
