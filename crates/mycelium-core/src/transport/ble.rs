//! BLE transport: dual-role GATT, driven by a platform bridge.
//!
//! The Rust side owns the authenticated link layer ([`super::link`]) and the
//! frame queue; Android and iOS own the radio. The bridge announces links by
//! whatever address it already has for them and relays opaque frames, so no
//! code path here installs a peer from an id anyone claimed (ADR-021,
//! ROADMAP T-34). A peer appears once it has proved possession of the
//! identity key its NodeId is derived from.

use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info};

use mycelium_crypto::identity::Identity;
use mycelium_protocol::types::{LinkQuality, NodeId};

use super::link::{AuthenticatedLinks, LinkAddr, LinkConfig, LinkDirective};
use super::{SendPriority, Transport, TransportError, TransportEvent, TransportType};

/// Messages queued while the platform is not collecting them.
///
/// Messages, not frames: the outbox holds what has not been sealed yet, so
/// that a frame's counter is taken in the order frames leave (ADR-021). A
/// queue this long holds at most half a megabyte even if every message is at
/// the MTU, which real traffic — envelopes of a few hundred bytes — never
/// approaches.
const MAX_OUTBOX: usize = 128;

/// Links held at once, in any stage. Well above the ~7 concurrent
/// connections a phone's BLE stack manages, so the radio is the binding
/// limit and this only bounds what a misbehaving bridge can make us store.
const MAX_LINKS: usize = 32;

/// Bytes one BLE frame carries, fragment header included.
///
/// The negotiated GATT MTU. The platform layer splits a frame further into
/// writes with its own 1-byte header (spec §8.4), which sits below this.
const BLE_FRAME_MTU: usize = 512;

/// Largest sealed frame reassembled from BLE frames.
///
/// The frame cap is not the message cap. A critical alert carrying three
/// co-signatures is 522 bytes — `217 + message + 96 × approvals` — so without
/// fragmentation it could not cross BLE at all, and neither could an alert
/// with a message over 295 bytes (ROADMAP T-39). Reassembly stops the frame
/// size being a cliff; this bound stops it being a memory hole. What a
/// *message* may be is [`BleTransport::mtu`], which is this less the sealed
/// frame's own overhead.
pub const BLE_MAX_MESSAGE: usize = 4096;

fn link_config() -> LinkConfig {
    LinkConfig {
        transport: TransportType::Ble,
        label: "BLE",
        frame_mtu: BLE_FRAME_MTU,
        max_frame: BLE_MAX_MESSAGE,
        max_links: MAX_LINKS,
        outbox_capacity: MAX_OUTBOX,
    }
}

/// BLE transport for short-range mesh communication.
///
/// Characteristics:
/// - Range: ~10-100m depending on environment
/// - Frame: 512 bytes (negotiated GATT MTU, may be smaller on older devices)
/// - Power: Low (designed for battery-constrained devices)
pub struct BleTransport {
    tx: broadcast::Sender<TransportEvent>,
    links: AuthenticatedLinks,
    started: Arc<RwLock<bool>>,
}

impl BleTransport {
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

    /// Number of frames waiting in the outbox.
    pub fn outbox_len(&self) -> usize {
        self.links.outbox_len()
    }

    /// Links held, in any stage. Mostly for tests and diagnostics.
    pub fn link_count(&self) -> usize {
        self.links.link_count()
    }

    /// Whether a peer has proved its identity on some live link.
    pub fn is_connected(&self, peer: &NodeId) -> bool {
        self.links.is_connected(peer)
    }

    /// Dequeue a pending send, with the link to write it on.
    ///
    /// Addressed to a *link*, not a peer: the first frames on a link leave
    /// before either end knows who the other is.
    /// The third element says whether the fragment belongs to a handshake
    /// frame: the platform layer must not delay or evict one, and cannot
    /// tell for itself, because a link counts as established here as soon as
    /// the peer's confirmation arrives — which can be before our own has
    /// left.
    pub fn dequeue_send(&self) -> Option<(LinkAddr, Vec<u8>, bool)> {
        let result = self.links.dequeue_send();
        if let Some((ref addr, ref data, _)) = result {
            debug!("BLE outbox dequeue: {} bytes for {}", data.len(), addr);
        }
        result
    }

    /// Take the next thing the platform layer must do with a link.
    pub fn next_directive(&self) -> Option<(LinkAddr, LinkDirective)> {
        self.links.next_directive()
    }

    /// The platform layer connected a link, in either GATT role.
    pub fn on_link_up(&self, addr: &str) {
        info!("BLE link up: {}", addr);
        self.links.link_up(addr);
    }

    /// The platform layer lost a link.
    pub fn on_link_down(&self, addr: &str) {
        debug!("BLE link down: {}", addr);
        self.links.link_down(addr);
    }

    /// One frame arrived on a link.
    pub fn on_link_data(&self, addr: &str, data: &[u8]) {
        debug!("BLE frame received: {} bytes on {}", data.len(), addr);
        self.links.link_data(addr, data);
    }
}

#[async_trait::async_trait]
impl Transport for BleTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Ble
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
        info!("BLE transport started");
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
        // Would read RSSI from platform BLE layer
        if self.links.is_connected(peer) {
            Some(LinkQuality {
                rssi: Some(-60),
                packet_loss: 0.0,
                latency_ms: 50,
                throughput_bps: 125_000, // ~1 Mbps BLE 5
            })
        } else {
            None
        }
    }

    fn connected_peers(&self) -> Vec<NodeId> {
        self.links.connected_peers()
    }

    fn mtu(&self) -> usize {
        // What a *message* may be: the transport fragments (ROADMAP T-39),
        // and the sealed frame's counter, header and tag come out of the
        // reassembly budget (ADR-021).
        self.links.mtu()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::link::SEALED_FRAME_OVERHEAD;

    /// Two nodes and the addresses each uses for the link to the other. The
    /// addresses deliberately differ per direction, as BLE's do.
    const A_TO_B: &str = "AA:BB:CC:DD:EE:01";
    const B_TO_A: &str = "AA:BB:CC:DD:EE:02";

    fn transport() -> (Arc<Identity>, BleTransport) {
        let identity = Arc::new(Identity::generate());
        (identity.clone(), BleTransport::new(identity))
    }

    async fn started() -> (Arc<Identity>, BleTransport) {
        let (identity, transport) = transport();
        transport.start().await.expect("start");
        (identity, transport)
    }

    /// Move every queued frame between two transports until neither has
    /// anything left, which is what the app's 50 ms poll does on a phone.
    fn pump(a: &BleTransport, b: &BleTransport) -> usize {
        let mut moved = 0;
        loop {
            let mut progress = false;
            while let Some((addr, frame, _)) = a.dequeue_send() {
                assert_eq!(&*addr, A_TO_B, "a only has one link");
                b.on_link_data(B_TO_A, &frame);
                progress = true;
                moved += 1;
            }
            while let Some((addr, frame, _)) = b.dequeue_send() {
                assert_eq!(&*addr, B_TO_A, "b only has one link");
                a.on_link_data(A_TO_B, &frame);
                progress = true;
                moved += 1;
            }
            if !progress {
                return moved;
            }
        }
    }

    fn directives(t: &BleTransport) -> Vec<(String, LinkDirective)> {
        let mut out = Vec::new();
        while let Some((addr, directive)) = t.next_directive() {
            out.push((addr.to_string(), directive));
        }
        out
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
    async fn test_transport_type() {
        let (_, transport) = transport();
        assert_eq!(transport.transport_type(), TransportType::Ble);
    }

    #[tokio::test]
    async fn test_the_message_mtu_leaves_room_for_the_seal() {
        let (_, transport) = transport();
        assert_eq!(transport.mtu(), BLE_MAX_MESSAGE - SEALED_FRAME_OVERHEAD);
        assert!(
            transport.mtu() < BLE_MAX_MESSAGE,
            "the counter, header and tag are not free"
        );
    }

    /// The whole point: both ends prove possession of the identity key their
    /// NodeId comes from, and only then is a peer installed.
    #[tokio::test]
    async fn test_two_links_authenticate_and_exchange_data() {
        let (a_id, a) = started().await;
        let (b_id, b) = started().await;
        let mut a_events = a.events();
        let mut b_events = b.events();

        a.on_link_up(A_TO_B);
        b.on_link_up(B_TO_A);
        assert!(a.connected_peers().is_empty(), "nothing proved yet");
        pump(&a, &b);

        assert_eq!(a.connected_peers(), vec![b_id.node_id()]);
        assert_eq!(b.connected_peers(), vec![a_id.node_id()]);
        assert!(
            matches!(
                a_events.try_recv(),
                Ok(TransportEvent::NeighborDiscovered { peer, .. }) if peer == b_id.node_id()
            ),
            "the peer is reported once proved"
        );
        assert_eq!(
            directives(&a),
            vec![(A_TO_B.to_string(), LinkDirective::Established)]
        );

        a.send(&b_id.node_id(), b"over a proved channel")
            .await
            .expect("queued");
        pump(&a, &b);
        assert_eq!(
            next_data(&mut b_events),
            Some((a_id.node_id(), b"over a proved channel".to_vec()))
        );

        b.send(&a_id.node_id(), b"and back").await.expect("queued");
        pump(&a, &b);
        assert_eq!(
            next_data(&mut a_events),
            Some((b_id.node_id(), b"and back".to_vec()))
        );
    }

    /// ROADMAP T-34's acceptance test. Capturing a completed exchange and
    /// replaying it buys an attacker nothing: the confirmation was sealed
    /// under a channel whose ephemeral secret it does not hold, so no peer
    /// and no route appear. Paired with the test above, where the same frames
    /// exchanged live succeed — so this cannot pass for the wrong reason.
    #[tokio::test]
    async fn test_a_replayed_identity_exchange_installs_no_peer_and_no_route() {
        let (a_id, a) = started().await;
        let (_, b) = started().await;

        // Capture everything A says on a link that completes honestly.
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
        assert!(captured.len() >= 2, "a hello and a confirmation at least");

        // A fresh victim, and an attacker that holds nothing but the
        // recording.
        let (_, victim) = started().await;
        let mut victim_events = victim.events();
        victim.on_link_up("AA:BB:CC:DD:EE:99");
        let _ = victim.dequeue_send();
        for frame in &captured {
            victim.on_link_data("AA:BB:CC:DD:EE:99", frame);
        }

        assert!(
            victim.connected_peers().is_empty(),
            "a replayed exchange proves nothing, so no peer is installed"
        );
        assert!(
            !victim.is_connected(&a_id.node_id()),
            "and the identity it replayed is not installed either"
        );
        assert!(
            victim_events.try_recv().is_err(),
            "no NeighborDiscovered, so TransportManager installs no route"
        );
        assert_eq!(
            directives(&victim),
            vec![("AA:BB:CC:DD:EE:99".to_string(), LinkDirective::Close)],
            "the bridge is told to drop the link"
        );
        assert_eq!(victim.link_count(), 0, "and nothing is left holding a slot");
    }

    /// A hello whose signature does not verify ends the link before any key
    /// exists.
    #[tokio::test]
    async fn test_a_tampered_hello_installs_nothing() {
        let (_, a) = started().await;
        let (_, b) = started().await;
        a.on_link_up(A_TO_B);
        b.on_link_up(B_TO_A);

        let (_, mut hello, _) = a.dequeue_send().expect("a's hello");
        let last = hello.len() - 1;
        hello[last] ^= 0x01;
        b.on_link_data(B_TO_A, &hello);

        assert!(b.connected_peers().is_empty());
        assert_eq!(b.link_count(), 0);
        assert_eq!(
            directives(&b),
            vec![(B_TO_A.to_string(), LinkDirective::Close)]
        );
    }

    /// Our own identity on the far end is a loopback the bridge can no longer
    /// recognise, since it does not see an id. The handshake catches it.
    #[tokio::test]
    async fn test_a_link_that_proves_our_own_identity_is_closed() {
        let identity = Arc::new(Identity::generate());
        let a = BleTransport::new(identity.clone());
        let mirror = BleTransport::new(identity.clone());
        a.start().await.expect("start");
        mirror.start().await.expect("start");

        a.on_link_up(A_TO_B);
        mirror.on_link_up(B_TO_A);
        pump(&a, &mirror);

        assert!(
            a.connected_peers().is_empty(),
            "we are not our own neighbour"
        );
        assert_eq!(a.link_count(), 0);
        assert!(directives(&a)
            .iter()
            .any(|(addr, d)| addr == A_TO_B && *d == LinkDirective::Close));
    }

    /// A frame on a link the bridge never announced is dropped, and the
    /// bridge is told to close whatever it has: a closed link must not be
    /// able to reopen itself with frames still in flight.
    #[tokio::test]
    async fn test_a_frame_on_an_unknown_link_opens_nothing() {
        let (_, a) = started().await;
        let (_, b) = started().await;
        a.on_link_up(A_TO_B);
        let (_, hello, _) = a.dequeue_send().expect("a's hello");

        b.on_link_data("AA:BB:CC:DD:EE:77", &hello);
        assert_eq!(b.link_count(), 0, "no link was created");
        assert_eq!(b.outbox_len(), 0, "and nothing was answered");
        assert_eq!(
            directives(&b),
            vec![("AA:BB:CC:DD:EE:77".to_string(), LinkDirective::Close)]
        );
    }

    /// The reason local links carry their frame counter. A lost fragment
    /// means a sealed frame never reassembles; with an implicit counter the
    /// receiver would stay a frame behind for good and nothing later would
    /// ever open again.
    #[tokio::test]
    async fn test_a_lost_fragment_does_not_wedge_the_link() {
        let (a_id, a) = started().await;
        let (b_id, b) = started().await;
        let mut b_events = b.events();
        a.on_link_up(A_TO_B);
        b.on_link_up(B_TO_A);
        pump(&a, &b);

        // A message that needs several fragments, of which one is dropped.
        let big = vec![7u8; BLE_FRAME_MTU * 3];
        a.send(&b_id.node_id(), &big).await.expect("queued");
        let mut frames = Vec::new();
        while let Some((_, frame, _)) = a.dequeue_send() {
            frames.push(frame);
        }
        assert!(frames.len() > 1, "the message did fragment");
        for frame in frames.iter().skip(1) {
            b.on_link_data(B_TO_A, frame);
        }
        assert!(
            next_data(&mut b_events).is_none(),
            "an incomplete message is not delivered"
        );

        // The next message must still arrive.
        a.send(&b_id.node_id(), b"after the loss")
            .await
            .expect("queued");
        pump(&a, &b);
        assert_eq!(
            next_data(&mut b_events),
            Some((a_id.node_id(), b"after the loss".to_vec())),
            "the link survives a lost frame"
        );
    }

    /// A data frame replayed on the same link is refused by its counter, and
    /// the link carries on.
    #[tokio::test]
    async fn test_a_replayed_data_frame_is_refused_without_dropping_the_link() {
        let (a_id, a) = started().await;
        let (b_id, b) = started().await;
        let mut b_events = b.events();
        a.on_link_up(A_TO_B);
        b.on_link_up(B_TO_A);
        pump(&a, &b);

        a.send(&b_id.node_id(), b"once only").await.expect("queued");
        let (_, frame, _) = a.dequeue_send().expect("one frame");
        b.on_link_data(B_TO_A, &frame);
        assert_eq!(
            next_data(&mut b_events),
            Some((a_id.node_id(), b"once only".to_vec()))
        );

        b.on_link_data(B_TO_A, &frame);
        assert!(
            next_data(&mut b_events).is_none(),
            "the same counter is accepted at most once"
        );
        assert!(
            b.is_connected(&a_id.node_id()),
            "and a replay cannot be used to kill the link"
        );
    }

    /// A DHT frame has no meaning on a radio link. Decoding it is possible —
    /// one codec serves every channel — so it is refused explicitly.
    #[tokio::test]
    async fn test_a_dht_frame_on_a_local_link_is_dropped() {
        use crate::dht::rpc::{encode_body, ChannelWireMessage, DhtRequest, DhtRequestBody};

        let (a_id, a) = started().await;
        let (b_id, b) = started().await;
        let mut b_events = b.events();
        a.on_link_up(A_TO_B);
        b.on_link_up(B_TO_A);
        pump(&a, &b);

        // Sealed by a genuine peer on a genuine channel: only the content is
        // wrong, which is what makes this worth refusing explicitly.
        let body = encode_body(&ChannelWireMessage::Dht(DhtRequest {
            request_id: 1,
            body: DhtRequestBody::Ping,
        }));
        a.send(&b_id.node_id(), b"a real message")
            .await
            .expect("queued");
        pump(&a, &b);
        let _ = next_data(&mut b_events);

        // Reach past `send` to put a DHT frame on the wire, which the public
        // API cannot do.
        a.links
            .send_raw_for_test(&b_id.node_id(), &body)
            .expect("sealed");
        pump(&a, &b);
        assert!(
            next_data(&mut b_events).is_none(),
            "a dht frame is not delivered as mesh data"
        );
        assert!(
            b.is_connected(&a_id.node_id()),
            "and the link is not torn down for it"
        );
    }

    /// An unfinished handshake is reaped, freeing its slot and telling the
    /// bridge to close it.
    #[tokio::test]
    async fn test_an_unfinished_handshake_is_reaped() {
        let (_, a) = started().await;
        a.on_link_up(A_TO_B);
        assert_eq!(a.link_count(), 1);

        a.links.expire_handshakes_for_test();
        assert_eq!(a.link_count(), 0, "the link is gone");
        assert_eq!(
            directives(&a),
            vec![(A_TO_B.to_string(), LinkDirective::Close)]
        );
    }

    /// Links are bounded, and a stranger filling the table cannot displace a
    /// peer that has already proved itself.
    #[tokio::test]
    async fn test_links_are_bounded_and_refuse_the_newcomer() {
        let (_, a) = started().await;
        for n in 0..MAX_LINKS {
            a.on_link_up(&format!("link-{n}"));
        }
        assert_eq!(a.link_count(), MAX_LINKS);

        a.on_link_up("one-too-many");
        assert_eq!(a.link_count(), MAX_LINKS, "the table is bounded");
        assert!(
            directives(&a)
                .iter()
                .any(|(addr, d)| addr == "one-too-many" && *d == LinkDirective::Close),
            "and the newcomer is the one refused"
        );
    }

    /// BLE runs both roles at once, so two devices hold two links to each
    /// other. Losing one must not report the peer lost.
    #[tokio::test]
    async fn test_a_peer_is_reported_lost_only_when_its_last_link_goes() {
        let (a_id, a) = started().await;
        let (b_id, b) = started().await;
        let mut b_events = b.events();

        // Two links, handshaken independently, as the two GATT roles do.
        for (a_addr, b_addr) in [("a-1", "b-1"), ("a-2", "b-2")] {
            a.on_link_up(a_addr);
            b.on_link_up(b_addr);
            loop {
                let mut progress = false;
                while let Some((addr, frame, _)) = a.dequeue_send() {
                    if &*addr == a_addr {
                        b.on_link_data(b_addr, &frame);
                        progress = true;
                    }
                }
                while let Some((addr, frame, _)) = b.dequeue_send() {
                    if &*addr == b_addr {
                        a.on_link_data(a_addr, &frame);
                        progress = true;
                    }
                }
                if !progress {
                    break;
                }
            }
        }
        assert!(b.is_connected(&a_id.node_id()));
        while b_events.try_recv().is_ok() {}

        b.on_link_down("b-1");
        assert!(
            b.is_connected(&a_id.node_id()),
            "the other role still holds the peer"
        );
        assert!(b_events.try_recv().is_err(), "and nothing was reported");

        b.on_link_down("b-2");
        assert!(!b.is_connected(&a_id.node_id()));
        assert!(
            matches!(
                b_events.try_recv(),
                Ok(TransportEvent::NeighborLost { peer, .. }) if peer == a_id.node_id()
            ),
            "the last link going is what loses the peer"
        );
        // Sending to it now fails rather than queueing for a dead link.
        assert!(matches!(
            b.send(&a_id.node_id(), b"gone").await,
            Err(TransportError::PeerNotConnected(_))
        ));
        let _ = b_id;
    }

    /// A bridge that is still delivering links after `stop()` must not be
    /// able to install a peer on a transport that has gone.
    #[tokio::test]
    async fn test_a_link_that_arrives_while_stopped_is_closed() {
        let (_, a) = transport();
        a.on_link_up(A_TO_B);
        assert_eq!(a.link_count(), 0, "no link is taken before start");
        assert_eq!(
            directives(&a),
            vec![(A_TO_B.to_string(), LinkDirective::Close)]
        );

        a.start().await.expect("start");
        a.on_link_up(A_TO_B);
        assert_eq!(a.link_count(), 1, "and one is taken after it");

        a.stop().await.expect("stop");
        let _ = directives(&a);
        a.on_link_up(A_TO_B);
        assert_eq!(a.link_count(), 0, "nor after stop");
    }

    /// A directive nobody collected is about the connection that was there
    /// before. Polled after the address came back, a stale `Close` would
    /// close the replacement.
    #[tokio::test]
    async fn test_a_stale_close_is_not_delivered_for_a_link_that_came_back() {
        let (_, a) = started().await;

        // A frame on an unknown link queues a close for that address.
        a.on_link_data(A_TO_B, b"not a link we know");
        // The bridge has not polled yet, and the address comes up.
        a.on_link_up(A_TO_B);

        assert!(
            directives(&a).is_empty(),
            "the close belonged to a connection that no longer exists"
        );
        assert_eq!(a.link_count(), 1, "and the new link stands");
    }

    /// Repeated frames on unknown links must not push a real close out of the
    /// queue: one directive per link, and a close outlives an establishment.
    #[tokio::test]
    async fn test_the_directive_queue_coalesces_and_keeps_closes() {
        let (_, a) = started().await;

        for _ in 0..200 {
            a.on_link_data("AA:BB:CC:DD:EE:55", b"noise");
        }
        let queued = directives(&a);
        assert_eq!(
            queued,
            vec![("AA:BB:CC:DD:EE:55".to_string(), LinkDirective::Close)],
            "one directive per link, however many frames arrive"
        );

        // A close is kept while there is room for it, and an establishment
        // is what gets dropped to make that room.
        a.on_link_data("AA:BB:CC:DD:EE:01", b"noise");
        for n in 0..(MAX_LINKS * 4 - 2) {
            a.on_link_data(&format!("fake-{n}"), b"noise");
        }
        let queued = directives(&a);
        assert_eq!(
            queued.first().map(|(addr, _)| addr.as_str()),
            Some("AA:BB:CC:DD:EE:01"),
            "the first close is still the first thing the bridge is told"
        );
        assert!(
            queued.iter().all(|(_, d)| *d == LinkDirective::Close),
            "and every directive in it is a close"
        );
        assert!(queued.len() <= MAX_LINKS * 4, "the queue is bounded");
    }

    /// A handshake frame may not be evicted to make room for traffic. It
    /// shares no queue with it: an emergency displaces the oldest frame of
    /// its own class, which would otherwise discard another link's
    /// confirmation and leave that peer waiting for one that never comes.
    #[tokio::test]
    async fn test_a_flood_of_alerts_cannot_displace_another_link_s_handshake() {
        let (_, a) = started().await;
        let (b_id, b) = started().await;

        // One established link, and a second one just announced.
        a.on_link_up(A_TO_B);
        b.on_link_up(B_TO_A);
        pump(&a, &b);
        assert!(a.is_connected(&b_id.node_id()));
        a.on_link_up("AA:BB:CC:DD:EE:33");

        // Fill the outbox with emergencies for the established peer.
        for _ in 0..(MAX_OUTBOX * 2) {
            let _ = a
                .send_with_priority(&b_id.node_id(), b"alert", SendPriority::Alert)
                .await;
        }

        let (addr, _, _) = a.dequeue_send().expect("something queued");
        assert_eq!(
            &*addr, "AA:BB:CC:DD:EE:33",
            "the waiting handshake leaves first and was never dropped"
        );
    }

    /// A directive nobody collected is about a link that no longer exists.
    /// An `established` delivered after the link went would mark it live in
    /// the bridge's bookkeeping, and a replacement of the same name would
    /// then slip past the bridge's own stale-link sweep.
    #[tokio::test]
    async fn test_a_link_that_goes_down_takes_its_directives_with_it() {
        let (_, a) = started().await;
        let (b_id, b) = started().await;
        a.on_link_up(A_TO_B);
        b.on_link_up(B_TO_A);
        pump(&a, &b);
        assert!(a.is_connected(&b_id.node_id()), "established");

        // The bridge has not polled yet, and the link drops.
        a.on_link_down(A_TO_B);
        assert!(
            directives(&a).is_empty(),
            "nothing is left to tell the bridge about a link that is gone"
        );
    }

    /// The outbox holds messages now, so its bound is a memory bound: at the
    /// MTU, this many messages is half a megabyte.
    #[tokio::test]
    async fn test_the_outbox_is_bounded_in_messages() {
        let (_, a) = started().await;
        let (b_id, b) = started().await;
        a.on_link_up(A_TO_B);
        b.on_link_up(B_TO_A);
        pump(&a, &b);
        let peer = b_id.node_id();

        a.send(&peer, b"the oldest").await.expect("queued");
        for _ in 1..MAX_OUTBOX {
            a.send(&peer, b"ordinary").await.expect("queued");
        }
        assert_eq!(a.outbox_len(), MAX_OUTBOX);

        // Past the bound the oldest ordinary message goes, as it does on
        // every transport's outbox (ADR-014): the queue is bounded and an
        // alert is never the one sacrificed. Nothing has been sealed yet, so
        // no counter is spent and the peer sees no gap.
        a.send(&peer, b"one more").await.expect("queued");
        assert_eq!(a.outbox_len(), MAX_OUTBOX, "the bound holds");
        let mut b_events = b.events();
        pump(&a, &b);
        let first = next_data(&mut b_events).expect("something arrived");
        assert_ne!(
            first.1,
            b"the oldest".to_vec(),
            "and what went is the oldest ordinary message"
        );

        a.send_with_priority(&peer, b"alert", SendPriority::Alert)
            .await
            .expect("an alert is never refused for a full queue");
    }

    /// A peer may hold several links, and the newest established one carries
    /// what we send. When that one goes, the newest *survivor* takes over —
    /// not whichever the table happens to offer first.
    #[tokio::test]
    async fn test_the_newest_surviving_link_takes_over_sending() {
        let (a_id, a) = started().await;
        let (b_id, b) = started().await;
        let peer = b_id.node_id();

        // Three links to one peer, established oldest first.
        for (a_addr, b_addr) in [("a-1", "b-1"), ("a-2", "b-2"), ("a-3", "b-3")] {
            a.on_link_up(a_addr);
            b.on_link_up(b_addr);
            loop {
                let mut progress = false;
                while let Some((addr, frame, _)) = a.dequeue_send() {
                    if &*addr == a_addr {
                        b.on_link_data(b_addr, &frame);
                        progress = true;
                    }
                }
                while let Some((addr, frame, _)) = b.dequeue_send() {
                    if &*addr == b_addr {
                        a.on_link_data(a_addr, &frame);
                        progress = true;
                    }
                }
                if !progress {
                    break;
                }
            }
        }
        assert!(a.is_connected(&peer));

        // Sends go on the newest.
        a.send(&peer, b"on the newest").await.expect("queued");
        let (addr, _, _) = a.dequeue_send().expect("a frame");
        assert_eq!(&*addr, "a-3");

        // Losing the newest falls back to the newest *survivor*, with an
        // older link still alive to be chosen wrongly.
        a.on_link_down("a-3");
        a.send(&peer, b"the survivor").await.expect("queued");
        let (addr, _, _) = a.dequeue_send().expect("a frame");
        assert_eq!(
            &*addr, "a-2",
            "the newer survivor, not whichever came to hand"
        );

        // And losing one that is not the selection leaves it alone.
        a.on_link_down("a-1");
        a.send(&peer, b"still a-2").await.expect("queued");
        let (addr, _, _) = a.dequeue_send().expect("a frame");
        assert_eq!(&*addr, "a-2");
        let _ = a_id;
    }

    /// The platform layer is told which fragments belong to a handshake,
    /// because it cannot tell: a link is established here the moment the
    /// peer's confirmation arrives, which can be before ours has left.
    #[tokio::test]
    async fn test_a_handshake_fragment_is_marked_for_the_bridge() {
        let (_, a) = started().await;
        let (b_id, b) = started().await;

        a.on_link_up(A_TO_B);
        let (_, hello, handshake) = a.dequeue_send().expect("a's hello");
        assert!(handshake, "the hello is marked");

        b.on_link_up(B_TO_A);
        b.on_link_data(B_TO_A, &hello);
        let mut confirm_seen = false;
        while let Some((_, frame, handshake)) = b.dequeue_send() {
            if handshake {
                confirm_seen = true;
            }
            a.on_link_data(A_TO_B, &frame);
        }
        assert!(confirm_seen, "so is the confirmation");
        pump(&a, &b);
        assert!(a.is_connected(&b_id.node_id()));

        a.send(&b_id.node_id(), b"ordinary").await.expect("queued");
        let (_, _, handshake) = a.dequeue_send().expect("a frame");
        assert!(!handshake, "and traffic is not");
    }

    #[tokio::test]
    async fn test_a_send_to_an_unproved_peer_is_refused() {
        let (_, a) = started().await;
        let stranger = NodeId([9u8; 32]);
        assert!(matches!(
            a.send(&stranger, b"hello").await,
            Err(TransportError::PeerNotConnected(_))
        ));
        assert_eq!(a.outbox_len(), 0, "and nothing is queued for it");
    }

    #[tokio::test]
    async fn test_a_send_before_start_is_refused() {
        let (_, a) = transport();
        assert!(matches!(
            a.send(&NodeId([9u8; 32]), b"hello").await,
            Err(TransportError::NotStarted)
        ));
    }

    /// A co-signed critical alert is 522 bytes and BLE frames carry 512, so
    /// before fragmentation it could not cross BLE at all (ROADMAP T-39).
    #[tokio::test]
    async fn test_a_message_larger_than_a_frame_crosses_ble() {
        let (a_id, a) = started().await;
        let (b_id, b) = started().await;
        let mut b_events = b.events();
        a.on_link_up(A_TO_B);
        b.on_link_up(B_TO_A);
        pump(&a, &b);

        let big: Vec<u8> = (0..700u32).map(|n| n as u8).collect();
        a.send(&b_id.node_id(), &big).await.expect("queued");
        // Counted on the way out: a message is one outbox entry and becomes
        // fragments when it leaves, so that its counter follows the wire.
        let mut frames = 0;
        while let Some((_, frame, _)) = a.dequeue_send() {
            frames += 1;
            b.on_link_data(B_TO_A, &frame);
        }
        assert!(frames > 1, "700 bytes does not fit one 512-byte frame");
        assert_eq!(
            next_data(&mut b_events),
            Some((a_id.node_id(), big)),
            "reassembled whole"
        );
    }

    #[tokio::test]
    async fn test_a_message_over_the_mtu_is_refused_before_fragmenting() {
        let (_, a) = started().await;
        let (b_id, b) = started().await;
        a.on_link_up(A_TO_B);
        b.on_link_up(B_TO_A);
        pump(&a, &b);

        let err = a
            .send(&b_id.node_id(), &vec![0u8; a.mtu() + 1])
            .await
            .expect_err("over the message bound");
        assert!(matches!(err, TransportError::ExceedsMtu { .. }), "{err:?}");
        assert_eq!(a.outbox_len(), 0, "and nothing was queued");

        a.send(&b_id.node_id(), &vec![0u8; a.mtu()])
            .await
            .expect("a message at the mtu still fits");
    }

    /// The outbox is where spec §9.5's "boosted priority in relay queues"
    /// happens: an alert leaves before ordinary traffic already waiting
    /// (ADR-014).
    #[tokio::test]
    async fn test_an_alert_leaves_the_outbox_before_ordinary_traffic() {
        let (_, a) = started().await;
        let (b_id, b) = started().await;
        a.on_link_up(A_TO_B);
        b.on_link_up(B_TO_A);
        pump(&a, &b);
        let peer = b_id.node_id();

        a.send(&peer, b"ordinary one").await.expect("queued");
        a.send(&peer, b"ordinary two").await.expect("queued");
        a.send_with_priority(&peer, b"alert", SendPriority::Alert)
            .await
            .expect("queued");

        // Frames are sealed, so compare what comes out the far end.
        let mut b_events = b.events();
        pump(&a, &b);
        let first = next_data(&mut b_events).expect("something arrived");
        assert_eq!(first.1, b"alert".to_vec(), "the alert goes first");
        assert_eq!(
            next_data(&mut b_events).expect("then the rest").1,
            b"ordinary one".to_vec()
        );
    }

    #[tokio::test]
    async fn test_stop_reports_every_proved_peer_lost() {
        let (a_id, a) = started().await;
        let (_, b) = started().await;
        let mut a_events = a.events();
        a.on_link_up(A_TO_B);
        b.on_link_up(B_TO_A);
        pump(&a, &b);
        while a_events.try_recv().is_ok() {}

        a.stop().await.expect("stop");
        assert!(a.connected_peers().is_empty());
        assert_eq!(a.link_count(), 0);
        assert!(
            matches!(a_events.try_recv(), Ok(TransportEvent::NeighborLost { .. })),
            "the routing layer is told, rather than left with a route to a stopped transport"
        );
        let _ = a_id;
    }
}
