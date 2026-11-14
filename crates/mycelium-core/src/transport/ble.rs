//! BLE (Bluetooth Low Energy) transport stub.
//!
//! On Android/iOS, the real implementation will use platform BLE APIs
//! via FFI callbacks. This stub provides the trait implementation structure.

use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

/// Maximum packets queued while the platform is not polling the outbox.
const MAX_OUTBOX: usize = 512;

/// Bytes one BLE frame carries, fragment header included.
///
/// The negotiated GATT MTU. The platform layer splits a frame further into
/// writes with its own 1-byte header (spec §8.4), which sits below this.
const BLE_FRAME_MTU: usize = 512;

/// Largest message reassembled from BLE frames.
///
/// The frame cap is not the message cap. A critical alert carrying three
/// co-signatures is 522 bytes — `217 + message + 96 × approvals` — so without
/// fragmentation it could not cross BLE at all, and neither could an alert
/// with a message over 295 bytes (ROADMAP T-39). Reassembly stops the frame
/// size being a cliff; this bound stops it being a memory hole.
pub const BLE_MAX_MESSAGE: usize = 4096;

use mycelium_protocol::types::{LinkQuality, NodeId};

use super::fragment::{fragment, Reassembler};
use super::{
    PriorityOutbox, SendPriority, Transport, TransportError, TransportEvent, TransportType,
};

/// FFI send callback type for BLE transport.
/// Parameters: peer_id (32 bytes), data pointer, data length.
/// Returns 0 on success, non-zero on failure.
pub type BleSendCallback = extern "C" fn(*const [u8; 32], *const u8, u32) -> i32;

/// BLE transport for short-range mesh communication.
///
/// Characteristics:
/// - Range: ~10-100m depending on environment
/// - MTU: 512 bytes (negotiated, may be smaller on older devices)
/// - Power: Low (designed for battery-constrained devices)
/// - Use: Discovery beacons, small control messages, session init
pub struct BleTransport {
    #[allow(dead_code)]
    local_id: NodeId,
    tx: broadcast::Sender<TransportEvent>,
    connected_peers: Arc<RwLock<Vec<NodeId>>>,
    started: Arc<RwLock<bool>>,
    send_callback: Arc<RwLock<Option<BleSendCallback>>>,
    /// Outbox queue for outgoing data. Dart polls this via FFI since it cannot
    /// provide a synchronous C callback across threads.
    #[allow(clippy::type_complexity)]
    outbox: Arc<Mutex<PriorityOutbox>>,
    /// In-progress reassemblies, shared with every other transport that has a
    /// frame cap (`transport::fragment`).
    reassembly: Arc<Mutex<Reassembler>>,
    /// Random per instance, so two senders' fragment ids cannot collide into
    /// one reassembly.
    sender_tag: u16,
    next_frag_id: Arc<Mutex<u16>>,
}

impl BleTransport {
    pub fn new(local_id: NodeId) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            local_id,
            tx,
            connected_peers: Arc::new(RwLock::new(Vec::new())),
            started: Arc::new(RwLock::new(false)),
            send_callback: Arc::new(RwLock::new(None)),
            outbox: Arc::new(Mutex::new(PriorityOutbox::new(MAX_OUTBOX))),
            reassembly: Arc::new(Mutex::new(Reassembler::new(BLE_MAX_MESSAGE, "BLE"))),
            sender_tag: rand::random(),
            next_frag_id: Arc::new(Mutex::new(0)),
        }
    }

    /// Number of packets waiting in the outbox.
    pub fn outbox_len(&self) -> usize {
        self.outbox.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// Dequeue a pending send from the outbox.
    /// Returns `Some((peer, data))` if there was a packet waiting, `None` otherwise.
    pub fn dequeue_send(&self) -> Option<(NodeId, Vec<u8>)> {
        let result = self.outbox.lock().ok()?.pop();
        if let Some((ref peer, ref data)) = result {
            debug!("BLE outbox dequeue: {} bytes for {}", data.len(), peer);
        }
        result
    }

    /// Register a platform send callback. When the Rust layer calls `send()`,
    /// this callback is invoked to deliver the data via the platform BLE API.
    pub async fn set_send_callback(&self, callback: BleSendCallback) {
        *self.send_callback.write().await = Some(callback);
    }

    /// Called by platform-specific code when a BLE peripheral is discovered.
    pub async fn on_peer_discovered(&self, peer: NodeId) {
        let mut peers = self.connected_peers.write().await;
        if !peers.contains(&peer) {
            info!("BLE peer discovered: {}", peer);
            peers.push(peer);
            let _ = self.tx.send(TransportEvent::NeighborDiscovered {
                peer,
                transport: TransportType::Ble,
            });
        }
    }

    /// Called by platform-specific code when a BLE peripheral disconnects.
    pub async fn on_peer_lost(&self, peer: NodeId) {
        let mut peers = self.connected_peers.write().await;
        peers.retain(|p| *p != peer);
        let _ = self.tx.send(TransportEvent::NeighborLost {
            peer,
            transport: TransportType::Ble,
        });
    }

    /// Called by platform-specific code when data arrives from a BLE peer.
    ///
    /// One frame in; a whole message out, once its fragments have all
    /// arrived. Incomplete and oversized reassemblies are bounded by the
    /// shared reassembler.
    pub async fn on_data_received(&self, peer: NodeId, data: Vec<u8>) {
        debug!("BLE frame received: {} bytes from {}", data.len(), peer);
        let message = match self.reassembly.lock() {
            // Keyed by peer as well as sender tag: BLE knows who wrote the
            // frame, so two peers cannot mix fragments by sharing a tag.
            Ok(mut r) => r.push(peer, &data),
            Err(_) => None,
        };
        if let Some(message) = message {
            let _ = self.tx.send(TransportEvent::DataReceived {
                peer,
                data: message,
                transport: TransportType::Ble,
            });
        }
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
        info!("BLE transport started");
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

        let peers = self.connected_peers.read().await;
        if !peers.contains(peer) {
            return Err(TransportError::PeerNotConnected(*peer));
        }

        if data.len() > self.mtu() {
            return Err(TransportError::ExceedsMtu {
                size: data.len(),
                mtu: self.mtu(),
            });
        }

        // One frame per GATT MTU, each carrying the fragment header, so a
        // message larger than a frame crosses BLE instead of being refused
        // (ROADMAP T-39).
        let frag_id = {
            let mut next = self
                .next_frag_id
                .lock()
                .map_err(|_| TransportError::Other("fragment id lock".into()))?;
            let id = *next;
            *next = next.wrapping_add(1);
            id
        };
        let frames = fragment(data, BLE_FRAME_MTU, self.sender_tag, frag_id)?;

        debug!(
            "BLE send: {} bytes to {} as {} frame(s)",
            data.len(),
            peer,
            frames.len()
        );

        // Use platform send callback if registered, otherwise queue for Dart polling
        let cb = self.send_callback.read().await;
        if let Some(callback) = *cb {
            let peer_bytes = peer.as_bytes();
            for frame in &frames {
                let result = callback(
                    peer_bytes as *const [u8; 32],
                    frame.as_ptr(),
                    frame.len() as u32,
                );
                if result != 0 {
                    return Err(TransportError::SendFailed(format!(
                        "BLE send callback returned {}",
                        result
                    )));
                }
            }
        } else {
            // Push to outbox for Dart to poll via mycelium_ble_dequeue_send.
            // All the fragments or none: a message missing one cannot be
            // reassembled, and reporting success for a half-queued batch stops
            // the manager trying another transport.
            if let Ok(mut outbox) = self.outbox.lock() {
                if outbox.push_batch(*peer, frames, priority).is_err() {
                    warn!("BLE outbox has no room for the fragments without displacing alerts");
                    return Err(TransportError::SendFailed(
                        "outbox is full of emergency traffic".to_string(),
                    ));
                }
                debug!("BLE outbox: queued, depth now {}", outbox.len());
            }
        }
        Ok(())
    }

    fn events(&self) -> broadcast::Receiver<TransportEvent> {
        self.tx.subscribe()
    }

    fn link_quality(&self, peer: &NodeId) -> Option<LinkQuality> {
        // Would read RSSI from platform BLE layer
        let peers = self.connected_peers.try_read().ok()?;
        if peers.contains(peer) {
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
        self.connected_peers
            .try_read()
            .map(|p| p.clone())
            .unwrap_or_default()
    }

    fn mtu(&self) -> usize {
        // What a *message* may be, not what one frame carries: the transport
        // fragments (ROADMAP T-39).
        BLE_MAX_MESSAGE
    }
}

#[cfg(test)]
mod tests {
    use super::super::fragment::FRAG_HEADER;
    use super::*;

    /// The outbox now holds frames, so a test comparing payloads has to skip
    /// the fragment header.
    fn payload(frame: &[u8]) -> &[u8] {
        &frame[FRAG_HEADER..]
    }

    async fn connected() -> (BleTransport, NodeId) {
        let transport = BleTransport::new(NodeId([1u8; 32]));
        transport.start().await.expect("start");
        let peer = NodeId([2u8; 32]);
        transport.on_peer_discovered(peer).await;
        (transport, peer)
    }

    /// The outbox is where spec §9.5's "boosted priority in relay queues"
    /// happens: an alert leaves before ordinary traffic already waiting
    /// (ADR-014).
    #[tokio::test]
    async fn test_an_alert_leaves_the_outbox_before_ordinary_traffic() {
        let (transport, peer) = connected().await;

        transport
            .send(&peer, b"ordinary one")
            .await
            .expect("queued");
        transport
            .send(&peer, b"ordinary two")
            .await
            .expect("queued");
        transport
            .send_with_priority(&peer, b"alert", SendPriority::Alert)
            .await
            .expect("queued");

        let (_, first) = transport.dequeue_send().expect("something queued");
        assert_eq!(payload(&first), b"alert", "the alert goes first");
        let (_, second) = transport.dequeue_send().expect("something queued");
        assert_eq!(
            payload(&second),
            b"ordinary one",
            "then the traffic in its own order"
        );
    }

    /// A full outbox drops ordinary traffic to make room for an alert, rather
    /// than refusing the alert.
    #[tokio::test]
    async fn test_a_full_outbox_makes_room_for_an_alert() {
        let (transport, peer) = connected().await;

        for _ in 0..MAX_OUTBOX {
            transport.send(&peer, b"ordinary").await.expect("queued");
        }
        assert_eq!(transport.outbox_len(), MAX_OUTBOX);

        transport
            .send_with_priority(&peer, b"alert", SendPriority::Alert)
            .await
            .expect("an alert is never refused for a full queue");
        assert_eq!(transport.outbox_len(), MAX_OUTBOX, "still bounded");
        let (_, first) = transport.dequeue_send().expect("something queued");
        assert_eq!(payload(&first), b"alert");
    }

    /// A co-signed critical alert is 522 bytes and BLE frames carry 512, so
    /// before fragmentation it could not cross BLE at all. The message now
    /// goes as several frames and arrives whole (ROADMAP T-39).
    #[tokio::test]
    async fn test_a_message_larger_than_a_frame_crosses_ble() {
        let (sender, peer) = connected().await;
        let big: Vec<u8> = (0..700u32).map(|n| n as u8).collect();

        sender.send(&peer, &big).await.expect("queued");
        assert!(
            sender.outbox_len() > 1,
            "700 bytes does not fit one 512-byte frame"
        );

        // The receiving side hands each frame to the transport and sees one
        // message come out.
        let (receiver, _) = connected().await;
        let mut events = receiver.events();
        while let Some((_, frame)) = sender.dequeue_send() {
            receiver.on_data_received(peer, frame).await;
        }

        match events.try_recv() {
            Ok(TransportEvent::DataReceived { data, .. }) => {
                assert_eq!(data, big, "reassembled whole")
            }
            other => panic!("expected one reassembled message, got {other:?}"),
        }
        assert!(
            events.try_recv().is_err(),
            "and exactly one: fragments are not reported individually"
        );
    }

    /// A message over the reassembly bound is refused at the sender, so it is
    /// never fragmented into frames nobody will put back together.
    #[tokio::test]
    async fn test_a_message_over_the_reassembly_bound_is_refused() {
        let (transport, peer) = connected().await;
        let huge = vec![0u8; BLE_MAX_MESSAGE + 1];
        let err = transport
            .send(&peer, &huge)
            .await
            .expect_err("over the message bound");
        assert!(matches!(err, TransportError::ExceedsMtu { .. }), "{err:?}");
        assert_eq!(transport.outbox_len(), 0, "and nothing was queued");
    }
}
