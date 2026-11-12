//! Flood handling for emergency broadcasts and channel messages:
//! verification order, freshness, reach and dedup (ROADMAP T-36, ADR-013).
//!
//! The scenario throughout is the one the defect allowed: a relay carrying a
//! legitimate message can read its cleartext envelope fields and immediately
//! send a copy of its own, differing only in what the receiver never
//! authenticated.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mycelium_core::transport::mock::{MockLinkConfig, MockNetwork, MockTransport};
use mycelium_core::transport::{Transport, TransportEvent};
use mycelium_crypto::emergency::{self, BroadcastContext};
use mycelium_crypto::identity::Identity;
use mycelium_node::config::NodeConfig;
use mycelium_node::events::NodeEvent;
use mycelium_node::node::Node;
use mycelium_protocol::codec::Envelope;
use mycelium_protocol::types::{MessageFlags, MessageId, NodeId, ProtocolVersion};
use mycelium_protocol::wire::{self, EmergencyCosigner, EmergencyLevel};
use mycelium_storage::contacts::ContactRecord;
use mycelium_storage::db::Database;
use tokio::sync::broadcast::Receiver;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A receiver, a relay that can hand it packets, an originator it trusts, and
/// three co-signers whose identity keys it holds.
struct Harness {
    bob: Node,
    bob_id: NodeId,
    relay: Arc<MockTransport>,
    network: Arc<MockNetwork>,
    originator: NodeId,
    cosigners: Vec<Identity>,
}

async fn harness() -> Harness {
    let bob_identity = Identity::generate();
    let bob_id = bob_identity.node_id();
    let bob = Node::new(
        NodeConfig::default(),
        Database::open_in_memory().expect("in-memory DB"),
        bob_identity,
    );

    let network = MockNetwork::new();
    let bob_t = Arc::new(MockTransport::new(bob_id, network.clone()).await);
    bob.transport_manager.add_transport(bob_t).await;
    bob.start().await.expect("node starts");

    let relay_id = Identity::generate().node_id();
    let relay = Arc::new(MockTransport::new(relay_id, network.clone()).await);
    relay.start().await.expect("relay transport starts");
    network
        .add_link(relay_id, bob_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Three co-signers Bob trusts directly (1-hop trust is 1.0, above the
    // 0.8 threshold) and whose Ed25519 keys he holds.
    let cosigners: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    {
        let mut tg = bob.trust_graph.write().await;
        for c in &cosigners {
            tg.add_vouch(bob_id, c.node_id());
        }
    }
    for c in &cosigners {
        bob.db
            .save_contact(&ContactRecord {
                node_id: c.node_id(),
                display_name: "cosigner".to_string(),
                public_key: c.public_key_bytes().to_vec(),
                trust_score: 1.0,
                is_verified: true,
                last_seen: None,
            })
            .expect("contact saved");
    }

    let originator = Identity::generate().node_id();
    Harness {
        bob,
        bob_id,
        relay,
        network,
        originator,
        cosigners,
    }
}

impl Harness {
    fn envelope(
        &self,
        id: MessageId,
        level: EmergencyLevel,
        signed_at: u64,
        message: &[u8],
        cosigners: &[EmergencyCosigner],
    ) -> Envelope {
        Envelope {
            source: self.originator,
            destination: NodeId::ZERO,
            message_id: id,
            ttl: 20,
            hop_count: 1,
            flags: MessageFlags::NONE,
            lamport_clock: 0,
            device_timestamp: signed_at,
            protocol_version: ProtocolVersion::CURRENT,
            payload: wire::serialize_emergency_broadcast(level, signed_at, message, cosigners),
        }
    }

    /// Co-signatures from all three trusted co-signers.
    fn approvals(
        &self,
        id: &MessageId,
        level: EmergencyLevel,
        signed_at: u64,
        message: &[u8],
    ) -> Vec<EmergencyCosigner> {
        let ctx = BroadcastContext {
            broadcast_id: id,
            originator: &self.originator,
            level,
            signed_at,
            message,
        };
        self.cosigners
            .iter()
            .map(|c| emergency::cosign(c, &ctx))
            .collect()
    }

    async fn deliver(&self, envelope: &Envelope) {
        self.relay
            .send(&self.bob_id, &envelope.serialize())
            .await
            .expect("relay delivers to Bob");
    }

    /// A node downstream of Bob, so the test can see what he passes on.
    async fn downstream(&self) -> (Arc<MockTransport>, NodeId) {
        let id = Identity::generate().node_id();
        let transport = Arc::new(MockTransport::new(id, self.network.clone()).await);
        transport.start().await.expect("downstream starts");
        self.network
            .add_link(self.bob_id, id, MockLinkConfig::default())
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        (transport, id)
    }
}

/// Whether an emergency broadcast reaches `rx` within `within`. Beacons and
/// other traffic are ignored.
async fn forwarded(
    rx: &mut Receiver<TransportEvent>,
    within: Duration,
    kind: wire::WirePayloadType,
) -> Option<Envelope> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(TransportEvent::DataReceived { data, .. })) => {
                if let Ok(envelope) = Envelope::deserialize(&data) {
                    if envelope.payload.first() == Some(&(kind as u8)) {
                        return Some(envelope);
                    }
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) | Err(_) => return None,
        }
    }
}

async fn forwarded_alert(rx: &mut Receiver<TransportEvent>, within: Duration) -> Option<Envelope> {
    forwarded(rx, within, wire::WirePayloadType::EmergencyBroadcast).await
}

/// The body of the next channel message forwarded to `rx`.
async fn forwarded_channel_body(
    rx: &mut Receiver<TransportEvent>,
    within: Duration,
) -> Option<Vec<u8>> {
    let envelope = forwarded(rx, within, wire::WirePayloadType::ChannelMessage).await?;
    let (_, _, data) = wire::deserialize_channel_message(&envelope.payload[1..]).ok()?;
    Some(data)
}

/// The next emergency alert Bob raises, or `None` if he raises none within
/// `within`.
async fn next_alert(rx: &mut Receiver<NodeEvent>, within: Duration) -> Option<String> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(NodeEvent::EmergencyBroadcast { message, .. })) => return Some(message),
            Ok(Ok(_)) => continue,
            Ok(Err(_)) | Err(_) => return None,
        }
    }
}

/// The defect: the dedup insert happened before verification, so a copy that
/// verified against nothing still claimed the alert's id. The real alert then
/// arrived and was dropped as a duplicate.
///
/// The forged copy here is identical to the real one in every field the
/// receiver acts on — id, source, level, date, message — so it cannot be
/// turned away by the dedup key alone. Only checking it before remembering it
/// works.
#[tokio::test]
async fn test_a_forged_copy_does_not_suppress_a_real_emergency_alert() {
    let h = harness().await;
    let id = MessageId::random();
    let signed_at = unix_now();
    let message = b"evacuate sector 7";

    let real = h.approvals(&id, EmergencyLevel::Critical, signed_at, message);
    let forged: Vec<EmergencyCosigner> = h
        .cosigners
        .iter()
        .map(|c| EmergencyCosigner {
            node_id: c.node_id(),
            signature: [7u8; 64],
        })
        .collect();

    let mut events = h.bob.event_tx.subscribe();

    h.deliver(&h.envelope(id, EmergencyLevel::Critical, signed_at, message, &forged))
        .await;
    assert_eq!(
        next_alert(&mut events, Duration::from_millis(300)).await,
        None,
        "the forged copy must not raise an alert of its own"
    );

    h.deliver(&h.envelope(id, EmergencyLevel::Critical, signed_at, message, &real))
        .await;
    assert_eq!(
        next_alert(&mut events, Duration::from_secs(2))
            .await
            .as_deref(),
        Some("evacuate sector 7"),
        "the real alert must still be accepted after the forged copy"
    );

    h.bob.stop().await;
}

/// A captured alert must stop being acceptable. Without a signed date it
/// verified forever, and the only thing between it and a second mesh-wide
/// flood was a dedup set that cleared itself at 10 000 entries.
#[tokio::test]
async fn test_an_emergency_alert_outside_its_validity_window_is_refused() {
    let h = harness().await;
    let now = unix_now();
    let message = b"evacuate sector 7";

    // Two hours old: past EMERGENCY_VALIDITY_SECS.
    let stale_id = MessageId::random();
    let stale_at = now - 7200;
    let stale = h.approvals(&stale_id, EmergencyLevel::Critical, stale_at, message);

    // Dated an hour ahead: past the tolerated clock skew.
    let future_id = MessageId::random();
    let future_at = now + 3600;
    let future = h.approvals(&future_id, EmergencyLevel::Critical, future_at, message);

    let fresh_id = MessageId::random();
    let fresh = h.approvals(&fresh_id, EmergencyLevel::Critical, now, message);

    let mut events = h.bob.event_tx.subscribe();

    h.deliver(&h.envelope(
        stale_id,
        EmergencyLevel::Critical,
        stale_at,
        message,
        &stale,
    ))
    .await;
    assert_eq!(
        next_alert(&mut events, Duration::from_millis(300)).await,
        None,
        "a correctly co-signed but stale alert must be refused"
    );

    h.deliver(&h.envelope(
        future_id,
        EmergencyLevel::Critical,
        future_at,
        message,
        &future,
    ))
    .await;
    assert_eq!(
        next_alert(&mut events, Duration::from_millis(300)).await,
        None,
        "a post-dated alert must be refused, or it would outlive every honest one"
    );

    // Control: the same alert, dated now, is accepted — so the two refusals
    // above are about the date and nothing else.
    h.deliver(&h.envelope(fresh_id, EmergencyLevel::Critical, now, message, &fresh))
        .await;
    assert_eq!(
        next_alert(&mut events, Duration::from_secs(2))
            .await
            .as_deref(),
        Some("evacuate sector 7"),
        "a fresh alert with the same content must be accepted"
    );

    h.bob.stop().await;
}

/// Checking before remembering means an attacker can make a receiver work,
/// so the work is budgeted — but the budget must not be spendable by padding.
/// Entries the receiver holds no identity key for are dismissed by an indexed
/// lookup and must not crowd out the three approvals that count (ADR-013).
#[tokio::test]
async fn test_approvals_past_a_padded_co_signer_list_still_count() {
    let h = harness().await;
    let id = MessageId::random();
    let signed_at = unix_now();
    let message = b"evacuate sector 7";

    // Twenty ids the receiver has never heard of, then the three real ones.
    let mut cosigners: Vec<EmergencyCosigner> = (0..20)
        .map(|_| EmergencyCosigner {
            node_id: Identity::generate().node_id(),
            signature: [3u8; 64],
        })
        .collect();
    cosigners.extend(h.approvals(&id, EmergencyLevel::Critical, signed_at, message));

    let mut events = h.bob.event_tx.subscribe();
    h.deliver(&h.envelope(id, EmergencyLevel::Critical, signed_at, message, &cosigners))
        .await;

    assert_eq!(
        next_alert(&mut events, Duration::from_secs(2))
            .await
            .as_deref(),
        Some("evacuate sector 7"),
        "three valid approvals must count wherever they sit in the list"
    );

    h.bob.stop().await;
}

/// The envelope's TTL is cleartext and cannot be part of the alert's identity,
/// since every hop decrements it. So a relay can deliver a captured alert with
/// its TTL spent: the receiver accepts it, has nothing to forward, and must
/// not then dismiss the genuine copy behind it — or the alert stops there and
/// everything downstream never hears it (ADR-013).
#[tokio::test]
async fn test_a_spent_ttl_copy_does_not_stop_the_flood() {
    let h = harness().await;
    let (downstream, _) = h.downstream().await;
    let mut relayed = downstream.events();

    let id = MessageId::random();
    let signed_at = unix_now();
    let message = b"evacuate sector 7";
    let approvals = h.approvals(&id, EmergencyLevel::Critical, signed_at, message);

    let mut spent = h.envelope(id, EmergencyLevel::Critical, signed_at, message, &approvals);
    spent.ttl = 0;
    let mut alive = spent.clone();
    alive.ttl = 20;

    let mut events = h.bob.event_tx.subscribe();

    h.deliver(&spent).await;
    assert_eq!(
        next_alert(&mut events, Duration::from_secs(2))
            .await
            .as_deref(),
        Some("evacuate sector 7"),
        "a spent copy is still a valid alert for this node"
    );
    assert!(
        forwarded_alert(&mut relayed, Duration::from_millis(300))
            .await
            .is_none(),
        "with no TTL left there is nothing to forward"
    );

    h.deliver(&alive).await;
    let onward = forwarded_alert(&mut relayed, Duration::from_secs(2))
        .await
        .expect("the copy with reach left must be forwarded downstream");
    assert_eq!(onward.message_id, id);
    assert!(onward.ttl > 0, "forwarded with reach to spare");

    // And it is not reported to this node's user twice.
    assert_eq!(
        next_alert(&mut events, Duration::from_millis(300)).await,
        None,
        "the same alert must not be raised a second time"
    );

    h.bob.stop().await;
}

/// An alert addressed to one node is not a flood. Such a copy still verifies
/// — the destination is not part of the digest, and cannot be — and it
/// reaches the handler instead of being routed away, so accepting it would
/// remember the alert and then forward it with a destination every downstream
/// node unicasts back here rather than flooding. The genuine broadcast behind
/// it would be a duplicate by then, and the alert would stop at this node
/// (ADR-013).
#[tokio::test]
async fn test_an_alert_addressed_to_us_is_not_a_flood() {
    let h = harness().await;
    let (downstream, _) = h.downstream().await;
    let mut relayed = downstream.events();

    let id = MessageId::random();
    let signed_at = unix_now();
    let message = b"evacuate sector 7";
    let approvals = h.approvals(&id, EmergencyLevel::Critical, signed_at, message);

    let mut addressed = h.envelope(id, EmergencyLevel::Critical, signed_at, message, &approvals);
    addressed.destination = h.bob_id;
    let broadcast = h.envelope(id, EmergencyLevel::Critical, signed_at, message, &approvals);

    let mut events = h.bob.event_tx.subscribe();

    h.deliver(&addressed).await;
    assert_eq!(
        next_alert(&mut events, Duration::from_millis(300)).await,
        None,
        "a flood addressed to one node is not a flood"
    );
    assert!(
        forwarded_alert(&mut relayed, Duration::from_millis(300))
            .await
            .is_none(),
        "and nothing of it is passed on"
    );

    h.deliver(&broadcast).await;
    assert_eq!(
        next_alert(&mut events, Duration::from_secs(2))
            .await
            .as_deref(),
        Some("evacuate sector 7"),
        "the genuine broadcast must still be accepted"
    );
    let onward = forwarded_alert(&mut relayed, Duration::from_secs(2))
        .await
        .expect("and forwarded downstream");
    assert_eq!(onward.destination, NodeId::ZERO);

    h.bob.stop().await;
}

/// Flood termination still has to work: a verbatim re-delivery of an accepted
/// alert raises nothing a second time.
#[tokio::test]
async fn test_an_accepted_alert_is_not_raised_twice() {
    let h = harness().await;
    let id = MessageId::random();
    let signed_at = unix_now();
    let message = b"evacuate sector 7";
    let approvals = h.approvals(&id, EmergencyLevel::Critical, signed_at, message);
    let envelope = h.envelope(id, EmergencyLevel::Critical, signed_at, message, &approvals);

    let mut events = h.bob.event_tx.subscribe();

    h.deliver(&envelope).await;
    assert_eq!(
        next_alert(&mut events, Duration::from_secs(2))
            .await
            .as_deref(),
        Some("evacuate sector 7")
    );

    h.deliver(&envelope).await;
    assert_eq!(
        next_alert(&mut events, Duration::from_millis(300)).await,
        None,
        "the second copy of an accepted alert must be deduplicated"
    );

    h.bob.stop().await;
}

// --- Channel floods -----------------------------------------------------
//
// A channel message is dedup'd the same way, so the same suppression applies
// to it. These two cover the paths an emergency test cannot reach, since the
// channel handler has nothing to verify.

fn channel_envelope(
    source: NodeId,
    destination: NodeId,
    id: MessageId,
    ttl: u8,
    channel: &[u8; 32],
    data: &[u8],
) -> Envelope {
    Envelope {
        source,
        destination,
        message_id: id,
        ttl,
        hop_count: 1,
        flags: MessageFlags::NONE,
        lamport_clock: 0,
        device_timestamp: unix_now(),
        protocol_version: ProtocolVersion::CURRENT,
        payload: wire::serialize_channel_message(channel, 0, data),
    }
}

/// Addressing a flood to one node is how an attacker gets it accepted and
/// then forwarded with a destination every downstream node will unicast back,
/// instead of flooding. The genuine broadcast is a duplicate by then, so the
/// message stops there — refusing the addressed copy is what keeps the flood
/// alive (ADR-013).
#[tokio::test]
async fn test_a_channel_message_addressed_to_us_is_not_a_flood() {
    let h = harness().await;
    let channel = [7u8; 32];
    h.bob
        .db
        .create_channel(&channel, "test", &h.originator)
        .expect("channel row");
    h.bob.db.subscribe_channel(&channel).expect("subscribed");

    let id = MessageId::random();
    let forged = channel_envelope(h.originator, h.bob_id, id, 20, &channel, b"forged");
    let genuine = channel_envelope(h.originator, NodeId::ZERO, id, 20, &channel, b"genuine");

    h.deliver(&forged).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        h.bob
            .db
            .get_channel_messages(&channel, 10, 0)
            .unwrap()
            .is_empty(),
        "a channel message addressed to one node is not a channel flood"
    );

    h.deliver(&genuine).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let stored = h.bob.db.get_channel_messages(&channel, 10, 0).unwrap();
    assert_eq!(stored.len(), 1, "the genuine flood must still be stored");
    assert_eq!(stored[0].data, b"genuine");

    h.bob.stop().await;
}

/// The channel flood is keyed on the message, not the envelope id, so a copy
/// that shares an id but nothing else cannot take its place in the flood.
///
/// What it can still take is the local row: `store_channel_message` is an
/// `INSERT OR IGNORE` keyed on the envelope id, so whichever copy arrives
/// first keeps it. Closing that needs the row's identity to change, or
/// channel messages to be authenticated — recorded in ROADMAP T-14, and
/// deliberately not asserted here. What is asserted is the half that is
/// fixed: the genuine message is still passed on rather than dismissed as a
/// duplicate of the forgery, so the rest of the mesh can have it.
#[tokio::test]
async fn test_a_forged_channel_copy_does_not_suppress_the_real_message() {
    let h = harness().await;
    let (downstream, _) = h.downstream().await;
    let mut relayed = downstream.events();

    let channel = [8u8; 32];
    let id = MessageId::random();

    h.deliver(&channel_envelope(
        h.originator,
        NodeId::ZERO,
        id,
        20,
        &channel,
        b"forged",
    ))
    .await;
    assert_eq!(
        forwarded_channel_body(&mut relayed, Duration::from_secs(2)).await,
        Some(b"forged".to_vec()),
        "the first copy is flooded onward"
    );

    h.deliver(&channel_envelope(
        h.originator,
        NodeId::ZERO,
        id,
        20,
        &channel,
        b"genuine",
    ))
    .await;
    assert_eq!(
        forwarded_channel_body(&mut relayed, Duration::from_secs(2)).await,
        Some(b"genuine".to_vec()),
        "the genuine message must not be dismissed as a duplicate of a copy \
         that shares only its envelope id"
    );

    h.bob.stop().await;
}

/// Addressed to a *third* node, a flood used to be handed to generic unicast
/// forwarding before any flood handler saw it: relayed hop by hop towards the
/// addressee, who refuses it at the end. Pointless traffic, and on the
/// emergency path it is traffic that skips the per-originator rate limit
/// altogether (ADR-013).
#[tokio::test]
async fn test_a_flood_addressed_to_a_third_node_is_not_relayed() {
    let h = harness().await;
    let (downstream, downstream_id) = h.downstream().await;
    let mut relayed = downstream.events();

    let id = MessageId::random();
    let signed_at = unix_now();
    let message = b"evacuate sector 7";
    let approvals = h.approvals(&id, EmergencyLevel::Critical, signed_at, message);

    // Addressed to the one node Bob has a route to, so a relay really would
    // happen without the guard.
    let mut addressed = h.envelope(id, EmergencyLevel::Critical, signed_at, message, &approvals);
    addressed.destination = downstream_id;

    let mut events = h.bob.event_tx.subscribe();
    h.deliver(&addressed).await;

    assert!(
        forwarded_alert(&mut relayed, Duration::from_millis(400))
            .await
            .is_none(),
        "an addressed flood must be dropped, not routed onward"
    );
    assert_eq!(
        next_alert(&mut events, Duration::from_millis(200)).await,
        None,
        "and it is not an alert for this node either"
    );

    h.bob.stop().await;
}
