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
use mycelium_crypto::emergency::OriginRejection;
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
    /// The alert's originator. An identity rather than an id, because a
    /// broadcast now carries its key and a signature over the alert and its
    /// approvals (ADR-014).
    originator: Identity,
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

    // Four co-signers Bob trusts directly (1-hop trust is 1.0, above the 0.8
    // threshold) and whose Ed25519 keys he holds. Four rather than three so a
    // test can strip one and still clear the "three valid" gate, which is the
    // only way to tell the origin signature is doing the work.
    let cosigners: Vec<Identity> = (0..4).map(|_| Identity::generate()).collect();
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

    let originator = Identity::generate();
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
    fn originator_id(&self) -> NodeId {
        self.originator.node_id()
    }

    /// An alert signed by its originator, as a genuine one is.
    fn envelope(
        &self,
        id: MessageId,
        level: EmergencyLevel,
        signed_at: u64,
        message: &[u8],
        cosigners: &[EmergencyCosigner],
    ) -> Envelope {
        self.envelope_signed_by(&self.originator, id, level, signed_at, message, cosigners)
    }

    /// An alert claiming `self.originator` as its source but signed by
    /// `signer` — what an attacker in radio range can produce.
    fn envelope_signed_by(
        &self,
        signer: &Identity,
        id: MessageId,
        level: EmergencyLevel,
        signed_at: u64,
        message: &[u8],
        cosigners: &[EmergencyCosigner],
    ) -> Envelope {
        let ctx = BroadcastContext {
            broadcast_id: &id,
            originator: &self.originator_id(),
            level,
            signed_at,
            message,
        };
        let signature = emergency::sign_broadcast(signer, &ctx, cosigners);
        Envelope {
            source: self.originator_id(),
            destination: NodeId::ZERO,
            message_id: id,
            ttl: 20,
            hop_count: 1,
            flags: MessageFlags::NONE,
            lamport_clock: 0,
            device_timestamp: signed_at,
            protocol_version: ProtocolVersion::CURRENT,
            payload: wire::serialize_emergency_broadcast(
                level,
                signed_at,
                &signer.public_key_bytes(),
                &signature,
                message,
                cosigners,
            ),
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
            originator: &self.originator_id(),
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

/// The defect T-37 closes: the trust gate scores the id in the packet, not the
/// peer that sent it, so an attacker needed no standing of its own — name a
/// source the receiver trusts and the alert was accepted and flooded. Only a
/// signature bound to that source stops it (ADR-014).
#[tokio::test]
async fn test_an_alert_signed_by_the_wrong_key_is_refused() {
    let h = harness().await;
    let (downstream, _) = h.downstream().await;
    let mut relayed = downstream.events();

    // Bob trusts the originator directly, so the trust gate would pass.
    {
        let mut tg = h.bob.trust_graph.write().await;
        tg.add_vouch(h.bob_id, h.originator_id());
    }

    let signed_at = unix_now();
    let message = b"evacuate sector 7";
    let attacker = Identity::generate();

    let mut events = h.bob.event_tx.subscribe();

    // Level 2 is the sharp case: no co-signatures are involved, so before the
    // origin signature there was nothing at all to check.
    let forged = h.envelope_signed_by(
        &attacker,
        MessageId::random(),
        EmergencyLevel::Urgent,
        signed_at,
        message,
        &[],
    );
    h.deliver(&forged).await;
    assert_eq!(
        next_alert(&mut events, Duration::from_millis(300)).await,
        None,
        "an alert signed by a key that does not hash to its source is not an alert"
    );
    assert!(
        forwarded_alert(&mut relayed, Duration::from_millis(200))
            .await
            .is_none(),
        "and nothing of it is passed on"
    );

    // The same alert from the originator itself is accepted, so the refusal
    // above is about the signature and nothing else.
    let genuine = h.envelope(
        MessageId::random(),
        EmergencyLevel::Urgent,
        signed_at,
        message,
        &[],
    );
    h.deliver(&genuine).await;
    assert_eq!(
        next_alert(&mut events, Duration::from_secs(2))
            .await
            .as_deref(),
        Some("evacuate sector 7"),
        "a genuine level-2 alert from a trusted originator must be accepted"
    );

    h.bob.stop().await;
}

/// A relay must not be able to weaken the approval list it passes on: the
/// originator's signature covers it, so a stripped copy is refused outright
/// rather than accepted with fewer approvals (ADR-014).
#[tokio::test]
async fn test_an_alert_with_a_stripped_approval_list_is_refused() {
    let h = harness().await;
    let id = MessageId::random();
    let signed_at = unix_now();
    let message = b"evacuate sector 7";
    let approvals = h.approvals(&id, EmergencyLevel::Critical, signed_at, message);

    // Signed over four approvals, delivered carrying three — so the copy
    // still clears the "three distinct valid co-signatures" gate, and only
    // the origin signature can tell it was edited.
    assert_eq!(approvals.len(), 4, "the harness provides four approvals");
    let full = h.envelope(id, EmergencyLevel::Critical, signed_at, message, &approvals);
    let mut stripped = full.clone();
    stripped.payload = wire::serialize_emergency_broadcast(
        EmergencyLevel::Critical,
        signed_at,
        &h.originator.public_key_bytes(),
        &full_signature(&full),
        message,
        &approvals[..3],
    );

    let mut events = h.bob.event_tx.subscribe();

    h.deliver(&stripped).await;
    assert_eq!(
        next_alert(&mut events, Duration::from_millis(300)).await,
        None,
        "the origin signature covers the approval list, so a stripped copy fails it"
    );

    h.deliver(&full).await;
    assert_eq!(
        next_alert(&mut events, Duration::from_secs(2))
            .await
            .as_deref(),
        Some("evacuate sector 7"),
        "the full alert is still accepted afterwards"
    );

    h.bob.stop().await;
}

/// A relay that strips approvals is refused, so the full copy behind it has to
/// get through — and be forwarded, since downstream nodes may hold keys for
/// the approvals this one could not check. It must not raise a second alert
/// locally (ADR-014).
#[tokio::test]
async fn test_a_fuller_approval_list_is_forwarded_without_raising_a_second_alert() {
    let h = harness().await;
    let (downstream, _) = h.downstream().await;
    let mut relayed = downstream.events();

    let id = MessageId::random();
    let signed_at = unix_now();
    let message = b"evacuate sector 7";
    let approvals = h.approvals(&id, EmergencyLevel::Critical, signed_at, message);

    // Both are genuine alerts from the originator; the second carries one
    // more approval, which is a different signed list and so a new origin.
    let three = h.envelope(
        id,
        EmergencyLevel::Critical,
        signed_at,
        message,
        &approvals[..3],
    );
    let four = h.envelope(id, EmergencyLevel::Critical, signed_at, message, &approvals);

    let mut events = h.bob.event_tx.subscribe();

    h.deliver(&three).await;
    assert_eq!(
        next_alert(&mut events, Duration::from_secs(2))
            .await
            .as_deref(),
        Some("evacuate sector 7")
    );
    assert!(
        forwarded_alert(&mut relayed, Duration::from_secs(2))
            .await
            .is_some(),
        "the first copy is flooded onward"
    );

    h.deliver(&four).await;
    let onward = forwarded_alert(&mut relayed, Duration::from_secs(2)).await;
    assert!(
        onward.is_some(),
        "a copy with a fuller approval list must travel too"
    );
    assert_eq!(
        next_alert(&mut events, Duration::from_millis(300)).await,
        None,
        "but the alert must not be reported to this node twice"
    );

    h.bob.stop().await;
}

/// The signature out of an alert envelope, for building a copy that keeps it.
fn full_signature(envelope: &Envelope) -> [u8; 64] {
    wire::deserialize_emergency_broadcast(&envelope.payload[1..])
        .expect("a signed alert parses")
        .signature
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
        .create_channel(&channel, "test", &h.originator_id())
        .expect("channel row");
    h.bob.db.subscribe_channel(&channel).expect("subscribed");

    let id = MessageId::random();
    let forged = channel_envelope(h.originator_id(), h.bob_id, id, 20, &channel, b"forged");
    let genuine = channel_envelope(
        h.originator_id(),
        NodeId::ZERO,
        id,
        20,
        &channel,
        b"genuine",
    );

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
        h.originator_id(),
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
        h.originator_id(),
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

// --- Raising an alert through the node ------------------------------------

/// A co-signature covers the broadcast id and the signing date, so both must
/// be fixed before approvals are collected — a send path that minted a fresh
/// id would make every collected approval useless (ADR-010, ADR-014).
#[tokio::test]
async fn test_an_alert_cosigned_over_its_draft_is_accepted() {
    let alice_identity = Identity::generate();
    let alice_id = alice_identity.node_id();
    let alice = Node::new(
        NodeConfig::default(),
        Database::open_in_memory().expect("in-memory DB"),
        alice_identity,
    );

    let bob_identity = Identity::generate();
    let bob_id = bob_identity.node_id();
    let bob = Node::new(
        NodeConfig::default(),
        Database::open_in_memory().expect("in-memory DB"),
        bob_identity,
    );

    let network = MockNetwork::new();
    alice
        .transport_manager
        .add_transport(Arc::new(
            MockTransport::new(alice_id, network.clone()).await,
        ))
        .await;
    bob.transport_manager
        .add_transport(Arc::new(MockTransport::new(bob_id, network.clone()).await))
        .await;
    alice.start().await.expect("alice starts");
    bob.start().await.expect("bob starts");
    network
        .add_link(alice_id, bob_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Bob trusts three co-signers and holds their keys.
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

    let mut events = bob.event_tx.subscribe();

    // Draft first, collect approvals over the draft, then raise it.
    let draft = alice.draft_emergency(EmergencyLevel::Critical, b"evacuate sector 7");
    let digest = alice.emergency_cosign_digest(&draft);
    let approvals: Vec<EmergencyCosigner> = cosigners
        .iter()
        .map(|c| EmergencyCosigner {
            node_id: c.node_id(),
            signature: c.sign(&digest).to_bytes(),
        })
        .collect();
    alice
        .raise_emergency(draft, &approvals)
        .await
        .expect("alice can raise it");

    assert_eq!(
        next_alert(&mut events, Duration::from_secs(2))
            .await
            .as_deref(),
        Some("evacuate sector 7"),
        "approvals collected over the draft must match the alert that is sent"
    );

    alice.stop().await;
    bob.stop().await;
}

/// The co-signer count is one byte, so a longer list must be cut before both
/// signing and serialization — cutting it after signing would produce
/// broadcasts whose own signature can never verify.
#[tokio::test]
async fn test_an_oversized_approval_list_still_produces_a_verifiable_alert() {
    let alice_identity = Identity::generate();
    let alice_id = alice_identity.node_id();
    let alice = Node::new(
        NodeConfig::default(),
        Database::open_in_memory().expect("in-memory DB"),
        alice_identity,
    );

    let network = MockNetwork::new();
    alice
        .transport_manager
        .add_transport(Arc::new(
            MockTransport::new(alice_id, network.clone()).await,
        ))
        .await;
    alice.start().await.expect("alice starts");

    let observer_id = Identity::generate().node_id();
    let observer = Arc::new(MockTransport::new(observer_id, network.clone()).await);
    observer.start().await.expect("observer starts");
    network
        .add_link(alice_id, observer_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut seen = observer.events();

    let draft = alice.draft_emergency(EmergencyLevel::Critical, b"evacuate sector 7");
    let digest = alice.emergency_cosign_digest(&draft);
    let signed_at = draft.signed_at;
    let id = draft.message_id;
    let many: Vec<EmergencyCosigner> = (0..300)
        .map(|_| {
            let c = Identity::generate();
            EmergencyCosigner {
                node_id: c.node_id(),
                signature: c.sign(&digest).to_bytes(),
            }
        })
        .collect();
    alice
        .raise_emergency(draft, &many)
        .await
        .expect("the mock transport's MTU is wide enough to carry it");

    let envelope = forwarded(
        &mut seen,
        Duration::from_secs(2),
        wire::WirePayloadType::EmergencyBroadcast,
    )
    .await
    .expect("alice floods the alert");
    let parsed = wire::deserialize_emergency_broadcast(&envelope.payload[1..])
        .expect("a 300-approval alert must still serialize to something parseable");
    assert_eq!(parsed.cosigners.len(), wire::MAX_EMERGENCY_COSIGNERS);

    let ctx = BroadcastContext {
        broadcast_id: &id,
        originator: &alice_id,
        level: EmergencyLevel::Critical,
        signed_at,
        message: b"evacuate sector 7",
    };
    assert_eq!(
        emergency::verify_origin(
            &parsed.identity_key,
            &alice_id,
            &ctx,
            &parsed.cosigners,
            &parsed.signature
        ),
        Ok(()) as Result<(), OriginRejection>,
        "the list must be cut before signing, not after"
    );

    alice.stop().await;
}

/// An alert is `217 + message_bytes + 96 × approvals` on the wire, so with a
/// BLE transport registered and no approvals it has 295 bytes of message to
/// spend — not characters, since a multi-byte character costs more than one.
/// A node refuses the alert that does not fit rather than flooding the links
/// that can carry it and stopping silently at every phone (T-39).
#[tokio::test]
async fn test_an_alert_too_large_for_the_narrowest_transport_is_refused() {
    use mycelium_core::transport::ble::BleTransport;

    let identity = Identity::generate();
    let node_id = identity.node_id();
    let node = Node::new(
        NodeConfig::default(),
        Database::open_in_memory().expect("in-memory DB"),
        identity,
    );
    node.transport_manager
        .add_transport(Arc::new(BleTransport::new(node_id)))
        .await;

    // ASCII, so 295 characters is 295 bytes.
    let fits = "x".repeat(295);
    let draft = node.draft_emergency(EmergencyLevel::Urgent, fits.as_bytes());
    assert!(
        node.raise_emergency(draft, &[]).await.is_ok(),
        "295 bytes is the most that fits BLE's 512-byte message"
    );

    let one_too_many = "x".repeat(296);
    let draft = node.draft_emergency(EmergencyLevel::Urgent, one_too_many.as_bytes());
    match node.raise_emergency(draft, &[]).await {
        Err(mycelium_node::node::NodeError::AlertTooLarge { size, limit }) => {
            assert_eq!(size, 513);
            assert_eq!(limit, 512);
        }
        other => panic!("expected a refusal at 513 bytes, got {other:?}"),
    }

    // 148 three-byte characters are 444 bytes and fit; 149 are 447 and do not
    // reach the limit either, so take the first count that does: the point is
    // that the limit counts bytes, so far fewer characters fit.
    let multibyte = "€".repeat(99); // 297 bytes
    assert_eq!(multibyte.len(), 297);
    let draft = node.draft_emergency(EmergencyLevel::Urgent, multibyte.as_bytes());
    assert!(
        node.raise_emergency(draft, &[]).await.is_err(),
        "99 three-byte characters are 297 bytes, over the same limit that 295 \
         ASCII characters just met"
    );
}

/// A receiver that co-signed the alert must count its own approval. The
/// contacts table never holds a node's own identity, so looking there first
/// made Bob discard the signature he had produced himself and refuse an alert
/// he had approved (ADR-010).
#[tokio::test]
async fn test_a_receiver_counts_its_own_co_signature() {
    let h = harness().await;

    // Bob is one of the three approvers; the other two are harness
    // co-signers, whose keys he holds and whom he trusts.
    {
        let mut tg = h.bob.trust_graph.write().await;
        tg.add_vouch(h.bob_id, h.originator_id());
    }

    let id = MessageId::random();
    let signed_at = unix_now();
    let message = b"evacuate sector 7";
    let ctx = BroadcastContext {
        broadcast_id: &id,
        originator: &h.originator_id(),
        level: EmergencyLevel::Critical,
        signed_at,
        message,
    };
    let digest = emergency::broadcast_digest(&ctx);

    let mut approvals = vec![EmergencyCosigner {
        node_id: h.bob_id,
        signature: h.bob.identity.sign(&digest).to_bytes(),
    }];
    approvals.extend(h.approvals(&id, EmergencyLevel::Critical, signed_at, message)[..2].to_vec());

    let mut events = h.bob.event_tx.subscribe();
    h.deliver(&h.envelope(id, EmergencyLevel::Critical, signed_at, message, &approvals))
        .await;

    assert_eq!(
        next_alert(&mut events, Duration::from_secs(2))
            .await
            .as_deref(),
        Some("evacuate sector 7"),
        "Bob's own approval is one of the three"
    );

    h.bob.stop().await;
}
