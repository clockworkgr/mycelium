//! Group discovery: a beacon hint is a hint, and the vouch behind it has to
//! be earned (ROADMAP T-04, ADR-019).
//!
//! The scenario throughout is the one the defect allowed: a node in radio
//! range reads the eight-byte group hint out of one beacon, puts it in its
//! own, and is auto-trusted at 1 hop — above every threshold in the protocol,
//! including the ones that gate emergency broadcasts.

use std::sync::Arc;
use std::time::Duration;

use mycelium_core::transport::mock::{MockLinkConfig, MockNetwork, MockTransport};
use mycelium_core::transport::{Transport, TransportEvent};
use mycelium_crypto::discovery::{
    derive_group_discovery_key, derive_group_proof_key, group_discovery_hint, group_proof_mac,
    GROUP_NONCE_LEN,
};
use mycelium_crypto::identity::Identity;
use mycelium_node::config::NodeConfig;
use mycelium_node::node::Node;
use mycelium_protocol::codec::Envelope;
use mycelium_protocol::types::{MessageFlags, MessageId, NodeId, NodeType, ProtocolVersion};
use mycelium_protocol::wire::{
    GroupProofChallengePayload, GroupProofResponsePayload, WirePayloadType,
};
use mycelium_storage::db::Database;
use tokio::sync::broadcast::Receiver;

const PASSPHRASE: &str = "the cat sat on the mat at midnight";

/// Bob, who is in a group, and a peer on the other end of one link.
struct Harness {
    bob: Node,
    bob_id: NodeId,
    peer: Arc<MockTransport>,
    peer_id: NodeId,
    peer_rx: Receiver<TransportEvent>,
    network: Arc<MockNetwork>,
}

async fn harness() -> Harness {
    harness_with_group(Some(PASSPHRASE)).await
}

async fn harness_with_group(passphrase: Option<&str>) -> Harness {
    let bob_identity = Identity::generate();
    let bob_id = bob_identity.node_id();
    let config = NodeConfig {
        group_seed: passphrase.map(|p| hex::encode(derive_group_discovery_key(p))),
        ..NodeConfig::default()
    };
    let bob = Node::new(
        config,
        Database::open_in_memory().expect("in-memory DB"),
        bob_identity,
    );

    let network = MockNetwork::new();
    let bob_t = Arc::new(MockTransport::new(bob_id, network.clone()).await);
    bob.transport_manager.add_transport(bob_t).await;
    bob.start().await.expect("node starts");

    let peer_id = Identity::generate().node_id();
    let peer = Arc::new(MockTransport::new(peer_id, network.clone()).await);
    peer.start().await.expect("peer transport starts");
    let peer_rx = peer.events();
    network
        .add_link(peer_id, bob_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    Harness {
        bob,
        bob_id,
        peer,
        peer_id,
        peer_rx,
        network,
    }
}

/// The next envelope of `kind` to arrive on `rx`, if one does. Beacons and
/// other traffic are ignored.
async fn envelope_of_kind(
    rx: &mut Receiver<TransportEvent>,
    kind: WirePayloadType,
    within: Duration,
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

impl Harness {
    /// The group key Bob holds, as a member would.
    fn group_key() -> [u8; 32] {
        derive_group_discovery_key(PASSPHRASE)
    }

    /// The eight bytes anyone in range can read out of a beacon.
    fn captured_hint() -> [u8; 8] {
        group_discovery_hint(&Self::group_key())
    }

    async fn deliver(&self, envelope: &Envelope) {
        self.peer
            .send(&self.bob_id, &envelope.serialize())
            .await
            .expect("peer delivers to Bob");
    }

    fn envelope(&self, destination: NodeId, payload: Vec<u8>) -> Envelope {
        Envelope {
            source: self.peer_id,
            destination,
            message_id: MessageId::random(),
            ttl: 1,
            hop_count: 0,
            flags: MessageFlags::SYSTEM,
            lamport_clock: 1,
            device_timestamp: 0,
            protocol_version: ProtocolVersion::CURRENT,
            payload,
        }
    }

    /// A beacon from the peer, carrying whatever hint it cares to claim.
    async fn beacon(&self, hint: Option<[u8; 8]>) {
        let beacon = mycelium_node::beacon::Beacon {
            node_id: self.peer_id,
            node_type: NodeType::Phone,
            display_name: "claims to be a member".to_string(),
            protocol_version: ProtocolVersion::CURRENT,
            battery_level: 90,
            neighbor_count: 1,
            lamport_clock: 1,
            group_discovery_hash: hint,
        };
        let mut payload = vec![WirePayloadType::Beacon as u8];
        payload.extend_from_slice(&beacon.serialize());
        let envelope = self.envelope(NodeId::ZERO, payload);
        self.deliver(&envelope).await;
    }

    /// The next envelope of `kind` Bob sends this peer, if one arrives.
    async fn sent_to_peer(&mut self, kind: WirePayloadType, within: Duration) -> Option<Envelope> {
        envelope_of_kind(&mut self.peer_rx, kind, within).await
    }

    /// A node on the far side of Bob, so a test can see what he passes on.
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

    async fn challenge(&mut self) -> Option<GroupProofChallengePayload> {
        let envelope = self
            .sent_to_peer(WirePayloadType::GroupProofChallenge, Duration::from_secs(2))
            .await?;
        assert_eq!(envelope.destination, self.peer_id, "challenge is unicast");
        assert_eq!(envelope.ttl, 1, "challenge is link-local");
        Some(
            GroupProofChallengePayload::deserialize_body(&envelope.payload[1..])
                .expect("challenge body parses"),
        )
    }

    async fn answer(&self, mac: [u8; 32]) {
        let payload = GroupProofResponsePayload { mac }.serialize();
        let envelope = self.envelope(self.bob_id, payload);
        self.deliver(&envelope).await;
    }

    /// Whether Bob vouches for the peer — in the graph he routes on, and in
    /// the database he reloads from.
    async fn vouched(&self) -> bool {
        let in_graph = self
            .bob
            .trust_graph
            .read()
            .await
            .has_vouched(&self.bob_id, &self.peer_id);
        let in_db = self
            .bob
            .db
            .get_vouches_by(&self.bob_id)
            .expect("vouches readable")
            .iter()
            .any(|v| v.vouchee_id == self.peer_id);
        assert_eq!(
            in_graph, in_db,
            "the graph and the database disagree about the vouch"
        );
        in_graph
    }
}

/// The defect itself: the hint earns a challenge now, not a vouch.
#[tokio::test]
async fn test_a_captured_hint_alone_earns_no_vouch() {
    let mut h = harness().await;
    h.beacon(Some(Harness::captured_hint())).await;

    assert!(
        h.challenge().await.is_some(),
        "a matching hint should be challenged"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !h.vouched().await,
        "a replayed hint must not be trusted on its own"
    );
}

#[tokio::test]
async fn test_the_answer_from_the_group_key_earns_the_vouch() {
    let mut h = harness().await;
    h.beacon(Some(Harness::captured_hint())).await;
    let challenge = h.challenge().await.expect("challenged");
    assert_eq!(challenge.group_hint, Harness::captured_hint());

    let proof_key = derive_group_proof_key(&Harness::group_key());
    h.answer(group_proof_mac(
        &proof_key,
        &challenge.nonce,
        &h.bob_id,
        &h.peer_id,
    ))
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        h.vouched().await,
        "a member that answered should be vouched"
    );
}

#[tokio::test]
async fn test_an_answer_under_another_key_earns_nothing() {
    let mut h = harness().await;
    h.beacon(Some(Harness::captured_hint())).await;
    let challenge = h.challenge().await.expect("challenged");

    let wrong = derive_group_proof_key(&derive_group_discovery_key("a guess"));
    h.answer(group_proof_mac(
        &wrong,
        &challenge.nonce,
        &h.bob_id,
        &h.peer_id,
    ))
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(!h.vouched().await);
}

/// What an attacker gets by challenging a real member: a MAC with its own id
/// in the verifier's place. It is worth nothing in the other direction.
#[tokio::test]
async fn test_an_answer_lifted_from_the_other_direction_earns_nothing() {
    let mut h = harness().await;
    h.beacon(Some(Harness::captured_hint())).await;
    let challenge = h.challenge().await.expect("challenged");

    let proof_key = derive_group_proof_key(&Harness::group_key());
    h.answer(group_proof_mac(
        &proof_key,
        &challenge.nonce,
        &h.peer_id, // ids swapped: collected, not earned
        &h.bob_id,
    ))
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(!h.vouched().await);
}

/// Even a correct MAC proves nothing over a nonce the verifier never chose.
#[tokio::test]
async fn test_an_answer_to_a_nonce_nobody_asked_for_earns_nothing() {
    let h = harness().await;
    let proof_key = derive_group_proof_key(&Harness::group_key());
    h.answer(group_proof_mac(
        &proof_key,
        &[0x42; GROUP_NONCE_LEN],
        &h.bob_id,
        &h.peer_id,
    ))
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(!h.vouched().await);
}

/// A guess costs the nonce. The next beacon, seconds later, does not buy
/// another one.
#[tokio::test]
async fn test_a_wrong_answer_does_not_buy_a_second_nonce() {
    let mut h = harness().await;
    h.beacon(Some(Harness::captured_hint())).await;
    let first = h.challenge().await.expect("challenged");

    h.answer([0u8; 32]).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.beacon(Some(Harness::captured_hint())).await;

    assert!(
        h.challenge().await.is_none(),
        "a second challenge inside the cooldown"
    );

    // And the spent nonce cannot be answered again, right answer or not.
    let proof_key = derive_group_proof_key(&Harness::group_key());
    h.answer(group_proof_mac(
        &proof_key,
        &first.nonce,
        &h.bob_id,
        &h.peer_id,
    ))
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!h.vouched().await);
}

/// A peer already vouched for is not challenged again on every beacon.
#[tokio::test]
async fn test_a_vouched_peer_is_not_challenged_again() {
    let mut h = harness().await;
    h.beacon(Some(Harness::captured_hint())).await;
    let challenge = h.challenge().await.expect("challenged");
    let proof_key = derive_group_proof_key(&Harness::group_key());
    h.answer(group_proof_mac(
        &proof_key,
        &challenge.nonce,
        &h.bob_id,
        &h.peer_id,
    ))
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(h.vouched().await);

    h.beacon(Some(Harness::captured_hint())).await;
    assert!(
        h.challenge().await.is_none(),
        "nothing left to prove, so nothing to ask"
    );
}

#[tokio::test]
async fn test_a_beacon_without_the_hint_is_not_challenged() {
    let mut h = harness().await;
    h.beacon(None).await;
    assert!(h.challenge().await.is_none());
    assert!(!h.vouched().await);
}

#[tokio::test]
async fn test_a_beacon_with_another_groups_hint_is_not_challenged() {
    let mut h = harness().await;
    h.beacon(Some(group_discovery_hint(&derive_group_discovery_key(
        "another community",
    ))))
    .await;
    assert!(h.challenge().await.is_none());
    assert!(!h.vouched().await);
}

/// The other side of the exchange: Bob answering a challenge, with the MAC
/// bound to the peer that asked and to himself.
#[tokio::test]
async fn test_a_challenge_is_answered_for_the_pairing_it_was_sent_in() {
    let mut h = harness().await;
    let nonce = [0x11; GROUP_NONCE_LEN];
    let payload = GroupProofChallengePayload {
        group_hint: Harness::captured_hint(),
        nonce,
    }
    .serialize();
    let envelope = h.envelope(h.bob_id, payload);
    h.deliver(&envelope).await;

    let reply = h
        .sent_to_peer(WirePayloadType::GroupProofResponse, Duration::from_secs(2))
        .await
        .expect("Bob answers a challenge about his own group");
    let response = GroupProofResponsePayload::deserialize_body(&reply.payload[1..])
        .expect("response body parses");

    let proof_key = derive_group_proof_key(&Harness::group_key());
    assert_eq!(
        response.mac,
        group_proof_mac(&proof_key, &nonce, &h.peer_id, &h.bob_id),
        "the answer names the asker and the answerer, in that order"
    );
    // And it is not the answer the asker would need to be vouched itself.
    assert_ne!(
        response.mac,
        group_proof_mac(&proof_key, &nonce, &h.bob_id, &h.peer_id)
    );
}

/// A challenge broadcast to everyone in range would make every member in
/// earshot an answering service for one packet.
#[tokio::test]
async fn test_a_challenge_addressed_to_everyone_is_not_answered() {
    let mut h = harness().await;
    let payload = GroupProofChallengePayload {
        group_hint: Harness::captured_hint(),
        nonce: [0x11; GROUP_NONCE_LEN],
    }
    .serialize();
    let envelope = h.envelope(NodeId::ZERO, payload);
    h.deliver(&envelope).await;

    assert!(h
        .sent_to_peer(WirePayloadType::GroupProofResponse, Duration::from_secs(1))
        .await
        .is_none());
}

#[tokio::test]
async fn test_a_challenge_about_another_group_is_not_answered() {
    let mut h = harness().await;
    let payload = GroupProofChallengePayload {
        group_hint: group_discovery_hint(&derive_group_discovery_key("another community")),
        nonce: [0x11; GROUP_NONCE_LEN],
    }
    .serialize();
    let envelope = h.envelope(h.bob_id, payload);
    h.deliver(&envelope).await;

    assert!(h
        .sent_to_peer(WirePayloadType::GroupProofResponse, Duration::from_secs(1))
        .await
        .is_none());
}

/// A node in no group has nothing to ask and nothing to answer.
#[tokio::test]
async fn test_a_node_in_no_group_stays_out_of_the_exchange() {
    let mut h = harness_with_group(None).await;
    h.beacon(Some(Harness::captured_hint())).await;
    assert!(h.challenge().await.is_none());

    let payload = GroupProofChallengePayload {
        group_hint: Harness::captured_hint(),
        nonce: [0x11; GROUP_NONCE_LEN],
    }
    .serialize();
    let envelope = h.envelope(h.bob_id, payload);
    h.deliver(&envelope).await;
    assert!(h
        .sent_to_peer(WirePayloadType::GroupProofResponse, Duration::from_secs(1))
        .await
        .is_none());
    assert!(!h.vouched().await);
}

/// Addressing proof traffic past this node must not buy a relay. The exchange
/// is link-local, and these two types are exempt from the trust-tiered
/// limiter — so forwarding them would be routing work a peer over its budget,
/// or blacklisted outright, could still ask for.
#[tokio::test]
async fn test_proof_traffic_addressed_to_a_third_node_is_not_forwarded() {
    let h = harness().await;
    let (downstream, down_id) = h.downstream().await;
    let mut down_rx = downstream.events();

    let challenge = GroupProofChallengePayload {
        group_hint: Harness::captured_hint(),
        nonce: [0x11; GROUP_NONCE_LEN],
    }
    .serialize();
    h.deliver(&h.envelope(down_id, challenge)).await;

    let response = GroupProofResponsePayload { mac: [0x22; 32] }.serialize();
    h.deliver(&h.envelope(down_id, response)).await;

    assert!(
        envelope_of_kind(
            &mut down_rx,
            WirePayloadType::GroupProofChallenge,
            Duration::from_secs(1)
        )
        .await
        .is_none(),
        "a challenge for someone else was relayed"
    );
    assert!(
        envelope_of_kind(
            &mut down_rx,
            WirePayloadType::GroupProofResponse,
            Duration::from_secs(1)
        )
        .await
        .is_none(),
        "a response for someone else was relayed"
    );
}

/// A vouch that could not be written is not a vouch. Granting it in memory
/// alone hides the failure twice over: `has_vouched` would stop us ever
/// challenging this peer again, and a restart rebuilds the graph from the
/// database, so the trust the node claims to hold would simply vanish.
#[tokio::test]
async fn test_a_vouch_that_cannot_be_stored_is_not_granted() {
    let mut h = harness().await;
    h.bob
        .db
        .conn()
        .execute_batch("DROP TABLE vouches")
        .expect("vouch storage removed under the node");

    h.beacon(Some(Harness::captured_hint())).await;
    let challenge = h.challenge().await.expect("challenged");
    let proof_key = derive_group_proof_key(&Harness::group_key());
    h.answer(group_proof_mac(
        &proof_key,
        &challenge.nonce,
        &h.bob_id,
        &h.peer_id,
    ))
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        !h.bob
            .trust_graph
            .read()
            .await
            .has_vouched(&h.bob_id, &h.peer_id),
        "trust granted in memory that no restart would ever see"
    );
}

/// A beacon is link-local too (§10.1), and the guard that stops proof traffic
/// being relayed covers it: a *unicast* beacon addressed past this node is
/// dropped, while the broadcast one every node actually sends is not.
#[tokio::test]
async fn test_a_unicast_beacon_for_a_third_node_is_not_forwarded() {
    let mut h = harness().await;
    let (downstream, down_id) = h.downstream().await;
    let mut down_rx = downstream.events();

    let beacon = mycelium_node::beacon::Beacon {
        node_id: h.peer_id,
        node_type: NodeType::Phone,
        display_name: "addressed past Bob".to_string(),
        protocol_version: ProtocolVersion::CURRENT,
        battery_level: 90,
        neighbor_count: 1,
        lamport_clock: 1,
        group_discovery_hash: Some(Harness::captured_hint()),
    };
    let mut payload = vec![WirePayloadType::Beacon as u8];
    payload.extend_from_slice(&beacon.serialize());
    h.deliver(&h.envelope(down_id, payload)).await;

    assert!(
        envelope_of_kind(
            &mut down_rx,
            WirePayloadType::Beacon,
            Duration::from_secs(1)
        )
        .await
        .is_none(),
        "a beacon for someone else was relayed"
    );
    // Nor was it treated as a beacon to us: no challenge, no contact.
    assert!(h.challenge().await.is_none());

    // The broadcast form still arrives and is still acted on.
    h.beacon(Some(Harness::captured_hint())).await;
    assert!(h.challenge().await.is_some());
}
