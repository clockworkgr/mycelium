//! Integration tests for daemon lifecycle: start/stop, transport registration,
//! network partition with DTN fallback, multi-hop routing, and conversation deletion.

use std::sync::Arc;
use std::time::Duration;

use mycelium_core::transport::mock::{MockLinkConfig, MockNetwork, MockTransport};
use mycelium_crypto::identity::Identity;
use mycelium_node::config::NodeConfig;
use mycelium_node::node::Node;
use mycelium_protocol::types::ContentType;
use mycelium_storage::db::Database;

fn make_node(identity: Identity) -> Node {
    let config = NodeConfig::default();
    let db = Database::open_in_memory().expect("in-memory DB");
    Node::new(config, db, identity)
}

/// Test that a node can start and stop cleanly.
#[tokio::test]
async fn test_node_start_stop() {
    let identity = Identity::generate();
    let node = make_node(identity);

    // Start
    node.start().await.expect("start");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Stop
    node.stop().await;
}

/// Test that register_transports wires BLE and WiFi Direct based on config.
#[tokio::test]
async fn test_register_transports_from_config() {
    let identity = Identity::generate();
    let mut config = NodeConfig::default();
    config.transports.ble = true;
    config.transports.wifi_direct = true;
    config.transports.mock = false;

    let db = Database::open_in_memory().unwrap();
    let node = Node::new(config, db, identity);

    // Before registration, no transports
    let peers_before = node.transport_manager.known_peers().await;
    assert_eq!(peers_before.len(), 0);

    // Register transports
    node.register_transports().await;

    // Node should start without error (even though BLE/WiFi Direct are stubs)
    node.start().await.expect("start with stubs");
    tokio::time::sleep(Duration::from_millis(50)).await;
    node.stop().await;
}

/// Test that network partition triggers DTN fallback when route discovery times out.
#[tokio::test]
async fn test_partition_triggers_dtn_fallback() {
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let carol_identity = Identity::generate();
    let alice_id = alice_identity.node_id();
    let bob_id = bob_identity.node_id();
    let carol_id = carol_identity.node_id();

    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);
    let carol = make_node(carol_identity);

    let network = MockNetwork::new();
    let alice_t = Arc::new(MockTransport::new(alice_id, network.clone()).await);
    let bob_t = Arc::new(MockTransport::new(bob_id, network.clone()).await);
    let carol_t = Arc::new(MockTransport::new(carol_id, network.clone()).await);

    alice.transport_manager.add_transport(alice_t.clone()).await;
    bob.transport_manager.add_transport(bob_t.clone()).await;
    carol.transport_manager.add_transport(carol_t.clone()).await;

    // Start Alice and Bob (Carol is not started yet — she's offline)
    alice.start().await.unwrap();
    bob.start().await.unwrap();
    carol.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Alice <-> Bob connected, but Carol is not reachable
    network
        .add_link(alice_id, bob_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Alice tries to send to Carol (no route exists)
    // This should trigger AODV discovery, timeout, and DTN fallback
    let msg_id = alice
        .send_message(carol_id, b"Hello Carol via DTN!", ContentType::Text)
        .await
        .expect("send should succeed (queued)");

    // The fallback must land on the scale of the discovery timeout (5 s), not
    // the maintenance interval. With one retry that is ~11 s: expiry detected
    // at ~5 s triggers the retry, the retry expires at ~10 s and enters DTN.
    //
    // This bound is the regression test for ROADMAP T-10. Before the fix the
    // sweep lived in the 30 s maintenance tick, so the first retry happened at
    // ~30 s and DTN at ~60 s; a 25 s bound fails on that code.
    const FALLBACK_BOUND: Duration = Duration::from_secs(25);
    let start = std::time::Instant::now();
    let mut status = String::new();
    while start.elapsed() < FALLBACK_BOUND {
        status = alice.db.get_message(&msg_id).unwrap().status;
        if status == "dtn_pending" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(
        status,
        "dtn_pending",
        "message should be dtn_pending within {:?} of the send (discovery timeout is 5 s), \
         still {:?} after {:?}",
        FALLBACK_BOUND,
        status,
        start.elapsed()
    );

    // Verify DTN bundle is persisted
    let dtn_used = alice.db.dtn_storage_used().unwrap();
    assert!(dtn_used > 0, "DTN storage should have bundles");

    alice.stop().await;
    bob.stop().await;
    carol.stop().await;
}

/// Test conversation deletion works end-to-end.
#[tokio::test]
async fn test_conversation_deletion() {
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let alice_id = alice_identity.node_id();
    let bob_id = bob_identity.node_id();

    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);

    let network = MockNetwork::new();
    let alice_t = Arc::new(MockTransport::new(alice_id, network.clone()).await);
    let bob_t = Arc::new(MockTransport::new(bob_id, network.clone()).await);

    alice.transport_manager.add_transport(alice_t.clone()).await;
    bob.transport_manager.add_transport(bob_t.clone()).await;

    alice.start().await.unwrap();
    bob.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    network
        .add_link(alice_id, bob_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Exchange some messages
    alice
        .send_message(bob_id, b"msg1", ContentType::Text)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    alice
        .send_message(bob_id, b"msg2", ContentType::Text)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Verify messages exist
    let convo = alice
        .db
        .get_conversation(&alice_id, &bob_id, 100, 0)
        .unwrap();
    assert!(convo.len() >= 2, "Should have messages before delete");

    // Delete the conversation
    let deleted = alice.db.delete_conversation(&alice_id, &bob_id).unwrap();
    assert!(deleted >= 2, "Should have deleted at least 2 messages");

    // Verify messages are gone
    let convo_after = alice
        .db
        .get_conversation(&alice_id, &bob_id, 100, 0)
        .unwrap();
    assert_eq!(
        convo_after.len(),
        0,
        "Conversation should be empty after delete"
    );

    // Conversation list should also be empty
    let conversations = alice.db.list_conversations(&alice_id).unwrap();
    assert_eq!(conversations.len(), 0, "No conversations after delete");

    alice.stop().await;
    bob.stop().await;
}

/// Test three-node multi-hop message relay: Alice -> Bob -> Carol.
#[tokio::test]
async fn test_three_node_multihop() {
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let carol_identity = Identity::generate();
    let alice_id = alice_identity.node_id();
    let bob_id = bob_identity.node_id();
    let carol_id = carol_identity.node_id();

    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);
    let carol = make_node(carol_identity);

    let network = MockNetwork::new();
    let alice_t = Arc::new(MockTransport::new(alice_id, network.clone()).await);
    let bob_t = Arc::new(MockTransport::new(bob_id, network.clone()).await);
    let carol_t = Arc::new(MockTransport::new(carol_id, network.clone()).await);

    alice.transport_manager.add_transport(alice_t.clone()).await;
    bob.transport_manager.add_transport(bob_t.clone()).await;
    carol.transport_manager.add_transport(carol_t.clone()).await;

    alice.start().await.unwrap();
    bob.start().await.unwrap();
    carol.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Alice <-> Bob <-> Carol (no direct Alice <-> Carol link)
    network
        .add_link(alice_id, bob_id, MockLinkConfig::default())
        .await;
    network
        .add_link(bob_id, carol_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Alice sends to Carol — needs route discovery through Bob
    let msg_id = alice
        .send_message(carol_id, b"Hello Carol via Bob!", ContentType::Text)
        .await
        .expect("send should succeed");

    // Wait for full multi-hop exchange:
    // RREQ: Alice->Bob->Carol, RREP: Carol->Bob->Alice (route found),
    // PrekeyRequest: Alice->Bob->Carol, PrekeyResponse: Carol->Bob->Alice,
    // SessionInit: Alice->Bob->Carol (with encrypted first message)
    // Each hop has ~10ms latency, many round trips needed
    tokio::time::sleep(Duration::from_millis(5000)).await;

    // Carol should have received the message
    let carol_msg = carol.db.get_message(&msg_id);
    assert!(
        carol_msg.is_ok(),
        "Carol should have received multi-hop message, got: {:?}",
        carol_msg.err()
    );
    let carol_msg = carol_msg.unwrap();
    assert_eq!(carol_msg.plaintext, b"Hello Carol via Bob!");
    assert_eq!(carol_msg.source, alice_id);
    assert!(carol_msg.is_incoming);

    alice.stop().await;
    bob.stop().await;
    carol.stop().await;
}

/// Test four-node mesh: Alice -> Bob -> Carol, Bob -> Dave.
/// Alice sends to Dave — needs route discovery A->B->D.
#[tokio::test]
async fn test_four_node_mesh_routing() {
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let carol_identity = Identity::generate();
    let dave_identity = Identity::generate();
    let alice_id = alice_identity.node_id();
    let bob_id = bob_identity.node_id();
    let carol_id = carol_identity.node_id();
    let dave_id = dave_identity.node_id();

    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);
    let carol = make_node(carol_identity);
    let dave = make_node(dave_identity);

    let network = MockNetwork::new();
    let alice_t = Arc::new(MockTransport::new(alice_id, network.clone()).await);
    let bob_t = Arc::new(MockTransport::new(bob_id, network.clone()).await);
    let carol_t = Arc::new(MockTransport::new(carol_id, network.clone()).await);
    let dave_t = Arc::new(MockTransport::new(dave_id, network.clone()).await);

    alice.transport_manager.add_transport(alice_t.clone()).await;
    bob.transport_manager.add_transport(bob_t.clone()).await;
    carol.transport_manager.add_transport(carol_t.clone()).await;
    dave.transport_manager.add_transport(dave_t.clone()).await;

    alice.start().await.unwrap();
    bob.start().await.unwrap();
    carol.start().await.unwrap();
    dave.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Mesh topology:
    //   Alice <-> Bob <-> Carol
    //                 \-> Dave
    network
        .add_link(alice_id, bob_id, MockLinkConfig::default())
        .await;
    network
        .add_link(bob_id, carol_id, MockLinkConfig::default())
        .await;
    network
        .add_link(bob_id, dave_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Alice sends to Dave — route discovery: A->B (broadcast RREQ)->D (reply)
    let msg_id = alice
        .send_message(dave_id, b"Hello Dave from Alice!", ContentType::Text)
        .await
        .expect("send should succeed");

    // Wait for RREQ flood, RREP, key exchange, and message delivery
    tokio::time::sleep(Duration::from_millis(5000)).await;

    // Dave should have received the message via Bob
    let dave_msg = dave.db.get_message(&msg_id);
    assert!(
        dave_msg.is_ok(),
        "Dave should have received message via Bob, got: {:?}",
        dave_msg.err()
    );
    let dave_msg = dave_msg.unwrap();
    assert_eq!(dave_msg.plaintext, b"Hello Dave from Alice!");
    assert_eq!(dave_msg.source, alice_id);

    alice.stop().await;
    bob.stop().await;
    carol.stop().await;
    dave.stop().await;
}

/// Test that AODV RREQ is broadcast to ALL neighbors (not just one).
/// Star topology with Alice in center: Bob <-> Alice <-> Carol.
#[tokio::test]
async fn test_rreq_broadcast_all_peers() {
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let carol_identity = Identity::generate();
    let alice_id = alice_identity.node_id();
    let bob_id = bob_identity.node_id();
    let carol_id = carol_identity.node_id();

    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);
    let carol = make_node(carol_identity);

    let network = MockNetwork::new();
    let alice_t = Arc::new(MockTransport::new(alice_id, network.clone()).await);
    let bob_t = Arc::new(MockTransport::new(bob_id, network.clone()).await);
    let carol_t = Arc::new(MockTransport::new(carol_id, network.clone()).await);

    alice.transport_manager.add_transport(alice_t.clone()).await;
    bob.transport_manager.add_transport(bob_t.clone()).await;
    carol.transport_manager.add_transport(carol_t.clone()).await;

    alice.start().await.unwrap();
    bob.start().await.unwrap();
    carol.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Star topology with Alice in center:
    //   Bob <-> Alice <-> Carol
    network
        .add_link(alice_id, bob_id, MockLinkConfig::default())
        .await;
    network
        .add_link(alice_id, carol_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Bob sends to Carol — RREQ goes to Alice, Alice re-broadcasts to Carol
    let msg_id = bob
        .send_message(carol_id, b"Hi Carol from Bob!", ContentType::Text)
        .await
        .expect("send should succeed");

    tokio::time::sleep(Duration::from_millis(5000)).await;

    let carol_msg = carol.db.get_message(&msg_id);
    assert!(
        carol_msg.is_ok(),
        "Carol should have received message through Alice, got: {:?}",
        carol_msg.err()
    );

    alice.stop().await;
    bob.stop().await;
    carol.stop().await;
}

/// Test route invalidation when a link drops.
/// Topology: Alice <-> Bob <-> Carol. First message succeeds,
/// then Bob <-> Carol link drops. Second message should not reach Carol.
#[tokio::test]
async fn test_route_invalidation_on_link_loss() {
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let carol_identity = Identity::generate();
    let alice_id = alice_identity.node_id();
    let bob_id = bob_identity.node_id();
    let carol_id = carol_identity.node_id();

    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);
    let carol = make_node(carol_identity);

    let network = MockNetwork::new();
    let alice_t = Arc::new(MockTransport::new(alice_id, network.clone()).await);
    let bob_t = Arc::new(MockTransport::new(bob_id, network.clone()).await);
    let carol_t = Arc::new(MockTransport::new(carol_id, network.clone()).await);

    alice.transport_manager.add_transport(alice_t.clone()).await;
    bob.transport_manager.add_transport(bob_t.clone()).await;
    carol.transport_manager.add_transport(carol_t.clone()).await;

    alice.start().await.unwrap();
    bob.start().await.unwrap();
    carol.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Alice <-> Bob <-> Carol
    network
        .add_link(alice_id, bob_id, MockLinkConfig::default())
        .await;
    network
        .add_link(bob_id, carol_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // First message succeeds
    let msg1_id = alice
        .send_message(carol_id, b"First message", ContentType::Text)
        .await
        .expect("send should succeed");

    tokio::time::sleep(Duration::from_millis(5000)).await;

    let carol_msg1 = carol.db.get_message(&msg1_id);
    assert!(carol_msg1.is_ok(), "First message should be delivered");

    // Break the Bob <-> Carol link
    network.remove_link(&bob_id, &carol_id).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Second message — Bob can't forward to Carol (link broken)
    let msg2_id = alice
        .send_message(carol_id, b"After partition", ContentType::Text)
        .await
        .expect("send should succeed (queued)");

    tokio::time::sleep(Duration::from_millis(2000)).await;

    let carol_msg2 = carol.db.get_message(&msg2_id);
    assert!(
        carol_msg2.is_err(),
        "Second message should NOT reach Carol after partition"
    );

    alice.stop().await;
    bob.stop().await;
    carol.stop().await;
}

/// Several messages queued for one unreachable destination must produce one
/// RREQ, not one per message.
///
/// Every envelope waiting on a destination waits on the same route, so a
/// single discovery serves all of them. Regression test for ROADMAP T-10:
/// `route_and_send` used to call `initiate_discovery` for every send, and the
/// retry sweep iterated per queued envelope, so N messages to one offline peer
/// flooded the mesh N times on the initial attempt and N times again on every
/// retry.
#[tokio::test]
async fn test_one_rreq_per_destination_not_per_message() {
    use mycelium_core::transport::{Transport, TransportEvent};
    use mycelium_protocol::codec::Envelope;
    use mycelium_protocol::wire::{self, WirePayloadType};

    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let alice_id = alice_identity.node_id();
    let bob_id = bob_identity.node_id();
    // Carol never joins the network, so no route to her can ever be found.
    let carol_id = Identity::generate().node_id();

    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);

    let network = MockNetwork::new();
    let alice_t = Arc::new(MockTransport::new(alice_id, network.clone()).await);
    let bob_t = Arc::new(MockTransport::new(bob_id, network.clone()).await);
    alice.transport_manager.add_transport(alice_t.clone()).await;
    bob.transport_manager.add_transport(bob_t.clone()).await;

    alice.start().await.unwrap();
    bob.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    network
        .add_link(alice_id, bob_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Count the RREQs for Carol that reach Bob. Bob's node also consumes this
    // stream; a broadcast channel allows both.
    let mut events = bob_t.events();
    let rreqs_for_carol = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = rreqs_for_carol.clone();
    tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            if let TransportEvent::DataReceived { data, .. } = event {
                let Ok(envelope) = Envelope::deserialize(&data) else {
                    continue;
                };
                let Some(&type_byte) = envelope.payload.first() else {
                    continue;
                };
                if WirePayloadType::from_byte(type_byte) != Some(WirePayloadType::AodvRreq) {
                    continue;
                }
                if let Ok((_, _, _, dest, _, _, _)) =
                    wire::deserialize_aodv_rreq(&envelope.payload[1..])
                {
                    if dest == carol_id {
                        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            }
        }
    });

    // Three messages to the same unreachable destination, back to back.
    for i in 0..3 {
        alice
            .send_message(carol_id, format!("msg {i}").as_bytes(), ContentType::Text)
            .await
            .expect("send is queued, not delivered");
    }

    // Let the initial discovery go out, but stay well inside the 5 s timeout
    // so no retry sweep has fired yet.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let after_initial = rreqs_for_carol.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        after_initial, 1,
        "three messages to one unreachable destination should emit exactly one \
         initial RREQ, got {after_initial}"
    );

    // A message queued well after the first one must join the in-flight
    // discovery rather than starting its own. This is the staggered case: with
    // a per-envelope deadline it would expire ~2 s after the others and emit
    // its own RREQ.
    tokio::time::sleep(Duration::from_millis(2_000)).await;
    alice
        .send_message(carol_id, b"late joiner", ContentType::Text)
        .await
        .expect("send is queued");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after_late = rreqs_for_carol.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        after_late, 1,
        "a message queued later must join the in-flight discovery, got {after_late}"
    );

    // Now let exactly one retry sweep fire (timeout 5 s, sweep every 1 s).
    tokio::time::sleep(Duration::from_millis(4_500)).await;
    let after_retry = rreqs_for_carol.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        after_retry, 2,
        "the retry sweep should emit one more RREQ for the destination, not one \
         per queued envelope nor one per stagger; got {after_retry} total"
    );

    alice.stop().await;
    bob.stop().await;
}
