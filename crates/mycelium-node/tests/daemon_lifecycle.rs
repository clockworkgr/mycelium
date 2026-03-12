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

    // Wait for AODV discovery timeout + retry + DTN fallback
    // Maintenance timer runs every 30s. First cycle at ~30s detects timeout (>5s),
    // retries RREQ. Second cycle at ~60s detects retry timeout, falls back to DTN.
    tokio::time::sleep(Duration::from_millis(65_000)).await;

    // After timeout, the message should be in DTN queue with status "dtn_pending"
    let alice_msg = alice.db.get_message(&msg_id).unwrap();
    assert_eq!(
        alice_msg.status, "dtn_pending",
        "Message should be dtn_pending after route discovery timeout, got: {}",
        alice_msg.status
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
