//! Advanced integration tests: delivery receipts, beacons, session persistence,
//! prekey persistence, and multi-message exchanges.

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

/// Test that delivery receipts update message status in sender's DB.
#[tokio::test]
async fn test_delivery_receipts() {
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let alice_node_id = alice_identity.node_id();
    let bob_node_id = bob_identity.node_id();

    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);

    let network = MockNetwork::new();
    let alice_t = Arc::new(MockTransport::new(alice_node_id, network.clone()).await);
    let bob_t = Arc::new(MockTransport::new(bob_node_id, network.clone()).await);

    alice.transport_manager.add_transport(alice_t.clone()).await;
    bob.transport_manager.add_transport(bob_t.clone()).await;

    alice.start().await.unwrap();
    bob.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    network
        .add_link(alice_node_id, bob_node_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Alice sends a message
    let msg_id = alice
        .send_message(bob_node_id, b"Receipt test", ContentType::Text)
        .await
        .unwrap();

    // Wait for full exchange: prekey req/resp + session init + message + receipt
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Bob should have received the message
    let bob_msg = bob.db.get_message(&msg_id).unwrap();
    assert_eq!(bob_msg.plaintext, b"Receipt test");

    // Alice's message should be marked as "delivered" by the receipt
    let alice_msg = alice.db.get_message(&msg_id).unwrap();
    assert_eq!(
        alice_msg.status, "delivered",
        "Alice's message should be marked delivered, got: {}",
        alice_msg.status
    );

    alice.stop().await;
    bob.stop().await;
}

/// Test that multiple messages work after session is established.
#[tokio::test]
async fn test_multiple_messages_after_session() {
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let alice_node_id = alice_identity.node_id();
    let bob_node_id = bob_identity.node_id();

    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);

    let network = MockNetwork::new();
    let alice_t = Arc::new(MockTransport::new(alice_node_id, network.clone()).await);
    let bob_t = Arc::new(MockTransport::new(bob_node_id, network.clone()).await);

    alice.transport_manager.add_transport(alice_t.clone()).await;
    bob.transport_manager.add_transport(bob_t.clone()).await;

    alice.start().await.unwrap();
    bob.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    network
        .add_link(alice_node_id, bob_node_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // First message establishes session
    let msg1 = alice
        .send_message(bob_node_id, b"msg1", ContentType::Text)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(bob.db.get_message(&msg1).is_ok(), "Bob should get msg1");

    // Subsequent messages should use the established session directly
    let msg2 = alice
        .send_message(bob_node_id, b"msg2", ContentType::Text)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let bob_msg2 = bob.db.get_message(&msg2);
    assert!(bob_msg2.is_ok(), "Bob should receive msg2");
    assert_eq!(bob_msg2.unwrap().plaintext, b"msg2");

    let msg3 = alice
        .send_message(bob_node_id, b"msg3", ContentType::Text)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let bob_msg3 = bob.db.get_message(&msg3);
    assert!(bob_msg3.is_ok(), "Bob should receive msg3");
    assert_eq!(bob_msg3.unwrap().plaintext, b"msg3");

    // Bob replies back
    let reply1 = bob
        .send_message(alice_node_id, b"reply1", ContentType::Text)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let alice_reply1 = alice.db.get_message(&reply1);
    assert!(alice_reply1.is_ok(), "Alice should receive reply1");
    assert_eq!(alice_reply1.unwrap().plaintext, b"reply1");

    // Verify conversation has messages from both sides
    let convo = alice
        .db
        .get_conversation(&alice_node_id, &bob_node_id, 100, 0)
        .unwrap();
    assert!(
        convo.len() >= 4,
        "Should have at least 4 messages (3 sent + 1 received), got {}",
        convo.len()
    );

    alice.stop().await;
    bob.stop().await;
}

/// Test beacon broadcasting and contact auto-creation.
#[tokio::test]
async fn test_beacon_creates_contacts() {
    // Use a short beacon interval for testing
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let alice_node_id = alice_identity.node_id();
    let bob_node_id = bob_identity.node_id();

    let alice_config = NodeConfig {
        display_name: "Alice".to_string(),
        beacon_interval_secs: 1,
        ..Default::default()
    };

    let bob_config = NodeConfig {
        display_name: "Bob".to_string(),
        beacon_interval_secs: 1,
        ..Default::default()
    };

    let alice_db = Database::open_in_memory().unwrap();
    let bob_db = Database::open_in_memory().unwrap();

    let alice = Node::new(alice_config, alice_db, alice_identity);
    let bob = Node::new(bob_config, bob_db, bob_identity);

    let network = MockNetwork::new();
    let alice_t = Arc::new(MockTransport::new(alice_node_id, network.clone()).await);
    let bob_t = Arc::new(MockTransport::new(bob_node_id, network.clone()).await);

    alice.transport_manager.add_transport(alice_t.clone()).await;
    bob.transport_manager.add_transport(bob_t.clone()).await;

    alice.start().await.unwrap();
    bob.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect nodes
    network
        .add_link(alice_node_id, bob_node_id, MockLinkConfig::default())
        .await;

    // Wait for at least one beacon to be exchanged (beacon interval = 1s)
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Bob should have a contact record for Alice (from her beacon)
    let alice_contact = bob.db.get_contact(&alice_node_id);
    assert!(
        alice_contact.is_ok(),
        "Bob should have a contact for Alice from beacon"
    );
    let alice_contact = alice_contact.unwrap();
    assert_eq!(alice_contact.display_name, "Alice");
    assert!(alice_contact.last_seen.is_some());

    // Alice should have a contact record for Bob
    let bob_contact = alice.db.get_contact(&bob_node_id);
    assert!(
        bob_contact.is_ok(),
        "Alice should have a contact for Bob from beacon"
    );
    assert_eq!(bob_contact.unwrap().display_name, "Bob");

    alice.stop().await;
    bob.stop().await;
}

/// Test session persistence across SessionManager serialize/deserialize.
#[tokio::test]
async fn test_session_persistence_roundtrip() {
    use mycelium_crypto::session::SessionManager;
    use mycelium_crypto::x3dh::PrekeyState;

    let alice_id = Identity::generate();
    let bob_id = Identity::generate();
    let bob_node_id = bob_id.node_id();

    let mut bob_prekey_state = PrekeyState::new(bob_id);
    bob_prekey_state.generate_one_time_prekeys(5);
    let bob_bundle = bob_prekey_state.bundle();

    let mut sm = SessionManager::new();
    let init_result = sm
        .initiate_session(&alice_id, bob_node_id, &bob_bundle)
        .unwrap();

    // Serialize and deserialize
    let session = sm.all_sessions().next().unwrap().1;
    let bytes = SessionManager::serialize_session(session);
    let restored = SessionManager::deserialize_session(&bytes).unwrap();

    assert_eq!(restored.peer_id, bob_node_id);
    assert_eq!(restored.safety_number, init_result.safety_number);
    assert!(!restored.is_verified);
}

/// Test prekey state persistence roundtrip.
#[tokio::test]
async fn test_prekey_state_persistence() {
    use mycelium_crypto::x3dh::PrekeyState;

    let identity = Identity::generate();
    let identity2 = Identity::from_bytes(&identity.to_bytes()).unwrap();

    let mut state = PrekeyState::new(identity);
    state.generate_one_time_prekeys(50);
    let original_spk_id = state.signed_prekey_id;
    let original_otp_count = state.one_time_prekeys.len();

    // Serialize
    let bytes = state.to_bytes();

    // Deserialize
    let restored = PrekeyState::from_bytes_with_identity(&bytes, identity2).unwrap();

    assert_eq!(restored.signed_prekey_id, original_spk_id);
    assert_eq!(restored.one_time_prekeys.len(), original_otp_count);

    // Verify the restored state can generate valid bundles
    let bundle = restored.bundle();
    assert_eq!(bundle.signed_prekey_id, original_spk_id);
    assert!(bundle.one_time_prekey.is_some());
}

/// Test prekey state persistence to/from DB.
#[tokio::test]
async fn test_prekey_state_db_persistence() {
    use mycelium_crypto::x3dh::PrekeyState;

    let db = Database::open_in_memory().unwrap();
    let identity = Identity::generate();

    let mut state = PrekeyState::new(identity);
    state.generate_one_time_prekeys(10);

    // Save to DB
    let bytes = state.to_bytes();
    db.save_prekey_state_blob(&bytes).unwrap();

    // Load from DB
    let loaded = db.load_prekey_state_blob().unwrap();
    assert_eq!(loaded, bytes);

    let identity2 = Identity::from_bytes(&state.identity.to_bytes()).unwrap();
    let restored = PrekeyState::from_bytes_with_identity(&loaded, identity2).unwrap();
    assert_eq!(restored.signed_prekey_id, state.signed_prekey_id);
    assert_eq!(restored.one_time_prekeys.len(), 10);
}

/// Test prekey cache DB persistence.
#[tokio::test]
async fn test_prekey_cache_persistence() {
    let db = Database::open_in_memory().unwrap();

    let node_id = [0xAA; 32];
    let bundle_data = vec![1, 2, 3, 4, 5];

    db.cache_prekey_bundle(&node_id, &bundle_data).unwrap();

    // Retrieve single
    let retrieved = db.get_cached_prekey_bundle(&node_id).unwrap();
    assert_eq!(retrieved, bundle_data);

    // List all
    let all = db.list_cached_prekey_bundles().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, node_id.to_vec());
    assert_eq!(all[0].1, bundle_data);
}

/// Test vouch persistence with trust graph integration.
#[tokio::test]
async fn test_vouch_persistence_and_trust() {
    use mycelium_crypto::wot::TrustGraph;
    use mycelium_protocol::types::NodeId;
    use mycelium_storage::vouches::VouchRecord;

    let db = Database::open_in_memory().unwrap();

    let alice = NodeId([1u8; 32]);
    let bob = NodeId([2u8; 32]);
    let carol = NodeId([3u8; 32]);

    // Save vouches
    let vouch1 = VouchRecord {
        voucher_id: alice,
        vouchee_id: bob,
        voucher_public_key: vec![0; 32],
        display_name: "Bob".to_string(),
        signature: vec![],
        timestamp: 1000,
    };
    let vouch2 = VouchRecord {
        voucher_id: bob,
        vouchee_id: carol,
        voucher_public_key: vec![0; 32],
        display_name: "Carol".to_string(),
        signature: vec![],
        timestamp: 1001,
    };
    db.save_vouch(&vouch1).unwrap();
    db.save_vouch(&vouch2).unwrap();

    // Rebuild trust graph from DB (simulates node restart)
    let mut tg = TrustGraph::new();
    let vouches = db.list_all_vouches().unwrap();
    for v in &vouches {
        tg.add_vouch(v.voucher_id, v.vouchee_id);
    }

    // Alice trusts Bob directly
    let score_bob = tg.trust_score(&alice, &bob);
    assert!(score_bob.value > 0.0);
    assert_eq!(score_bob.hops, 1);

    // Alice trusts Carol through Bob (2 hops)
    let score_carol = tg.trust_score(&alice, &carol);
    assert!(score_carol.value > 0.0);
    assert_eq!(score_carol.hops, 2);
}
