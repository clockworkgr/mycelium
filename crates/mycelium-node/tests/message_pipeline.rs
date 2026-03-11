//! End-to-end integration test: Two nodes exchange messages via MockTransport.
//!
//! Proves: session establishment, message encryption, routing, decryption,
//! and storage all work together in the full pipeline.

use std::sync::Arc;
use std::time::Duration;

use mycelium_core::transport::mock::{MockLinkConfig, MockNetwork, MockTransport};
use mycelium_crypto::identity::Identity;
use mycelium_node::config::NodeConfig;
use mycelium_node::node::Node;
use mycelium_protocol::types::ContentType;
use mycelium_storage::db::Database;

/// Create a test node with an in-memory DB and identity.
fn make_node(identity: Identity) -> Node {
    let config = NodeConfig::default();
    let db = Database::open_in_memory().expect("in-memory DB");
    Node::new(config, db, identity)
}

#[tokio::test]
async fn test_two_nodes_exchange_messages() {
    // Setup: two identities
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();

    let alice_node_id = alice_identity.node_id();
    let bob_node_id = bob_identity.node_id();

    // Create nodes
    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);

    // Create a mock network and connect them
    let network = MockNetwork::new();
    let alice_transport = Arc::new(MockTransport::new(alice_node_id, network.clone()).await);
    let bob_transport = Arc::new(MockTransport::new(bob_node_id, network.clone()).await);

    alice
        .transport_manager
        .add_transport(alice_transport.clone())
        .await;
    bob.transport_manager
        .add_transport(bob_transport.clone())
        .await;

    // Start both nodes
    alice.start().await.expect("alice start");
    bob.start().await.expect("bob start");

    // Allow event loops to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create a bidirectional link (triggers NeighborDiscovered on both sides)
    network
        .add_link(alice_node_id, bob_node_id, MockLinkConfig::default())
        .await;

    // Wait for neighbor discovery events to propagate
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Step 1: Alice sends a message to Bob.
    // Since there's no session, this will:
    //   1. Queue the message
    //   2. Send a PrekeyRequest to Bob
    //   3. Bob responds with PrekeyResponse
    //   4. Alice receives the response, initiates session, sends SessionInit + encrypted msg
    //   5. Bob accepts session, decrypts the message
    let msg_id = alice
        .send_message(bob_node_id, b"Hello Bob!", ContentType::Text)
        .await
        .expect("alice send");

    // Wait for the full prekey exchange + session init + message delivery
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify: Bob should have received the message in his DB
    let bob_msg = bob.db.get_message(&msg_id);
    assert!(
        bob_msg.is_ok(),
        "Bob should have the message in DB, got: {:?}",
        bob_msg.err()
    );
    let bob_msg = bob_msg.unwrap();
    assert_eq!(bob_msg.plaintext, b"Hello Bob!");
    assert_eq!(bob_msg.source, alice_node_id);
    assert_eq!(bob_msg.destination, bob_node_id);
    assert!(bob_msg.is_incoming);
    assert_eq!(bob_msg.content_type, "text");

    // Step 2: Bob sends a reply to Alice.
    // Bob now has a session with Alice, so this should be direct encrypted message.
    let reply_id = bob
        .send_message(alice_node_id, b"Hi Alice!", ContentType::Text)
        .await
        .expect("bob send");

    // Wait for delivery
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Verify: Alice should have received the reply
    let alice_msg = alice.db.get_message(&reply_id);
    assert!(
        alice_msg.is_ok(),
        "Alice should have Bob's reply, got: {:?}",
        alice_msg.err()
    );
    let alice_msg = alice_msg.unwrap();
    assert_eq!(alice_msg.plaintext, b"Hi Alice!");
    assert_eq!(alice_msg.source, bob_node_id);
    assert!(alice_msg.is_incoming);

    // Step 3: Verify conversation query works
    let alice_convo = alice
        .db
        .get_conversation(&alice_node_id, &bob_node_id, 100, 0)
        .expect("conversation query");
    assert!(
        alice_convo.len() >= 2,
        "Alice should have 2+ messages in conversation, got {}",
        alice_convo.len()
    );

    // Cleanup
    alice.stop().await;
    bob.stop().await;
}

#[tokio::test]
async fn test_send_to_self_fails() {
    let identity = Identity::generate();
    let node = make_node(identity);
    let self_id = node.node_id;

    let result = node
        .send_message(self_id, b"hello self", ContentType::Text)
        .await;
    assert!(result.is_err(), "Sending to self should fail");
}
