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

/// A ratchet advance that cannot be persisted must abort the send.
///
/// `encrypt_for` moves the sending chain forward in memory. If that advance is
/// lost — a failed database write — and the ciphertext has already gone out,
/// the next start reloads the old chain position and encrypts a different
/// plaintext at the same position, re-using an AES-GCM nonce under the same
/// key. The send must fail instead, leaving nothing on the wire.
///
/// Regression test for ROADMAP T-07. Before the fix `persist_session` discarded
/// the storage error with `let _ = db.save_session(..)` and the message was
/// transmitted anyway, so Bob received it and `send_message` returned `Ok`.
#[tokio::test]
async fn test_send_fails_when_ratchet_state_cannot_be_persisted() {
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let alice_node_id = alice_identity.node_id();
    let bob_node_id = bob_identity.node_id();

    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);

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

    alice.start().await.expect("alice start");
    bob.start().await.expect("bob start");
    tokio::time::sleep(Duration::from_millis(50)).await;
    network
        .add_link(alice_node_id, bob_node_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Establish the session normally first.
    let first = alice
        .send_message(bob_node_id, b"establish session", ContentType::Text)
        .await
        .expect("first send");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        bob.db.get_message(&first).is_ok(),
        "precondition: the session must be established and the first message delivered"
    );

    // Break only session persistence. The messages table stays intact, so the
    // send gets as far as encrypting and then fails to store the new state.
    alice
        .db
        .conn()
        .execute_batch("DROP TABLE sessions;")
        .expect("drop sessions table");

    let result = alice
        .send_message(bob_node_id, b"must not be sent", ContentType::Text)
        .await;

    assert!(
        result.is_err(),
        "send must fail when the ratchet advance cannot be persisted, got {:?}",
        result.as_ref().map(|id| id.to_string())
    );

    // And nothing may have reached Bob.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let bob_messages = bob
        .db
        .get_conversation(&bob_node_id, &alice_node_id, 100, 0)
        .expect("bob conversation");
    assert!(
        bob_messages
            .iter()
            .all(|m| m.plaintext != b"must not be sent"),
        "Bob must not have received a message whose ratchet state was never persisted"
    );
}

/// Messages queued awaiting a session must not be left pending forever when
/// their ratchet state cannot be persisted.
///
/// `pending_messages` is drained only by an incoming `PrekeyResponse`. A later
/// send takes the session or cached-bundle branch and never touches the queue,
/// so a requeue on persistence failure stranded messages indefinitely while
/// `send_message` had already returned `Ok`. They are now marked `failed`.
///
/// Regression test for Codex round 3 finding #1 on ROADMAP T-07.
#[tokio::test]
async fn test_queued_messages_fail_when_session_cannot_be_persisted() {
    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let alice_node_id = alice_identity.node_id();
    let bob_node_id = bob_identity.node_id();

    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);

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

    alice.start().await.expect("alice start");
    bob.start().await.expect("bob start");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // No link yet: the message is queued and the prekey request has nowhere to
    // go, so nothing has reached Bob when we break storage below.
    let msg_id = alice
        .send_message(bob_node_id, b"never sendable", ContentType::Text)
        .await
        .expect("send is accepted and queued");

    alice
        .db
        .conn()
        .execute_batch("DROP TABLE sessions;")
        .expect("drop sessions table");

    // Now connect them. Alice's prekey request goes out, Bob answers, and
    // Alice tries to establish the session — which cannot be persisted.
    network
        .add_link(alice_node_id, bob_node_id, MockLinkConfig::default())
        .await;

    let mut status = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        status = alice.db.get_message(&msg_id).unwrap().status;
        if status == "failed" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(
        status, "failed",
        "a message whose session could not be persisted must be reported failed, \
         not left pending forever"
    );

    // And Bob must not have it.
    let bob_messages = bob
        .db
        .get_conversation(&bob_node_id, &alice_node_id, 100, 0)
        .expect("bob conversation");
    assert!(
        bob_messages
            .iter()
            .all(|m| m.plaintext != b"never sendable"),
        "Bob must not have received it"
    );
}

/// A peer that rotated its signed prekey must still accept a `SessionInit`
/// built from the bundle we cached before the rotation.
///
/// End-to-end counterpart to the `x3dh` unit tests for ROADMAP T-06. Before
/// the fix the responder ran X3DH — and seeded the Double Ratchet — with
/// whichever signed prekey was current, ignoring the `signed_prekey_id` the
/// initiator put on the wire, so the AEAD tag failed and the message was
/// silently dropped.
#[tokio::test]
async fn test_session_from_bundle_cached_before_rotation() {
    use std::time::Instant;

    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let alice_node_id = alice_identity.node_id();
    let bob_node_id = bob_identity.node_id();

    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);

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

    alice.start().await.expect("alice start");
    bob.start().await.expect("bob start");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Alice caches Bob's bundle...
    let cached = bob.prekey_state.read().await.bundle();
    let cached_spk_id = cached.signed_prekey_id;
    alice
        .prekey_cache
        .write()
        .await
        .insert(bob_node_id, (cached, Instant::now()));

    // ...and then Bob rotates.
    bob.prekey_state.write().await.rotate_signed_prekey();
    assert_ne!(
        bob.prekey_state.read().await.signed_prekey_id,
        cached_spk_id,
        "precondition: the rotation must change the id"
    );

    network
        .add_link(alice_node_id, bob_node_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let msg_id = alice
        .send_message(bob_node_id, b"across a rotation", ContentType::Text)
        .await
        .expect("alice send");

    let mut delivered = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if bob.db.get_message(&msg_id).is_ok() {
            delivered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        delivered,
        "a session built from a bundle cached before the rotation must still work"
    );
    assert_eq!(
        bob.db.get_message(&msg_id).unwrap().plaintext,
        b"across a rotation"
    );
}

/// A bundle older than the retention window must produce a rejection that
/// makes the initiator discard it, rather than retrying against it forever.
#[tokio::test]
async fn test_stale_bundle_is_rejected_and_discarded() {
    use std::time::Instant;

    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let alice_node_id = alice_identity.node_id();
    let bob_node_id = bob_identity.node_id();

    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);

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

    alice.start().await.expect("alice start");
    bob.start().await.expect("bob start");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let cached = bob.prekey_state.read().await.bundle();
    alice
        .prekey_cache
        .write()
        .await
        .insert(bob_node_id, (cached, Instant::now()));

    // Rotate past the retention window, so the cached signed prekey is gone.
    {
        let mut ps = bob.prekey_state.write().await;
        for _ in 0..=mycelium_crypto::x3dh::MAX_RETAINED_SIGNED_PREKEYS {
            ps.rotate_signed_prekey();
        }
    }

    network
        .add_link(alice_node_id, bob_node_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let doomed_id = alice
        .send_message(bob_node_id, b"doomed", ContentType::Text)
        .await
        .expect("send is accepted locally");

    // Bob refuses and says so; Alice drops the dead bundle so her next attempt
    // re-requests a fresh one.
    let mut discarded = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if !alice.prekey_cache.read().await.contains_key(&bob_node_id) {
            discarded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        discarded,
        "a SessionReject must make the initiator discard the unusable cached bundle"
    );

    // And the message that died with the handshake must be reported, not left
    // claiming "sent". The first version took the message ids after
    // `remove_session` had already cleared them, so nothing was ever marked.
    let mut status = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        status = alice.db.get_message(&doomed_id).unwrap().status;
        if status == "failed" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        status, "failed",
        "a message sent under a rejected handshake must be reported failed"
    );
}

/// A forged `SessionReject` must not tear down a session the peer has used.
///
/// Round 5 finding #1: the first version of this handler keyed off "did we
/// initiate within 60 seconds", so a forgery could kill a working session
/// established moments earlier. Confirmation is now "we have successfully
/// decrypted something from this peer", which only their ratchet could have
/// produced.
#[tokio::test]
async fn test_forged_reject_cannot_tear_down_a_used_session() {
    use mycelium_protocol::codec::Envelope;
    use mycelium_protocol::types::{MessageFlags, MessageId, ProtocolVersion};
    use mycelium_protocol::wire::{self, SessionRejectReason};

    let alice_identity = Identity::generate();
    let bob_identity = Identity::generate();
    let alice_node_id = alice_identity.node_id();
    let bob_node_id = bob_identity.node_id();
    let bob_public_key = bob_identity.public_key_bytes();

    let alice = make_node(alice_identity);
    let bob = make_node(bob_identity);

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

    alice.start().await.expect("alice start");
    bob.start().await.expect("bob start");
    tokio::time::sleep(Duration::from_millis(50)).await;
    network
        .add_link(alice_node_id, bob_node_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Establish a session and get a reply, so Alice has decrypted something
    // from Bob and the handshake is confirmed.
    alice
        .send_message(bob_node_id, b"hello", ContentType::Text)
        .await
        .expect("alice send");
    tokio::time::sleep(Duration::from_millis(600)).await;
    let reply_id = bob
        .send_message(alice_node_id, b"hi back", ContentType::Text)
        .await
        .expect("bob reply");
    let mut confirmed = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if alice.db.get_message(&reply_id).is_ok() {
            confirmed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        confirmed,
        "precondition: Alice must have decrypted Bob's reply"
    );

    // Now inject a reject that looks like it came from Bob, well inside the
    // 60 s window the old implementation trusted.
    let forged = Envelope {
        source: bob_node_id,
        destination: alice_node_id,
        message_id: MessageId::random(),
        ttl: 10,
        hop_count: 0,
        flags: MessageFlags::SYSTEM,
        lamport_clock: 0,
        device_timestamp: 0,
        protocol_version: ProtocolVersion::CURRENT,
        payload: wire::serialize_session_reject(
            SessionRejectReason::StaleSignedPrekey,
            &bob_public_key,
        ),
    };
    // Precondition: Alice cached Bob's bundle during the handshake. Acting on
    // the reject would discard it, so it is the observable the teardown
    // cannot hide — delivery alone is not, because Alice would silently
    // re-handshake and the message would arrive anyway.
    assert!(
        alice.prekey_cache.read().await.contains_key(&bob_node_id),
        "precondition: Alice should have cached Bob's prekey bundle"
    );

    network
        .deliver(bob_node_id, alice_node_id, forged.serialize())
        .await
        .expect("deliver forged reject");
    tokio::time::sleep(Duration::from_millis(400)).await;

    assert!(
        alice.prekey_cache.read().await.contains_key(&bob_node_id),
        "a forged SessionReject must be ignored for a confirmed session: the cached \
         bundle was discarded, which means the session was torn down too"
    );

    // And traffic still flows.
    let after_id = alice
        .send_message(bob_node_id, b"still working", ContentType::Text)
        .await
        .expect("alice send after forged reject");
    let mut still_working = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if bob.db.get_message(&after_id).is_ok() {
            still_working = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(still_working, "traffic must continue after a forged reject");
}
