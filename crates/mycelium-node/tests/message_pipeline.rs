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

/// Neither a forged `SessionReject` nor a late authentic one may tear down a
/// session the peer has used.
///
/// Round 5 finding #1: the first version of this handler keyed off "did we
/// initiate within 60 seconds", so a forgery could kill a working session
/// established moments earlier. Confirmation is now "we have successfully
/// decrypted something from this peer", which only their ratchet could have
/// produced. Since T-35 a reject is also signed, so this covers both an
/// authentic reject that arrives late — what DTN handshakes do routinely —
/// and one whose signature is garbage.
#[tokio::test]
async fn test_a_reject_cannot_tear_down_a_used_session() {
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
    let init_id = alice
        .send_message(bob_node_id, b"hello", ContentType::Text)
        .await
        .expect("alice send");
    // A reject names the transcript of the SessionInit it refuses, so the
    // test needs the one Alice recorded. With no cached bundle her first send
    // only asks for one, and the SessionInit goes out when Bob's
    // PrekeyResponse arrives — so wait for it, and read it before Bob's reply
    // confirms the handshake and clears it.
    let mut transcript = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        transcript = alice
            .session_manager
            .read()
            .await
            .handshake_transcript(&bob_node_id);
        if transcript.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let transcript = transcript.expect("Alice should have sent a SessionInit");
    let _ = init_id;
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

    // An authentic reject, signed by Bob over the very SessionInit Alice
    // sent, arriving after she has decrypted his reply.
    let reason = SessionRejectReason::StaleSignedPrekey;
    let reject_envelope = |payload: Vec<u8>| Envelope {
        source: bob_node_id,
        destination: alice_node_id,
        message_id: MessageId::random(),
        ttl: 10,
        hop_count: 0,
        flags: MessageFlags::SYSTEM,
        lamport_clock: 0,
        device_timestamp: 0,
        protocol_version: ProtocolVersion::CURRENT,
        payload,
    };
    let authentic = reject_envelope(wire::serialize_session_reject(
        reason,
        &bob_public_key,
        &transcript,
        &mycelium_crypto::reject::sign_reject(&bob.identity, &transcript, &alice_node_id, reason),
    ));
    // And a forgery: Bob's public key, but a signature nobody made.
    let forged = reject_envelope(wire::serialize_session_reject(
        reason,
        &bob_public_key,
        &transcript,
        &[0u8; 64],
    ));
    // Precondition: Alice cached Bob's bundle during the handshake. Acting on
    // the reject would discard it, so it is the observable the teardown
    // cannot hide — delivery alone is not, because Alice would silently
    // re-handshake and the message would arrive anyway.
    assert!(
        alice.prekey_cache.read().await.contains_key(&bob_node_id),
        "precondition: Alice should have cached Bob's prekey bundle"
    );

    for (envelope, what) in [(authentic, "authentic but late"), (forged, "forged")] {
        network
            .deliver(bob_node_id, alice_node_id, envelope.serialize())
            .await
            .expect("deliver reject");
        tokio::time::sleep(Duration::from_millis(400)).await;

        assert!(
            alice.prekey_cache.read().await.contains_key(&bob_node_id),
            "an {} SessionReject must be ignored for a confirmed session: the cached \
             bundle was discarded, which means the session was torn down too",
            what
        );
    }

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

/// A forged `SessionReject` must be ignored even while the handshake it names
/// is unconfirmed — the case the signature exists for (T-35).
///
/// Before rejects were signed, this was the whole attack: a reject is acted on
/// precisely when a handshake is outstanding, so anyone who knew a peer had
/// just initiated could discard its cached bundle and fail its message by
/// naming that peer. The authentic reject at the end is the control: the same
/// envelope, signed, does act.
#[tokio::test]
async fn test_a_forged_reject_is_ignored_while_the_handshake_is_unconfirmed() {
    use std::time::Instant;

    use mycelium_crypto::x3dh::PrekeyState;
    use mycelium_protocol::codec::Envelope;
    use mycelium_protocol::types::{MessageFlags, MessageId, ProtocolVersion};
    use mycelium_protocol::wire::{self, SessionRejectReason};

    let alice_identity = Identity::generate();
    let alice_node_id = alice_identity.node_id();
    // A peer that never runs: Alice only needs a bundle to handshake against,
    // and nothing must reply, or the handshake would be confirmed.
    let peer_identity = Identity::generate();
    let peer_node_id = peer_identity.node_id();

    let alice = make_node(alice_identity);
    let network = MockNetwork::new();
    let alice_transport = Arc::new(MockTransport::new(alice_node_id, network.clone()).await);
    let peer_transport = Arc::new(MockTransport::new(peer_node_id, network.clone()).await);
    alice
        .transport_manager
        .add_transport(alice_transport.clone())
        .await;
    let _ = peer_transport;
    alice.start().await.expect("alice start");
    network
        .add_link(alice_node_id, peer_node_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut peer_state = PrekeyState::new(Identity::from_bytes(&peer_identity.to_bytes()).unwrap());
    peer_state.generate_one_time_prekeys(2);
    alice
        .prekey_cache
        .write()
        .await
        .insert(peer_node_id, (peer_state.bundle(), Instant::now()));

    let doomed_id = alice
        .send_message(peer_node_id, b"outstanding", ContentType::Text)
        .await
        .expect("send is accepted locally");
    assert!(
        alice.prekey_cache.read().await.contains_key(&peer_node_id),
        "precondition: the bundle Alice handshook against is cached"
    );
    let transcript = alice
        .session_manager
        .read()
        .await
        .handshake_transcript(&peer_node_id)
        .expect("Alice recorded her SessionInit");

    let reason = SessionRejectReason::DecryptFailed;
    let reject = |signature: [u8; 64]| Envelope {
        source: peer_node_id,
        destination: alice_node_id,
        message_id: MessageId::random(),
        ttl: 10,
        hop_count: 0,
        flags: MessageFlags::SYSTEM,
        lamport_clock: 0,
        device_timestamp: 0,
        protocol_version: ProtocolVersion::CURRENT,
        payload: wire::serialize_session_reject(
            reason,
            &peer_identity.public_key_bytes(),
            &transcript,
            &signature,
        ),
    };

    network
        .deliver(peer_node_id, alice_node_id, reject([0u8; 64]).serialize())
        .await
        .expect("deliver forged reject");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        alice.prekey_cache.read().await.contains_key(&peer_node_id),
        "a reject with a signature nobody made must not discard the bundle"
    );
    assert_ne!(
        alice.db.get_message(&doomed_id).unwrap().status,
        "failed",
        "a forged reject must not report the message dead"
    );

    // The indirect forgery, which is why the signature covers a transcript
    // and not the envelope's message id. An attacker who watched Alice's
    // SessionInit can send the peer a *malformed* init carrying Alice's id,
    // source and public key — all cleartext — and the peer will sign a
    // genuine rejection of it. The signature is real; the trigger was not.
    // Alice must refuse it because the transcript is not the one she sent.
    let elsewhere = mycelium_crypto::reject::init_transcript(b"an init Alice never sent");
    let provoked = Envelope {
        source: peer_node_id,
        destination: alice_node_id,
        message_id: MessageId::random(),
        ttl: 10,
        hop_count: 0,
        flags: MessageFlags::SYSTEM,
        lamport_clock: 0,
        device_timestamp: 0,
        protocol_version: ProtocolVersion::CURRENT,
        payload: wire::serialize_session_reject(
            reason,
            &peer_identity.public_key_bytes(),
            &elsewhere,
            &mycelium_crypto::reject::sign_reject(
                &peer_identity,
                &elsewhere,
                &alice_node_id,
                reason,
            ),
        ),
    };
    network
        .deliver(peer_node_id, alice_node_id, provoked.serialize())
        .await
        .expect("deliver provoked reject");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        alice.prekey_cache.read().await.contains_key(&peer_node_id),
        "a validly signed rejection of a SessionInit Alice never sent must be ignored"
    );
    assert_ne!(
        alice.db.get_message(&doomed_id).unwrap().status,
        "failed",
        "and must not report her message dead"
    );

    // The control: the same reject, signed by the peer it claims to be from.
    let signature =
        mycelium_crypto::reject::sign_reject(&peer_identity, &transcript, &alice_node_id, reason);
    network
        .deliver(peer_node_id, alice_node_id, reject(signature).serialize())
        .await
        .expect("deliver authentic reject");
    let mut acted = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if !alice.prekey_cache.read().await.contains_key(&peer_node_id) {
            acted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        acted,
        "an authentic reject must still discard the unusable bundle"
    );
    assert_eq!(
        alice.db.get_message(&doomed_id).unwrap().status,
        "failed",
        "and report the message that died with the handshake"
    );
}

/// A replayed `SessionInit` must be answered with silence, not a signed
/// rejection of it (T-35, ADR-012).
///
/// Duplicate detection keys on the envelope's `message_id`, which the
/// transcript does not cover, so a relay can re-deliver an init we accepted
/// under a fresh id. Its one-time prekey is spent and the ratchet has moved
/// past its message, so accepting fails — and the rejection that used to
/// follow was a *valid* rejection of an init the peer really sent, which the
/// peer would act on: exactly the teardown the signature was meant to prevent.
#[tokio::test]
async fn test_a_replayed_session_init_draws_no_rejection() {
    use mycelium_crypto::session::SessionManager;
    use mycelium_protocol::codec::Envelope;
    use mycelium_protocol::types::{MessageFlags, MessageId, ProtocolVersion};
    use mycelium_protocol::wire::{
        EncryptedPayload, SessionInitPayload, WirePayloadType, WireRatchetHeader,
    };

    let alice_identity = Identity::generate();
    let alice_node_id = alice_identity.node_id();
    let peer_identity = Identity::generate();
    let peer_node_id = peer_identity.node_id();

    let alice = make_node(alice_identity);
    let network = MockNetwork::new();
    let alice_transport = Arc::new(MockTransport::new(alice_node_id, network.clone()).await);
    alice
        .transport_manager
        .add_transport(alice_transport.clone())
        .await;
    alice.start().await.expect("alice start");

    // The peer is only a mailbox here: registering its own channel is how the
    // test sees what Alice sends back.
    let (peer_tx, mut peer_rx) = tokio::sync::broadcast::channel(64);
    network.register_node(peer_node_id, peer_tx).await;
    network
        .add_link(peer_node_id, alice_node_id, MockLinkConfig::default())
        .await;
    network
        .add_link(alice_node_id, peer_node_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Build a genuine SessionInit from the peer to Alice.
    let alice_bundle = alice.prekey_state.read().await.bundle();
    let mut peer_sessions = SessionManager::new();
    let init_result = peer_sessions
        .initiate_session(&peer_identity, alice_node_id, &alice_bundle, true)
        .expect("peer initiates");
    // Same associated data the node builds: source, destination and the
    // content type, which is authenticated so a relay cannot retype a message
    // (T-35, ADR-012).
    let ad = {
        let mut buf = Vec::with_capacity(65);
        buf.extend_from_slice(peer_node_id.as_bytes());
        buf.extend_from_slice(alice_node_id.as_bytes());
        buf.push(0);
        buf
    };
    let (header, ciphertext) = peer_sessions
        .encrypt_for(&alice_node_id, b"hello", &ad)
        .expect("peer encrypts");
    let init_payload = SessionInitPayload {
        ephemeral_public: init_result.ephemeral_public,
        identity_key: peer_identity.public_key_bytes(),
        signed_prekey_id: init_result.used_signed_prekey_id,
        one_time_prekey_id: init_result.used_one_time_prekey_id,
        encrypted_payload: EncryptedPayload {
            content_type: 0,
            header: WireRatchetHeader {
                dh_public: header.dh_public,
                previous_chain_length: header.previous_chain_length,
                message_number: header.message_number,
            },
            ciphertext,
        }
        .serialize(),
    }
    .serialize();

    let envelope = |payload: Vec<u8>| Envelope {
        source: peer_node_id,
        destination: alice_node_id,
        message_id: MessageId::random(),
        ttl: 10,
        hop_count: 0,
        flags: MessageFlags::SYSTEM,
        lamport_clock: 1,
        device_timestamp: 0,
        protocol_version: ProtocolVersion::CURRENT,
        payload,
    };

    // Accepted once.
    network
        .deliver(
            peer_node_id,
            alice_node_id,
            envelope(init_payload.clone()).serialize(),
        )
        .await
        .expect("deliver init");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        alice
            .session_manager
            .read()
            .await
            .has_session(&peer_node_id),
        "precondition: Alice accepted the SessionInit"
    );

    // Replayed under a fresh envelope id, which is what duplicate detection
    // keys on.
    network
        .deliver(
            peer_node_id,
            alice_node_id,
            envelope(init_payload).serialize(),
        )
        .await
        .expect("deliver replay");
    tokio::time::sleep(Duration::from_millis(400)).await;

    let mut rejects = 0;
    while let Ok(event) = peer_rx.try_recv() {
        if let mycelium_core::transport::TransportEvent::DataReceived { data, .. } = event {
            if let Ok(env) = Envelope::deserialize(&data) {
                if env.payload.first().copied() == Some(WirePayloadType::SessionReject as u8) {
                    rejects += 1;
                }
            }
        }
    }
    assert_eq!(
        rejects, 0,
        "a replayed SessionInit must draw no rejection: a valid one would tear \
         down the peer's live handshake"
    );

    // The control, so the silence above is not just a test that cannot see
    // rejections. It has to come from a peer Alice holds *no* session with:
    // under ADR-015 she rejects only then, because with a session in place a
    // failure is as likely to be a replay or a tie-break loser's init, and
    // signing a valid rejection of an init the peer really sent is what tore
    // down live handshakes. A tampered copy from the same peer therefore draws
    // nothing — which is the rule, not a gap.
    let stranger_identity = Identity::generate();
    let stranger_node_id = stranger_identity.node_id();
    let (stranger_tx, mut stranger_rx) = tokio::sync::broadcast::channel(64);
    network.register_node(stranger_node_id, stranger_tx).await;
    network
        .add_link(stranger_node_id, alice_node_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let alice_bundle = alice.prekey_state.read().await.bundle();
    let mut stranger_sessions = SessionManager::new();
    let stranger_init = stranger_sessions
        .initiate_session(&stranger_identity, alice_node_id, &alice_bundle, true)
        .expect("stranger initiates");
    let ad = {
        let mut buf = Vec::with_capacity(65);
        buf.extend_from_slice(stranger_node_id.as_bytes());
        buf.extend_from_slice(alice_node_id.as_bytes());
        buf.push(0);
        buf
    };
    let (header, ciphertext) = stranger_sessions
        .encrypt_for(&alice_node_id, b"hello", &ad)
        .expect("stranger encrypts");
    let mut tampered_payload = EncryptedPayload {
        content_type: 0,
        header: WireRatchetHeader {
            dh_public: header.dh_public,
            previous_chain_length: header.previous_chain_length,
            message_number: header.message_number,
        },
        ciphertext,
    };
    *tampered_payload.ciphertext.last_mut().unwrap() ^= 0x01;
    let tampered = SessionInitPayload {
        ephemeral_public: stranger_init.ephemeral_public,
        identity_key: stranger_identity.public_key_bytes(),
        signed_prekey_id: stranger_init.used_signed_prekey_id,
        one_time_prekey_id: stranger_init.used_one_time_prekey_id,
        encrypted_payload: tampered_payload.serialize(),
    }
    .serialize();

    let stranger_envelope = Envelope {
        source: stranger_node_id,
        destination: alice_node_id,
        message_id: MessageId::random(),
        ttl: 10,
        hop_count: 0,
        flags: MessageFlags::SYSTEM,
        lamport_clock: 1,
        device_timestamp: 0,
        protocol_version: ProtocolVersion::CURRENT,
        payload: tampered,
    };
    network
        .deliver(
            stranger_node_id,
            alice_node_id,
            stranger_envelope.serialize(),
        )
        .await
        .expect("deliver tampered init");
    tokio::time::sleep(Duration::from_millis(400)).await;
    let mut saw_reject = false;
    while let Ok(event) = stranger_rx.try_recv() {
        if let mycelium_core::transport::TransportEvent::DataReceived { data, .. } = event {
            if let Ok(env) = Envelope::deserialize(&data) {
                if env.payload.first().copied() == Some(WirePayloadType::SessionReject as u8) {
                    saw_reject = true;
                }
            }
        }
    }
    assert!(
        saw_reject,
        "an init Alice refuses from a peer she has no session with must still \
         draw a rejection, or this test proves nothing"
    );
}

/// A `SessionInit` carrying no message still proves the initiator's identity
/// key — `SHA-256(identity_key)` matched its source — so the key must be
/// recorded, as the message-carrying path does. Without it, that peer's
/// emergency co-signatures can never be counted: nothing else on the wire
/// carries the key, so later encrypted traffic does not repair it (ADR-010).
#[tokio::test]
async fn test_a_message_less_session_init_records_the_identity_key() {
    use mycelium_crypto::session::SessionManager;
    use mycelium_protocol::codec::Envelope;
    use mycelium_protocol::types::{MessageFlags, MessageId, ProtocolVersion};
    use mycelium_protocol::wire::SessionInitPayload;

    let alice_identity = Identity::generate();
    let alice_node_id = alice_identity.node_id();
    let peer_identity = Identity::generate();
    let peer_node_id = peer_identity.node_id();

    let alice = make_node(alice_identity);
    let network = MockNetwork::new();
    let alice_transport = Arc::new(MockTransport::new(alice_node_id, network.clone()).await);
    alice
        .transport_manager
        .add_transport(alice_transport.clone())
        .await;
    alice.start().await.expect("alice start");

    let (peer_tx, _peer_rx) = tokio::sync::broadcast::channel(64);
    network.register_node(peer_node_id, peer_tx).await;
    network
        .add_link(peer_node_id, alice_node_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        alice.db.get_contact_identity_key(&peer_node_id).is_none(),
        "no key for the peer before the handshake"
    );

    // The signed-prekey-only variant, which is the only form a message-less
    // init may take: with no message to authenticate the initiator there is
    // nothing to justify spending a one-time prekey, so an init that names one
    // is refused (ADR-015). The handshake pays for that with its
    // one-time-prekey forward secrecy.
    let alice_bundle = {
        let mut bundle = alice.prekey_state.read().await.bundle();
        bundle.one_time_prekey = None;
        bundle.one_time_prekey_id = None;
        bundle
    };
    let mut peer_sessions = SessionManager::new();
    let init_result = peer_sessions
        .initiate_session(&peer_identity, alice_node_id, &alice_bundle, false)
        .expect("peer initiates");
    assert!(init_result.used_one_time_prekey_id.is_none());
    let init_payload = SessionInitPayload {
        ephemeral_public: init_result.ephemeral_public,
        identity_key: peer_identity.public_key_bytes(),
        signed_prekey_id: init_result.used_signed_prekey_id,
        one_time_prekey_id: init_result.used_one_time_prekey_id,
        // No enclosed message: the path this test is about.
        encrypted_payload: Vec::new(),
    }
    .serialize();

    // `SessionInitPayload::serialize` already carries the type byte.
    let envelope = Envelope {
        source: peer_node_id,
        destination: alice_node_id,
        message_id: MessageId::random(),
        ttl: 10,
        hop_count: 0,
        flags: MessageFlags::SYSTEM,
        lamport_clock: 1,
        device_timestamp: 0,
        protocol_version: ProtocolVersion::CURRENT,
        payload: init_payload,
    };
    network
        .deliver(peer_node_id, alice_node_id, envelope.serialize())
        .await
        .expect("delivered");
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        alice.db.get_contact_identity_key(&peer_node_id),
        Some(peer_identity.public_key_bytes()),
        "the key proved by a message-less init must be recorded"
    );

    alice.stop().await;
}

/// A `SessionInit` whose nested payload is not an `EncryptedMessage` is
/// refused outright, not treated as carrying no message.
///
/// The message-less path installs a session with nothing proving the
/// initiator sent the init, which is only acceptable because such an init
/// carries nothing at all. A non-empty payload of an unknown type that fell
/// through to that path would hand a forgery the unauthenticated route while
/// claiming to carry a message (ADR-015).
#[tokio::test]
async fn test_a_session_init_with_an_unknown_nested_type_is_refused() {
    use mycelium_crypto::session::SessionManager;
    use mycelium_protocol::codec::Envelope;
    use mycelium_protocol::types::{MessageFlags, MessageId, ProtocolVersion};
    use mycelium_protocol::wire::{SessionInitPayload, WirePayloadType};

    let alice_identity = Identity::generate();
    let alice_node_id = alice_identity.node_id();
    let peer_identity = Identity::generate();
    let peer_node_id = peer_identity.node_id();

    let alice = make_node(alice_identity);
    let network = MockNetwork::new();
    let alice_transport = Arc::new(MockTransport::new(alice_node_id, network.clone()).await);
    alice
        .transport_manager
        .add_transport(alice_transport.clone())
        .await;
    alice.start().await.expect("alice start");

    let (peer_tx, _peer_rx) = tokio::sync::broadcast::channel(64);
    network.register_node(peer_node_id, peer_tx).await;
    network
        .add_link(peer_node_id, alice_node_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Signed-prekey-only, so the nested type is the *only* thing wrong with
    // this init: an init naming a one-time prekey is refused by the
    // message-less path on its own, which would make this test pass without
    // the nested-type check doing anything.
    let alice_bundle = {
        let mut bundle = alice.prekey_state.read().await.bundle();
        bundle.one_time_prekey = None;
        bundle.one_time_prekey_id = None;
        bundle
    };
    let mut peer_sessions = SessionManager::new();
    let init_result = peer_sessions
        .initiate_session(&peer_identity, alice_node_id, &alice_bundle, true)
        .expect("peer initiates");
    assert!(init_result.used_one_time_prekey_id.is_none());

    // A well-formed init in every respect except the nested type: a
    // `GroupMessage` where an `EncryptedMessage` belongs.
    let init_payload = SessionInitPayload {
        ephemeral_public: init_result.ephemeral_public,
        identity_key: peer_identity.public_key_bytes(),
        signed_prekey_id: init_result.used_signed_prekey_id,
        one_time_prekey_id: init_result.used_one_time_prekey_id,
        encrypted_payload: vec![WirePayloadType::GroupMessage as u8, 1, 2, 3],
    }
    .serialize();

    let envelope = Envelope {
        source: peer_node_id,
        destination: alice_node_id,
        message_id: MessageId::random(),
        ttl: 10,
        hop_count: 0,
        flags: MessageFlags::SYSTEM,
        lamport_clock: 1,
        device_timestamp: 0,
        protocol_version: ProtocolVersion::CURRENT,
        payload: init_payload,
    };
    network
        .deliver(peer_node_id, alice_node_id, envelope.serialize())
        .await
        .expect("delivered");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The message-less path records the identity key it proved and installs a
    // session; neither may have happened here.
    assert!(
        alice.db.get_contact_identity_key(&peer_node_id).is_none(),
        "an init with an unknown nested type must not reach the \
         unauthenticated message-less path"
    );
    assert!(
        !alice
            .session_manager
            .read()
            .await
            .has_session(&peer_node_id),
        "and no session may be installed for it"
    );

    alice.stop().await;
}

/// A replay of the `SessionInit` we discarded under ADR-007's tie-break must
/// not install the session we discarded.
///
/// The tie-break winner decrypts the loser's first message and keeps its own
/// session. Spending the one-time prekey on authentication makes a replay fail
/// — but only for an init that named one. A **signed-prekey-only** loser spends
/// nothing, and once the 60-second initiation window has passed (or a restart
/// has forgotten it) the replay takes the ordinary accept path, authenticates
/// against the retained signed prekey, and replaces a working session with the
/// one both sides had agreed to abandon. The winner therefore records the init
/// it answered and discarded (ADR-015).
///
/// What this test carries on its own is the wiring: that the winner makes that
/// record, in the right place and under the lock that answered the init. With
/// the initiation window still open the old code survives this replay too — it
/// re-decrypts and discards again — so the assertion that fails without the
/// fix is the one about the record. The damaging path, a replay once the window
/// has gone, is `session::tests::test_a_discarded_init_survives_a_restart`,
/// which controls the restart exactly and shows the init still live with only
/// the record standing in its way.
#[tokio::test]
async fn test_a_replayed_tie_break_loser_cannot_install_its_session() {
    use mycelium_crypto::session::SessionManager;
    use mycelium_crypto::x3dh::PrekeyState;
    use mycelium_protocol::codec::Envelope;
    use mycelium_protocol::types::{ContentType, MessageFlags, MessageId, ProtocolVersion};
    use mycelium_protocol::wire::{EncryptedPayload, SessionInitPayload, WireRatchetHeader};
    use std::time::Instant;

    // Alice must be the tie-break winner, which is the lower NodeId.
    let (alice_identity, peer_identity) = loop {
        let a = Identity::generate();
        let b = Identity::generate();
        if a.node_id().as_bytes() < b.node_id().as_bytes() {
            break (a, b);
        }
    };
    let alice_node_id = alice_identity.node_id();
    let peer_node_id = peer_identity.node_id();

    let alice = make_node(alice_identity);
    let network = MockNetwork::new();
    let alice_transport = Arc::new(MockTransport::new(alice_node_id, network.clone()).await);
    alice
        .transport_manager
        .add_transport(alice_transport.clone())
        .await;
    alice.start().await.expect("alice start");

    let (peer_tx, _peer_rx) = tokio::sync::broadcast::channel(64);
    network.register_node(peer_node_id, peer_tx).await;
    network
        .add_link(peer_node_id, alice_node_id, MockLinkConfig::default())
        .await;
    network
        .add_link(alice_node_id, peer_node_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Alice initiates first, from a cached bundle, so her own handshake is
    // outstanding when the peer's init arrives: that is the tie-break.
    let peer_prekeys = PrekeyState::new(Identity::from_bytes(&peer_identity.to_bytes()).unwrap());
    alice
        .prekey_cache
        .write()
        .await
        .insert(peer_node_id, (peer_prekeys.bundle(), Instant::now()));
    alice
        .send_message(peer_node_id, b"ours", ContentType::Text)
        .await
        .expect("alice initiates");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The peer's competing init, signed-prekey-only: nothing in it for the
    // tie-break to spend.
    let alice_bundle = {
        let mut bundle = alice.prekey_state.read().await.bundle();
        bundle.one_time_prekey = None;
        bundle.one_time_prekey_id = None;
        bundle
    };
    let mut peer_sessions = SessionManager::new();
    let peer_init = peer_sessions
        .initiate_session(&peer_identity, alice_node_id, &alice_bundle, true)
        .expect("peer initiates");
    assert!(peer_init.used_one_time_prekey_id.is_none());

    let ad = {
        let mut buf = Vec::with_capacity(65);
        buf.extend_from_slice(peer_node_id.as_bytes());
        buf.extend_from_slice(alice_node_id.as_bytes());
        buf.push(ContentType::Text as u8);
        buf
    };
    let (header, ciphertext) = peer_sessions
        .encrypt_for(&alice_node_id, b"theirs", &ad)
        .expect("peer encrypts");
    let loser_init = SessionInitPayload {
        ephemeral_public: peer_init.ephemeral_public,
        identity_key: peer_identity.public_key_bytes(),
        signed_prekey_id: peer_init.used_signed_prekey_id,
        one_time_prekey_id: None,
        encrypted_payload: EncryptedPayload {
            content_type: ContentType::Text as u8,
            header: WireRatchetHeader {
                dh_public: header.dh_public,
                previous_chain_length: header.previous_chain_length,
                message_number: header.message_number,
            },
            ciphertext,
        }
        .serialize(),
    }
    .serialize();

    let deliver = |payload: Vec<u8>| {
        let network = network.clone();
        async move {
            let envelope = Envelope {
                source: peer_node_id,
                destination: alice_node_id,
                message_id: MessageId::random(),
                ttl: 10,
                hop_count: 0,
                flags: MessageFlags::SYSTEM,
                lamport_clock: 1,
                device_timestamp: 0,
                protocol_version: ProtocolVersion::CURRENT,
                payload,
            };
            network
                .deliver(peer_node_id, alice_node_id, envelope.serialize())
                .await
                .expect("delivered");
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    };

    deliver(loser_init.clone()).await;

    // Alice kept hers: the session was not accepted from the peer's init.
    {
        let sm = alice.session_manager.read().await;
        let accepted_binding = sm
            .all_sessions()
            .find(|(id, _)| **id == peer_node_id)
            .map(|(_, s)| s.accepted_binding)
            .expect("alice holds a session with the peer");
        assert_eq!(
            accepted_binding, None,
            "the tie-break winner keeps the session it initiated"
        );
    }

    // And the handshake she answered is on record, keyed on the bound header
    // and held by the prekey state, so it outlives both this session and the
    // initiation window.
    let binding = mycelium_protocol::wire::session_init_binding(
        &peer_init.ephemeral_public,
        &peer_identity.public_key_bytes(),
        peer_init.used_signed_prekey_id,
        None,
        true,
    );
    assert!(
        alice
            .prekey_state
            .read()
            .await
            .has_answered_handshake(&binding),
        "the handshake Alice answered and discarded must be on record"
    );

    // The replay: the same init bytes under a fresh envelope id, which is what
    // gets past duplicate detection.
    //
    // The initiation window is not what stops it, and does not have to be
    // expired here to show that: `is_replayed_init` is consulted at the top of
    // `handle_session_init`, before the payload is parsed and long before the
    // tie-break is evaluated, so the record decides this whether the window is
    // open or not. That the record survives the restart that certainly loses
    // the window is `session::tests::test_a_discarded_init_survives_a_restart`.
    deliver(loser_init).await;

    let sm = alice.session_manager.read().await;
    let accepted_binding = sm
        .all_sessions()
        .find(|(id, _)| **id == peer_node_id)
        .map(|(_, s)| s.accepted_binding)
        .expect("alice still holds a session with the peer");
    assert_eq!(
        accepted_binding, None,
        "a replayed tie-break loser must not replace the surviving session"
    );
    drop(sm);
    assert!(
        alice
            .prekey_state
            .read()
            .await
            .has_answered_handshake(&binding),
        "and the record must still be there after the replay"
    );

    alice.stop().await;
}

/// An init carrying anything but the first message of its chain is refused,
/// and nothing is lost.
///
/// A relay that captured a later message on the same chain could wrap it into
/// a copy of the init and get that in first, under a fresh envelope id. The
/// session would be installed and the handshake put on record, so the genuine
/// init — arriving second with the conversation's *first* message inside — was
/// met with silence and that message was lost. Silently: the session works,
/// nothing is reported failed, and nothing retries.
///
/// An init encloses message 0 or it is not that init, so the copy is refused
/// before the derivation. The genuine init is then answered normally, and the
/// captured message arrives as what it always was — an ordinary message
/// (ADR-007, ADR-015).
#[tokio::test]
async fn test_a_reordered_message_in_an_init_is_refused_and_nothing_is_lost() {
    use mycelium_crypto::session::SessionManager;
    use mycelium_protocol::codec::Envelope;
    use mycelium_protocol::types::{MessageFlags, MessageId, ProtocolVersion};
    use mycelium_protocol::wire::{EncryptedPayload, SessionInitPayload, WireRatchetHeader};

    let alice_identity = Identity::generate();
    let alice_node_id = alice_identity.node_id();
    let peer_identity = Identity::generate();
    let peer_node_id = peer_identity.node_id();

    let alice = make_node(alice_identity);
    let network = MockNetwork::new();
    let alice_transport = Arc::new(MockTransport::new(alice_node_id, network.clone()).await);
    alice
        .transport_manager
        .add_transport(alice_transport.clone())
        .await;
    alice.start().await.expect("alice start");

    let (peer_tx, _peer_rx) = tokio::sync::broadcast::channel(64);
    network.register_node(peer_node_id, peer_tx).await;
    network
        .add_link(peer_node_id, alice_node_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let alice_bundle = alice.prekey_state.read().await.bundle();
    let mut peer_sessions = SessionManager::new();
    let init = peer_sessions
        .initiate_session(&peer_identity, alice_node_id, &alice_bundle, true)
        .expect("peer initiates");

    let ad = {
        let mut buf = Vec::with_capacity(65);
        buf.extend_from_slice(peer_node_id.as_bytes());
        buf.extend_from_slice(alice_node_id.as_bytes());
        buf.push(ContentType::Text as u8);
        buf
    };
    // The conversation's first message, which travels inside the init, and the
    // one after it, which a relay gets a copy of.
    let (h0, c0) = peer_sessions
        .encrypt_for(&alice_node_id, b"the first thing", &ad)
        .expect("peer encrypts the first");
    let (h1, c1) = peer_sessions
        .encrypt_for(&alice_node_id, b"the second thing", &ad)
        .expect("peer encrypts the second");

    let init_with = |header: WireRatchetHeader, ciphertext: Vec<u8>| {
        SessionInitPayload {
            ephemeral_public: init.ephemeral_public,
            identity_key: peer_identity.public_key_bytes(),
            signed_prekey_id: init.used_signed_prekey_id,
            one_time_prekey_id: init.used_one_time_prekey_id,
            encrypted_payload: EncryptedPayload {
                content_type: ContentType::Text as u8,
                header,
                ciphertext,
            }
            .serialize(),
        }
        .serialize()
    };
    let wire_header = |h: &mycelium_crypto::double_ratchet::RatchetHeader| WireRatchetHeader {
        dh_public: h.dh_public,
        previous_chain_length: h.previous_chain_length,
        message_number: h.message_number,
    };

    let deliver = |payload: Vec<u8>, message_id: MessageId| {
        let network = network.clone();
        async move {
            let envelope = Envelope {
                source: peer_node_id,
                destination: alice_node_id,
                message_id,
                ttl: 10,
                hop_count: 0,
                flags: MessageFlags::SYSTEM,
                lamport_clock: 1,
                device_timestamp: 0,
                protocol_version: ProtocolVersion::CURRENT,
                payload,
            };
            network
                .deliver(peer_node_id, alice_node_id, envelope.serialize())
                .await
                .expect("delivered");
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    };

    // A retagged payload is refused whatever the state of the handshake: the
    // nested type is checked before the record is consulted, so an unknown one
    // can never reach a path that changes anything (ADR-015).
    let retagged = SessionInitPayload {
        ephemeral_public: init.ephemeral_public,
        identity_key: peer_identity.public_key_bytes(),
        signed_prekey_id: init.used_signed_prekey_id,
        one_time_prekey_id: init.used_one_time_prekey_id,
        encrypted_payload: {
            let mut p = EncryptedPayload {
                content_type: ContentType::Text as u8,
                header: wire_header(&h0),
                ciphertext: c0.clone(),
            }
            .serialize();
            p[0] = mycelium_protocol::wire::WirePayloadType::GroupMessage as u8;
            p
        },
    }
    .serialize();
    let retagged_id = MessageId::random();
    deliver(retagged, retagged_id).await;
    assert!(alice.db.get_message(&retagged_id).is_err());
    assert!(!alice
        .session_manager
        .read()
        .await
        .has_session(&peer_node_id));

    // The relay's copy next: the peer's init header, the *second* message
    // inside it, an envelope id of the attacker's choosing.
    let forged_id = MessageId::random();
    deliver(init_with(wire_header(&h1), c1.clone()), forged_id).await;
    assert!(
        alice.db.get_message(&forged_id).is_err(),
        "an init carrying a later message of the chain must be refused"
    );
    assert!(
        !alice
            .session_manager
            .read()
            .await
            .has_session(&peer_node_id),
        "and must install nothing, or it has answered the handshake"
    );

    // The genuine init is therefore answered normally, and its message — the
    // first of the conversation — arrives.
    let genuine_id = MessageId::random();
    deliver(init_with(wire_header(&h0), c0), genuine_id).await;
    assert_eq!(
        alice
            .db
            .get_message(&genuine_id)
            .expect("the first message of the conversation must not be lost")
            .plaintext,
        b"the first thing"
    );

    // And the message the relay had a copy of arrives as what it always was.
    let second_id = MessageId::random();
    deliver(
        EncryptedPayload {
            content_type: ContentType::Text as u8,
            header: wire_header(&h1),
            ciphertext: c1,
        }
        .serialize(),
        second_id,
    )
    .await;
    assert_eq!(
        alice
            .db
            .get_message(&second_id)
            .expect("the second message arrives on the ordinary path")
            .plaintext,
        b"the second thing"
    );

    alice.stop().await;
}

/// A receipt acknowledges a handshake even when the conversation it belongs to
/// has been deleted.
///
/// A one-way conversation — the peer reads and acknowledges but never replies —
/// never confirms its handshake, so the sweep would abandon a working session.
/// The acknowledgement cannot come from the message rows: the user can delete
/// them, and a receipt can arrive days later over DTN, so recognising one that
/// way left the evidence to be deleted before it was ever recorded. The
/// handshake knows which messages it sent (ADR-015, T-42).
#[tokio::test]
async fn test_a_receipt_acknowledges_a_handshake_after_history_is_deleted() {
    use mycelium_protocol::codec::Envelope;
    use mycelium_protocol::types::{MessageFlags, MessageId, ProtocolVersion};
    use mycelium_protocol::wire::{serialize_receipt, ReceiptType};
    use std::time::Instant;

    let alice_identity = Identity::generate();
    let alice_node_id = alice_identity.node_id();
    let peer_identity = Identity::generate();
    let peer_node_id = peer_identity.node_id();

    let alice = make_node(alice_identity);
    let network = MockNetwork::new();
    let alice_transport = Arc::new(MockTransport::new(alice_node_id, network.clone()).await);
    alice
        .transport_manager
        .add_transport(alice_transport.clone())
        .await;
    alice.start().await.expect("alice start");

    let (peer_tx, _peer_rx) = tokio::sync::broadcast::channel(64);
    network.register_node(peer_node_id, peer_tx).await;
    network
        .add_link(peer_node_id, alice_node_id, MockLinkConfig::default())
        .await;
    network
        .add_link(alice_node_id, peer_node_id, MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Alice initiates and sends, from a cached bundle, so there is a handshake
    // the peer has not confirmed.
    let peer_prekeys = mycelium_crypto::x3dh::PrekeyState::new(
        Identity::from_bytes(&peer_identity.to_bytes()).unwrap(),
    );
    alice
        .prekey_cache
        .write()
        .await
        .insert(peer_node_id, (peer_prekeys.bundle(), Instant::now()));
    let init_message = alice
        .send_message(peer_node_id, b"are you there", ContentType::Text)
        .await
        .expect("alice sends");
    // A second message, which travels under the session rather than inside the
    // init. Only a receipt for one of *these* is evidence the peer kept the
    // session: the init's own message is decrypted by an ADR-007 tie-break
    // winner with a session it discards, and it receipts that honestly.
    let follow_up = alice
        .send_message(peer_node_id, b"still there?", ContentType::Text)
        .await
        .expect("alice sends again");
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(
        alice
            .session_manager
            .read()
            .await
            .stale_handshakes(Duration::ZERO)
            .len(),
        1,
        "unconfirmed and unacknowledged: the sweep would take it"
    );

    // The user clears the conversation before the receipts arrive.
    alice
        .db
        .delete_conversation(&alice_node_id, &peer_node_id)
        .expect("history deleted");
    assert!(alice.db.get_message(&init_message).is_err());

    let deliver_receipt = |for_message: MessageId| {
        let network = network.clone();
        async move {
            let envelope = Envelope {
                source: peer_node_id,
                destination: alice_node_id,
                message_id: MessageId::random(),
                ttl: 10,
                hop_count: 0,
                flags: MessageFlags::NONE,
                lamport_clock: 1,
                device_timestamp: 0,
                protocol_version: ProtocolVersion::CURRENT,
                payload: serialize_receipt(&for_message, ReceiptType::Delivered),
            };
            network
                .deliver(peer_node_id, alice_node_id, envelope.serialize())
                .await
                .expect("delivered");
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    };

    // A receipt for the init's own message vouches for nothing.
    deliver_receipt(init_message).await;
    assert_eq!(
        alice
            .session_manager
            .read()
            .await
            .stale_handshakes(Duration::ZERO)
            .len(),
        1,
        "the tie-break winner receipts that message with a session it discards, \
         so it is no evidence the peer kept one"
    );

    deliver_receipt(follow_up).await;
    assert!(
        alice
            .session_manager
            .read()
            .await
            .stale_handshakes(Duration::ZERO)
            .is_empty(),
        "the peer has decrypted something of ours, so this session is not dead"
    );

    alice.stop().await;
}
