//! End-to-end group messaging: sender keys are distributed over pairwise
//! sessions when members are added, so a group message encrypted by one
//! node decrypts on the others.

use std::sync::Arc;
use std::time::Duration;

use mycelium_core::transport::mock::{MockLinkConfig, MockNetwork, MockTransport};
use mycelium_crypto::identity::Identity;
use mycelium_node::config::NodeConfig;
use mycelium_node::node::Node;
use mycelium_protocol::types::{ContentType, NodeId};
use mycelium_storage::db::Database;

fn make_node(identity: Identity) -> Node {
    let config = NodeConfig::default();
    let db = Database::open_in_memory().expect("in-memory DB");
    Node::new(config, db, identity)
}

async fn wait_until<F: Fn() -> bool>(f: F, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    f()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_group_key_distribution_and_message() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    let identities: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let ids: Vec<NodeId> = identities.iter().map(|i| i.node_id()).collect();
    let nodes: Vec<Node> = identities.into_iter().map(make_node).collect();
    let (alice, bob, carol) = (&nodes[0], &nodes[1], &nodes[2]);

    let network = MockNetwork::new();
    for (node, id) in nodes.iter().zip(&ids) {
        let t = Arc::new(MockTransport::new(*id, network.clone()).await);
        node.transport_manager.add_transport(t).await;
        node.start().await.expect("start");
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Full mesh of direct links
    network
        .add_link(ids[0], ids[1], MockLinkConfig::default())
        .await;
    network
        .add_link(ids[0], ids[2], MockLinkConfig::default())
        .await;
    network
        .add_link(ids[1], ids[2], MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Alice creates a group and adds Bob, then Carol.
    let group_id = alice.create_group().await.expect("create group");
    alice
        .add_group_member(group_id, ids[1])
        .await
        .expect("add bob");
    alice
        .add_group_member(group_id, ids[2])
        .await
        .expect("add carol");

    // Distribution needs a prekey exchange + session per pair, then the
    // recipients answer with their own keys.
    let all_keyed = wait_until(
        || {
            let rt = tokio::runtime::Handle::current();
            tokio::task::block_in_place(|| {
                rt.block_on(async {
                    let a = alice.groups.read().await;
                    let b = bob.groups.read().await;
                    let c = carol.groups.read().await;
                    let ok = |g: &mycelium_crypto::group::SenderKeyGroup, others: &[NodeId]| {
                        others.iter().all(|o| g.member_keys.contains_key(o))
                    };
                    a.get(&group_id)
                        .map(|g| ok(g, &[ids[1], ids[2]]))
                        .unwrap_or(false)
                        && b.get(&group_id)
                            .map(|g| ok(g, &[ids[0], ids[2]]))
                            .unwrap_or(false)
                        && c.get(&group_id)
                            .map(|g| ok(g, &[ids[0], ids[1]]))
                            .unwrap_or(false)
                })
            })
        },
        Duration::from_secs(5),
    )
    .await;
    assert!(
        all_keyed,
        "every member should hold every other member's sender key"
    );

    // No chat rows were created by the key distribution.
    assert_eq!(bob.db.list_conversations(&ids[1]).unwrap().len(), 0);

    // Alice posts to the group; Bob and Carol decrypt it.
    let msg_id = alice
        .send_group_message(group_id, b"hello group", ContentType::Text)
        .await
        .expect("send group message");
    let delivered = wait_until(
        || bob.db.get_message(&msg_id).is_ok() && carol.db.get_message(&msg_id).is_ok(),
        Duration::from_secs(3),
    )
    .await;
    assert!(delivered, "group message should reach both members");
    let bob_msg = bob.db.get_message(&msg_id).unwrap();
    assert_eq!(bob_msg.plaintext, b"hello group");
    assert_eq!(bob_msg.source, ids[0]);
    assert_eq!(bob_msg.destination, NodeId::from_bytes(group_id));

    // Bob replies; Alice and Carol decrypt with Bob's distributed key.
    let reply_id = bob
        .send_group_message(group_id, b"hi from bob", ContentType::Text)
        .await
        .expect("bob group message");
    let delivered = wait_until(
        || alice.db.get_message(&reply_id).is_ok() && carol.db.get_message(&reply_id).is_ok(),
        Duration::from_secs(3),
    )
    .await;
    assert!(
        delivered,
        "bob's group message should reach alice and carol"
    );

    // Alice removes Carol: her key rotates and Bob still decrypts, Carol does not.
    alice
        .remove_group_member(group_id, ids[2])
        .await
        .expect("remove carol");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after_id = alice
        .send_group_message(group_id, b"carol is gone", ContentType::Text)
        .await
        .expect("send after removal");
    let bob_got = wait_until(
        || bob.db.get_message(&after_id).is_ok(),
        Duration::from_secs(3),
    )
    .await;
    assert!(bob_got, "bob should decrypt after key rotation");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        carol.db.get_message(&after_id).is_err(),
        "removed member must not decrypt messages after rotation"
    );
    {
        let b = bob.groups.read().await;
        assert!(
            !b.get(&group_id).unwrap().is_member(&ids[2]),
            "bob learns the new roster from alice's distribution"
        );
    }

    for node in &nodes {
        node.stop().await;
    }
}

/// A sender-key chain advance that cannot be persisted must abort the group send.
///
/// Same hazard as the pairwise ratchet (ROADMAP T-07): `SenderKeyGroup::encrypt`
/// advances the chain key in memory, and the group AEAD derives its nonce from
/// the iteration. If the new iteration is lost but the ciphertext went out, the
/// next start re-encrypts a different plaintext at the same iteration, re-using
/// a nonce under the same key.
///
/// Before the fix `send_group_message` discarded the error with
/// `let _ = self.db.save_group_blob(..)` and sent to every member anyway.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_group_send_fails_when_chain_state_cannot_be_persisted() {
    let identities: Vec<Identity> = (0..2).map(|_| Identity::generate()).collect();
    let ids: Vec<NodeId> = identities.iter().map(|i| i.node_id()).collect();
    let nodes: Vec<Node> = identities.into_iter().map(make_node).collect();
    let (alice, bob) = (&nodes[0], &nodes[1]);

    let network = MockNetwork::new();
    for (node, id) in nodes.iter().zip(&ids) {
        let t = Arc::new(MockTransport::new(*id, network.clone()).await);
        node.transport_manager.add_transport(t).await;
        node.start().await.expect("start");
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    network
        .add_link(ids[0], ids[1], MockLinkConfig::default())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let group_id = alice.create_group().await.expect("create group");
    alice
        .add_group_member(group_id, ids[1])
        .await
        .expect("add bob");

    // Wait for the sender keys to reach each other, or the first message
    // arrives before Bob can decrypt it.
    let keyed = wait_until(
        || {
            let rt = tokio::runtime::Handle::current();
            tokio::task::block_in_place(|| {
                rt.block_on(async {
                    let b = bob.groups.read().await;
                    b.get(&group_id)
                        .map(|g| g.member_keys.contains_key(&ids[0]))
                        .unwrap_or(false)
                })
            })
        },
        Duration::from_secs(5),
    )
    .await;
    assert!(keyed, "precondition: Bob must hold Alice's sender key");

    // A normal group message first, so we know the group path works.
    let first_id = alice
        .send_group_message(group_id, b"hello group", ContentType::Text)
        .await
        .expect("first group send");
    assert!(
        wait_until(
            || bob.db.get_message(&first_id).is_ok(),
            Duration::from_secs(5),
        )
        .await,
        "precondition: Bob must receive the first group message"
    );

    // Group state lives as a blob in `config`. Break only that.
    alice
        .db
        .conn()
        .execute_batch("DROP TABLE config;")
        .expect("drop config table");

    let result = alice
        .send_group_message(group_id, b"must not be sent", ContentType::Text)
        .await;

    assert!(
        result.is_err(),
        "group send must fail when the chain advance cannot be persisted, got {:?}",
        result.as_ref().map(|id| id.to_string())
    );

    tokio::time::sleep(Duration::from_millis(300)).await;
    let bob_msgs = bob
        .db
        .get_conversation(&ids[1], &NodeId::from_bytes(group_id), 100, 0)
        .expect("bob group conversation");
    assert!(
        bob_msgs.iter().all(|m| m.plaintext != b"must not be sent"),
        "Bob must not have received a group message whose chain state was never persisted"
    );
}
