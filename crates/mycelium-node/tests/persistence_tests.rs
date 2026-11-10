//! Tests for DTN persistence, group state persistence, prekey cache expiry,
//! conversation listing, and group serialization roundtrips.

use mycelium_crypto::group::{SenderKey, SenderKeyGroup};
use mycelium_protocol::types::{MessageId, NodeId};
use mycelium_storage::db::Database;
use mycelium_storage::dtn::DtnBundleRecord;

// --- DTN Persistence Tests ---

#[test]
fn test_dtn_bundle_db_roundtrip() {
    let db = Database::open_in_memory().unwrap();
    let msg_id = MessageId::random();
    let dest = NodeId([2u8; 32]);
    let src = NodeId([1u8; 32]);

    let record = DtnBundleRecord {
        message_id: msg_id,
        destination: dest,
        source: src,
        payload: b"encrypted payload".to_vec(),
        copies_remaining: 4,
        expires_at: 9999999999,
        size: 17,
    };

    db.store_dtn_bundle(&record).unwrap();

    let bundles = db.list_all_dtn_bundles().unwrap();
    assert_eq!(bundles.len(), 1);
    assert_eq!(bundles[0].message_id, msg_id);
    assert_eq!(bundles[0].copies_remaining, 4);
    assert_eq!(bundles[0].payload, b"encrypted payload");
}

#[test]
fn test_dtn_bundle_update_copies() {
    let db = Database::open_in_memory().unwrap();
    let msg_id = MessageId::random();

    let record = DtnBundleRecord {
        message_id: msg_id,
        destination: NodeId([2u8; 32]),
        source: NodeId([1u8; 32]),
        payload: b"data".to_vec(),
        copies_remaining: 8,
        expires_at: 9999999999,
        size: 4,
    };

    db.store_dtn_bundle(&record).unwrap();
    db.update_dtn_copies(&msg_id, 3).unwrap();

    let bundles = db.get_dtn_bundles_for(&NodeId([2u8; 32])).unwrap();
    assert_eq!(bundles[0].copies_remaining, 3);
}

#[test]
fn test_dtn_bundle_expire() {
    let db = Database::open_in_memory().unwrap();

    for i in 0..5 {
        let record = DtnBundleRecord {
            message_id: MessageId::random(),
            destination: NodeId([2u8; 32]),
            source: NodeId([1u8; 32]),
            payload: vec![i],
            copies_remaining: 1,
            expires_at: if i < 3 { 100 } else { 9999999999 }, // 3 expired, 2 valid
            size: 1,
        };
        db.store_dtn_bundle(&record).unwrap();
    }

    let expired = db.expire_dtn_bundles(1000).unwrap();
    assert_eq!(expired, 3);

    let remaining = db.list_all_dtn_bundles().unwrap();
    assert_eq!(remaining.len(), 2);
}

#[test]
fn test_dtn_storage_used() {
    let db = Database::open_in_memory().unwrap();

    for i in 0..3 {
        let payload = vec![0u8; (i + 1) * 100];
        let record = DtnBundleRecord {
            message_id: MessageId::random(),
            destination: NodeId([2u8; 32]),
            source: NodeId([1u8; 32]),
            payload,
            copies_remaining: 1,
            expires_at: 9999999999,
            size: (i + 1) * 100,
        };
        db.store_dtn_bundle(&record).unwrap();
    }

    let used = db.dtn_storage_used().unwrap();
    assert_eq!(used, 100 + 200 + 300);
}

// --- Group State Persistence Tests ---

#[test]
fn test_group_serialization_roundtrip() {
    let mut group_id = [0u8; 32];
    group_id[0] = 0xAA;

    let mut group = SenderKeyGroup::new(group_id);

    let alice = NodeId([1u8; 32]);
    let bob = NodeId([2u8; 32]);
    group.add_member(alice, SenderKey::generate());
    group.add_member(bob, SenderKey::generate());

    let bytes = group.to_bytes();
    let restored = SenderKeyGroup::from_bytes(&bytes).unwrap();

    assert_eq!(restored.group_id, group_id);
    assert_eq!(restored.member_count(), 2);
    assert!(restored.member_keys.contains_key(&alice));
    assert!(restored.member_keys.contains_key(&bob));
    assert_eq!(
        restored.our_sender_key.chain_key,
        group.our_sender_key.chain_key
    );
    assert_eq!(
        restored.our_sender_key.iteration,
        group.our_sender_key.iteration
    );
}

#[test]
fn test_group_serialization_empty() {
    let group_id = [0xBB; 32];
    let group = SenderKeyGroup::new(group_id);

    let bytes = group.to_bytes();
    let restored = SenderKeyGroup::from_bytes(&bytes).unwrap();

    assert_eq!(restored.group_id, group_id);
    assert_eq!(restored.member_count(), 0);
}

#[test]
fn test_group_serialization_too_short() {
    assert!(SenderKeyGroup::from_bytes(&[0u8; 10]).is_none());
    assert!(SenderKeyGroup::from_bytes(&[]).is_none());
}

#[test]
fn test_group_db_persistence() {
    let db = Database::open_in_memory().unwrap();

    let group_id = [0xCC; 32];
    let mut group = SenderKeyGroup::new(group_id);
    group.add_member(NodeId([1u8; 32]), SenderKey::generate());

    let blob = group.to_bytes();
    db.save_group_blob(&group_id, &blob).unwrap();

    let loaded = db.load_group_blob(&group_id).unwrap();
    let restored = SenderKeyGroup::from_bytes(&loaded).unwrap();
    assert_eq!(restored.group_id, group_id);
    assert_eq!(restored.member_count(), 1);

    // List all groups
    let all = db.list_group_blobs().unwrap();
    assert_eq!(all.len(), 1);

    // Remove
    db.remove_group_blob(&group_id).unwrap();
    let all = db.list_group_blobs().unwrap();
    assert_eq!(all.len(), 0);
}

// --- Prekey Cache Tests ---

#[test]
fn test_prekey_cache_remove() {
    let db = Database::open_in_memory().unwrap();
    let node_id = [0xDD; 32];

    db.cache_prekey_bundle(&node_id, b"bundle_data").unwrap();
    let cached = db.get_cached_prekey_bundle(&node_id).unwrap();
    assert_eq!(cached, b"bundle_data");

    db.remove_cached_prekey_bundle(&node_id).unwrap();
    assert!(db.get_cached_prekey_bundle(&node_id).is_err());
}

// --- Conversation List Tests ---

#[test]
fn test_conversation_list() {
    use mycelium_protocol::types::MessageId;
    use mycelium_storage::messages::MessageRecord;

    let db = Database::open_in_memory().unwrap();
    let alice = NodeId([1u8; 32]);
    let bob = NodeId([2u8; 32]);
    let carol = NodeId([3u8; 32]);

    // Alice → Bob messages
    for i in 0..3 {
        let msg = MessageRecord {
            message_id: MessageId::random(),
            source: alice,
            destination: bob,
            content_type: "text".to_string(),
            plaintext: format!("msg {}", i).into_bytes(),
            lamport_clock: i as u64,
            device_timestamp: 1000 + i as u64,
            status: "sent".to_string(),
            is_incoming: false,
        };
        db.insert_message(&msg).unwrap();
    }

    // Carol → Alice messages
    for i in 0..2 {
        let msg = MessageRecord {
            message_id: MessageId::random(),
            source: carol,
            destination: alice,
            content_type: "text".to_string(),
            plaintext: format!("from carol {}", i).into_bytes(),
            lamport_clock: 10 + i as u64,
            device_timestamp: 2000 + i as u64,
            status: "received".to_string(),
            is_incoming: true,
        };
        db.insert_message(&msg).unwrap();
    }

    let conversations = db.list_conversations(&alice).unwrap();
    assert_eq!(conversations.len(), 2);

    // Most recent first (Carol at timestamp 2001, Bob at 1002)
    assert_eq!(conversations[0].peer_id, carol);
    assert_eq!(conversations[0].message_count, 2);
    assert!(conversations[0].has_unread); // Carol's messages are "received" status

    assert_eq!(conversations[1].peer_id, bob);
    assert_eq!(conversations[1].message_count, 3);
    assert!(!conversations[1].has_unread); // Alice's sent messages
}

// --- Group Encrypt/Decrypt Persistence ---

#[test]
fn test_group_state_survives_encrypt_decrypt() {
    let group_id = [0xEE; 32];
    let alice_id = NodeId([1u8; 32]);

    let mut group = SenderKeyGroup::new(group_id);
    let alice_sk = SenderKey::generate();
    group.add_member(alice_id, alice_sk);

    // Encrypt a message (advances our sender key)
    let _msg1 = group.encrypt(b"hello group").unwrap();
    let _msg2 = group.encrypt(b"second message").unwrap();

    // Serialize after encryption
    let bytes = group.to_bytes();
    let mut restored = SenderKeyGroup::from_bytes(&bytes).unwrap();

    // Restored group should continue from where we left off
    assert_eq!(restored.our_sender_key.iteration, 2);

    // Encrypt another message in restored state
    let msg3 = restored.encrypt(b"third message").unwrap();
    assert_eq!(msg3.iteration, 2); // Should be iteration 2
}
