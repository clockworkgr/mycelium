//! FFI bindings for mobile platforms (Android/iOS).
//!
//! This crate exposes the Mycelium node API via C-compatible FFI.
//! When UniFFI is integrated, proc macros will generate Kotlin/Swift bindings.
//!
//! For v0.1, we provide a simple C API that the Android JNI layer calls.

use std::cell::RefCell;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::{Arc, OnceLock};

use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tracing::info;

use mycelium_crypto::identity::Identity;
use mycelium_node::config::NodeConfig;
use mycelium_node::node::Node;
use mycelium_protocol::types::{ContentType, NodeId};
use mycelium_storage::db::Database;

// Thread-local storage for message plaintext data.
// Keeps plaintext alive until the next mycelium_get_messages call.
thread_local! {
    static MESSAGE_PLAINTEXTS: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::new());
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

fn set_last_error(msg: impl Into<String>) {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(msg.into());
    });
}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tokio runtime")
    })
}

// --- Error Retrieval API ---

/// Get the last error message. Copies into `out_buf` and null-terminates.
///
/// Returns the length of the error message (excluding null terminator),
/// or 0 if no error is stored.
///
/// # Safety
/// - `out_buf` must point to `buf_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_last_error(out_buf: *mut u8, buf_len: u32) -> i32 {
    if out_buf.is_null() || buf_len == 0 {
        return 0;
    }

    LAST_ERROR.with(|cell| {
        let err = cell.borrow();
        match err.as_ref() {
            Some(msg) => {
                let bytes = msg.as_bytes();
                let copy_len = bytes.len().min((buf_len - 1) as usize);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, copy_len);
                *out_buf.add(copy_len) = 0;
                copy_len as i32
            }
            None => {
                *out_buf = 0;
                0
            }
        }
    })
}

/// Clear the last error message.
#[no_mangle]
pub extern "C" fn mycelium_clear_error() {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Opaque handle to a MyceliumNode.
pub struct MyceliumNode {
    node: Arc<Node>,
    /// Handle to the API server task (started with the node).
    api_handle: std::sync::Mutex<Option<JoinHandle<()>>>,
}

/// Data record returned to FFI callers.
#[repr(C)]
pub struct MessageInfo {
    pub message_id: [u8; 16],
    pub source: [u8; 32],
    pub destination: [u8; 32],
    pub content_type: u8,
    pub timestamp: u64,
    pub status: u8,
    pub is_incoming: bool,
    /// Pointer to plaintext data (valid until next mycelium_get_messages call).
    pub plaintext: *const u8,
    pub plaintext_len: u32,
}

#[repr(C)]
pub struct ConversationInfo {
    pub peer_id: [u8; 32],
    pub last_message_time: u64,
    pub unread_count: u32,
}

#[repr(C)]
pub struct NetworkStatus {
    pub neighbor_count: u32,
    pub is_connected: bool,
    pub battery_level: u8,
    pub dtn_queue_size: u32,
}

/// Create a new Mycelium node.
///
/// # Safety
/// `data_dir` and `display_name` must be valid C strings.
#[no_mangle]
pub unsafe extern "C" fn mycelium_node_new(
    data_dir: *const c_char,
    display_name: *const c_char,
) -> *mut MyceliumNode {
    let data_dir = match CStr::from_ptr(data_dir).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error("Invalid UTF-8 in data_dir");
            return std::ptr::null_mut();
        }
    };
    let display_name = match CStr::from_ptr(display_name).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error("Invalid UTF-8 in display_name");
            return std::ptr::null_mut();
        }
    };

    let config = NodeConfig {
        data_dir: data_dir.clone(),
        display_name,
        ..NodeConfig::default()
    };

    let _ = std::fs::create_dir_all(&data_dir);

    // Load or generate identity
    let identity_path = format!("{}/identity.key", data_dir);
    let identity = if let Ok(bytes) = std::fs::read(&identity_path) {
        let arr: [u8; 96] = match bytes.try_into() {
            Ok(a) => a,
            Err(_) => return std::ptr::null_mut(),
        };
        match Identity::from_bytes(&arr) {
            Ok(id) => id,
            Err(_) => return std::ptr::null_mut(),
        }
    } else {
        let id = Identity::generate();
        if std::fs::write(&identity_path, id.to_bytes()).is_err() {
            return std::ptr::null_mut();
        }
        id
    };

    // Open persistent database (derive encryption key from identity)
    let db_path = format!("{}/mycelium.db", data_dir);
    let db_key = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"mycelium-db-key:");
        hasher.update(identity.to_bytes());
        hasher.finalize()
    };
    let db = match Database::open(&db_path, &db_key) {
        Ok(db) => db,
        Err(_) => return std::ptr::null_mut(),
    };

    let node = Arc::new(Node::new(config, db, identity));
    Box::into_raw(Box::new(MyceliumNode {
        node,
        api_handle: std::sync::Mutex::new(None),
    }))
}

/// Start the node and the local API server.
///
/// # Safety
/// `handle` must be a valid pointer from `mycelium_node_new`.
#[no_mangle]
pub unsafe extern "C" fn mycelium_node_start(handle: *mut MyceliumNode) -> bool {
    let mycelium = &(*handle);
    let node = &mycelium.node;
    let started = runtime().block_on(async { node.start().await.is_ok() });

    if started {
        // Start the API server on localhost:9735
        let api_config = &node.config.api;
        if api_config.enabled {
            let node_clone = Arc::clone(node);
            let config = api_config.clone();
            match runtime().block_on(mycelium_api::start_server(node_clone, &config)) {
                Ok(api_task) => {
                    info!("API server started on {}:{}", config.bind_address, config.port);
                    if let Ok(mut guard) = mycelium.api_handle.lock() {
                        *guard = Some(api_task);
                    }
                }
                Err(e) => {
                    info!("API server failed to start: {}", e);
                }
            }
        }
    }

    started
}

/// Stop the node and API server.
///
/// # Safety
/// `handle` must be a valid pointer from `mycelium_node_new`.
#[no_mangle]
pub unsafe extern "C" fn mycelium_node_stop(handle: *mut MyceliumNode) {
    let mycelium = &(*handle);

    // Abort the API server
    if let Ok(mut guard) = mycelium.api_handle.lock() {
        if let Some(api_task) = guard.take() {
            api_task.abort();
        }
    }

    let node = &mycelium.node;
    runtime().block_on(async { node.stop().await });
}

/// Get the node ID as a 32-byte array.
///
/// # Safety
/// `handle` must be a valid pointer, `out` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_node_id(handle: *const MyceliumNode, out: *mut [u8; 32]) {
    let node = &(*handle).node;
    (*out) = *node.node_id.as_bytes();
}

/// Free the node handle.
///
/// # Safety
/// `handle` must be a valid pointer from `mycelium_node_new`, called exactly once.
#[no_mangle]
pub unsafe extern "C" fn mycelium_node_free(handle: *mut MyceliumNode) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

// --- Messaging API ---

fn content_type_from_u8(b: u8) -> ContentType {
    match b {
        0 => ContentType::Text,
        1 => ContentType::Image,
        2 => ContentType::File,
        3 => ContentType::GpsPin,
        4 => ContentType::VoiceNote,
        5 => ContentType::Receipt,
        6 => ContentType::System,
        _ => ContentType::Text,
    }
}

fn content_type_to_u8(ct: &str) -> u8 {
    match ct {
        "text" => 0,
        "image" => 1,
        "file" => 2,
        "gps_pin" => 3,
        "voice_note" => 4,
        "receipt" => 5,
        "system" => 6,
        _ => 0,
    }
}

fn status_to_u8(s: &str) -> u8 {
    match s {
        "pending" => 0,
        "sent" => 1,
        "received" => 2,
        "delivered" => 3,
        "read" => 4,
        "dtn_pending" => 5,
        "failed" => 6,
        _ => 0,
    }
}

/// Send a message to a destination node.
///
/// Returns 0 on success, negative error code on failure.
/// On success, `out_message_id` is filled with the 16-byte message ID.
///
/// # Safety
/// - `handle` must be a valid pointer from `mycelium_node_new`.
/// - `destination` must point to 32 bytes.
/// - `data` must point to `data_len` bytes.
/// - `out_message_id` must point to 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_send_message(
    handle: *mut MyceliumNode,
    destination: *const [u8; 32],
    data: *const u8,
    data_len: u32,
    content_type: u8,
    out_message_id: *mut [u8; 16],
) -> i32 {
    if handle.is_null() || destination.is_null() || data.is_null() || out_message_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let dest = NodeId::from_bytes(*destination);
    let plaintext = std::slice::from_raw_parts(data, data_len as usize);
    let ct = content_type_from_u8(content_type);

    let result = runtime().block_on(async { node.send_message(dest, plaintext, ct).await });

    match result {
        Ok(msg_id) => {
            (*out_message_id) = *msg_id.as_bytes();
            0
        }
        Err(e) => {
            set_last_error(format!("send_message failed: {}", e));
            -2
        }
    }
}

/// Get messages for a conversation with a peer.
///
/// Returns the number of messages written to `out_messages`, or negative on error.
///
/// # Safety
/// - `handle` must be a valid pointer from `mycelium_node_new`.
/// - `peer_id` must point to 32 bytes.
/// - `out_messages` must point to `out_capacity` MessageInfo structs.
#[no_mangle]
pub unsafe extern "C" fn mycelium_get_messages(
    handle: *const MyceliumNode,
    peer_id: *const [u8; 32],
    limit: u32,
    offset: u32,
    out_messages: *mut MessageInfo,
    out_capacity: u32,
) -> i32 {
    if handle.is_null() || peer_id.is_null() || out_messages.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    let messages = match node.db.get_conversation(&node.node_id, &peer, limit, offset) {
        Ok(msgs) => msgs,
        Err(_) => return -2,
    };

    let count = messages.len().min(out_capacity as usize);

    // Store plaintexts in thread-local so pointers stay valid until next call
    MESSAGE_PLAINTEXTS.with(|cell| {
        let mut plaintexts = cell.borrow_mut();
        plaintexts.clear();
        for msg in messages.iter().take(count) {
            plaintexts.push(msg.plaintext.clone());
        }
    });

    MESSAGE_PLAINTEXTS.with(|cell| {
        let plaintexts = cell.borrow();
        for (i, msg) in messages.iter().take(count).enumerate() {
            let info = &mut *out_messages.add(i);
            info.message_id = *msg.message_id.as_bytes();
            info.source = *msg.source.as_bytes();
            info.destination = *msg.destination.as_bytes();
            info.content_type = content_type_to_u8(&msg.content_type);
            info.timestamp = msg.device_timestamp;
            info.status = status_to_u8(&msg.status);
            info.is_incoming = msg.is_incoming;
            info.plaintext = plaintexts[i].as_ptr();
            info.plaintext_len = plaintexts[i].len() as u32;
        }
    });

    count as i32
}

// --- Contact API ---

#[repr(C)]
pub struct ContactInfo {
    pub node_id: [u8; 32],
    pub display_name_len: u32,
    pub trust_score: f32,
    pub is_verified: bool,
    pub last_seen: u64,
}

/// Get the number of contacts.
///
/// # Safety
/// `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn mycelium_contact_count(handle: *const MyceliumNode) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let node = &(*handle).node;
    match node.db.list_contacts() {
        Ok(contacts) => contacts.len() as i32,
        Err(_) => -2,
    }
}

/// Get contacts list. Returns number of contacts written.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `out_contacts` must point to `out_capacity` ContactInfo structs.
/// - `out_names` must point to a buffer of `names_capacity` bytes for concatenated display names.
#[no_mangle]
pub unsafe extern "C" fn mycelium_get_contacts(
    handle: *const MyceliumNode,
    out_contacts: *mut ContactInfo,
    out_capacity: u32,
    out_names: *mut u8,
    names_capacity: u32,
) -> i32 {
    if handle.is_null() || out_contacts.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let contacts = match node.db.list_contacts() {
        Ok(c) => c,
        Err(_) => return -2,
    };

    let count = contacts.len().min(out_capacity as usize);
    let mut name_offset: u32 = 0;

    for (i, contact) in contacts.iter().take(count).enumerate() {
        let info = &mut *out_contacts.add(i);
        info.node_id = *contact.node_id.as_bytes();
        info.trust_score = contact.trust_score;
        info.is_verified = contact.is_verified;
        info.last_seen = contact.last_seen.unwrap_or(0);

        let name_bytes = contact.display_name.as_bytes();
        let name_len = name_bytes.len().min((names_capacity - name_offset) as usize);
        info.display_name_len = name_len as u32;

        if !out_names.is_null() && name_len > 0 {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                out_names.add(name_offset as usize),
                name_len,
            );
            name_offset += name_len as u32;
        }
    }

    count as i32
}

// --- Group Messaging API ---

/// Send a message to a group.
///
/// Returns 0 on success, negative on error.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `group_id` must point to 32 bytes.
/// - `data` must point to `data_len` bytes.
/// - `out_message_id` must point to 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_send_group_message(
    handle: *mut MyceliumNode,
    group_id: *const [u8; 32],
    data: *const u8,
    data_len: u32,
    content_type: u8,
    out_message_id: *mut [u8; 16],
) -> i32 {
    if handle.is_null() || group_id.is_null() || data.is_null() || out_message_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let gid = *group_id;
    let plaintext = std::slice::from_raw_parts(data, data_len as usize);
    let ct = content_type_from_u8(content_type);

    let result = runtime().block_on(async { node.send_group_message(gid, plaintext, ct).await });

    match result {
        Ok(msg_id) => {
            (*out_message_id) = *msg_id.as_bytes();
            0
        }
        Err(_) => -2,
    }
}

// --- Network Status API ---

/// Get current network status.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `out_status` must point to a valid NetworkStatus struct.
#[no_mangle]
pub unsafe extern "C" fn mycelium_network_status(
    handle: *const MyceliumNode,
    out_status: *mut NetworkStatus,
) -> i32 {
    if handle.is_null() || out_status.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let status = &mut *out_status;

    let peers = runtime().block_on(async { node.transport_manager.known_peers().await });
    status.neighbor_count = peers.len() as u32;
    status.is_connected = !peers.is_empty();

    let battery_level = runtime().block_on(async {
        let bm = node.battery.read().await;
        bm.battery_level().unwrap_or(100)
    });
    status.battery_level = battery_level;
    status.dtn_queue_size = node.db.dtn_storage_used().unwrap_or(0) as u32;

    0
}

// --- Trust / Vouch API ---

/// Add a trust vouch for a peer.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `vouchee_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_add_vouch(
    handle: *mut MyceliumNode,
    vouchee_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || vouchee_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let voucher = node.node_id;
    let vouchee = NodeId::from_bytes(*vouchee_id);

    // Add to in-memory trust graph
    runtime().block_on(async {
        let mut tg = node.trust_graph.write().await;
        tg.add_vouch(voucher, vouchee);
    });

    // Persist vouch to DB
    use mycelium_storage::vouches::VouchRecord;
    let record = VouchRecord {
        voucher_id: voucher,
        vouchee_id: vouchee,
        voucher_public_key: node.identity.public_key_bytes().to_vec(),
        display_name: String::new(),
        signature: Vec::new(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    match node.db.save_vouch(&record) {
        Ok(()) => 0,
        Err(_) => -2,
    }
}

/// Get the trust score for a peer.
///
/// Returns the trust score (0.0 - 1.0), or -1.0 on error.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_trust_score(
    handle: *const MyceliumNode,
    peer_id: *const [u8; 32],
) -> f32 {
    if handle.is_null() || peer_id.is_null() {
        return -1.0;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    runtime().block_on(async {
        let tg = node.trust_graph.read().await;
        let score = tg.trust_score(&node.node_id, &peer);
        score.value
    })
}

/// Verify a session (mark as verified after safety number comparison).
///
/// Returns 0 on success, -1 on error (no session).
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_verify_session(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    let verified = runtime().block_on(async {
        let mut sm = node.session_manager.write().await;
        sm.verify_session(&peer)
    });

    if verified { 0 } else { -1 }
}

/// Get the safety number for a peer session as a null-terminated string.
///
/// Returns the length of the safety number written (excluding null terminator),
/// or -1 on error (no session).
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
/// - `out_buf` must point to `buf_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_safety_number(
    handle: *const MyceliumNode,
    peer_id: *const [u8; 32],
    out_buf: *mut u8,
    buf_len: u32,
) -> i32 {
    if handle.is_null() || peer_id.is_null() || out_buf.is_null() || buf_len == 0 {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    let safety_number = runtime().block_on(async {
        let sm = node.session_manager.read().await;
        sm.safety_number(&peer).map(|s| s.to_string())
    });

    match safety_number {
        Some(sn) => {
            let bytes = sn.as_bytes();
            let copy_len = bytes.len().min((buf_len - 1) as usize);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, copy_len);
            *out_buf.add(copy_len) = 0; // null terminator
            copy_len as i32
        }
        None => -1,
    }
}

// --- Conversation List API ---

/// Conversation summary returned to FFI callers.
#[repr(C)]
pub struct ConversationSummary {
    pub peer_id: [u8; 32],
    pub last_message_time: u64,
    pub message_count: u32,
    pub has_unread: bool,
}

/// Get a list of conversations (unique peers we've exchanged messages with).
///
/// Returns the number of conversations written, or negative on error.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `out_conversations` must point to `out_capacity` ConversationSummary structs.
#[no_mangle]
pub unsafe extern "C" fn mycelium_get_conversations(
    handle: *const MyceliumNode,
    out_conversations: *mut ConversationSummary,
    out_capacity: u32,
) -> i32 {
    if handle.is_null() || out_conversations.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let conversations = match node.db.list_conversations(&node.node_id) {
        Ok(c) => c,
        Err(_) => return -2,
    };

    let count = conversations.len().min(out_capacity as usize);
    for (i, conv) in conversations.iter().take(count).enumerate() {
        let info = &mut *out_conversations.add(i);
        info.peer_id = *conv.peer_id.as_bytes();
        info.last_message_time = conv.last_message_time;
        info.message_count = conv.message_count;
        info.has_unread = conv.has_unread;
    }

    count as i32
}

// --- Battery Update API ---

/// Update battery state from the platform.
///
/// # Safety
/// - `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn mycelium_update_battery(
    handle: *mut MyceliumNode,
    battery_level: i16,
    is_charging: bool,
) -> i32 {
    if handle.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let level = if battery_level < 0 {
        None
    } else {
        Some(battery_level as u8)
    };

    runtime().block_on(async {
        let peers = node.transport_manager.known_peers().await;
        let mut bm = node.battery.write().await;
        bm.update(level, is_charging, peers.len() as u16);
    });

    0
}

// --- Group Management API ---

/// Create a new group with a random group ID.
///
/// Returns 0 on success, fills out_group_id with the 32-byte group ID.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `out_group_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_create_group(
    handle: *mut MyceliumNode,
    out_group_id: *mut [u8; 32],
) -> i32 {
    if handle.is_null() || out_group_id.is_null() {
        return -1;
    }

    use mycelium_crypto::group::SenderKeyGroup;

    let node = &(*handle).node;
    let mut group_id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut group_id);

    let group = SenderKeyGroup::new(group_id);
    let blob = group.to_bytes();

    runtime().block_on(async {
        let mut groups = node.groups.write().await;
        groups.insert(group_id, group);
    });

    let _ = node.db.save_group_blob(&group_id, &blob);
    (*out_group_id) = group_id;
    0
}

/// Add a member to a group.
///
/// Returns 0 on success, -1 on invalid args, -2 on group not found.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `group_id` must point to 32 bytes.
/// - `member_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_add_group_member(
    handle: *mut MyceliumNode,
    group_id: *const [u8; 32],
    member_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || group_id.is_null() || member_id.is_null() {
        return -1;
    }

    use mycelium_crypto::group::SenderKey;

    let node = &(*handle).node;
    let gid = *group_id;
    let mid = NodeId::from_bytes(*member_id);

    let result = runtime().block_on(async {
        let mut groups = node.groups.write().await;
        match groups.get_mut(&gid) {
            Some(group) => {
                // Generate a sender key for the new member placeholder
                // In practice, their real sender key comes via SenderKeyDistribution message
                group.add_member(mid, SenderKey::generate());
                let _ = node.db.save_group_blob(&gid, &group.to_bytes());
                0i32
            }
            None => -2,
        }
    });

    result
}

// --- Message Receive Callback API ---

/// Callback type for incoming message notifications.
/// Parameters: source (32 bytes), message_id (16 bytes), content_type (u8), timestamp (u64)
pub type MessageCallback = extern "C" fn(
    source: *const [u8; 32],
    message_id: *const [u8; 16],
    content_type: u8,
    timestamp: u64,
);

/// Register a callback to be invoked when a new message is received.
///
/// The callback runs on a background thread — do not perform blocking work in it.
/// Call with null to unregister.
///
/// # Safety
/// - `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn mycelium_set_message_callback(
    handle: *mut MyceliumNode,
    callback: Option<MessageCallback>,
) -> i32 {
    if handle.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let db = node.db.clone();
    let local_id = node.node_id;

    // Spawn a polling task that checks for new messages
    if let Some(cb) = callback {
        runtime().spawn(async move {
            let mut last_check = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            loop {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                // Check for new incoming messages since last check
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                if let Ok(conversations) = db.list_conversations(&local_id) {
                    for conv in &conversations {
                        if conv.last_message_time > last_check && conv.has_unread {
                            // Fetch the most recent message to get details
                            if let Ok(msgs) = db.get_conversation(&local_id, &conv.peer_id, 1, 0) {
                                if let Some(msg) = msgs.last() {
                                    if msg.is_incoming && msg.device_timestamp > last_check {
                                        let src = msg.source.as_bytes();
                                        let mid = msg.message_id.as_bytes();
                                        let ct = content_type_to_u8(&msg.content_type);
                                        cb(src as *const [u8; 32], mid as *const [u8; 16], ct, msg.device_timestamp);
                                    }
                                }
                            }
                        }
                    }
                }

                last_check = now;
            }
        });
    }

    0
}

// --- Transport Registration API ---

/// Register the BLE transport for this node.
///
/// Returns 0 on success.
///
/// # Safety
/// - `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn mycelium_register_ble_transport(handle: *mut MyceliumNode) -> i32 {
    if handle.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let ble = Arc::new(mycelium_core::transport::ble::BleTransport::new(node.node_id));
    runtime().block_on(async {
        node.transport_manager.add_transport(ble.clone()).await;
        *node.ble_transport.write().await = Some(ble);
    });
    0
}

/// Register the Wi-Fi Direct transport for this node.
///
/// Returns 0 on success.
///
/// # Safety
/// - `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn mycelium_register_wifi_direct_transport(
    handle: *mut MyceliumNode,
) -> i32 {
    if handle.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let wifi = Arc::new(mycelium_core::transport::wifi_direct::WifiDirectTransport::new(
        node.node_id,
    ));
    runtime().block_on(async {
        node.transport_manager.add_transport(wifi.clone()).await;
        *node.wifi_transport.write().await = Some(wifi);
    });
    0
}

// --- Transport Event Injection API ---
// These functions let the Android/iOS platform layer feed BLE/WiFi Direct
// events into the Rust transport layer.

/// Notify the BLE transport that a peer was discovered.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_ble_on_peer_discovered(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    runtime().block_on(async {
        let guard = node.ble_transport.read().await;
        if let Some(ble) = guard.as_ref() {
            ble.on_peer_discovered(peer).await;
            0
        } else {
            -2 // BLE transport not registered
        }
    })
}

/// Notify the BLE transport that a peer was lost.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_ble_on_peer_lost(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    runtime().block_on(async {
        let guard = node.ble_transport.read().await;
        if let Some(ble) = guard.as_ref() {
            ble.on_peer_lost(peer).await;
            0
        } else {
            -2
        }
    })
}

/// Feed data received from BLE into the transport layer.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
/// - `data` must point to `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_ble_on_data_received(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
    data: *const u8,
    data_len: u32,
) -> i32 {
    if handle.is_null() || peer_id.is_null() || data.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);
    let payload = std::slice::from_raw_parts(data, data_len as usize).to_vec();

    runtime().block_on(async {
        let guard = node.ble_transport.read().await;
        if let Some(ble) = guard.as_ref() {
            ble.on_data_received(peer, payload).await;
            0
        } else {
            -2
        }
    })
}

/// Notify the Wi-Fi Direct transport that a peer connected.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_wifi_on_peer_connected(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    runtime().block_on(async {
        let guard = node.wifi_transport.read().await;
        if let Some(wifi) = guard.as_ref() {
            wifi.on_peer_connected(peer).await;
            0
        } else {
            -2
        }
    })
}

/// Notify the Wi-Fi Direct transport that a peer disconnected.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_wifi_on_peer_disconnected(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    runtime().block_on(async {
        let guard = node.wifi_transport.read().await;
        if let Some(wifi) = guard.as_ref() {
            wifi.on_peer_disconnected(peer).await;
            0
        } else {
            -2
        }
    })
}

/// Feed data received from Wi-Fi Direct into the transport layer.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
/// - `data` must point to `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_wifi_on_data_received(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
    data: *const u8,
    data_len: u32,
) -> i32 {
    if handle.is_null() || peer_id.is_null() || data.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);
    let payload = std::slice::from_raw_parts(data, data_len as usize).to_vec();

    runtime().block_on(async {
        let guard = node.wifi_transport.read().await;
        if let Some(wifi) = guard.as_ref() {
            wifi.on_data_received(peer, payload).await;
            0
        } else {
            -2
        }
    })
}

// --- Transport Send Callback API ---

/// Dequeue one pending BLE send from the outbox.
///
/// Returns 1 if a packet was dequeued (fills out params), 0 if empty, -1 on error.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `out_peer_id` must point to 32 bytes.
/// - `out_data` must point to `data_capacity` bytes.
/// - `out_data_len` must point to a valid u32.
#[no_mangle]
pub unsafe extern "C" fn mycelium_ble_dequeue_send(
    handle: *mut MyceliumNode,
    out_peer_id: *mut [u8; 32],
    out_data: *mut u8,
    data_capacity: u32,
    out_data_len: *mut u32,
) -> i32 {
    if handle.is_null() || out_peer_id.is_null() || out_data.is_null() || out_data_len.is_null() {
        return -1;
    }

    let node = &(*handle).node;

    let result = runtime().block_on(async {
        let guard = node.ble_transport.read().await;
        guard.as_ref().and_then(|ble| ble.dequeue_send())
    });

    match result {
        Some((peer, data)) => {
            let copy_len = data.len().min(data_capacity as usize);
            (*out_peer_id) = *peer.as_bytes();
            std::ptr::copy_nonoverlapping(data.as_ptr(), out_data, copy_len);
            (*out_data_len) = copy_len as u32;
            1
        }
        None => 0,
    }
}

/// Register a callback for sending data via BLE.
///
/// When the Rust layer needs to send data to a BLE peer, this callback is invoked.
/// The platform layer should implement the actual BLE write operation.
///
/// Callback signature: `fn(peer_id: *const [u8; 32], data: *const u8, data_len: u32) -> i32`
/// Returns 0 on success, non-zero on failure.
///
/// # Safety
/// - `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn mycelium_ble_set_send_callback(
    handle: *mut MyceliumNode,
    callback: mycelium_core::transport::ble::BleSendCallback,
) -> i32 {
    if handle.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    runtime().block_on(async {
        let guard = node.ble_transport.read().await;
        if let Some(ble) = guard.as_ref() {
            ble.set_send_callback(callback).await;
            0
        } else {
            -2
        }
    })
}

/// Register a callback for sending data via Wi-Fi Direct.
///
/// Callback signature: `fn(peer_id: *const [u8; 32], data: *const u8, data_len: u32) -> i32`
///
/// # Safety
/// - `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn mycelium_wifi_set_send_callback(
    handle: *mut MyceliumNode,
    callback: mycelium_core::transport::wifi_direct::WifiSendCallback,
) -> i32 {
    if handle.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    runtime().block_on(async {
        let guard = node.wifi_transport.read().await;
        if let Some(wifi) = guard.as_ref() {
            wifi.set_send_callback(callback).await;
            0
        } else {
            -2
        }
    })
}

// --- Message Deletion API ---

/// Delete all messages in a conversation with a peer.
///
/// Returns 0 on success, negative on error.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_delete_conversation(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    match node.db.delete_conversation(&node.node_id, &peer) {
        Ok(_) => 0,
        Err(_) => -2,
    }
}

// --- Mark-as-Read / Unread Count API ---

/// Mark all incoming messages from a peer as read.
///
/// Returns the number of messages marked, or negative on error.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_mark_read(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    runtime().block_on(async { node.mark_read_and_notify(peer).await }) as i32
}

/// Get the number of unread messages from a specific peer.
///
/// Returns the count, or negative on error.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_unread_count(
    handle: *const MyceliumNode,
    peer_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    match node.db.unread_count(&node.node_id, &peer) {
        Ok(count) => count as i32,
        Err(_) => -2,
    }
}

/// Get total unread message count across all conversations.
///
/// Returns the count, or negative on error.
///
/// # Safety
/// - `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn mycelium_total_unread_count(handle: *const MyceliumNode) -> i32 {
    if handle.is_null() {
        return -1;
    }

    let node = &(*handle).node;

    match node.db.total_unread_count(&node.node_id) {
        Ok(count) => count as i32,
        Err(_) => -2,
    }
}

// --- Display Name API ---

/// Set the display name for a contact.
///
/// Returns 0 on success, negative on error.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
/// - `name` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn mycelium_set_display_name(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
    name: *const c_char,
) -> i32 {
    if handle.is_null() || peer_id.is_null() || name.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);
    let display_name = match CStr::from_ptr(name).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };

    use mycelium_storage::contacts::ContactRecord;

    // Load existing contact or create new one
    let mut contact = node.db.get_contact(&peer).unwrap_or(ContactRecord {
        node_id: peer,
        display_name: String::new(),
        public_key: Vec::new(),
        trust_score: 0.0,
        is_verified: false,
        last_seen: None,
    });
    contact.display_name = display_name;

    match node.db.save_contact(&contact) {
        Ok(()) => 0,
        Err(_) => -2,
    }
}

/// Get the display name for a contact.
///
/// Returns the length of the name written (excluding null terminator),
/// or -1 on error, or 0 if no display name is set.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
/// - `out_buf` must point to `buf_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_get_display_name(
    handle: *const MyceliumNode,
    peer_id: *const [u8; 32],
    out_buf: *mut u8,
    buf_len: u32,
) -> i32 {
    if handle.is_null() || peer_id.is_null() || out_buf.is_null() || buf_len == 0 {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    match node.db.get_contact(&peer) {
        Ok(contact) => {
            let bytes = contact.display_name.as_bytes();
            let copy_len = bytes.len().min((buf_len - 1) as usize);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, copy_len);
            *out_buf.add(copy_len) = 0; // null terminator
            copy_len as i32
        }
        Err(_) => 0, // No contact found, return 0 length
    }
}

// --- Group Query API ---

/// Get the number of members in a group.
///
/// Returns member count, or negative on error.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `group_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_group_member_count(
    handle: *const MyceliumNode,
    group_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || group_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let gid = *group_id;

    runtime().block_on(async {
        let groups = node.groups.read().await;
        match groups.get(&gid) {
            Some(group) => group.member_count() as i32,
            None => -2,
        }
    })
}

/// Get the member IDs of a group.
///
/// Returns number of members written, or negative on error.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `group_id` must point to 32 bytes.
/// - `out_members` must point to `out_capacity` arrays of 32 bytes each.
#[no_mangle]
pub unsafe extern "C" fn mycelium_get_group_members(
    handle: *const MyceliumNode,
    group_id: *const [u8; 32],
    out_members: *mut [u8; 32],
    out_capacity: u32,
) -> i32 {
    if handle.is_null() || group_id.is_null() || out_members.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let gid = *group_id;

    runtime().block_on(async {
        let groups = node.groups.read().await;
        match groups.get(&gid) {
            Some(group) => {
                let members: Vec<&NodeId> = group.member_keys.keys().collect();
                let count = members.len().min(out_capacity as usize);
                for (i, member) in members.iter().take(count).enumerate() {
                    *out_members.add(i) = *member.as_bytes();
                }
                count as i32
            }
            None => -2,
        }
    })
}

/// Remove a member from a group.
///
/// Returns 0 on success, -2 if group not found.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `group_id` must point to 32 bytes.
/// - `member_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_remove_group_member(
    handle: *mut MyceliumNode,
    group_id: *const [u8; 32],
    member_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || group_id.is_null() || member_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let gid = *group_id;
    let mid = NodeId::from_bytes(*member_id);

    runtime().block_on(async {
        let mut groups = node.groups.write().await;
        match groups.get_mut(&gid) {
            Some(group) => {
                group.remove_member(&mid);
                let _ = node.db.save_group_blob(&gid, &group.to_bytes());
                0i32
            }
            None => -2,
        }
    })
}
