//! FFI bindings for mobile platforms (Android/iOS).
//!
//! This crate exposes the Mycelium node API via C-compatible FFI.
//! When UniFFI is integrated, proc macros will generate Kotlin/Swift bindings.
//!
//! For v0.1, we provide a simple C API that the Android JNI layer calls.

use std::cell::RefCell;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, OnceLock};

use std::sync::Once;
use tokio::runtime::Runtime;
use tracing::info;

use mycelium_core::transport::internet::{InternetConfig, InternetTransport};
use mycelium_core::transport::Transport;
use mycelium_crypto::identity::Identity;
use mycelium_node::config::NodeConfig;
use mycelium_node::dht_marks::DbMarkStore;
use mycelium_node::node::Node;
use mycelium_protocol::types::{ContentType, NodeId};
use mycelium_storage::db::Database;

// Thread-local storage for message plaintext data.
// Keeps plaintext alive until the next mycelium_get_messages call.
thread_local! {
    static MESSAGE_PLAINTEXTS: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn set_last_error(msg: impl Into<String>) {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(msg.into());
    });
}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static TRACING_INIT: Once = Once::new();

/// Stores the active node pointer so the Dart layer can recover it
/// after the Flutter engine restarts (process stayed alive via daemon service).
static ACTIVE_NODE: AtomicPtr<MyceliumNode> = AtomicPtr::new(std::ptr::null_mut());

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
    /// Handle to the API server (started with the node).
    api_handle: std::sync::Mutex<Option<mycelium_api::ApiServerHandle>>,
    /// Guards against a second `mycelium_node_start`, which would spawn a
    /// duplicate event loop and fail to rebind the API port.
    started: std::sync::atomic::AtomicBool,
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

/// Diagnostic: check if the API server port is reachable from the Rust side.
/// Returns 1 if TCP connect to 127.0.0.1:9735 succeeds, 0 if not.
/// If it fails, the error reason is stored in LAST_ERROR.
#[no_mangle]
pub extern "C" fn mycelium_api_check() -> i32 {
    use std::net::TcpStream;
    match TcpStream::connect_timeout(
        &"127.0.0.1:9735".parse().unwrap(),
        std::time::Duration::from_secs(2),
    ) {
        Ok(_) => 1,
        Err(e) => {
            set_last_error(format!("API check failed: {}", e));
            0
        }
    }
}

/// Diagnostic: check the API server handle status.
/// Returns: 0 = no node, 1 = node exists but no API handle, 2 = API handle exists (task running),
///          3 = API handle exists (task finished).
#[no_mangle]
pub extern "C" fn mycelium_api_handle_status() -> i32 {
    let ptr = ACTIVE_NODE.load(Ordering::Acquire);
    if ptr.is_null() {
        return 0;
    }
    let mycelium = unsafe { &*ptr };
    match mycelium.api_handle.lock() {
        Ok(guard) => match guard.as_ref() {
            None => 1,
            Some(handle) => {
                if handle.is_finished() {
                    3
                } else {
                    2
                }
            }
        },
        Err(_) => {
            set_last_error("API handle mutex poisoned");
            -1
        }
    }
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
    // Initialize tracing → Android logcat (once)
    TRACING_INIT.call_once(|| {
        #[cfg(target_os = "android")]
        {
            use tracing_subscriber::layer::SubscriberExt;
            if let Ok(layer) = tracing_android::layer("Mycelium") {
                let subscriber = tracing_subscriber::registry().with(layer);
                let _ = tracing::subscriber::set_global_default(subscriber);
            }
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = tracing_subscriber::fmt::try_init();
        }
    });

    if data_dir.is_null() || display_name.is_null() {
        set_last_error("data_dir and display_name must not be NULL");
        return std::ptr::null_mut();
    }

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

    let mut config = NodeConfig {
        data_dir: data_dir.clone(),
        display_name,
        ..NodeConfig::default()
    };

    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        set_last_error(format!("create_dir_all({}): {}", data_dir, e));
        return std::ptr::null_mut();
    }

    // The API server requires a bearer token; the app reads it back from
    // <data_dir>/api.token (owner-only file).
    match mycelium_api::load_or_create_api_token(&data_dir) {
        Ok(token) => config.api.auth_token = Some(token),
        Err(e) => {
            set_last_error(format!("api token ({}): {}", data_dir, e));
            return std::ptr::null_mut();
        }
    }

    // Load or generate identity
    let identity_path = format!("{}/identity.key", data_dir);
    let identity = if let Ok(bytes) = std::fs::read(&identity_path) {
        let arr: [u8; 96] = match bytes.try_into() {
            Ok(a) => a,
            Err(_) => {
                set_last_error(format!("identity file wrong size at {}", identity_path));
                return std::ptr::null_mut();
            }
        };
        match Identity::from_bytes(&arr) {
            Ok(id) => id,
            Err(e) => {
                set_last_error(format!("identity deserialize: {}", e));
                return std::ptr::null_mut();
            }
        }
    } else {
        let id = Identity::generate();
        if let Err(e) = std::fs::write(&identity_path, id.to_bytes()) {
            set_last_error(format!("identity write({}): {}", identity_path, e));
            return std::ptr::null_mut();
        }
        id
    };

    // Open persistent database (derive encryption key from identity)
    let db_path = format!("{}/mycelium.db", data_dir);
    let db_key = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"mycelium-db-key:");
        hasher.update(identity.to_bytes());
        hasher.finalize()
    };
    let db = match Database::open(&db_path, &db_key) {
        Ok(db) => db,
        Err(e) => {
            set_last_error(format!("db open({}): {}", db_path, e));
            return std::ptr::null_mut();
        }
    };

    let node = Arc::new(Node::new(config, db, identity));
    let ptr = Box::into_raw(Box::new(MyceliumNode {
        node,
        api_handle: std::sync::Mutex::new(None),
        started: std::sync::atomic::AtomicBool::new(false),
    }));
    ACTIVE_NODE.store(ptr, Ordering::Release);
    ptr
}

/// Start the node and the local API server.
///
/// # Safety
/// `handle` must be a valid pointer from `mycelium_node_new`.
#[no_mangle]
pub unsafe extern "C" fn mycelium_node_start(handle: *mut MyceliumNode) -> bool {
    if handle.is_null() {
        set_last_error("handle must not be NULL");
        return false;
    }
    let mycelium = &(*handle);
    if mycelium.started.swap(true, Ordering::AcqRel) {
        info!("Node already started, ignoring duplicate start");
        return true;
    }
    let node = &mycelium.node;
    let start_result = runtime().block_on(async { node.start().await });

    match start_result {
        Ok(()) => {
            info!("Node started successfully");
        }
        Err(e) => {
            let msg = format!("Node start failed: {}", e);
            info!("{}", msg);
            set_last_error(&msg);
            mycelium.started.store(false, Ordering::Release);
            return false;
        }
    }

    // Start the API server on localhost:9735
    let api_config = &node.config.api;
    if api_config.enabled {
        let node_clone = Arc::clone(node);
        let config = api_config.clone();
        match runtime().block_on(mycelium_api::start_server(node_clone, &config)) {
            Ok(api_task) => {
                info!(
                    "API server started on {}:{}",
                    config.bind_address, config.port
                );
                if let Ok(mut guard) = mycelium.api_handle.lock() {
                    *guard = Some(api_task);
                }
            }
            Err(e) => {
                let msg = format!("API server failed to start: {}", e);
                info!("{}", msg);
                set_last_error(&msg);
                // Node started but API server failed — still return true
                // so the caller knows the node is running
            }
        }
    }

    true
}

/// Stop the node and API server.
///
/// # Safety
/// `handle` must be a valid pointer from `mycelium_node_new`.
#[no_mangle]
pub unsafe extern "C" fn mycelium_node_stop(handle: *mut MyceliumNode) {
    if handle.is_null() {
        return;
    }
    let mycelium = &(*handle);

    // Stop the API server and every task it spawned
    if let Ok(mut guard) = mycelium.api_handle.lock() {
        if let Some(api) = guard.take() {
            api.shutdown();
        }
    }

    let node = &mycelium.node;
    runtime().block_on(async { node.stop().await });
    mycelium.started.store(false, Ordering::Release);
}

/// Get the node ID as a 32-byte array.
///
/// # Safety
/// `handle` must be a valid pointer, `out` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_node_id(handle: *const MyceliumNode, out: *mut [u8; 32]) {
    if handle.is_null() || out.is_null() {
        return;
    }
    let node = &(*handle).node;
    (*out) = *node.node_id.as_bytes();
}

/// Free the node handle.
///
/// Drains the DHT mark writer first. The writer is a detached task owned by the
/// engine, and dropping the handle used to abandon whatever it had not reached:
/// high-water marks lost with no storage error to show for it, and worse, a
/// task still holding queued deletions that could apply *after* a new handle
/// over the same database had restored those marks — erasing rollback
/// protection the new engine believed it had (ADR-016).
///
/// Bounded by the flush's own timeout, so a stuck backend delays this by
/// seconds rather than hanging it. A flush that times out leaves the hazard
/// open, which is ROADMAP T-46: nothing here can enforce that one engine owns
/// a database, and `mycelium_node_new` does not refuse a second handle.
///
/// # Safety
/// `handle` must be a valid pointer from `mycelium_node_new`, called exactly once.
#[no_mangle]
pub unsafe extern "C" fn mycelium_node_free(handle: *mut MyceliumNode) {
    if !handle.is_null() {
        let mycelium = &*handle;
        runtime().block_on(async {
            let internet = mycelium.node.internet_transport.read().await.clone();
            if let Some(internet) = internet {
                internet.dht().flush_marks().await;
            }
        });
        ACTIVE_NODE.store(std::ptr::null_mut(), Ordering::Release);
        drop(Box::from_raw(handle));
    }
}

/// Get the existing node handle (if the node is still alive in this process).
///
/// Returns NULL if no node has been created, or if it was freed.
/// Used by the Dart layer to recover the handle after the Flutter engine restarts.
#[no_mangle]
pub extern "C" fn mycelium_node_get_existing() -> *mut MyceliumNode {
    ACTIVE_NODE.load(Ordering::Acquire)
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

    let messages = match node
        .db
        .get_conversation(&node.node_id, &peer, limit, offset)
    {
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
        let mut name_len = name_bytes
            .len()
            .min((names_capacity - name_offset) as usize);
        // Never cut a multi-byte UTF-8 sequence in half.
        while name_len > 0 && !contact.display_name.is_char_boundary(name_len) {
            name_len -= 1;
        }
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
    // Number of queued bundles (not bytes), matching /v1/network/status.
    status.dtn_queue_size =
        runtime().block_on(async { node.routing.read().await.dtn().bundle_count() as u32 });

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

    if verified {
        0
    } else {
        -1
    }
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
        Some(battery_level.min(100) as u8)
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

    let node = &(*handle).node;
    match runtime().block_on(node.create_group()) {
        Ok(group_id) => {
            (*out_group_id) = group_id;
            0
        }
        Err(e) => {
            set_last_error(format!("create_group: {}", e));
            -2
        }
    }
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

    let node = &(*handle).node;
    let gid = *group_id;
    let mid = NodeId::from_bytes(*member_id);

    // Adds the member and distributes sender keys over pairwise sessions.
    match runtime().block_on(node.add_group_member(gid, mid)) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("add_group_member: {}", e));
            -2
        }
    }
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
                                        cb(
                                            src as *const [u8; 32],
                                            mid as *const [u8; 16],
                                            ct,
                                            msg.device_timestamp,
                                        );
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
    // The identity, not the id: this transport proves who it is now
    // (ADR-021, ROADMAP T-34).
    let ble = Arc::new(mycelium_core::transport::ble::BleTransport::new(
        node.identity_handle(),
    ));
    runtime().block_on(async {
        node.transport_manager.replace_transport(ble.clone()).await;
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
pub unsafe extern "C" fn mycelium_register_wifi_direct_transport(handle: *mut MyceliumNode) -> i32 {
    if handle.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let wifi = Arc::new(
        mycelium_core::transport::wifi_direct::WifiDirectTransport::new(node.identity_handle()),
    );
    runtime().block_on(async {
        node.transport_manager.replace_transport(wifi.clone()).await;
        *node.wifi_transport.write().await = Some(wifi);
    });
    0
}

// --- Transport Event Injection API ---
// These functions let the Android/iOS platform layer feed BLE/Wi-Fi Direct
// links into the Rust transport layer.
//
// Links, not peers. The bridge reports the address it already has for a
// connection and relays opaque frames; who is on the other end is settled by
// the handshake in `mycelium_core::transport::link`, and nothing here can
// install an id the platform claimed (ADR-021, ROADMAP T-34).

/// Read a link address from the platform layer.
///
/// # Safety
/// - `addr` must point to a NUL-terminated UTF-8 string.
unsafe fn link_addr(addr: *const c_char) -> Option<String> {
    let text = CStr::from_ptr(addr).to_str().ok()?;
    // `MAX_LINK_ADDR` counts the NUL terminator, so an address this long
    // always fits back into a caller's buffer of that size. Refusing the
    // boundary case here is what stops an address being accepted inbound
    // and then undeliverable outbound, which would strand the link.
    if text.is_empty() || text.len() + 1 > mycelium_core::transport::link::MAX_LINK_ADDR {
        return None;
    }
    Some(text.to_string())
}

/// Write a link address back to the platform layer, NUL-terminated.
///
/// Returns false when it does not fit, in which case nothing is written: a
/// truncated address would name a different link.
///
/// # Safety
/// - `out` must point to `capacity` writable bytes.
unsafe fn write_link_addr(addr: &str, out: *mut c_char, capacity: u32) -> bool {
    let needed = addr.len() + 1;
    if needed > capacity as usize {
        set_last_error(format!(
            "link address of {} bytes exceeds caller buffer of {} bytes",
            needed, capacity
        ));
        return false;
    }
    std::ptr::copy_nonoverlapping(addr.as_ptr() as *const c_char, out, addr.len());
    *out.add(addr.len()) = 0;
    true
}

/// Notify the BLE transport that a link came up, in either GATT role.
///
/// Returns 0 on success, -1 on a bad argument, -2 if BLE is not registered.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `addr` must point to a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn mycelium_ble_on_link_up(
    handle: *mut MyceliumNode,
    addr: *const c_char,
) -> i32 {
    if handle.is_null() || addr.is_null() {
        return -1;
    }
    let Some(addr) = link_addr(addr) else {
        return -1;
    };

    let node = &(*handle).node;
    runtime().block_on(async {
        let guard = node.ble_transport.read().await;
        if let Some(ble) = guard.as_ref() {
            ble.on_link_up(&addr);
            0
        } else {
            -2 // BLE transport not registered
        }
    })
}

/// Notify the BLE transport that a link went away.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `addr` must point to a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn mycelium_ble_on_link_down(
    handle: *mut MyceliumNode,
    addr: *const c_char,
) -> i32 {
    if handle.is_null() || addr.is_null() {
        return -1;
    }
    let Some(addr) = link_addr(addr) else {
        return -1;
    };

    let node = &(*handle).node;
    runtime().block_on(async {
        let guard = node.ble_transport.read().await;
        if let Some(ble) = guard.as_ref() {
            ble.on_link_down(&addr);
            0
        } else {
            -2
        }
    })
}

/// Feed one frame received on a BLE link into the transport layer.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `addr` must point to a NUL-terminated UTF-8 string.
/// - `data` must point to `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_ble_on_link_data(
    handle: *mut MyceliumNode,
    addr: *const c_char,
    data: *const u8,
    data_len: u32,
) -> i32 {
    if handle.is_null() || addr.is_null() || data.is_null() {
        return -1;
    }
    let Some(addr) = link_addr(addr) else {
        return -1;
    };
    let payload = std::slice::from_raw_parts(data, data_len as usize).to_vec();

    let node = &(*handle).node;
    runtime().block_on(async {
        let guard = node.ble_transport.read().await;
        if let Some(ble) = guard.as_ref() {
            ble.on_link_data(&addr, &payload);
            0
        } else {
            -2
        }
    })
}

/// Notify the Wi-Fi Direct transport that a socket came up.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `addr` must point to a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn mycelium_wifi_on_link_up(
    handle: *mut MyceliumNode,
    addr: *const c_char,
) -> i32 {
    if handle.is_null() || addr.is_null() {
        return -1;
    }
    let Some(addr) = link_addr(addr) else {
        return -1;
    };

    let node = &(*handle).node;
    runtime().block_on(async {
        let guard = node.wifi_transport.read().await;
        if let Some(wifi) = guard.as_ref() {
            wifi.on_link_up(&addr);
            0
        } else {
            -2
        }
    })
}

/// Notify the Wi-Fi Direct transport that a socket went away.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `addr` must point to a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn mycelium_wifi_on_link_down(
    handle: *mut MyceliumNode,
    addr: *const c_char,
) -> i32 {
    if handle.is_null() || addr.is_null() {
        return -1;
    }
    let Some(addr) = link_addr(addr) else {
        return -1;
    };

    let node = &(*handle).node;
    runtime().block_on(async {
        let guard = node.wifi_transport.read().await;
        if let Some(wifi) = guard.as_ref() {
            wifi.on_link_down(&addr);
            0
        } else {
            -2
        }
    })
}

/// Feed one frame received on a Wi-Fi Direct link into the transport layer.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `addr` must point to a NUL-terminated UTF-8 string.
/// - `data` must point to `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_wifi_on_link_data(
    handle: *mut MyceliumNode,
    addr: *const c_char,
    data: *const u8,
    data_len: u32,
) -> i32 {
    if handle.is_null() || addr.is_null() || data.is_null() {
        return -1;
    }
    let Some(addr) = link_addr(addr) else {
        return -1;
    };
    let payload = std::slice::from_raw_parts(data, data_len as usize).to_vec();

    let node = &(*handle).node;
    runtime().block_on(async {
        let guard = node.wifi_transport.read().await;
        if let Some(wifi) = guard.as_ref() {
            wifi.on_link_data(&addr, &payload);
            0
        } else {
            -2
        }
    })
}

// --- Transport Outbox API ---

/// Dequeue one pending BLE frame, with the link to write it on.
///
/// Returns 1 if a frame was dequeued (fills out params), 0 if empty,
/// -1 on error, -3 if the frame does not fit `out_data`, -5 if the address
/// does not fit `out_addr`.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `out_addr` must point to `addr_capacity` writable bytes.
/// - `out_data` must point to `data_capacity` writable bytes.
/// - `out_data_len` must point to a valid u32.
#[no_mangle]
pub unsafe extern "C" fn mycelium_ble_dequeue_send(
    handle: *mut MyceliumNode,
    out_addr: *mut c_char,
    addr_capacity: u32,
    out_data: *mut u8,
    data_capacity: u32,
    out_data_len: *mut u32,
    out_is_handshake: *mut u32,
) -> i32 {
    if handle.is_null()
        || out_addr.is_null()
        || out_data.is_null()
        || out_data_len.is_null()
        || out_is_handshake.is_null()
    {
        return -1;
    }

    let node = &(*handle).node;
    let result = runtime().block_on(async {
        let guard = node.ble_transport.read().await;
        guard.as_ref().and_then(|ble| ble.dequeue_send())
    });

    match result {
        Some((addr, data, handshake)) => {
            if data.len() > data_capacity as usize {
                // A truncated frame would corrupt the peer's reassembly; drop
                // it and report the problem instead of handing out garbage.
                set_last_error(format!(
                    "outbox frame of {} bytes exceeds caller buffer of {} bytes; dropped",
                    data.len(),
                    data_capacity
                ));
                (*out_data_len) = data.len() as u32;
                return -3;
            }
            // The frame has already left the outbox, so a buffer too small
            // for the address drops it. The peer tolerates the gap: a local
            // link's frames carry their counter precisely so a lost one is
            // survivable (ADR-021).
            if !write_link_addr(&addr, out_addr, addr_capacity) {
                return -5;
            }
            std::ptr::copy_nonoverlapping(data.as_ptr(), out_data, data.len());
            (*out_data_len) = data.len() as u32;
            // The platform layer must neither delay nor evict a handshake
            // frame, and cannot work out which one is: a link is established
            // in Rust as soon as the peer's confirmation arrives, which can
            // be before our own confirmation has left (ADR-021).
            (*out_is_handshake) = u32::from(handshake);
            1
        }
        None => 0,
    }
}

/// Dequeue one pending Wi-Fi Direct frame, with the link to write it on.
///
/// Returns 1 if a frame was dequeued (fills out params), 0 if empty,
/// -1 on error, -3 if the frame does not fit `out_data`, -5 if the address
/// does not fit `out_addr`.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `out_addr` must point to `addr_capacity` writable bytes.
/// - `out_data` must point to `data_capacity` writable bytes.
/// - `out_data_len` must point to a valid u32.
#[no_mangle]
pub unsafe extern "C" fn mycelium_wifi_dequeue_send(
    handle: *mut MyceliumNode,
    out_addr: *mut c_char,
    addr_capacity: u32,
    out_data: *mut u8,
    data_capacity: u32,
    out_data_len: *mut u32,
    out_is_handshake: *mut u32,
) -> i32 {
    if handle.is_null()
        || out_addr.is_null()
        || out_data.is_null()
        || out_data_len.is_null()
        || out_is_handshake.is_null()
    {
        return -1;
    }

    let node = &(*handle).node;
    let result = runtime().block_on(async {
        let guard = node.wifi_transport.read().await;
        guard.as_ref().and_then(|wifi| wifi.dequeue_send())
    });

    match result {
        Some((addr, data, handshake)) => {
            if data.len() > data_capacity as usize {
                set_last_error(format!(
                    "outbox frame of {} bytes exceeds caller buffer of {} bytes; dropped",
                    data.len(),
                    data_capacity
                ));
                (*out_data_len) = data.len() as u32;
                return -3;
            }
            if !write_link_addr(&addr, out_addr, addr_capacity) {
                return -5;
            }
            std::ptr::copy_nonoverlapping(data.as_ptr(), out_data, data.len());
            (*out_data_len) = data.len() as u32;
            // The platform layer must neither delay nor evict a handshake
            // frame, and cannot work out which one is: a link is established
            // in Rust as soon as the peer's confirmation arrives, which can
            // be before our own confirmation has left (ADR-021).
            (*out_is_handshake) = u32::from(handshake);
            1
        }
        None => 0,
    }
}

/// What the platform layer must do with a link.
pub const MYCELIUM_LINK_ESTABLISHED: u32 = 1;
pub const MYCELIUM_LINK_CLOSE: u32 = 2;

fn link_event_code(directive: mycelium_core::transport::link::LinkDirective) -> u32 {
    match directive {
        mycelium_core::transport::link::LinkDirective::Established => MYCELIUM_LINK_ESTABLISHED,
        mycelium_core::transport::link::LinkDirective::Close => MYCELIUM_LINK_CLOSE,
    }
}

/// Take the next thing the platform layer must do with a BLE link.
///
/// `MYCELIUM_LINK_ESTABLISHED` (1) means the handshake completed and the
/// bridge can stop retrying that address. `MYCELIUM_LINK_CLOSE` (2) means
/// close it and do not immediately redial: the handshake failed, timed out,
/// named us, or there was no room for it. Nothing was installed.
///
/// Returns 1 if an event was dequeued, 0 if none, -1 on error, -5 if the
/// address does not fit `out_addr`.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `out_addr` must point to `addr_capacity` writable bytes.
/// - `out_event` must point to a valid u32.
#[no_mangle]
pub unsafe extern "C" fn mycelium_ble_dequeue_link_event(
    handle: *mut MyceliumNode,
    out_addr: *mut c_char,
    addr_capacity: u32,
    out_event: *mut u32,
) -> i32 {
    if handle.is_null() || out_addr.is_null() || out_event.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let result = runtime().block_on(async {
        let guard = node.ble_transport.read().await;
        guard.as_ref().and_then(|ble| ble.next_directive())
    });

    match result {
        Some((addr, directive)) => {
            if !write_link_addr(&addr, out_addr, addr_capacity) {
                return -5;
            }
            (*out_event) = link_event_code(directive);
            1
        }
        None => 0,
    }
}

/// Take the next thing the platform layer must do with a Wi-Fi Direct link.
///
/// Codes are as in `mycelium_ble_dequeue_link_event`.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `out_addr` must point to `addr_capacity` writable bytes.
/// - `out_event` must point to a valid u32.
#[no_mangle]
pub unsafe extern "C" fn mycelium_wifi_dequeue_link_event(
    handle: *mut MyceliumNode,
    out_addr: *mut c_char,
    addr_capacity: u32,
    out_event: *mut u32,
) -> i32 {
    if handle.is_null() || out_addr.is_null() || out_event.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let result = runtime().block_on(async {
        let guard = node.wifi_transport.read().await;
        guard.as_ref().and_then(|wifi| wifi.next_directive())
    });

    match result {
        Some((addr, directive)) => {
            if !write_link_addr(&addr, out_addr, addr_capacity) {
                return -5;
            }
            (*out_event) = link_event_code(directive);
            1
        }
        None => 0,
    }
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

    // Rotates our sender key and redistributes it to the remaining members.
    match runtime().block_on(node.remove_group_member(gid, mid)) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("remove_group_member: {}", e));
            -2
        }
    }
}

// --- Display Name ---

/// Set the node's display name (used in beacons).
///
/// Returns 0 on success, -1 on invalid args.
///
/// # Safety
/// - `handle` must be a valid pointer from `mycelium_node_new()`.
/// - `name` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn mycelium_set_node_display_name(
    handle: *mut MyceliumNode,
    name: *const c_char,
) -> i32 {
    if handle.is_null() || name.is_null() {
        return -1;
    }

    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error("Invalid UTF-8 in name");
            return -1;
        }
    };

    // Note: NodeConfig is not behind a RwLock, but the beacon task clones
    // display_name at start. For runtime updates, we'd need interior mutability.
    // For now, this is intended to be called before node.start().
    // The config is in a non-mutable Arc, so we log the intent.
    tracing::info!("mycelium_set_display_name called with: {}", name_str);

    0
}

// --- LoRa Transport FFI ---

/// Register the LoRa transport for this node.
///
/// Creates a LoRa transport with default config (US 915 MHz, SF10, ADR enabled).
///
/// Returns 0 on success.
///
/// # Safety
/// - `handle` must be a valid pointer from `mycelium_node_new`.
#[no_mangle]
pub unsafe extern "C" fn mycelium_register_lora_transport(handle: *mut MyceliumNode) -> i32 {
    if handle.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let lora = Arc::new(mycelium_core::transport::lora::LoraTransport::new(
        mycelium_core::transport::lora::LoraConfig::default(),
    ));
    runtime().block_on(async {
        node.transport_manager.replace_transport(lora.clone()).await;
        *node.lora_transport.write().await = Some(lora);
    });
    0
}

/// Register the LoRa transport with custom configuration.
///
/// Returns 0 on success, -1 on invalid args.
///
/// # Safety
/// - `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn mycelium_register_lora_transport_configured(
    handle: *mut MyceliumNode,
    frequency_mhz: f32,
    spreading_factor: u8,
    bandwidth_khz: u16,
    tx_power_dbm: i8,
    duty_cycle_limit: f32,
    adaptive_data_rate: bool,
) -> i32 {
    if handle.is_null() {
        return -1;
    }

    let config = mycelium_core::transport::lora::LoraConfig {
        frequency_mhz,
        spreading_factor,
        bandwidth_khz,
        tx_power_dbm,
        duty_cycle_limit,
        adaptive_data_rate,
    };

    let node = &(*handle).node;
    let lora = Arc::new(mycelium_core::transport::lora::LoraTransport::new(config));
    runtime().block_on(async {
        node.transport_manager.replace_transport(lora.clone()).await;
        *node.lora_transport.write().await = Some(lora);
    });
    0
}

/// Notify the LoRa transport that a peer was discovered.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_lora_on_peer_discovered(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    runtime().block_on(async {
        let guard = node.lora_transport.read().await;
        if let Some(lora) = guard.as_ref() {
            lora.on_peer_discovered(peer).await;
            0
        } else {
            -2
        }
    })
}

/// Notify the LoRa transport that a peer was lost.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_lora_on_peer_lost(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    runtime().block_on(async {
        let guard = node.lora_transport.read().await;
        if let Some(lora) = guard.as_ref() {
            lora.on_peer_lost(peer).await;
            0
        } else {
            -2
        }
    })
}

/// Feed data received from the LoRa module into the transport layer.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
/// - `data` must point to `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_lora_on_data_received(
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
        let guard = node.lora_transport.read().await;
        if let Some(lora) = guard.as_ref() {
            lora.on_data_received(peer, payload).await;
            0
        } else {
            -2
        }
    })
}

/// Dequeue one pending LoRa send from the outbox.
///
/// Returns 1 if a packet was dequeued (fills out params), 0 if empty, -1 on error.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `out_peer_id` must point to 32 bytes.
/// - `out_data` must point to `data_capacity` bytes.
/// - `out_data_len` must point to a valid u32.
#[no_mangle]
pub unsafe extern "C" fn mycelium_lora_dequeue_send(
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
        let guard = node.lora_transport.read().await;
        guard.as_ref().and_then(|lora| lora.dequeue_send())
    });

    match result {
        Some((peer, data)) => {
            if data.len() > data_capacity as usize {
                // A truncated frame would corrupt the peer's reassembly; drop it
                // and report the problem instead of handing out garbage.
                set_last_error(format!(
                    "outbox packet of {} bytes exceeds caller buffer of {} bytes; dropped",
                    data.len(),
                    data_capacity
                ));
                (*out_data_len) = data.len() as u32;
                return -3;
            }
            (*out_peer_id) = *peer.as_bytes();
            std::ptr::copy_nonoverlapping(data.as_ptr(), out_data, data.len());
            (*out_data_len) = data.len() as u32;
            1
        }
        None => 0,
    }
}

/// Report a successful LoRa transmission for ADR negotiation.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_lora_report_tx_success(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    runtime().block_on(async {
        let guard = node.lora_transport.read().await;
        if let Some(lora) = guard.as_ref() {
            lora.report_tx_success(&peer);
            0
        } else {
            -2
        }
    })
}

/// Report a failed LoRa transmission for ADR negotiation.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_lora_report_tx_failure(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    runtime().block_on(async {
        let guard = node.lora_transport.read().await;
        if let Some(lora) = guard.as_ref() {
            lora.report_tx_failure(&peer);
            0
        } else {
            -2
        }
    })
}

// --- BT Classic Transport FFI ---

/// Register the Bluetooth Classic SPP transport for this node.
///
/// Returns 0 on success.
///
/// # Safety
/// - `handle` must be a valid pointer from `mycelium_node_new`.
#[no_mangle]
pub unsafe extern "C" fn mycelium_register_bt_classic_transport(handle: *mut MyceliumNode) -> i32 {
    if handle.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let bt = Arc::new(mycelium_core::transport::bt_classic::BtClassicTransport::new());
    runtime().block_on(async {
        node.transport_manager.replace_transport(bt.clone()).await;
        *node.bt_classic_transport.write().await = Some(bt);
    });
    0
}

/// Notify the BT Classic transport that a peer connected via SPP.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_bt_classic_on_peer_connected(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    runtime().block_on(async {
        let guard = node.bt_classic_transport.read().await;
        if let Some(bt) = guard.as_ref() {
            bt.on_peer_connected(peer).await;
            0
        } else {
            -2
        }
    })
}

/// Notify the BT Classic transport that a peer disconnected.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_bt_classic_on_peer_disconnected(
    handle: *mut MyceliumNode,
    peer_id: *const [u8; 32],
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    let peer = NodeId::from_bytes(*peer_id);

    runtime().block_on(async {
        let guard = node.bt_classic_transport.read().await;
        if let Some(bt) = guard.as_ref() {
            bt.on_peer_disconnected(peer).await;
            0
        } else {
            -2
        }
    })
}

/// Feed data received from BT Classic into the transport layer.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `peer_id` must point to 32 bytes.
/// - `data` must point to `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_bt_classic_on_data_received(
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
        let guard = node.bt_classic_transport.read().await;
        if let Some(bt) = guard.as_ref() {
            bt.on_data_received(peer, payload).await;
            0
        } else {
            -2
        }
    })
}

/// Dequeue one pending BT Classic send from the outbox.
///
/// Returns 1 if a packet was dequeued (fills out params), 0 if empty, -1 on error.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `out_peer_id` must point to 32 bytes.
/// - `out_data` must point to `data_capacity` bytes.
/// - `out_data_len` must point to a valid u32.
#[no_mangle]
pub unsafe extern "C" fn mycelium_bt_classic_dequeue_send(
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
        let guard = node.bt_classic_transport.read().await;
        guard.as_ref().and_then(|bt| bt.dequeue_send())
    });

    match result {
        Some((peer, data)) => {
            if data.len() > data_capacity as usize {
                // A truncated frame would corrupt the peer's reassembly; drop it
                // and report the problem instead of handing out garbage.
                set_last_error(format!(
                    "outbox packet of {} bytes exceeds caller buffer of {} bytes; dropped",
                    data.len(),
                    data_capacity
                ));
                (*out_data_len) = data.len() as u32;
                return -3;
            }
            (*out_peer_id) = *peer.as_bytes();
            std::ptr::copy_nonoverlapping(data.as_ptr(), out_data, data.len());
            (*out_data_len) = data.len() as u32;
            1
        }
        None => 0,
    }
}

// --- Internet Transport API ---

/// Register the Internet (TCP) transport with default settings (port 9736).
///
/// Returns 0 on success, -1 on null handle, or -3 if an internet transport is
/// already registered — it is left running and untouched. Changing the
/// internet transport means stopping the node and starting it again: a second
/// DHT engine over the same database would have its own mark writer, with no
/// ordering against the first's (ROADMAP T-46).
///
/// # Safety
/// - `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn mycelium_register_internet_transport(handle: *mut MyceliumNode) -> i32 {
    if handle.is_null() {
        return -1;
    }

    let node = &(*handle).node;
    // The same durable marks the node's own registration uses. An
    // FFI-registered transport that quietly fell back to in-memory marks
    // would lose rollback protection on exactly the platform where restarts
    // are most frequent (ADR-016, T-38).
    let internet = Arc::new(InternetTransport::with_mark_store(
        node.identity_handle(),
        InternetConfig::default(),
        Arc::new(DbMarkStore::new(node.db.clone())),
    ));
    runtime().block_on(async {
        // Settle whatever was registered before, rather than dropping it.
        //
        // Two DHT engines over one database have two independent mark-writer
        // tasks and no ordering between them, so the old engine's pending
        // eviction can land after the new engine has restored and erase a mark
        // it had just adopted. A *confirmed* drain of the old writer is the
        // only thing that establishes an order between the two.
        //
        // Stop first, then confirm. Draining before the stop proved nothing:
        // the old transport was still serving, so it could queue more writes
        // in the gap, and `stop()`'s own flush only warns. Stopping quiesces
        // admission — no accept loop, no connections — and the drain after it
        // is therefore final.
        //
        // If it still will not drain, the old transport is restarted and the
        // replacement refused, because the alternatives are both worse:
        // installing the new engine risks the silent loss of the protection
        // this database exists to hold, and leaving the old one stopped would
        // hand back no transport at all.
        // The write guard is held across the whole swap, which is what makes
        // it exclusive: it is the lock every path that reaches the internet
        // transport takes, so nothing can dial or reuse the old transport
        // between the stop and the swap, and two concurrent registrations
        // cannot both get as far as installing an engine over this database.
        // Refused rather than replaced, when one is already registered.
        //
        // A second DHT engine over this node's database brings its own mark
        // writer, and there is no ordering between two writers: one engine's
        // eviction can land after the other's restoration and erase a mark it
        // had just adopted, which is the rollback protection the database
        // exists to hold (ADR-016).
        //
        // Making a swap safe needs the old engine to be provably quiet, and
        // `stop()` cannot give that. Its connection drain is bounded and only
        // warns, so a stuck handler can still be alive — and still admitting
        // records — when `stop()` returns, whatever the mark writer says about
        // having caught up. Four successive attempts at sequencing this each
        // uncovered the next hole; not creating the second engine closes the
        // class instead. Doing it properly is ROADMAP T-46.
        //
        // The slot lock is held across the check and the install, so two
        // concurrent registrations cannot both get past it.
        let mut slot = node.internet_transport.write().await;
        if slot.is_some() {
            return -3;
        }
        node.transport_manager
            .replace_transport(internet.clone())
            .await;
        *slot = Some(internet);
        0
    })
}

/// Register the Internet (TCP) transport with custom port and bootstrap nodes.
///
/// `bootstrap_csv` is a comma-separated list of "ip:port" entries (or NULL for none).
///
/// Returns 0 on success, -1 on null handle, -2 on invalid port, or -3 if an
/// internet transport is already registered — it is left running and
/// untouched. Changing the internet transport means stopping the node and
/// starting it again: a second DHT engine over the same database would have
/// its own mark writer, with no ordering against the first's (ROADMAP T-46).
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `bootstrap_csv` must be a valid C string or NULL.
#[no_mangle]
pub unsafe extern "C" fn mycelium_register_internet_transport_configured(
    handle: *mut MyceliumNode,
    port: u16,
    bootstrap_csv: *const c_char,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    if port == 0 {
        return -2;
    }

    let bootstrap: Vec<std::net::SocketAddr> = if !bootstrap_csv.is_null() {
        let csv = CStr::from_ptr(bootstrap_csv).to_string_lossy();
        csv.split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    } else {
        Vec::new()
    };

    let config = InternetConfig {
        listen_addr: format!("0.0.0.0:{}", port).parse().unwrap(),
        bootstrap_nodes: bootstrap,
        max_connections: 64,
    };

    let node = &(*handle).node;
    let internet = Arc::new(InternetTransport::with_mark_store(
        node.identity_handle(),
        config,
        Arc::new(DbMarkStore::new(node.db.clone())),
    ));
    runtime().block_on(async {
        // Settle whatever was registered before, rather than dropping it.
        //
        // Two DHT engines over one database have two independent mark-writer
        // tasks and no ordering between them, so the old engine's pending
        // eviction can land after the new engine has restored and erase a mark
        // it had just adopted. A *confirmed* drain of the old writer is the
        // only thing that establishes an order between the two.
        //
        // Stop first, then confirm. Draining before the stop proved nothing:
        // the old transport was still serving, so it could queue more writes
        // in the gap, and `stop()`'s own flush only warns. Stopping quiesces
        // admission — no accept loop, no connections — and the drain after it
        // is therefore final.
        //
        // If it still will not drain, the old transport is restarted and the
        // replacement refused, because the alternatives are both worse:
        // installing the new engine risks the silent loss of the protection
        // this database exists to hold, and leaving the old one stopped would
        // hand back no transport at all.
        // The write guard is held across the whole swap, which is what makes
        // it exclusive: it is the lock every path that reaches the internet
        // transport takes, so nothing can dial or reuse the old transport
        // between the stop and the swap, and two concurrent registrations
        // cannot both get as far as installing an engine over this database.
        // Refused rather than replaced, when one is already registered.
        //
        // A second DHT engine over this node's database brings its own mark
        // writer, and there is no ordering between two writers: one engine's
        // eviction can land after the other's restoration and erase a mark it
        // had just adopted, which is the rollback protection the database
        // exists to hold (ADR-016).
        //
        // Making a swap safe needs the old engine to be provably quiet, and
        // `stop()` cannot give that. Its connection drain is bounded and only
        // warns, so a stuck handler can still be alive — and still admitting
        // records — when `stop()` returns, whatever the mark writer says about
        // having caught up. Four successive attempts at sequencing this each
        // uncovered the next hole; not creating the second engine closes the
        // class instead. Doing it properly is ROADMAP T-46.
        //
        // The slot lock is held across the check and the install, so two
        // concurrent registrations cannot both get past it.
        let mut slot = node.internet_transport.write().await;
        if slot.is_some() {
            return -3;
        }
        node.transport_manager
            .replace_transport(internet.clone())
            .await;
        *slot = Some(internet);
        0
    })
}

/// Connect to a peer at the given "ip:port" address via the Internet transport.
///
/// On success, writes the peer's 32-byte NodeId into `out_peer_id` and returns 0.
/// Returns -1 on null args, -2 if transport not registered, -3 on connection failure.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `addr` must be a valid C string.
/// - `out_peer_id` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_internet_connect_to(
    handle: *mut MyceliumNode,
    addr: *const c_char,
    out_peer_id: *mut [u8; 32],
) -> i32 {
    if handle.is_null() || addr.is_null() || out_peer_id.is_null() {
        return -1;
    }

    let addr_str = CStr::from_ptr(addr).to_string_lossy();
    let sock_addr: std::net::SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => {
            set_last_error(format!("Invalid address: {}", addr_str));
            return -3;
        }
    };

    let node = &(*handle).node;

    runtime().block_on(async {
        let guard = node.internet_transport.read().await;
        if let Some(ref inet) = *guard {
            match inet.connect_to(sock_addr).await {
                Ok(peer_id) => {
                    (*out_peer_id) = *peer_id.as_bytes();
                    0
                }
                Err(e) => {
                    set_last_error(format!("Connect failed: {}", e));
                    -3
                }
            }
        } else {
            set_last_error("Internet transport not registered");
            -2
        }
    })
}

/// Get the number of connected Internet transport peers.
///
/// Returns the peer count (>= 0), or -1 on null handle, -2 if not registered.
///
/// # Safety
/// - `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn mycelium_internet_peer_count(handle: *mut MyceliumNode) -> i32 {
    if handle.is_null() {
        return -1;
    }

    let node = &(*handle).node;

    runtime().block_on(async {
        let guard = node.internet_transport.read().await;
        if let Some(ref inet) = *guard {
            inet.connected_peers().len() as i32
        } else {
            -2
        }
    })
}
