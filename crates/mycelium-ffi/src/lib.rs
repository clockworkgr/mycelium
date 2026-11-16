//! FFI bindings for mobile platforms (Android/iOS).
//!
//! This crate exposes the Mycelium node API via C-compatible FFI.
//! When UniFFI is integrated, proc macros will generate Kotlin/Swift bindings.
//!
//! For v0.1, we provide a simple C API that the Android JNI layer calls.

use std::cell::RefCell;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

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

/// Store a message for `mycelium_last_error` to hand back.
///
/// Neither the thread-local access nor the borrow may panic: this is called
/// from the panic guard's own recovery path, where a second panic would unwind
/// across the FFI boundary (see `store_caught_panic`). Failing to record a
/// message is a lost diagnostic; failing to return is undefined behaviour.
fn set_last_error(msg: impl Into<String>) {
    let msg = msg.into();
    let _ = LAST_ERROR.try_with(|cell| {
        if let Ok(mut slot) = cell.try_borrow_mut() {
            *slot = Some(msg);
        }
    });
}

/// A panic was caught crossing the FFI boundary (ADR-018). The message, with
/// the panic's location, is readable through `mycelium_last_error`.
pub const MYCELIUM_ERR_PANIC: i32 = -99;

/// The call was refused before it ran: it blocks on the async runtime, and the
/// calling thread is already driving that runtime (ROADMAP T-01).
pub const MYCELIUM_ERR_REENTRANT: i32 = -98;

/// The failure value for one FFI return shape (ADR-018).
///
/// One implementation per shape, so "a negative code for `i32`, null for a
/// pointer, false for a bool" is written once rather than in 64 hand-written
/// wrappers that would drift. `f32` and `()` are shapes ADR-018 did not name:
/// `-1.0` is what `mycelium_trust_score` already documents as its error value,
/// and a `void` function has no return channel at all — `LAST_ERROR` is its
/// only report.
trait FfiFailure: Sized {
    /// Returned when the body panicked.
    fn failure() -> Self;

    /// Returned when the call was refused before the body ran. Shapes with a
    /// single failure value cannot tell the caller which happened; the stored
    /// message always can.
    fn refused() -> Self {
        Self::failure()
    }
}

impl FfiFailure for i32 {
    fn failure() -> Self {
        MYCELIUM_ERR_PANIC
    }

    fn refused() -> Self {
        MYCELIUM_ERR_REENTRANT
    }
}

impl FfiFailure for bool {
    fn failure() -> Self {
        false
    }
}

impl FfiFailure for f32 {
    fn failure() -> Self {
        -1.0
    }
}

impl<T> FfiFailure for *mut T {
    fn failure() -> Self {
        std::ptr::null_mut()
    }
}

impl FfiFailure for () {
    fn failure() -> Self {}
}

thread_local! {
    /// Where the last panic on this thread was raised. A panic payload carries
    /// the message but not the location, and the location is the half a bug
    /// report needs, so the hook below records it here for the guard to pick up.
    static PANIC_SITE: RefCell<Option<String>> = const { RefCell::new(None) };
}

static PANIC_HOOK_INIT: Once = Once::new();

/// Install the panic hook that records a panic's location.
///
/// Chained in front of whatever hook was already installed, so the default
/// stderr report (and the test harness's capture) still happens.
///
/// Recording the location is infallible, and nothing else here may be
/// anything else. Logging in particular is not — a subscriber is arbitrary
/// code — and a hook is the one place a panic cannot be contained, because it
/// runs while the thread is unwinding, where a second panic aborts before any
/// `catch_unwind` sees it. The log therefore happens in `store_caught_panic`,
/// after the catch.
///
/// Logging only *unguarded* panics here was tried, and is worse than it looks:
/// a subscriber that panics would then be reported through that same
/// subscriber, which aborts. Measured rather than reasoned about —
/// `test_a_panicking_tracing_subscriber_does_not_turn_a_panic_into_an_abort`
/// failed in exactly that way. What leaving it out costs is that a panic in a
/// spawned task still reaches no diagnostic on Android, which is where it was
/// before this change and is not what T-01 is about.
///
/// Every step is infallible or ignored. A panic raised inside a panic hook
/// aborts the process.
///
/// Skipped entirely while the calling thread is unwinding, because
/// `take_hook` and `set_hook` both panic when called from a panicking thread —
/// and a panic raised during unwinding aborts immediately, uncatchably, from
/// the one function whose job is to stop that happening. The reachable shape
/// is a Rust destructor that calls into this library as the stack unwinds past
/// it. The check sits outside `call_once` on purpose: consuming the `Once`
/// here would leave the hook permanently uninstalled, so what is lost is the
/// location of this one panic rather than of every later one.
fn install_panic_hook() {
    if std::thread::panicking() {
        return;
    }
    PANIC_HOOK_INIT.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let site = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_else(|| "<unknown location>".to_string());
            let _ = PANIC_SITE.try_with(|cell| {
                if let Ok(mut slot) = cell.try_borrow_mut() {
                    *slot = Some(site);
                }
            });
            previous(info);
        }));
    });
}

/// Record a caught panic in `LAST_ERROR`.
///
/// Every step here has to be panic-free. This runs *after* `catch_unwind` has
/// handed the payload back, so a panic raised here would unwind out of the
/// guard and across the FFI boundary — the abort the guard exists to prevent,
/// reintroduced by the guard itself. Unwinding has already dropped the frames
/// that held the error cell, so a plain `borrow_mut()` would in fact succeed;
/// `try_borrow_mut` is the cheap way not to depend on that reasoning staying
/// true, and `try_with` covers a thread whose thread-locals are already
/// destroyed. Failing to record a message is the acceptable outcome here;
/// failing to return is not.
fn store_caught_panic(function: &str, payload: Box<dyn std::any::Any + Send>) {
    // Take the message by value, which also decides how the payload is
    // disposed of. Dropping it happens *here*, outside `catch_unwind`, so a
    // `Drop` implementation that panicked would unwind across the boundary —
    // the abort the guard prevents, reached through the payload instead of the
    // body. `panic!` produces a `&'static str` or a `String`, neither of which
    // can panic on drop, so those are dropped normally. Anything else arrived
    // through `panic_any` with a destructor this crate knows nothing about,
    // and is leaked instead: memory lost once per panic is the cheaper of the
    // two failures, and a panic is already a defect to fix.
    let message = match payload.downcast::<String>() {
        Ok(text) => *text,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(text) => (*text).to_string(),
            Err(payload) => {
                std::mem::forget(payload);
                "panic with a payload that is not a string".to_string()
            }
        },
    };

    let site = PANIC_SITE
        .try_with(|cell| cell.try_borrow_mut().ok().and_then(|mut slot| slot.take()))
        .ok()
        .flatten();

    let text = match site {
        Some(site) => format!("panic in {} at {}: {}", function, site, message),
        None => format!("panic in {}: {}", function, message),
    };

    // Logged here, not in the hook: this runs after the panic was caught, so a
    // subscriber that panics can be contained rather than aborting the process
    // on its way out. Its payload is forgotten for the reason above.
    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tracing::error!(function, panic = %text, "caught at the Mycelium FFI boundary");
    })) {
        std::mem::forget(payload);
    }

    set_last_error(text);
}

/// Note that a blocking FFI call was refused for re-entrancy.
fn refuse_reentrant_call(function: &str) {
    tracing::warn!(
        function,
        "refused a blocking FFI call made from a runtime thread"
    );
    set_last_error(format!(
        "{} blocks on the async runtime, and the calling thread is already \
         driving it; call it from a thread outside the runtime (ROADMAP T-01)",
        function
    ));
}

/// Wrap an FFI function body in a panic guard (ADR-018).
///
/// Every exported function in this crate opens with this macro or with
/// [`ffi_guard_blocking`], and `test_every_exported_function_is_guarded`
/// enforces that, so a new function that forgets the guard fails the test suite
/// instead of unwinding across the boundary in the field.
///
/// The function's own name travels with the guard because that is what the
/// stored message leads with. `test_every_exported_function_is_guarded` checks
/// the literal against the function it wraps, so the two cannot drift.
///
/// `AssertUnwindSafe` is justified here once rather than in 64 places. What the
/// closure captures is the caller's raw pointers and `'static` statics; a
/// caught panic returns a failure value and touches none of it afterwards.
/// What it cannot promise is that a panic part-way through writing an
/// out-parameter leaves that buffer whole — so the boundary's contract, stated
/// in `mycelium.h`, is that **out-parameters are unspecified when a function
/// returns its failure value**. A panic may also leave one of this crate's
/// mutexes poisoned, which is why every lock here recovers from poison rather
/// than propagating it: a guard that converted a crash into a permanently
/// wedged FFI would be no improvement.
macro_rules! ffi_guard {
    ($function:literal, $body:block) => {{
        install_panic_hook();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(value) => value,
            Err(payload) => {
                store_caught_panic($function, payload);
                FfiFailure::failure()
            }
        }
    }};
}

/// Wrap an FFI function body that blocks on the async runtime.
///
/// Adds a re-entrancy check in front of [`ffi_guard`]'s panic guard, before the
/// body runs and therefore before any side effect: a `block_on` from a thread
/// that is already driving the runtime does not deadlock, it panics
/// ("Cannot start a runtime from within a runtime"), which without a guard
/// aborts the app. The only in-process caller that could do it is the message
/// callback registered by `mycelium_set_message_callback`, which runs on a
/// spawned task; its documentation already says not to block there.
///
/// `Handle::try_current()` is the whole of what tokio exposes, and it answers a
/// wider question than the one being asked: blocking is legal inside
/// `spawn_blocking` and inside `block_in_place`, and both are indistinguishable
/// from a future through every public API (measured, tokio 1.50). Refusing all
/// three is the conservative direction — the refusal is reported and
/// recoverable, the panic was not — and nothing in this repository calls the
/// FFI from either of the two. `ffi_guard`'s own `catch_unwind` remains the
/// backstop for any context this prediction gets wrong.
macro_rules! ffi_guard_blocking {
    ($function:literal, $body:block) => {
        ffi_guard!($function, {
            if tokio::runtime::Handle::try_current().is_ok() {
                refuse_reentrant_call($function);
                return FfiFailure::refused();
            }
            $body
        })
    };
}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static TRACING_INIT: Once = Once::new();

/// Holds a reference to the active node so the Dart layer can recover a handle
/// after the Flutter engine restarts (the process stayed alive through the
/// daemon service).
///
/// A reference, not a pointer. This used to be an `AtomicPtr` to a
/// `Box::into_raw` allocation, which made `mycelium_node_get_existing` hand out
/// a borrowed pointer that the next `mycelium_node_free` turned into a dangling
/// one, and made `mycelium_api_handle_status` dereference it with no ownership
/// at all (ROADMAP T-01).
static ACTIVE_NODE: Mutex<Option<Arc<MyceliumNode>>> = Mutex::new(None);

/// Lock the registry, recovering from a poisoning.
///
/// A guarded panic can poison this mutex, and what it guards is one
/// `Option<Arc<_>>` that no panic can leave half-written. Propagating the
/// poison would turn a single caught panic into an FFI that can never create
/// or recover a node again — the crash-to-wedge trade ADR-018 explicitly set
/// out to avoid.
fn active_node() -> MutexGuard<'static, Option<Arc<MyceliumNode>>> {
    ACTIVE_NODE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

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
    ffi_guard!("mycelium_last_error", {
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
    })
}

/// Clear the last error message.
#[no_mangle]
pub extern "C" fn mycelium_clear_error() {
    ffi_guard!("mycelium_clear_error", {
        LAST_ERROR.with(|cell| {
            *cell.borrow_mut() = None;
        });
    })
}

/// Opaque handle to a MyceliumNode.
pub struct MyceliumNode {
    node: Arc<Node>,
    /// Handle to the API server (started with the node).
    api_handle: Mutex<Option<mycelium_api::ApiServerHandle>>,
    /// Guards against a second `mycelium_node_start`, which would spawn a
    /// duplicate event loop and fail to rebind the API port.
    started: std::sync::atomic::AtomicBool,
    /// Held for the whole of a start or a stop, so the two cannot interleave.
    ///
    /// A start and a stop each move several pieces of state — the `started`
    /// flag, the node's own tasks, the API server's handle — and an
    /// interleaving can leave them disagreeing: a start that reaches the API
    /// server just after a stop took its handle leaves a server answering for
    /// a node that is being torn down. Each transition now completes before
    /// the other begins.
    lifecycle: Mutex<()>,
}

impl MyceliumNode {
    /// Reach the API server handle, recovering from a poisoned lock.
    ///
    /// Poisoning became a state worth handling the moment panics stopped
    /// ending the process (ADR-018): a caught panic while this was held leaves
    /// it poisoned, and treating that as "no handle" would strand a running
    /// API server that `mycelium_node_stop` could then never shut down, or
    /// discard the handle a fresh `mycelium_node_start` had just produced.
    /// What it guards is one `Option`, which a panic cannot leave
    /// half-written, so recovering is both safe and the only useful answer.
    fn api_handle(&self) -> MutexGuard<'_, Option<mycelium_api::ApiServerHandle>> {
        self.api_handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Take the lifecycle lock, recovering from a poisoning for the same
    /// reason as above: it guards an ordering, not a value, and a caught panic
    /// must not make the node unstoppable.
    fn lifecycle(&self) -> MutexGuard<'_, ()> {
        self.lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
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
    ffi_guard!("mycelium_api_check", {
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
    })
}

/// Diagnostic: check the API server handle status.
/// Returns: 0 = no node, 1 = node exists but no API handle, 2 = API handle exists (task running),
///          3 = API handle exists (task finished). A poisoned lock is recovered
/// rather than reported, so the status describes the server either way.
#[no_mangle]
pub extern "C" fn mycelium_api_handle_status() -> i32 {
    ffi_guard!("mycelium_api_handle_status", {
        let Some(mycelium) = active_node().as_ref().map(Arc::clone) else {
            return 0;
        };
        // Bound, rather than left as the tail expression: the lock guard must
        // be released before the reference it was taken from goes out of scope.
        let status = match mycelium.api_handle().as_ref() {
            None => 1,
            Some(handle) => {
                if handle.is_finished() {
                    3
                } else {
                    2
                }
            }
        };
        status
    })
}

/// Create a new Mycelium node.
///
/// Returns an owning handle, or NULL with the reason in `mycelium_last_error`.
/// The handle is reference-counted: pass it to `mycelium_node_free` exactly
/// once, and treat every handle `mycelium_node_get_existing` returns as another
/// reference needing its own free (ROADMAP T-01).
///
/// # Safety
/// `data_dir` and `display_name` must be valid C strings.
#[no_mangle]
pub unsafe extern "C" fn mycelium_node_new(
    data_dir: *const c_char,
    display_name: *const c_char,
) -> *mut MyceliumNode {
    ffi_guard!("mycelium_node_new", {
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
        let handle = Arc::new(MyceliumNode {
            node,
            api_handle: Mutex::new(None),
            started: std::sync::atomic::AtomicBool::new(false),
            lifecycle: Mutex::new(()),
        });

        // The registry keeps a reference of its own, so what
        // `mycelium_node_get_existing` hands back is an owning reference rather
        // than a borrowed pointer. Any node registered before this one is
        // released here but not destroyed if the caller still holds a handle to
        // it; nothing in this library stops a second node over the same data
        // directory, which is ROADMAP T-46.
        let replaced = active_node().replace(Arc::clone(&handle));
        drop(replaced);

        Arc::into_raw(handle) as *mut MyceliumNode
    })
}

/// Puts `started` back if the start path does not reach the point where the
/// node is live.
///
/// A second `mycelium_node_start` is a deliberate no-op, so the flag means
/// "this node is running". A panic now returns instead of ending the process
/// (ADR-018), which introduced a third way out of the start path: the flag
/// would say "running" while nothing ran, and every retry would answer
/// success. The error paths used to reset it by hand; this resets it on every
/// exit that is not the successful one.
struct StartedFlag<'a> {
    flag: &'a std::sync::atomic::AtomicBool,
    succeeded: bool,
}

impl<'a> StartedFlag<'a> {
    fn armed(flag: &'a std::sync::atomic::AtomicBool) -> Self {
        Self {
            flag,
            succeeded: false,
        }
    }

    fn succeeded(mut self) {
        self.succeeded = true;
    }
}

impl Drop for StartedFlag<'_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.flag.store(false, Ordering::Release);
        }
    }
}

/// Puts `started` back in step with the node on the way out of a stop.
///
/// A stop moves through states the FFI cannot see from outside: `Node::stop`
/// logs, then cancels every task, then drains the transports. A panic before
/// the cancellation leaves the node running; one after it leaves the node
/// finished. Guessing either way gets the other case wrong — "stuck started"
/// means the app is told a dead node is running, for the life of the process,
/// and "cleared too early" invites a second `Node::start` over live tasks. So
/// this asks the node instead, on every exit, and the flag ends up describing
/// what actually happened.
struct StoppedFlag<'a> {
    mycelium: &'a MyceliumNode,
    was_started: bool,
}

impl<'a> StoppedFlag<'a> {
    fn armed(mycelium: &'a MyceliumNode) -> Self {
        Self {
            mycelium,
            was_started: mycelium.started.load(Ordering::Acquire),
        }
    }
}

impl Drop for StoppedFlag<'_> {
    fn drop(&mut self) {
        // A stop can only ever take the flag from true to false. Reconciling
        // with the cancellation token alone would *set* it on a handle that
        // was never started — a stop that unwinds before cancelling would
        // then leave "running" behind it, and the next start would skip
        // `Node::start` altogether.
        let still_running = self.was_started && !self.mycelium.node.is_stopped();
        self.mycelium
            .started
            .store(still_running, Ordering::Release);
    }
}

/// Start the local API server, unless it is already running or disabled.
///
/// Separate from `mycelium_node_start`, and idempotent, because the node and
/// its API server became two states that can disagree once a panic stopped
/// ending the process: the node can be live with the server unstarted, and the
/// only caller who could notice is the one being told "already started". Every
/// start attempt therefore passes through here.
///
/// Serialization comes from the caller's lifecycle lock — both call sites hold
/// it — and **not** from holding the handle slot across the attempt. Holding it
/// would mean running arbitrary code under that lock: a tracing subscriber that
/// called `mycelium_api_handle_status` would deadlock on it, and no panic guard
/// can contain a deadlock. The slot is taken twice, briefly, instead.
///
/// A server that has *finished* is left alone — restarting a crashed API server
/// is a decision this function is not the place for, and
/// `mycelium_api_handle_status` reports it as 3.
fn start_api_server(mycelium: &MyceliumNode) {
    let config = &mycelium.node.config.api;
    if !config.enabled {
        return;
    }

    if mycelium.api_handle().is_some() {
        return;
    }

    match runtime().block_on(mycelium_api::start_server(
        Arc::clone(&mycelium.node),
        config,
    )) {
        Ok(api_task) => {
            // Stored before anything else can unwind: the handle is the only
            // way `mycelium_node_stop` can shut this server down, and dropping
            // it would leave the task running and the port bound with nothing
            // able to reach it.
            *mycelium.api_handle() = Some(api_task);
            info!(
                "API server started on {}:{}",
                config.bind_address, config.port
            );
        }
        Err(e) => {
            let msg = format!("API server failed to start: {}", e);
            info!("{}", msg);
            set_last_error(&msg);
            // The node is running either way, which is what the caller is
            // told; the next start attempt tries the server again.
        }
    }
}

/// Start the node and the local API server.
///
/// # Safety
/// `handle` must be a valid pointer from `mycelium_node_new`.
#[no_mangle]
pub unsafe extern "C" fn mycelium_node_start(handle: *mut MyceliumNode) -> bool {
    ffi_guard_blocking!("mycelium_node_start", {
        if handle.is_null() {
            set_last_error("handle must not be NULL");
            return false;
        }
        let mycelium = &(*handle);
        let _lifecycle = mycelium.lifecycle();

        // A stopped node cannot be restarted: `Node::stop` cancels a token
        // that nothing resets, so `Node::start` would spawn tasks that exit
        // immediately and report success. Refusing says so instead; the way
        // back is a new handle, which is a second engine over the same
        // database and therefore ROADMAP T-46.
        if mycelium.node.is_stopped() {
            set_last_error(
                "this node has been stopped and cannot be restarted; create a new handle",
            );
            return false;
        }

        if mycelium.started.swap(true, Ordering::AcqRel) {
            info!("Node already started, ignoring duplicate start");
            // Not simply `true`: the node being live does not mean the API
            // server is. A caught panic can land between the two, and the
            // Flutter layer talks to the node *through* that server, so a
            // retry that answered "already started" would leave the app with a
            // running node it cannot reach, for good.
            start_api_server(mycelium);
            return true;
        }
        // Nothing between the swap above and this line can panic, so the flag
        // cannot be left set by a start that never happened.
        let started = StartedFlag::armed(&mycelium.started);
        let node = &mycelium.node;
        let start_result = runtime().block_on(async { node.start().await });

        match start_result {
            Ok(()) => {
                // Committed here, not at the end: from this point the event
                // loop, the beacon and the transports are live, so the flag
                // describes reality and a retry must stay a no-op. Holding the
                // reset until the API server was up would have let a panic in
                // between hand the caller a second start — and a second
                // `Node::start` is a duplicate event loop, which is worse than
                // the stuck flag the reset exists to prevent.
                started.succeeded();
                info!("Node started successfully");
            }
            Err(e) => {
                let msg = format!("Node start failed: {}", e);
                info!("{}", msg);
                set_last_error(&msg);
                return false;
            }
        }

        start_api_server(mycelium);

        true
    })
}

/// Stop the node and API server.
///
/// # Safety
/// `handle` must be a valid pointer from `mycelium_node_new`.
#[no_mangle]
pub unsafe extern "C" fn mycelium_node_stop(handle: *mut MyceliumNode) {
    ffi_guard_blocking!("mycelium_node_stop", {
        if handle.is_null() {
            return;
        }
        let mycelium = &(*handle);
        let _lifecycle = mycelium.lifecycle();

        // Stop the API server and every task it spawned. The handle is taken
        // under the lock and shut down after it is released: `take` cannot
        // panic, so the window in which this lock can be poisoned at all is
        // closed, rather than only recovered from.
        let api = mycelium.api_handle().take();
        if let Some(api) = api {
            api.shutdown();
        }

        let _stopped = StoppedFlag::armed(mycelium);
        let node = &mycelium.node;
        runtime().block_on(async { node.stop().await });
    })
}

/// Get the node ID as a 32-byte array.
///
/// # Safety
/// `handle` must be a valid pointer, `out` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn mycelium_node_id(handle: *const MyceliumNode, out: *mut [u8; 32]) {
    ffi_guard!("mycelium_node_id", {
        if handle.is_null() || out.is_null() {
            return;
        }
        let node = &(*handle).node;
        (*out) = *node.node_id.as_bytes();
    })
}

/// Release one reference to the node.
///
/// The node itself is destroyed when the last handle is freed, so freeing one
/// handle no longer invalidates another: before T-01 this dropped the single
/// allocation whatever else was outstanding, and a handle recovered through
/// `mycelium_node_get_existing` was left dangling. Freeing also unregisters the
/// node, so `mycelium_node_get_existing` stops handing out new references to
/// something the caller has finished with.
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
/// The drain runs on every call rather than only on the last reference. It is
/// idempotent and bounded, and deciding "am I the last?" would be a race
/// between two concurrent frees in which neither sees itself as last and the
/// marks are lost — the hazard this drain exists to close.
///
/// Because it blocks, a call from a thread inside the runtime is refused
/// (`ADR-023`): the handle is then **not** released, which leaks a reference
/// rather than dropping a node whose marks were never drained.
///
/// # Safety
/// `handle` must be a handle from `mycelium_node_new` or
/// `mycelium_node_get_existing`, passed here exactly once. Freeing the same
/// handle twice, or a copy of one already freed, corrupts the reference count.
#[no_mangle]
pub unsafe extern "C" fn mycelium_node_free(handle: *mut MyceliumNode) {
    ffi_guard_blocking!("mycelium_node_free", {
        if handle.is_null() {
            return;
        }
        // Takes back the one reference this handle stands for.
        let mycelium = Arc::from_raw(handle as *const MyceliumNode);

        runtime().block_on(async {
            let internet = mycelium.node.internet_transport.read().await.clone();
            if let Some(internet) = internet {
                internet.dht().flush_marks().await;
            }
        });

        // Stop handing out references to a node the caller has finished with,
        // and release the registry's own. Outstanding handles stay valid — that
        // is the point of the reference count — and the node is destroyed when
        // the last of them is freed.
        let registered = {
            let mut slot = active_node();
            let same = slot
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &mycelium));
            if same {
                slot.take()
            } else {
                None
            }
        };
        drop(registered);
        drop(mycelium);
    })
}

/// Get a handle to the existing node, if one is still registered.
///
/// Returns NULL if no node has been created, or if the registered one has been
/// freed. Used by the Dart layer to recover a handle after the Flutter engine
/// restarts.
///
/// **The returned handle is an owning reference** and must be passed to
/// `mycelium_node_free` exactly once, like the one from `mycelium_node_new`.
/// Every handle to one node is the same address, so pointer comparison still
/// identifies the node (ROADMAP T-01).
#[no_mangle]
pub extern "C" fn mycelium_node_get_existing() -> *mut MyceliumNode {
    ffi_guard!("mycelium_node_get_existing", {
        match active_node().as_ref() {
            Some(handle) => Arc::into_raw(Arc::clone(handle)) as *mut MyceliumNode,
            None => std::ptr::null_mut(),
        }
    })
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
    ffi_guard_blocking!("mycelium_send_message", {
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
    })
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
    ffi_guard!("mycelium_get_messages", {
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
    })
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
    ffi_guard!("mycelium_contact_count", {
        if handle.is_null() {
            return -1;
        }
        let node = &(*handle).node;
        match node.db.list_contacts() {
            Ok(contacts) => contacts.len() as i32,
            Err(_) => -2,
        }
    })
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
    ffi_guard!("mycelium_get_contacts", {
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
    })
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
    ffi_guard_blocking!("mycelium_send_group_message", {
        if handle.is_null() || group_id.is_null() || data.is_null() || out_message_id.is_null() {
            return -1;
        }

        let node = &(*handle).node;
        let gid = *group_id;
        let plaintext = std::slice::from_raw_parts(data, data_len as usize);
        let ct = content_type_from_u8(content_type);

        let result =
            runtime().block_on(async { node.send_group_message(gid, plaintext, ct).await });

        match result {
            Ok(msg_id) => {
                (*out_message_id) = *msg_id.as_bytes();
                0
            }
            Err(_) => -2,
        }
    })
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
    ffi_guard_blocking!("mycelium_network_status", {
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
    })
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
    ffi_guard_blocking!("mycelium_add_vouch", {
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
    })
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
    ffi_guard_blocking!("mycelium_trust_score", {
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
    ffi_guard_blocking!("mycelium_verify_session", {
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
    })
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
    ffi_guard_blocking!("mycelium_safety_number", {
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
    })
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
    ffi_guard!("mycelium_get_conversations", {
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
    })
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
    ffi_guard_blocking!("mycelium_update_battery", {
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
    })
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
    ffi_guard_blocking!("mycelium_create_group", {
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
    })
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
    ffi_guard_blocking!("mycelium_add_group_member", {
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
    })
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
/// The callback runs on a thread driving the async runtime — do not perform
/// blocking work in it, and do not call a Mycelium function that blocks from
/// inside it: such a call is refused rather than taking the process down
/// (ADR-023), with `MYCELIUM_ERR_REENTRANT` from an `i32` function and the
/// shape's own failure value from the others. Hand the work to another thread.
/// Call with null to unregister.
///
/// # Safety
/// - `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn mycelium_set_message_callback(
    handle: *mut MyceliumNode,
    callback: Option<MessageCallback>,
) -> i32 {
    ffi_guard!("mycelium_set_message_callback", {
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
                                if let Ok(msgs) =
                                    db.get_conversation(&local_id, &conv.peer_id, 1, 0)
                                {
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
    })
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
    ffi_guard_blocking!("mycelium_register_ble_transport", {
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
    })
}

/// Register the Wi-Fi Direct transport for this node.
///
/// Returns 0 on success.
///
/// # Safety
/// - `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn mycelium_register_wifi_direct_transport(handle: *mut MyceliumNode) -> i32 {
    ffi_guard_blocking!("mycelium_register_wifi_direct_transport", {
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
    })
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
    ffi_guard_blocking!("mycelium_ble_on_link_up", {
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
    ffi_guard_blocking!("mycelium_ble_on_link_down", {
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
    ffi_guard_blocking!("mycelium_ble_on_link_data", {
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
    ffi_guard_blocking!("mycelium_wifi_on_link_up", {
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
    ffi_guard_blocking!("mycelium_wifi_on_link_down", {
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
    ffi_guard_blocking!("mycelium_wifi_on_link_data", {
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
    ffi_guard_blocking!("mycelium_ble_dequeue_send", {
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
    })
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
    ffi_guard_blocking!("mycelium_wifi_dequeue_send", {
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
    })
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
    ffi_guard_blocking!("mycelium_ble_dequeue_link_event", {
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
    })
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
    ffi_guard_blocking!("mycelium_wifi_dequeue_link_event", {
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
    ffi_guard!("mycelium_delete_conversation", {
        if handle.is_null() || peer_id.is_null() {
            return -1;
        }

        let node = &(*handle).node;
        let peer = NodeId::from_bytes(*peer_id);

        match node.db.delete_conversation(&node.node_id, &peer) {
            Ok(_) => 0,
            Err(_) => -2,
        }
    })
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
    ffi_guard_blocking!("mycelium_mark_read", {
        if handle.is_null() || peer_id.is_null() {
            return -1;
        }

        let node = &(*handle).node;
        let peer = NodeId::from_bytes(*peer_id);

        runtime().block_on(async { node.mark_read_and_notify(peer).await }) as i32
    })
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
    ffi_guard!("mycelium_unread_count", {
        if handle.is_null() || peer_id.is_null() {
            return -1;
        }

        let node = &(*handle).node;
        let peer = NodeId::from_bytes(*peer_id);

        match node.db.unread_count(&node.node_id, &peer) {
            Ok(count) => count as i32,
            Err(_) => -2,
        }
    })
}

/// Get total unread message count across all conversations.
///
/// Returns the count, or negative on error.
///
/// # Safety
/// - `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn mycelium_total_unread_count(handle: *const MyceliumNode) -> i32 {
    ffi_guard!("mycelium_total_unread_count", {
        if handle.is_null() {
            return -1;
        }

        let node = &(*handle).node;

        match node.db.total_unread_count(&node.node_id) {
            Ok(count) => count as i32,
            Err(_) => -2,
        }
    })
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
    ffi_guard!("mycelium_set_display_name", {
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
    })
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
    ffi_guard!("mycelium_get_display_name", {
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
    })
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
    ffi_guard_blocking!("mycelium_group_member_count", {
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
    ffi_guard_blocking!("mycelium_get_group_members", {
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
    ffi_guard_blocking!("mycelium_remove_group_member", {
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
    })
}

// --- Display Name ---

/// Rename the running node, as announced in beacons and reported by
/// `GET /v1/node/status`.
///
/// Returns 0 on success, -1 on invalid args — including an **empty** name,
/// which a beacon cannot express: a receiver reads an empty name field as "no
/// information" and keeps the name it has. Takes effect on the next beacon.
/// The name is **not persisted**: it comes from `mycelium_node_new`'s
/// `display_name` (or the daemon's config) on every start, so a rename that
/// should outlive the process has to be made there.
///
/// Until T-01 this validated its argument, logged it and returned 0 without
/// renaming anything, so every caller was told a rename had happened that had
/// not.
///
/// # Safety
/// - `handle` must be a valid pointer from `mycelium_node_new()`.
/// - `name` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn mycelium_set_node_display_name(
    handle: *mut MyceliumNode,
    name: *const c_char,
) -> i32 {
    ffi_guard!("mycelium_set_node_display_name", {
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

        // An empty name is the one rename the mesh cannot carry. A beacon
        // field of zero length means "no information" to a receiver, which
        // keeps the name it already has (`node.rs`, beacon reception), so
        // accepting this would set the API's answer and leave every peer
        // showing the previous name for good. `mycelium_node_new` still
        // accepts an empty name, because then no peer has a previous one.
        if name_str.is_empty() {
            set_last_error(
                "a display name cannot be emptied: a beacon's empty name means \
                 'unchanged' to a peer, so this would only change what the API \
                 reports",
            );
            return -1;
        }

        info!("renaming this node to {:?}", name_str);
        (*handle).node.set_display_name(name_str);

        0
    })
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
    ffi_guard_blocking!("mycelium_register_lora_transport", {
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
    })
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
    ffi_guard_blocking!("mycelium_register_lora_transport_configured", {
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
    })
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
    ffi_guard_blocking!("mycelium_lora_on_peer_discovered", {
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
    ffi_guard_blocking!("mycelium_lora_on_peer_lost", {
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
    ffi_guard_blocking!("mycelium_lora_on_data_received", {
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
    ffi_guard_blocking!("mycelium_lora_dequeue_send", {
        if handle.is_null() || out_peer_id.is_null() || out_data.is_null() || out_data_len.is_null()
        {
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
    })
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
    ffi_guard_blocking!("mycelium_lora_report_tx_success", {
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
    ffi_guard_blocking!("mycelium_lora_report_tx_failure", {
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
    ffi_guard_blocking!("mycelium_register_bt_classic_transport", {
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
    })
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
    ffi_guard_blocking!("mycelium_bt_classic_on_peer_connected", {
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
    ffi_guard_blocking!("mycelium_bt_classic_on_peer_disconnected", {
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
    ffi_guard_blocking!("mycelium_bt_classic_on_data_received", {
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
    ffi_guard_blocking!("mycelium_bt_classic_dequeue_send", {
        if handle.is_null() || out_peer_id.is_null() || out_data.is_null() || out_data_len.is_null()
        {
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
    })
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
    ffi_guard_blocking!("mycelium_register_internet_transport", {
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
    ffi_guard_blocking!("mycelium_register_internet_transport_configured", {
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
    ffi_guard_blocking!("mycelium_internet_connect_to", {
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
    ffi_guard_blocking!("mycelium_internet_peer_count", {
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
    })
}

// --- Panic-guard fixtures (test builds only) ---
//
// ADR-018 asks for a test per return shape that deliberately panics *across the
// boundary*, because a guard that is never exercised is not a guard. These are
// real `extern "C"` functions, so the panic really does reach a C ABI frame and
// the guard really is what stops it there; they exist only in test builds, so
// the shipped library gains no panic triggers. They are audited by
// `test_every_exported_function_is_guarded` along with the other 64.

#[cfg(test)]
#[no_mangle]
pub extern "C" fn mycelium_test_panic_i32() -> i32 {
    ffi_guard!("mycelium_test_panic_i32", {
        panic!("deliberate panic from an i32 function")
    })
}

#[cfg(test)]
#[no_mangle]
pub extern "C" fn mycelium_test_panic_bool() -> bool {
    ffi_guard!("mycelium_test_panic_bool", {
        panic!("deliberate panic from a bool function")
    })
}

#[cfg(test)]
#[no_mangle]
pub extern "C" fn mycelium_test_panic_f32() -> f32 {
    ffi_guard!("mycelium_test_panic_f32", {
        panic!("deliberate panic from an f32 function")
    })
}

#[cfg(test)]
#[no_mangle]
pub extern "C" fn mycelium_test_panic_pointer() -> *mut MyceliumNode {
    ffi_guard!("mycelium_test_panic_pointer", {
        panic!("deliberate panic from a pointer function")
    })
}

#[cfg(test)]
#[no_mangle]
pub extern "C" fn mycelium_test_panic_void() {
    ffi_guard!("mycelium_test_panic_void", {
        panic!("deliberate panic from a void function")
    })
}

/// Panics with the error cell borrowed, which is the shape
/// `mycelium_last_error` has when it reads the message out.
#[cfg(test)]
#[no_mangle]
pub extern "C" fn mycelium_test_panic_while_error_borrowed() -> i32 {
    ffi_guard!("mycelium_test_panic_while_error_borrowed", {
        LAST_ERROR.with(|cell| {
            let _held = cell.borrow();
            panic!("deliberate panic with the error cell borrowed")
        })
    })
}

/// A payload whose destructor panics, for the one case that can still reach
/// across the boundary after `catch_unwind` has returned: disposing of the
/// panic payload itself.
#[cfg(test)]
struct PanicOnDrop;

#[cfg(test)]
impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        panic!("a panic payload's destructor panicked");
    }
}

#[cfg(test)]
#[no_mangle]
pub extern "C" fn mycelium_test_panic_with_hostile_payload() -> i32 {
    ffi_guard!("mycelium_test_panic_with_hostile_payload", {
        std::panic::panic_any(PanicOnDrop)
    })
}

/// Takes the `started` flag exactly as `mycelium_node_start` does, then
/// unwinds, so the reset guard can be tested without a way to make
/// `Node::start` panic on demand.
///
/// # Safety
/// `handle` must be a valid pointer from `mycelium_node_new`.
#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn mycelium_test_panic_mid_start(handle: *mut MyceliumNode) -> bool {
    ffi_guard!("mycelium_test_panic_mid_start", {
        let mycelium = &*handle;
        if mycelium.started.swap(true, Ordering::AcqRel) {
            return true;
        }
        let _started = StartedFlag::armed(&mycelium.started);
        panic!("a start path that unwinds");
    })
}

/// Unwinds out of a stop, either side of the cancellation, so the flag
/// reconciliation can be tested in both directions — a `Node::stop` that
/// panics at its first log has cancelled nothing, one that panics while
/// draining transports has cancelled everything, and the right answer differs.
///
/// # Safety
/// `handle` must be a valid pointer from `mycelium_node_new`.
#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn mycelium_test_panic_in_stop(
    handle: *mut MyceliumNode,
    after_cancelling: bool,
) {
    ffi_guard_blocking!("mycelium_test_panic_in_stop", {
        let mycelium = &*handle;
        let _lifecycle = mycelium.lifecycle();
        let _stopped = StoppedFlag::armed(mycelium);
        if after_cancelling {
            runtime().block_on(async { mycelium.node.stop().await });
        }
        panic!("a stop path that unwinds");
    })
}

/// Blocks on the runtime and returns what the future produced, so the
/// re-entrancy refusal can be tested on a body that really would block.
#[cfg(test)]
#[no_mangle]
pub extern "C" fn mycelium_test_blocking_i32() -> i32 {
    ffi_guard_blocking!("mycelium_test_blocking_i32", {
        runtime().block_on(async { 7 })
    })
}

/// How many references to this node are outstanding, for the tests that check
/// the ownership arithmetic. The borrow is given straight back, so the count is
/// unchanged by asking.
#[cfg(test)]
fn handle_reference_count(handle: *const MyceliumNode) -> usize {
    let handle = unsafe { Arc::from_raw(handle) };
    let count = Arc::strong_count(&handle);
    let _ = Arc::into_raw(handle);
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// `ACTIVE_NODE` is process-wide, so the tests that create a node take
    /// turns rather than clobbering each other's registry entry.
    static NODE_TESTS: Mutex<()> = Mutex::new(());

    fn temp_data_dir(tag: &str) -> String {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir()
            .join(format!("mycelium-ffi-{}-{}", tag, unique))
            .to_string_lossy()
            .to_string()
    }

    /// Create a node in a fresh data directory, returning the handle and the
    /// directory to clean up.
    fn new_test_node(tag: &str) -> (*mut MyceliumNode, String) {
        let dir = temp_data_dir(tag);
        let dir_c = CString::new(dir.clone()).unwrap();
        let name_c = CString::new("Before").unwrap();
        let handle = unsafe { mycelium_node_new(dir_c.as_ptr(), name_c.as_ptr()) };
        assert!(!handle.is_null(), "node_new failed: {}", last_error());
        (handle, dir)
    }

    /// Read `LAST_ERROR` back the way the Dart layer does.
    fn last_error() -> String {
        let mut buf = [0u8; 1024];
        let len = unsafe { mycelium_last_error(buf.as_mut_ptr(), buf.len() as u32) };
        assert!(len >= 0, "mycelium_last_error returned {}", len);
        String::from_utf8_lossy(&buf[..len as usize]).to_string()
    }

    /// Every exported name, from the C header this crate ships.
    fn header_functions(header: &str) -> Vec<String> {
        let mut found = Vec::new();
        for (index, _) in header.match_indices("mycelium_") {
            // A declaration, not a mention in a comment: the name is followed
            // by its parameter list.
            let name: String = header[index..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let after = &header[index + name.len()..];
            if after.starts_with('(') && !found.contains(&name) {
                found.push(name);
            }
        }
        found
    }

    /// Split the source into exported functions and their bodies.
    ///
    /// Line-based on purpose: rustfmt closes a top-level item with a `}` in
    /// column 0 and never puts one inside a body, which makes the end of a
    /// function unambiguous without a brace-and-string scanner that would have
    /// to be correct about format strings and char literals to be worth
    /// anything.
    fn exported_functions(source: &str) -> Vec<(String, String)> {
        let lines: Vec<&str> = source.lines().collect();
        let mut found = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            let name = match line
                .strip_prefix("pub extern \"C\" fn ")
                .or_else(|| line.strip_prefix("pub unsafe extern \"C\" fn "))
            {
                Some(rest) => rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect::<String>(),
                None => {
                    // Anything this parse does not recognise would be exported
                    // without being audited, and the count below would not
                    // notice, because an unseen function cannot make the total
                    // wrong. `extern "C-unwind"` is the real case: it would
                    // make unwinding legal across the boundary and skip the
                    // guard in one step.
                    assert!(
                        !(line.contains("extern \"C") && line.contains("fn mycelium_")),
                        "line {} declares an exported function this audit \
                         cannot parse, so nothing would check its guard: {}",
                        index + 1,
                        line.trim()
                    );
                    continue;
                }
            };
            assert!(
                name.starts_with("mycelium_"),
                "exported function {} does not carry the mycelium_ prefix",
                name
            );
            let mut signature_end = index;
            while !lines[signature_end].trim_end().ends_with('{') {
                signature_end += 1;
                assert!(
                    signature_end < index + 20,
                    "could not find the start of {}'s body",
                    name
                );
            }
            let mut body_end = signature_end + 1;
            while lines[body_end] != "}" {
                body_end += 1;
                assert!(body_end < lines.len(), "could not find the end of {}", name);
            }
            found.push((name, lines[signature_end + 1..body_end].join("\n")));
        }
        found
    }

    /// The claim ADR-018 makes — "a new extern function that forgets the guard
    /// is a visible omission rather than a silent one" — is only true if
    /// something checks. This is that something: every exported function opens
    /// with a guard, names itself to the guard so the stored message is
    /// accurate, and takes the blocking flavour exactly when its body blocks on
    /// the runtime.
    #[test]
    fn test_every_exported_function_is_guarded() {
        let functions = exported_functions(include_str!("lib.rs"));
        let mut shipped = 0;
        for (name, body) in &functions {
            let opening = body
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or_default()
                .trim();
            let blocks = body.contains("runtime().block_on");
            let expected = if blocks {
                format!("ffi_guard_blocking!(\"{}\", {{", name)
            } else {
                format!("ffi_guard!(\"{}\", {{", name)
            };
            assert_eq!(
                opening,
                expected,
                "{} must open with {} (it {} block on the runtime)",
                name,
                expected,
                if blocks { "does" } else { "does not" }
            );
            if !name.starts_with("mycelium_test_") {
                shipped += 1;
            }
        }
        assert_eq!(
            shipped, 64,
            "the exported FFI surface is 64 functions (spec §17.2); \
             a change here means the header, the iOS symbol list and the three \
             xcconfig -u lists move too"
        );
    }

    /// Both lifecycle transitions must take the same lock, or neither is
    /// serialized against the other: a start that reaches the API server just
    /// after a stop took its handle leaves a server answering for a node being
    /// torn down. Mutual exclusion is the mutex's job; what can drift is a new
    /// entry point that forgets to take it.
    #[test]
    fn test_both_lifecycle_transitions_take_the_lifecycle_lock() {
        let functions = exported_functions(include_str!("lib.rs"));
        for name in ["mycelium_node_start", "mycelium_node_stop"] {
            let (_, body) = functions
                .iter()
                .find(|(found, _)| found == name)
                .unwrap_or_else(|| panic!("{} is exported from this crate", name));
            assert!(
                body.contains("mycelium.lifecycle()"),
                "{} moves lifecycle state and must take the lifecycle lock",
                name
            );
        }
    }

    /// Two of the four files that have to move together. A function missing
    /// from the header is one `ffigen` never generates, so Dart can only reach
    /// it by a hand-written lookup that fails at runtime — which is the defect
    /// T-01 removed from three call sites. The iOS symbol list and the three
    /// xcconfig `-u` lists are the other two, and live outside this crate.
    #[test]
    fn test_the_header_declares_exactly_the_exported_functions() {
        let exported: Vec<String> = exported_functions(include_str!("lib.rs"))
            .into_iter()
            .map(|(name, _)| name)
            .filter(|name| !name.starts_with("mycelium_test_"))
            .collect();
        let declared = header_functions(include_str!("../include/mycelium.h"));

        for name in &exported {
            assert!(
                declared.contains(name),
                "{} is exported from Rust but not declared in mycelium.h, so \
                 ffigen will not generate a binding for it",
                name
            );
        }
        for name in &declared {
            assert!(
                exported.contains(name),
                "mycelium.h declares {}, which this crate does not export: a \
                 caller linking against it fails at load time",
                name
            );
        }
    }

    #[test]
    fn test_a_panic_in_an_i32_function_returns_the_negative_sentinel() {
        mycelium_clear_error();
        assert_eq!(mycelium_test_panic_i32(), MYCELIUM_ERR_PANIC);
        let error = last_error();
        assert!(
            error.contains("deliberate panic from an i32 function"),
            "message was {:?}",
            error
        );
        assert!(
            error.contains("mycelium_test_panic_i32"),
            "the message names the function that panicked: {:?}",
            error
        );
        assert!(
            error.contains("lib.rs:"),
            "the message carries the panic's location: {:?}",
            error
        );
    }

    #[test]
    fn test_a_panic_in_a_bool_function_returns_false() {
        mycelium_clear_error();
        assert!(!mycelium_test_panic_bool());
        assert!(last_error().contains("deliberate panic from a bool function"));
    }

    #[test]
    fn test_a_panic_in_an_f32_function_returns_the_documented_error_value() {
        mycelium_clear_error();
        assert_eq!(mycelium_test_panic_f32(), -1.0);
        assert!(last_error().contains("deliberate panic from an f32 function"));
    }

    #[test]
    fn test_a_panic_in_a_pointer_function_returns_null() {
        mycelium_clear_error();
        assert!(mycelium_test_panic_pointer().is_null());
        assert!(last_error().contains("deliberate panic from a pointer function"));
    }

    #[test]
    fn test_a_panic_in_a_void_function_is_reported_through_the_error_channel() {
        mycelium_clear_error();
        mycelium_test_panic_void();
        assert!(last_error().contains("deliberate panic from a void function"));
    }

    /// Unwinding drops the borrow guard before the guard's recovery path runs,
    /// so recording the message works. The non-panicking accessors in
    /// `set_last_error` are what make that true whichever way it goes: a
    /// recovery path that panicked would unwind across the boundary, which is
    /// the undefined behaviour the guard exists to remove.
    #[test]
    fn test_a_panic_with_the_error_cell_borrowed_still_records_a_message() {
        mycelium_clear_error();
        assert_eq!(
            mycelium_test_panic_while_error_borrowed(),
            MYCELIUM_ERR_PANIC
        );
        assert!(last_error().contains("deliberate panic with the error cell borrowed"));
    }

    /// The payload is disposed of after `catch_unwind` has returned, so a
    /// destructor that panics there would unwind across the boundary. Before
    /// the payload was forgotten rather than dropped, this test aborted the
    /// test binary.
    #[test]
    fn test_a_panic_payload_with_a_hostile_destructor_does_not_escape() {
        mycelium_clear_error();
        assert_eq!(
            mycelium_test_panic_with_hostile_payload(),
            MYCELIUM_ERR_PANIC
        );
        let error = last_error();
        assert!(
            error.contains("not a string"),
            "an unrecognised payload is reported as such: {:?}",
            error
        );
        assert!(error.contains("mycelium_test_panic_with_hostile_payload"));
    }

    /// A caught panic can leave a lock poisoned, which is a state that only
    /// exists now that a panic no longer ends the process. Reporting it as an
    /// error would strand a running API server that `node_stop` could never
    /// reach.
    #[test]
    fn test_a_poisoned_api_handle_lock_is_recovered_not_reported() {
        let _serial = NODE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let (handle, dir) = new_test_node("poison");

        let held = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = unsafe { &*handle }.api_handle.lock().unwrap();
            panic!("poison the API handle lock");
        }));
        assert!(held.is_err());
        assert!(
            unsafe { &*handle }.api_handle.is_poisoned(),
            "the panic above is what poisons the lock; without that this test \
             proves nothing"
        );

        assert_eq!(
            mycelium_api_handle_status(),
            1,
            "the node exists and has no API handle — the state the lock holds, \
             not a complaint about the lock"
        );

        unsafe { mycelium_node_free(handle) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_a_blocking_function_runs_from_a_thread_outside_the_runtime() {
        mycelium_clear_error();
        assert_eq!(mycelium_test_blocking_i32(), 7);
    }

    /// The case that aborts the app today: tokio refuses a `block_on` from a
    /// thread already driving the runtime by panicking, and nothing caught it.
    #[test]
    fn test_a_blocking_function_called_from_a_runtime_thread_is_refused() {
        let (code, message) = runtime().block_on(async {
            mycelium_clear_error();
            (mycelium_test_blocking_i32(), last_error())
        });
        assert_eq!(code, MYCELIUM_ERR_REENTRANT);
        assert!(
            message.contains("mycelium_test_blocking_i32") && message.contains("runtime"),
            "the refusal says which call and why: {:?}",
            message
        );
    }

    /// Run the rest of a test in a fresh process.
    ///
    /// Some of what the guard rests on is process-global — the `Once` that
    /// installs the panic hook, the global tracing subscriber — so a test of it
    /// proves nothing in a process where another test has already got there
    /// first. The child's output is captured rather than inherited, so the
    /// suite prints one set of numbers and a failure still shows why.
    fn in_a_fresh_process(test_name: &str, marker: &str, body: impl FnOnce()) {
        if std::env::var(marker).is_ok() {
            body();
            return;
        }
        let output = std::process::Command::new(
            std::env::current_exe().expect("the test binary's own path"),
        )
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(marker, "1")
        .output()
        .expect("re-run this test in a child process");
        assert!(
            output.status.success(),
            "the child process did not survive: {:?}\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    /// `take_hook` panics when the calling thread is already unwinding, so a
    /// first guarded call made from a destructor during unwinding would panic
    /// inside the guard's own setup — and a panic during unwinding aborts
    /// before any `catch_unwind` can see it.
    ///
    /// Without the `thread::panicking()` check the child dies on SIGABRT.
    #[test]
    fn test_the_first_guarded_call_while_unwinding_does_not_abort() {
        in_a_fresh_process(
            "tests::test_the_first_guarded_call_while_unwinding_does_not_abort",
            "MYCELIUM_FFI_UNWIND_CHILD",
            || {
                struct CallsIntoTheFfiWhileUnwinding;

                impl Drop for CallsIntoTheFfiWhileUnwinding {
                    fn drop(&mut self) {
                        assert!(
                            std::thread::panicking(),
                            "this destructor must run during unwinding, or the \
                         test proves nothing"
                        );
                        // The first guarded call in this process.
                        mycelium_clear_error();
                    }
                }

                let outcome = std::panic::catch_unwind(|| {
                    let _probe = CallsIntoTheFfiWhileUnwinding;
                    panic!("unwind past a destructor that calls into the FFI");
                });
                assert!(outcome.is_err());
            },
        );
    }

    /// A subscriber is arbitrary code, and the guard logs the panic it caught.
    /// Logging from inside the panic hook would abort on a subscriber like this
    /// one; logging after the catch contains it.
    #[test]
    fn test_a_panicking_tracing_subscriber_does_not_turn_a_panic_into_an_abort() {
        in_a_fresh_process(
            "tests::test_a_panicking_tracing_subscriber_does_not_turn_a_panic_into_an_abort",
            "MYCELIUM_FFI_HOSTILE_SUBSCRIBER",
            || {
                struct PanickingSubscriber;

                impl tracing::Subscriber for PanickingSubscriber {
                    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                        true
                    }

                    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                        tracing::span::Id::from_u64(1)
                    }

                    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

                    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

                    fn event(&self, _: &tracing::Event<'_>) {
                        panic!("a subscriber that panics on every event");
                    }

                    fn enter(&self, _: &tracing::span::Id) {}

                    fn exit(&self, _: &tracing::span::Id) {}
                }

                tracing::subscriber::set_global_default(PanickingSubscriber)
                    .expect("this child installs the only subscriber");

                mycelium_clear_error();
                assert_eq!(mycelium_test_panic_i32(), MYCELIUM_ERR_PANIC);
                assert!(last_error().contains("deliberate panic from an i32 function"));
            },
        );
    }

    /// The other half of the start flag, and the harder one: a panic *after*
    /// `Node::start` has succeeded must leave the flag set, because the event
    /// loop, the beacon and the transports are already live and a second
    /// `Node::start` would duplicate all three. The first version of the reset
    /// guard held the flag until the API server was up and failed this.
    ///
    /// Driven through the real `mycelium_node_start` by a subscriber that
    /// panics on the first event from this crate: `Node::start`'s own logs
    /// carry other targets, so the panic lands exactly at
    /// `info!("Node started successfully")`.
    #[test]
    fn test_a_panic_after_the_node_is_live_does_not_offer_a_second_start() {
        in_a_fresh_process(
            "tests::test_a_panic_after_the_node_is_live_does_not_offer_a_second_start",
            "MYCELIUM_FFI_LATE_PANIC",
            || {
                struct PanicsOnceOnFfiEvents {
                    fired: std::sync::atomic::AtomicBool,
                }

                impl tracing::Subscriber for PanicsOnceOnFfiEvents {
                    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                        true
                    }

                    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                        tracing::span::Id::from_u64(1)
                    }

                    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

                    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

                    fn event(&self, event: &tracing::Event<'_>) {
                        if event.metadata().target() == "mycelium_ffi"
                            && !self.fired.swap(true, Ordering::SeqCst)
                        {
                            panic!("the first log the FFI emits after a successful start");
                        }
                    }

                    fn enter(&self, _: &tracing::span::Id) {}

                    fn exit(&self, _: &tracing::span::Id) {}
                }

                tracing::subscriber::set_global_default(PanicsOnceOnFfiEvents {
                    fired: std::sync::atomic::AtomicBool::new(false),
                })
                .expect("this child installs the only subscriber");

                let (handle, dir) = new_test_node("latepanic");
                assert!(
                    !unsafe { mycelium_node_start(handle) },
                    "the panic is caught and reported as a failed start"
                );
                assert!(
                    unsafe { &*handle }.started.load(Ordering::Acquire),
                    "the node is live, whatever the return value says: the flag \
                     must not invite a second Node::start"
                );
                assert_eq!(
                    mycelium_api_handle_status(),
                    1,
                    "the panic landed before the API server was started"
                );

                assert!(
                    unsafe { mycelium_node_start(handle) },
                    "a retry is the duplicate-start no-op for the node"
                );
                // ... but not for the API server, which the first attempt
                // never reached. The app talks to the node through it, so a
                // retry that only said "already started" would leave a running
                // node unreachable for the life of the process. Either outcome
                // of the attempt proves it was made: the port is bound, or the
                // failure is reported.
                let status = mycelium_api_handle_status();
                assert!(
                    status == 2 || last_error().contains("API server failed to start"),
                    "the retry must reach API startup; status was {} and the \
                     last error was {:?}",
                    status,
                    last_error()
                );

                unsafe { mycelium_node_stop(handle) };
                unsafe { mycelium_node_free(handle) };
                let _ = std::fs::remove_dir_all(&dir);
            },
        );
    }

    /// A stop that unwinds leaves the flag describing what actually happened,
    /// because the two halves of a stop need opposite answers: before the
    /// cancellation the node is still running, after it the node is finished.
    /// Guessing one way strands the app with a dead node it is told is
    /// running; guessing the other invites a second `Node::start` over live
    /// tasks.
    #[test]
    fn test_a_stop_that_unwinds_leaves_the_flag_describing_the_node() {
        let _serial = NODE_TESTS.lock().unwrap_or_else(|e| e.into_inner());

        let (early, early_dir) = new_test_node("stopearly");
        unsafe { &*early }.started.store(true, Ordering::Release);
        unsafe { mycelium_test_panic_in_stop(early, false) };
        assert!(
            unsafe { &*early }.started.load(Ordering::Acquire),
            "nothing was cancelled, so the node is still running"
        );
        assert!(!unsafe { &*early }.node.is_stopped());
        unsafe { mycelium_node_free(early) };
        let _ = std::fs::remove_dir_all(&early_dir);

        // The same unwinding stop on a handle that was never started must not
        // leave "running" behind it, or the next start skips `Node::start`.
        let (fresh, fresh_dir) = new_test_node("stopfresh");
        unsafe { mycelium_test_panic_in_stop(fresh, false) };
        assert!(
            !unsafe { &*fresh }.started.load(Ordering::Acquire),
            "a stop may clear this flag, never set it"
        );
        unsafe { mycelium_node_free(fresh) };
        let _ = std::fs::remove_dir_all(&fresh_dir);

        let (late, late_dir) = new_test_node("stoplate");
        unsafe { &*late }.started.store(true, Ordering::Release);
        unsafe { mycelium_test_panic_in_stop(late, true) };
        assert!(
            !unsafe { &*late }.started.load(Ordering::Acquire),
            "the tasks are cancelled, so a later start must not answer \
             'already running' for a node that is finished"
        );
        assert!(unsafe { &*late }.node.is_stopped());
        unsafe { mycelium_node_free(late) };
        let _ = std::fs::remove_dir_all(&late_dir);
    }

    /// A stopped node cannot be restarted — `Node::stop` cancels a token
    /// nothing resets — so a start after a stop used to spawn tasks that
    /// exited immediately, start the API server over them, and report success.
    #[test]
    fn test_a_stopped_node_refuses_to_start_again() {
        let _serial = NODE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let (handle, dir) = new_test_node("restart");

        unsafe { mycelium_node_stop(handle) };
        assert!(unsafe { &*handle }.node.is_stopped());

        mycelium_clear_error();
        assert!(
            !unsafe { mycelium_node_start(handle) },
            "a stopped node must not report a start it cannot perform"
        );
        let error = last_error();
        assert!(
            error.contains("cannot be restarted"),
            "the refusal says what to do instead: {:?}",
            error
        );
        assert!(
            !unsafe { &*handle }.started.load(Ordering::Acquire),
            "the refusal happens before the flag is touched"
        );
        assert_eq!(
            mycelium_api_handle_status(),
            1,
            "and before the API server is started"
        );

        unsafe { mycelium_node_free(handle) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A panic between taking the `started` flag and finishing the start used
    /// to leave the flag set, so every retry answered "already running" for a
    /// node that was not.
    #[test]
    fn test_a_start_that_unwinds_leaves_the_node_startable() {
        let _serial = NODE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let (handle, dir) = new_test_node("startflag");

        assert!(!unsafe { &*handle }.started.load(Ordering::Acquire));
        assert!(!unsafe { mycelium_test_panic_mid_start(handle) });
        assert!(
            !unsafe { &*handle }.started.load(Ordering::Acquire),
            "a start that unwound must leave the node startable, or the app is \
             told it is running for the rest of the process"
        );
        assert!(last_error().contains("a start path that unwinds"));

        unsafe { mycelium_node_free(handle) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The hazard T-01 names: `get_existing` handed out a pointer that the next
    /// `node_free` invalidated. Now each handle is a reference, and the node
    /// outlives every free but the last.
    #[test]
    fn test_a_recovered_handle_survives_another_handles_free() {
        let _serial = NODE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let (first, dir) = new_test_node("refcount");

        let recovered = mycelium_node_get_existing();
        assert_eq!(
            recovered, first,
            "every handle to one node is the same address, so Dart can still \
             compare them"
        );
        assert_eq!(
            handle_reference_count(first),
            3,
            "the caller's handle, the registry's reference, and the recovered one"
        );

        let mut id_before = [0u8; 32];
        unsafe { mycelium_node_id(recovered, &mut id_before) };
        assert_ne!(id_before, [0u8; 32]);

        unsafe { mycelium_node_free(first) };

        assert!(
            mycelium_node_get_existing().is_null(),
            "a freed node is no longer handed out"
        );
        assert_eq!(
            handle_reference_count(recovered),
            1,
            "the registry's reference went with the free; the recovered handle \
             is the last one"
        );

        // Before T-01 this read freed memory.
        let mut id_after = [0u8; 32];
        unsafe { mycelium_node_id(recovered, &mut id_after) };
        assert_eq!(id_before, id_after);

        unsafe { mycelium_node_free(recovered) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The one rename the mesh cannot carry: a beacon's empty name field means
    /// "unchanged" to a receiver, so accepting it would change only what the
    /// API reports and leave every peer on the old name.
    #[test]
    fn test_a_node_cannot_be_renamed_to_nothing() {
        let _serial = NODE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let (handle, dir) = new_test_node("emptyname");

        mycelium_clear_error();
        let empty = CString::new("").unwrap();
        assert_eq!(
            unsafe { mycelium_set_node_display_name(handle, empty.as_ptr()) },
            -1
        );
        assert_eq!(
            unsafe { &*handle }.node.display_name(),
            "Before",
            "a refused rename changes nothing"
        );
        assert!(last_error().contains("cannot be emptied"));

        unsafe { mycelium_node_free(handle) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `mycelium_set_node_display_name` used to log the name and return 0
    /// without renaming anything.
    #[test]
    fn test_renaming_the_node_reaches_what_announces_it() {
        let _serial = NODE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let (handle, dir) = new_test_node("rename");
        assert_eq!(unsafe { &*handle }.node.display_name(), "Before");

        let after = CString::new("After").unwrap();
        assert_eq!(
            unsafe { mycelium_set_node_display_name(handle, after.as_ptr()) },
            0
        );
        assert_eq!(
            unsafe { &*handle }.node.display_name(),
            "After",
            "the name the beacon task and /v1/node/status read"
        );

        unsafe { mycelium_node_free(handle) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The refusal lands before the body, so it cannot half-complete: this
    /// function would otherwise reject the null handle with -1 first.
    #[test]
    fn test_a_real_blocking_function_refuses_before_it_reads_its_arguments() {
        assert_eq!(
            unsafe { mycelium_internet_peer_count(std::ptr::null_mut()) },
            -1,
            "outside the runtime the argument check is what answers"
        );
        let refused = runtime()
            .block_on(async { unsafe { mycelium_internet_peer_count(std::ptr::null_mut()) } });
        assert_eq!(refused, MYCELIUM_ERR_REENTRANT);
    }
}
