use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use mycelium_core::dtn::spray_and_wait::{DtnAction, DtnBundle, DtnConfig, DtnEngine, DtnError};
use mycelium_core::routing::aodv::{
    AodvAction, AodvMessage, AodvRouter, RouteError, RouteReply, RouteRequest,
};
use mycelium_core::routing::coordinator::{RoutingCoordinator, RoutingDecision};
use mycelium_core::transport::manager::TransportManager;
use mycelium_core::transport::{TransportError, TransportEvent};
use mycelium_crypto::double_ratchet::RatchetHeader;
use mycelium_crypto::group::{GroupError, SenderKey, SenderKeyGroup};
use mycelium_crypto::identity::{node_id_from_public_key, Identity};
use mycelium_crypto::session::{SessionError, SessionManager};
use mycelium_crypto::wot::TrustGraph;
use mycelium_crypto::x3dh::{PrekeyBundle, PrekeyState, X3dhError};
use mycelium_protocol::codec::{CodecError, Envelope};
use mycelium_protocol::types::{
    ContentType, LamportClock, MessageFlags, MessageId, NodeId, NodeType, ProtocolVersion,
};
use mycelium_protocol::wire::{
    self, EncryptedPayload, PrekeyBundlePayload, ReceiptType, SessionInitPayload, WirePayloadType,
    WireRatchetHeader,
};
use mycelium_storage::db::{Database, StorageError};
use mycelium_storage::dtn::DtnBundleRecord;
use mycelium_storage::messages::MessageRecord;
use mycelium_storage::sessions::SessionRecord;

use crate::battery::BatteryManager;
use crate::config::NodeConfig;
use crate::events::NodeEvent;
use crate::rate_limiter::RateLimiter;

/// Errors from high-level node operations.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum NodeError {
    #[error("no session with peer")]
    NoSession,
    #[error("no prekey bundle for peer")]
    NoPrekeyBundle,
    #[error("routing failed: {0}")]
    RoutingFailed(String),
    #[error("crypto error: {0}")]
    CryptoError(#[from] SessionError),
    #[error("storage error: {0}")]
    StorageError(#[from] StorageError),
    #[error("transport error: {0}")]
    TransportError(#[from] TransportError),
    #[error("codec error: {0}")]
    CodecError(#[from] CodecError),
    #[error("group error: {0}")]
    GroupError(#[from] GroupError),
    #[error("sending to self")]
    SendToSelf,
    #[error("group not found")]
    GroupNotFound,
}

/// A message waiting for a session to be established.
#[derive(Debug)]
struct PendingMessage {
    plaintext: Vec<u8>,
    content_type: ContentType,
    message_id: MessageId,
}

/// An envelope waiting for a route to its destination.
struct PendingRoute {
    envelope_bytes: Vec<u8>,
    message_id: MessageId,
}

/// One in-flight route discovery, with every envelope waiting on it.
///
/// The deadline and retry count belong to the destination, not to each
/// envelope: all of them are waiting for the same route, so they share one
/// attempt. Keeping them per envelope meant staggered sends produced
/// staggered retries and an RREQ flood per message (ROADMAP T-10).
struct PendingDiscovery {
    envelopes: Vec<PendingRoute>,
    started_at: Instant,
    retries: u8,
}

impl PendingDiscovery {
    fn new() -> Self {
        Self {
            envelopes: Vec::new(),
            started_at: Instant::now(),
            retries: 0,
        }
    }
}

/// Maximum number of AODV discovery retries before DTN fallback.
const MAX_DISCOVERY_RETRIES: u8 = 1;

/// How often the pending-route queue is checked against
/// `RoutingCoordinator::discovery_timeout()`. Must be well below that timeout
/// or the fallback is late; see ROADMAP T-10.
const DISCOVERY_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Two peers that initiate a session with each other within this window are
/// treated as a simultaneous initiation (see `handle_session_init`).
const SIMULTANEOUS_INIT_WINDOW: Duration = Duration::from_secs(60);

/// Maintenance ticks between signed-prekey rotations: weekly, at the 30 s tick.
///
/// Coupled to `MAX_RETAINED_SIGNED_PREKEYS` and to the 7-day prekey-bundle
/// cache lifetime: `MAX_RETAINED_SIGNED_PREKEYS * 7 days >= 7 days`, so a peer
/// initiating from any unexpired cached bundle finds the secret it needs.
const SPK_ROTATION_TICKS: u32 = 7 * 24 * 3600 / 30;

/// The main Mycelium node, tying together all subsystems.
pub struct Node {
    pub identity: Identity,
    pub node_id: NodeId,
    pub config: NodeConfig,
    pub transport_manager: Arc<TransportManager>,
    pub routing: Arc<RwLock<RoutingCoordinator>>,
    pub session_manager: Arc<RwLock<SessionManager>>,
    pub prekey_state: Arc<RwLock<PrekeyState>>,
    pub rate_limiter: Arc<RwLock<RateLimiter>>,
    pub battery: Arc<RwLock<BatteryManager>>,
    pub db: Arc<Database>,
    pub trust_graph: Arc<RwLock<TrustGraph>>,
    pub groups: Arc<RwLock<HashMap<[u8; 32], SenderKeyGroup>>>,
    lamport_clock: Arc<RwLock<LamportClock>>,
    pub prekey_cache: Arc<RwLock<HashMap<NodeId, (PrekeyBundle, Instant)>>>,
    pending_messages: Arc<RwLock<HashMap<NodeId, Vec<PendingMessage>>>>,
    pending_routes: Arc<RwLock<HashMap<NodeId, PendingDiscovery>>>,
    cancel: CancellationToken,
    /// Handle to BLE transport for platform FFI callbacks.
    pub ble_transport: Arc<RwLock<Option<Arc<mycelium_core::transport::ble::BleTransport>>>>,
    /// Handle to Wi-Fi Direct transport for platform FFI callbacks.
    pub wifi_transport:
        Arc<RwLock<Option<Arc<mycelium_core::transport::wifi_direct::WifiDirectTransport>>>>,
    /// Handle to LoRa transport for platform FFI callbacks.
    #[allow(dead_code)]
    pub lora_transport: Arc<RwLock<Option<Arc<mycelium_core::transport::lora::LoraTransport>>>>,
    /// Handle to BT Classic transport for platform FFI callbacks.
    #[allow(dead_code)]
    pub bt_classic_transport:
        Arc<RwLock<Option<Arc<mycelium_core::transport::bt_classic::BtClassicTransport>>>>,
    /// Handle to Internet transport for API visibility and FFI registration.
    pub internet_transport:
        Arc<RwLock<Option<Arc<mycelium_core::transport::internet::InternetTransport>>>>,
    /// Broadcast channel for node events (consumed by API server / WebSocket clients).
    pub event_tx: tokio::sync::broadcast::Sender<NodeEvent>,
    /// Dedup set for channel messages (prevents re-processing flooded messages).
    seen_channel_messages: Arc<RwLock<HashSet<MessageId>>>,
    /// Members we have already sent our current sender key to, per group.
    /// Not persisted: after a restart the key is simply re-sent once.
    key_sent_to: Arc<RwLock<HashMap<[u8; 32], HashSet<NodeId>>>>,
    /// Truncated hash of local group discovery key for beacon matching.
    pub local_group_hash: Option<[u8; 8]>,
}

/// Everything the send pipeline needs. Built from `&Node` for public
/// methods and from the event loop's cloned handles for handlers that must
/// reply (e.g. answering a sender-key distribution with our own key).
struct SendCtx<'a> {
    local_id: NodeId,
    identity: &'a Identity,
    db: &'a Database,
    transport_manager: &'a TransportManager,
    routing: &'a RwLock<RoutingCoordinator>,
    session_manager: &'a RwLock<SessionManager>,
    prekey_cache: &'a RwLock<HashMap<NodeId, (PrekeyBundle, Instant)>>,
    pending_messages: &'a RwLock<HashMap<NodeId, Vec<PendingMessage>>>,
    pending_routes: &'a RwLock<HashMap<NodeId, PendingDiscovery>>,
    lamport_clock: &'a RwLock<LamportClock>,
    groups: &'a RwLock<HashMap<[u8; 32], SenderKeyGroup>>,
    key_sent_to: &'a RwLock<HashMap<[u8; 32], HashSet<NodeId>>>,
}

#[allow(dead_code)]
impl Node {
    /// Create a new node with the given config.
    pub fn new(config: NodeConfig, db: Database, identity: Identity) -> Self {
        let node_id = identity.node_id();
        let aodv = AodvRouter::new(node_id);

        let dtn_config = DtnConfig {
            max_storage_bytes: config.dtn.max_storage_mb as usize * 1024 * 1024,
            per_identity_quota_bytes: config.dtn.per_identity_quota_mb as usize * 1024 * 1024,
            ttl: Duration::from_secs(config.dtn.ttl_hours as u64 * 3600),
            spray_copies: config.dtn.spray_copies,
        };

        let dtn = DtnEngine::new(dtn_config);
        let routing = RoutingCoordinator::new(node_id, aodv, dtn);
        let prekey_state = PrekeyState::new(identity_clone_for_prekeys(&identity));

        // Load trust graph from stored vouches
        let mut trust_graph = TrustGraph::new();
        if let Ok(vouches) = db.list_all_vouches() {
            for v in &vouches {
                trust_graph.add_vouch(v.voucher_id, v.vouchee_id);
            }
        }

        let (event_tx, _) = tokio::sync::broadcast::channel(256);

        // Compute local group discovery hash from config
        let local_group_hash = config.group_seed.as_ref().and_then(|hex_str| {
            let key_bytes = hex::decode(hex_str).ok()?;
            if key_bytes.len() == 32 {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(&key_bytes);
                let mut truncated = [0u8; 8];
                truncated.copy_from_slice(&hash[..8]);
                Some(truncated)
            } else {
                None
            }
        });

        let battery = if matches!(config.node_type, crate::config::NodeTypeConfig::Supernode) {
            BatteryManager::always_on()
        } else {
            BatteryManager::new()
        };

        Self {
            identity,
            node_id,
            config,
            transport_manager: Arc::new(TransportManager::new()),
            routing: Arc::new(RwLock::new(routing)),
            session_manager: Arc::new(RwLock::new(SessionManager::new())),
            prekey_state: Arc::new(RwLock::new(prekey_state)),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new())),
            battery: Arc::new(RwLock::new(battery)),
            db: Arc::new(db),
            trust_graph: Arc::new(RwLock::new(trust_graph)),
            groups: Arc::new(RwLock::new(HashMap::new())),
            lamport_clock: Arc::new(RwLock::new(LamportClock::new())),
            prekey_cache: Arc::new(RwLock::new(HashMap::new())),
            pending_messages: Arc::new(RwLock::new(HashMap::new())),
            pending_routes: Arc::new(RwLock::new(HashMap::new())),
            cancel: CancellationToken::new(),
            ble_transport: Arc::new(RwLock::new(None)),
            wifi_transport: Arc::new(RwLock::new(None)),
            lora_transport: Arc::new(RwLock::new(None)),
            bt_classic_transport: Arc::new(RwLock::new(None)),
            internet_transport: Arc::new(RwLock::new(None)),
            event_tx,
            seen_channel_messages: Arc::new(RwLock::new(HashSet::new())),
            key_sent_to: Arc::new(RwLock::new(HashMap::new())),
            local_group_hash,
        }
    }

    /// Start the node: init transports, start routing, begin event loop.
    pub async fn start(&self) -> Result<(), anyhow::Error> {
        info!("Starting Mycelium node {}", self.node_id);

        // Load or generate prekey state
        {
            let mut prekey_state = self.prekey_state.write().await;
            match self.db.load_prekey_state_blob() {
                Ok(blob) => {
                    let blob = zeroize::Zeroizing::new(blob);
                    let identity = identity_clone_for_prekeys(&self.identity);
                    if let Some(restored) = PrekeyState::from_bytes_with_identity(&blob, identity) {
                        info!(
                            "Restored prekey state: spk_id={}, {} one-time prekeys",
                            restored.signed_prekey_id,
                            restored.one_time_prekeys.len()
                        );
                        *prekey_state = restored;
                    } else {
                        debug!("Failed to deserialize prekey state, generating fresh");
                        prekey_state.generate_one_time_prekeys(100);
                        let _ = self.db.save_prekey_state_blob(&zeroize::Zeroizing::new(
                            prekey_state.to_bytes(),
                        ));
                    }
                }
                Err(_) => {
                    // No saved state; generate fresh prekeys and persist
                    prekey_state.generate_one_time_prekeys(100);
                    let _ = self
                        .db
                        .save_prekey_state_blob(&zeroize::Zeroizing::new(prekey_state.to_bytes()));
                    info!("Generated fresh prekey state with 100 one-time prekeys");
                }
            }
        }

        // Load persisted sessions from database
        {
            let mut sm = self.session_manager.write().await;
            if let Ok(records) = self.db.list_sessions() {
                for record in records {
                    // The blob holds the root key and both chain keys; wipe
                    // our copy once the session is rebuilt from it.
                    let session_data = zeroize::Zeroizing::new(record.session_data);
                    match SessionManager::deserialize_session(&session_data) {
                        Ok(session) => {
                            info!("Restored session with {}", session.peer_id);
                            sm.restore_session(session);
                        }
                        Err(e) => {
                            debug!("Failed to restore session for {:?}: {}", record.peer_id, e);
                        }
                    }
                }
            }
        }

        // Load cached prekey bundles from database
        {
            let mut cache = self.prekey_cache.write().await;
            if let Ok(entries) = self.db.list_cached_prekey_bundles() {
                for (node_id_bytes, bundle_data) in entries {
                    if node_id_bytes.len() != 32 || bundle_data.is_empty() {
                        continue;
                    }
                    let node_id = NodeId::from_bytes(node_id_bytes.try_into().unwrap_or([0; 32]));
                    // Deserialize: the stored data is the PrekeyBundlePayload body (without type byte)
                    if let Ok(bp) = PrekeyBundlePayload::deserialize_body(&bundle_data) {
                        let bundle = PrekeyBundle {
                            identity_key: bp.identity_key,
                            signed_prekey: bp.signed_prekey,
                            signed_prekey_signature: bp.signed_prekey_signature,
                            signed_prekey_id: bp.signed_prekey_id,
                            one_time_prekey: bp.one_time_prekey,
                            one_time_prekey_id: bp.one_time_prekey_id,
                        };
                        cache.insert(node_id, (bundle, Instant::now()));
                    }
                }
                if !cache.is_empty() {
                    info!("Restored {} cached prekey bundles", cache.len());
                }
            }
        }

        // Load persisted group state from database
        {
            let mut groups = self.groups.write().await;
            if let Ok(blobs) = self.db.list_group_blobs() {
                for blob in blobs {
                    // Holds our sender chain key and every member's.
                    let blob = zeroize::Zeroizing::new(blob);
                    if let Some(group) = SenderKeyGroup::from_bytes(&blob) {
                        let gid = group.group_id;
                        groups.insert(gid, group);
                    }
                }
                if !groups.is_empty() {
                    info!("Restored {} group states", groups.len());
                }
            }
        }

        // Reconstruct the origin flag for rows written before migration v3,
        // which defaults everything to relay traffic (Codex P2, ROADMAP T-11).
        match self.db.backfill_dtn_local_origin(&self.node_id) {
            Ok(n) if n > 0 => info!("Marked {} restored DTN bundles as locally originated", n),
            Ok(_) => {}
            Err(e) => warn!("Could not backfill DTN bundle origin: {}", e),
        }

        // Load persisted DTN bundles from database
        {
            let mut routing = self.routing.write().await;
            if let Ok(records) = self.db.list_all_dtn_bundles() {
                let now_epoch = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut loaded = 0;
                for record in records {
                    // Skip already-expired bundles
                    if record.expires_at <= now_epoch {
                        let _ = self.db.remove_dtn_bundle(&record.message_id);
                        continue;
                    }
                    let remaining_secs = record.expires_at - now_epoch;
                    let sprayed_to = record.sprayed_to.clone();
                    let bundle = DtnBundle {
                        message_id: record.message_id,
                        destination: record.destination,
                        source: record.source,
                        payload: record.payload,
                        copies_remaining: record.copies_remaining,
                        expires_at: Instant::now() + Duration::from_secs(remaining_secs),
                        created_at: Instant::now(), // approximate
                        size: record.size,
                        is_local: record.is_local,
                    };
                    // `store_restored`, not `store_relay`: a restart must not
                    // turn the user's own bundles into relay traffic, nor
                    // forget which peers already hold a copy (ROADMAP T-11).
                    let _ = routing.dtn_mut().store_restored(bundle, sprayed_to);
                    loaded += 1;
                }
                if loaded > 0 {
                    info!("Restored {} DTN bundles from database", loaded);
                }
            }
        }

        // Start transports
        self.transport_manager.start().await?;

        // Start event loop
        let transport_manager = self.transport_manager.clone();
        let routing = self.routing.clone();
        let session_manager = self.session_manager.clone();
        let prekey_state = self.prekey_state.clone();
        let rate_limiter = self.rate_limiter.clone();
        let trust_graph = self.trust_graph.clone();
        let groups = self.groups.clone();
        let db = self.db.clone();
        let lamport_clock = self.lamport_clock.clone();
        let prekey_cache = self.prekey_cache.clone();
        let pending_messages = self.pending_messages.clone();
        let pending_routes = self.pending_routes.clone();
        let battery = self.battery.clone();
        let event_tx = self.event_tx.clone();
        let seen_channel_messages = self.seen_channel_messages.clone();
        let key_sent_to = self.key_sent_to.clone();
        let local_group_hash = self.local_group_hash;
        let cancel = self.cancel.clone();
        let node_id = self.node_id;
        let identity_bytes = self.identity.to_bytes();

        tokio::spawn(async move {
            let mut rx = transport_manager.events();
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        info!("Node event loop shutting down");
                        break;
                    }
                    event = rx.recv() => {
                        match event {
                            Ok(event) => {
                                let identity = Identity::from_bytes(&identity_bytes)
                                    .expect("identity roundtrip failed");
                                Self::handle_transport_event(
                                    &event,
                                    &routing,
                                    &session_manager,
                                    &prekey_state,
                                    &rate_limiter,
                                    &trust_graph,
                                    &groups,
                                    &transport_manager,
                                    &db,
                                    &identity,
                                    node_id,
                                    &lamport_clock,
                                    &prekey_cache,
                                    &pending_messages,
                                    &pending_routes,
                                    &battery,
                                    &event_tx,
                                    &seen_channel_messages,
                                    local_group_hash,
                                    &key_sent_to,
                                ).await;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                warn!("Node event loop lagged, dropped {} transport events", n);
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                warn!("Transport event channel closed, stopping event loop");
                                break;
                            }
                        }
                    }
                }
            }
        });

        // Maintenance timer
        let routing_m = self.routing.clone();
        let prekey_state_m = self.prekey_state.clone();
        let prekey_cache_m = self.prekey_cache.clone();
        let rate_limiter_m = self.rate_limiter.clone();
        let cancel_m = self.cancel.clone();
        let db_m = self.db.clone();
        let mut spk_rotation_counter: u32 = 0;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = cancel_m.cancelled() => break,
                    _ = interval.tick() => {
                        // Route expiry, DTN expiry and RREQ dedup pruning.
                        // The route-discovery timeout is swept by its own
                        // task below, not here: this interval is 30 s and
                        // the timeout is 5 s.
                        routing_m.write().await.maintenance();

                        // Expire old DTN bundles
                        let now_secs = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let _ = db_m.expire_dtn_bundles(now_secs);

                        // Prekey replenishment: refill if below 20 unused one-time prekeys
                        {
                            let mut ps = prekey_state_m.write().await;
                            let current_count = ps.one_time_prekeys.len() as u32;
                            if current_count < 20 {
                                let to_generate = 100 - current_count;
                                ps.generate_one_time_prekeys(to_generate);
                                let _ = db_m.save_prekey_state_blob(&zeroize::Zeroizing::new(ps.to_bytes()));
                                debug!("Replenished {} one-time prekeys (had {})", to_generate, current_count);
                            }

                            // Signed prekey rotation: weekly, as specified
                            // (MYCELIUM_SPEC.md 5.2). This interval and
                            // `MAX_RETAINED_SIGNED_PREKEYS` are coupled: the
                            // retained keys must span the bundle-cache
                            // lifetime below (7 days), or a peer initiating
                            // from a still-valid cached bundle fails. It used
                            // to rotate every 24 h, which two retained keys
                            // cannot cover (ADR-009).
                            spk_rotation_counter += 1;
                            if spk_rotation_counter >= SPK_ROTATION_TICKS {
                                spk_rotation_counter = 0;
                                ps.rotate_signed_prekey();
                                let _ = db_m.save_prekey_state_blob(&zeroize::Zeroizing::new(ps.to_bytes()));
                                debug!("Rotated signed prekey, new id={}", ps.signed_prekey_id);
                            }
                        }

                        // Clean up expired rate limiter state and blacklist entries
                        {
                            let mut rl = rate_limiter_m.write().await;
                            rl.cleanup();
                        }

                        // Expire prekey bundles older than 7 days
                        {
                            let max_age = Duration::from_secs(7 * 24 * 3600);
                            let mut cache = prekey_cache_m.write().await;
                            let before = cache.len();
                            cache.retain(|node_id, (_, cached_at)| {
                                let keep = cached_at.elapsed() < max_age;
                                if !keep {
                                    let _ = db_m.remove_cached_prekey_bundle(node_id.as_bytes());
                                }
                                keep
                            });
                            let expired = before - cache.len();
                            if expired > 0 {
                                debug!("Expired {} stale prekey bundles from cache", expired);
                            }
                        }
                    }
                }
            }
        });

        // Route-discovery timeout sweep.
        //
        // This has its own ticker because it must fire on the scale of
        // `RoutingCoordinator::discovery_timeout()` (5 s). Folding it into the
        // 30 s maintenance tick delayed every DTN fallback to 30-35 s for the
        // first retry and 60-65 s to actually enter DTN, six times the
        // specified timeout (MYCELIUM_SPEC.md 7.3).
        let routing_d = self.routing.clone();
        let pending_routes_d = self.pending_routes.clone();
        let transport_d = self.transport_manager.clone();
        let cancel_d = self.cancel.clone();
        let db_d = self.db.clone();
        let node_id_d = self.node_id;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(DISCOVERY_SWEEP_INTERVAL);
            loop {
                tokio::select! {
                    _ = cancel_d.cancelled() => break,
                    _ = interval.tick() => {
                        let disc_timeout = routing_d.read().await.discovery_timeout();

                        // Partition the queue without holding any other lock.
                        // `retry` is a set of destinations, not of envelopes:
                        // every envelope waiting on the same destination is
                        // waiting on the same single route, so one RREQ serves
                        // all of them. Collecting per envelope broadcast one
                        // RREQ per queued message per retry.
                        let mut retry: Vec<NodeId> = Vec::new();
                        let mut to_dtn: Vec<(NodeId, PendingRoute)> = Vec::new();
                        {
                            let mut pr = pending_routes_d.write().await;
                            pr.retain(|dest, discovery| {
                                if discovery.started_at.elapsed() <= disc_timeout {
                                    return true;
                                }
                                if discovery.retries < MAX_DISCOVERY_RETRIES {
                                    // One more attempt for this destination,
                                    // covering every envelope queued on it.
                                    discovery.retries += 1;
                                    discovery.started_at = Instant::now();
                                    retry.push(*dest);
                                    return true;
                                }
                                // Attempts exhausted: everything waiting on
                                // this destination goes to store-and-carry.
                                for route in discovery.envelopes.drain(..) {
                                    to_dtn.push((*dest, route));
                                }
                                false
                            });
                        }

                        // One RREQ per destination per sweep.
                        for dest in retry {
                            let rreq = {
                                let mut r = routing_d.write().await;
                                r.initiate_discovery(dest)
                            };
                            debug!("Retrying AODV discovery for {}", dest);
                            Self::broadcast_aodv_static(&rreq, node_id_d, &transport_d).await;
                        }

                        // Retries exhausted: store and carry instead.
                        for (dest, route) in to_dtn {
                            debug!(
                                "Route discovery for {} exhausted retries, falling back to DTN",
                                dest
                            );
                            // A route may have arrived while this envelope was
                            // between the queue and here, in which case its
                            // flush found nothing. Decide and commit under a
                            // single routing write lock: checking under a read
                            // lock and inserting under a write lock leaves the
                            // same gap for NeighborDiscovered to slot into.
                            enum Disposition {
                                Send(NodeId),
                                Stored,
                                Refused(DtnError),
                            }

                            let envelope_bytes = route.envelope_bytes;
                            let disposition = {
                                let mut r = routing_d.write().await;
                                match r.route_message(&dest) {
                                    RoutingDecision::SendRealtime { next_hop } => {
                                        Disposition::Send(next_hop)
                                    }
                                    _ => match r.fallback_to_dtn(
                                        route.message_id,
                                        dest,
                                        node_id_d,
                                        envelope_bytes.clone(),
                                    ) {
                                        Ok(()) => {
                                            if let Some(bundle) =
                                                r.dtn().get_bundle(&route.message_id)
                                            {
                                                persist_dtn_bundle(&db_d, bundle);
                                            }
                                            Disposition::Stored
                                        }
                                        Err(e) => Disposition::Refused(e),
                                    },
                                }
                            };

                            match disposition {
                                Disposition::Send(next_hop) => {
                                    debug!(
                                        "Route to {} appeared during the sweep; sending {} directly",
                                        dest, route.message_id
                                    );
                                    if transport_d
                                        .send(&next_hop, &envelope_bytes)
                                        .await
                                        .is_ok()
                                    {
                                        let _ = db_d
                                            .mark_message_sent(&route.message_id);
                                    } else {
                                        // The route went away again. Store and
                                        // carry rather than losing it.
                                        let mut r = routing_d.write().await;
                                        match r.fallback_to_dtn(
                                            route.message_id,
                                            dest,
                                            node_id_d,
                                            envelope_bytes,
                                        ) {
                                            Ok(()) => {
                                                if let Some(bundle) =
                                                    r.dtn().get_bundle(&route.message_id)
                                                {
                                                    persist_dtn_bundle(&db_d, bundle);
                                                }
                                                // Guarded, like every DTN
                                                // transition (T-35).
                                                let _ = db_d
                                                    .mark_message_dtn_pending(&route.message_id);
                                            }
                                            Err(e) => {
                                                warn!(
                                                    "Dropping message {} for {}: send failed and \
                                                     the DTN store refused it: {}",
                                                    route.message_id, dest, e
                                                );
                                                let _ = db_d.update_message_status(
                                                    &route.message_id,
                                                    "failed",
                                                );
                                            }
                                        }
                                    }
                                }
                                Disposition::Stored => {
                                    // Guarded: a message a rejection already
                                    // failed cannot be revived here, since
                                    // its ciphertext belongs to a ratchet
                                    // that no longer exists (T-35).
                                    let _ =
                                        db_d.mark_message_dtn_pending(&route.message_id);
                                }
                                Disposition::Refused(e) => {
                                    // The envelope has already left the pending
                                    // queue, so it is gone. Say so rather than
                                    // reporting it as queued for delivery
                                    // (MYCELIUM_SPEC.md 7.2).
                                    warn!(
                                        "Dropping message {} for {}: DTN store refused it: {}",
                                        route.message_id, dest, e
                                    );
                                    let _ =
                                        db_d.update_message_status(&route.message_id, "failed");
                                }
                            }
                        }
                    }
                }
            }
        });

        // Beacon broadcasting timer
        let transport_manager_b = self.transport_manager.clone();
        let lamport_clock_b = self.lamport_clock.clone();
        let battery_b = self.battery.clone();
        let cancel_b = self.cancel.clone();
        let node_id_b = self.node_id;
        let display_name_b = self.config.display_name.clone();
        let node_type_b = match self.config.node_type {
            crate::config::NodeTypeConfig::Phone => NodeType::Phone,
            crate::config::NodeTypeConfig::Supernode => NodeType::Supernode,
        };
        let local_group_hash_b = self.local_group_hash;
        let beacon_interval = Duration::from_secs(self.config.beacon_interval_secs.max(1));

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(beacon_interval);
            loop {
                tokio::select! {
                    _ = cancel_b.cancelled() => break,
                    _ = interval.tick() => {
                        let clock_val = {
                            let clock = lamport_clock_b.read().await;
                            clock.0
                        };
                        let battery_level = {
                            let bm = battery_b.read().await;
                            bm.battery_level().unwrap_or(100)
                        };
                        let peers = transport_manager_b.known_peers().await;
                        let neighbor_count = peers.len() as u16;

                        let beacon = crate::beacon::Beacon {
                            node_id: node_id_b,
                            node_type: node_type_b,
                            display_name: display_name_b.clone(),
                            protocol_version: ProtocolVersion::CURRENT,
                            battery_level,
                            neighbor_count,
                            lamport_clock: clock_val,
                            group_discovery_hash: local_group_hash_b,
                        };

                        let beacon_data = beacon.serialize();
                        // Wrap beacon in an Envelope with SYSTEM flag
                        let payload = {
                            let mut p = Vec::with_capacity(1 + beacon_data.len());
                            p.push(WirePayloadType::Beacon as u8);
                            p.extend_from_slice(&beacon_data);
                            p
                        };
                        let envelope = Envelope {
                            source: node_id_b,
                            destination: NodeId::ZERO, // broadcast
                            message_id: MessageId::random(),
                            ttl: 1, // beacons don't get forwarded
                            hop_count: 0,
                            flags: MessageFlags::SYSTEM,
                            lamport_clock: clock_val,
                            device_timestamp: 0,
                            protocol_version: ProtocolVersion::CURRENT,
                            payload,
                        };

                        let data = envelope.serialize();
                        for peer in &peers {
                            let _ = transport_manager_b.send(peer, &data).await;
                        }
                        // Broadcast media (LoRa) hear us before they know us.
                        let _ = transport_manager_b.broadcast(&data).await;
                    }
                }
            }
        });

        info!("Node {} started successfully", self.node_id);
        Ok(())
    }

    /// Register transports based on config. Call before `start()`.
    pub async fn register_transports(&self) {
        use mycelium_core::transport::ble::BleTransport;
        use mycelium_core::transport::internet::{InternetConfig, InternetTransport};
        use mycelium_core::transport::wifi_direct::WifiDirectTransport;

        if self.config.transports.ble {
            let ble = Arc::new(BleTransport::new(self.node_id));
            self.transport_manager.add_transport(ble.clone()).await;
            *self.ble_transport.write().await = Some(ble);
            info!("Registered BLE transport");
        }
        if self.config.transports.wifi_direct {
            let wifi = Arc::new(WifiDirectTransport::new(self.node_id));
            self.transport_manager.add_transport(wifi.clone()).await;
            *self.wifi_transport.write().await = Some(wifi);
            info!("Registered Wi-Fi Direct transport");
        }
        if self.config.transports.internet_tunnel {
            let inet_cfg = &self.config.transports.internet;
            let bootstrap: Vec<std::net::SocketAddr> = inet_cfg
                .bootstrap_nodes
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            let internet = Arc::new(InternetTransport::new(
                self.identity_handle(),
                InternetConfig {
                    listen_addr: format!("0.0.0.0:{}", inet_cfg.listen_port).parse().unwrap(),
                    bootstrap_nodes: bootstrap,
                    max_connections: inet_cfg.max_connections,
                },
            ));
            self.transport_manager.add_transport(internet.clone()).await;
            *self.internet_transport.write().await = Some(internet);
            info!(
                "Registered Internet transport on port {}",
                inet_cfg.listen_port
            );
        }
    }

    /// A clone of this node's identity behind an `Arc`.
    ///
    /// The internet transport has to sign its handshake with the identity key,
    /// and deriving its NodeId from the same key is what keeps the two from
    /// disagreeing (spec §14.3).
    pub fn identity_handle(&self) -> Arc<Identity> {
        Arc::new(identity_clone_for_prekeys(&self.identity))
    }

    /// Stop the node gracefully.
    pub async fn stop(&self) {
        info!("Stopping Mycelium node {}", self.node_id);
        self.cancel.cancel();
        let _ = self.transport_manager.stop().await;
    }

    /// Send a message to a destination node.
    pub async fn send_message(
        &self,
        destination: NodeId,
        plaintext: &[u8],
        content_type: ContentType,
    ) -> Result<MessageId, NodeError> {
        Self::send_encrypted(&self.send_ctx(), destination, plaintext, content_type, true).await
    }

    fn send_ctx(&self) -> SendCtx<'_> {
        SendCtx {
            local_id: self.node_id,
            identity: &self.identity,
            db: &self.db,
            transport_manager: &self.transport_manager,
            routing: &self.routing,
            session_manager: &self.session_manager,
            prekey_cache: &self.prekey_cache,
            pending_messages: &self.pending_messages,
            pending_routes: &self.pending_routes,
            lamport_clock: &self.lamport_clock,
            groups: &self.groups,
            key_sent_to: &self.key_sent_to,
        }
    }

    /// Core of the 1:1 send pipeline. `store` controls whether the outgoing
    /// message is recorded in the conversation history (protocol/system
    /// messages such as sender-key distributions are not).
    async fn send_encrypted(
        ctx: &SendCtx<'_>,
        destination: NodeId,
        plaintext: &[u8],
        content_type: ContentType,
        store: bool,
    ) -> Result<MessageId, NodeError> {
        if destination == ctx.local_id {
            return Err(NodeError::SendToSelf);
        }

        let message_id = MessageId::random();
        let clock_val = {
            let mut clock = ctx.lamport_clock.write().await;
            clock.tick()
        };
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Store outgoing message in DB
        if store {
            let record = MessageRecord {
                message_id,
                source: ctx.local_id,
                destination,
                content_type: content_type_str(content_type),
                plaintext: plaintext.to_vec(),
                lamport_clock: clock_val.0,
                device_timestamp: timestamp,
                status: "pending".to_string(),
                is_incoming: false,
            };
            ctx.db.insert_message(&record)?;
        }

        // Check if session exists
        let has_session = {
            let sm = ctx.session_manager.read().await;
            sm.has_session(&destination)
        };

        if !has_session {
            // Check prekey cache
            let bundle = {
                let cache = ctx.prekey_cache.read().await;
                cache.get(&destination).map(|(b, _)| b.clone())
            };

            info!(
                "send_message: no session with {}, has_prekey={}",
                destination,
                bundle.is_some()
            );

            if let Some(bundle) = bundle {
                // Initiate session from cached prekey bundle
                if let Err(e) = Self::initiate_session_and_send(
                    ctx,
                    destination,
                    &bundle,
                    plaintext,
                    content_type,
                    message_id,
                    clock_val,
                    timestamp,
                )
                .await
                {
                    // The row was inserted as "pending" above and nothing will
                    // retry it, so leaving it pending would show the user a
                    // message that is in fact never going anywhere.
                    if store {
                        let _ = ctx.db.update_message_status(&message_id, "failed");
                    }
                    return Err(e);
                }
            } else {
                info!(
                    "send_message: queuing msg and sending prekey request to {}",
                    destination
                );
                // Queue message and send prekey request
                {
                    let mut pm = ctx.pending_messages.write().await;
                    pm.entry(destination).or_default().push(PendingMessage {
                        plaintext: plaintext.to_vec(),
                        content_type,
                        message_id,
                    });
                }

                // Send prekey request
                let prekey_req_payload =
                    wire::serialize_prekey_request(&ctx.identity.public_key_bytes());
                let envelope = Envelope {
                    source: ctx.local_id,
                    destination,
                    message_id: MessageId::random(),
                    ttl: 10,
                    hop_count: 0,
                    flags: MessageFlags::SYSTEM,
                    lamport_clock: clock_val.0,
                    device_timestamp: timestamp,
                    protocol_version: ProtocolVersion::CURRENT,
                    payload: prekey_req_payload,
                };
                Self::route_and_send(ctx, envelope, message_id).await?;
            }

            return Ok(message_id);
        }

        // Session exists — encrypt and send
        let ad = build_ad(
            ctx.local_id,
            destination,
            content_type_to_byte(content_type),
        );
        let (header, ciphertext) = {
            let mut sm = ctx.session_manager.write().await;
            let encrypted = sm.encrypt_for(&destination, plaintext, &ad)?;
            // Under the same lock as the ratchet advance: a message sent
            // before the peer has confirmed the handshake dies with it, and
            // recording it separately let a concurrent accept or confirmation
            // land in between (T-35). Ignored when there is no unconfirmed
            // handshake.
            sm.record_unconfirmed_message(destination, message_id);
            encrypted
        };

        // Persist the ratchet advance before the ciphertext can leave.
        if let Err(e) = Self::persist_session(ctx.session_manager, ctx.db, &destination).await {
            if store {
                let _ = ctx.db.update_message_status(&message_id, "failed");
            }
            return Err(e.into());
        }

        let enc_payload = EncryptedPayload {
            content_type: content_type_to_byte(content_type),
            header: WireRatchetHeader {
                dh_public: header.dh_public,
                previous_chain_length: header.previous_chain_length,
                message_number: header.message_number,
            },
            ciphertext,
        };

        let envelope = Envelope {
            source: ctx.local_id,
            destination,
            message_id,
            ttl: 10,
            hop_count: 0,
            flags: MessageFlags::NONE,
            lamport_clock: clock_val.0,
            device_timestamp: timestamp,
            protocol_version: ProtocolVersion::CURRENT,
            payload: enc_payload.serialize(),
        };

        Self::route_and_send(ctx, envelope, message_id).await?;
        Ok(message_id)
    }

    // --- Groups ---

    /// Create a new group with a random id. We are its first member.
    pub async fn create_group(&self) -> Result<[u8; 32], NodeError> {
        let mut group_id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut group_id);
        let group = SenderKeyGroup::new(group_id);
        Self::persist_group_blob(&self.db, &group_id, &group)?;
        self.groups.write().await.insert(group_id, group);
        Ok(group_id)
    }

    /// Add a member and hand every member (old and new) our sender key plus
    /// the updated roster over their pairwise sessions. The new member replies
    /// with its own key and existing members send theirs to it.
    pub async fn add_group_member(
        &self,
        group_id: [u8; 32],
        member: NodeId,
    ) -> Result<(), NodeError> {
        if member == self.node_id {
            return Err(NodeError::SendToSelf);
        }
        {
            let mut groups = self.groups.write().await;
            let group = groups.get_mut(&group_id).ok_or(NodeError::GroupNotFound)?;
            group.add_pending_member(member);
            Self::persist_group_blob(&self.db, &group_id, group)?;
        }
        // Everyone must learn the new roster: forget who already has our
        // key so the refreshed distribution goes to every member.
        {
            let mut sent = self.key_sent_to.write().await;
            sent.remove(&group_id);
        }
        Self::distribute_sender_key(&self.send_ctx(), group_id, &[]).await;
        Ok(())
    }

    /// Remove a member. Our sender key is rotated and re-sent to the
    /// remaining members together with the new roster.
    pub async fn remove_group_member(
        &self,
        group_id: [u8; 32],
        member: NodeId,
    ) -> Result<(), NodeError> {
        {
            let mut groups = self.groups.write().await;
            let group = groups.get_mut(&group_id).ok_or(NodeError::GroupNotFound)?;
            group.remove_member(&member);
            Self::persist_group_blob(&self.db, &group_id, group)?;
        }
        {
            let mut sent = self.key_sent_to.write().await;
            sent.remove(&group_id);
        }
        Self::distribute_sender_key(&self.send_ctx(), group_id, &[member]).await;
        Ok(())
    }

    /// Send our current sender key and roster to every member of the group
    /// we have not sent it to yet (as a System message over the pairwise
    /// session, establishing one if needed). Failures are logged: the send
    /// pipeline queues messages until a session exists.
    async fn distribute_sender_key(ctx: &SendCtx<'_>, group_id: [u8; 32], removed: &[NodeId]) {
        let (payload, members) = {
            let groups = ctx.groups.read().await;
            let Some(group) = groups.get(&group_id) else {
                return;
            };
            let sk = group.our_sender_key_for_distribution();
            let payload =
                wire::serialize_sender_key_distribution(&wire::SenderKeyDistributionPayload {
                    group_id,
                    chain_key: sk.chain_key,
                    iteration: sk.iteration,
                    members: group.members.clone(),
                    removed: removed.to_vec(),
                });
            (payload, group.members.clone())
        };

        let targets: Vec<NodeId> = {
            let sent = ctx.key_sent_to.read().await;
            let done = sent.get(&group_id);
            members
                .into_iter()
                .filter(|m| *m != ctx.local_id)
                .filter(|m| done.map(|d| !d.contains(m)).unwrap_or(true))
                .collect()
        };

        for target in targets {
            match Self::send_encrypted(ctx, target, &payload, ContentType::System, false).await {
                Ok(_) => {
                    ctx.key_sent_to
                        .write()
                        .await
                        .entry(group_id)
                        .or_default()
                        .insert(target);
                    debug!(
                        "Sent sender key for group {:?} to {}",
                        &group_id[..4],
                        target
                    );
                }
                Err(e) => debug!(
                    "Sender key for group {:?} to {} not sent: {}",
                    &group_id[..4],
                    target,
                    e
                ),
            }
        }
    }

    /// Install a sender key received from `source` inside an authenticated
    /// pairwise message, merge the roster it carries, and reply with our own
    /// key to members that do not have it yet.
    async fn install_sender_key(ctx: &SendCtx<'_>, source: NodeId, body: &[u8]) {
        let dist = match wire::deserialize_sender_key_distribution(body) {
            Ok(d) => d,
            Err(e) => {
                debug!("Bad sender key distribution from {}: {}", source, e);
                return;
            }
        };
        let group_id = dist.group_id;
        let sender_key = SenderKey::from_parts(dist.chain_key, dist.iteration);

        {
            let mut groups = ctx.groups.write().await;
            match groups.get_mut(&group_id) {
                Some(group) => {
                    // Only current members may update the roster or keys.
                    if !group.is_member(&source) {
                        debug!(
                            "Ignoring sender key from non-member {} for group {:?}",
                            source,
                            &group_id[..4]
                        );
                        return;
                    }
                    group.add_member(source, sender_key);
                    // Rosters only add: a member that has not yet heard of a
                    // newer addition sends a shorter list, which must not be
                    // read as a removal. Removals are explicit.
                    for m in &dist.members {
                        if *m != ctx.local_id {
                            group.add_pending_member(*m);
                        }
                    }
                    if dist.removed.contains(&ctx.local_id) {
                        info!("Removed from group {:?} by {}", &group_id[..4], source);
                        groups.remove(&group_id);
                        let _ = ctx.db.remove_group_blob(&group_id);
                        return;
                    }
                    for m in &dist.removed {
                        group.forget_member(m);
                    }
                    let _ = Self::persist_group_blob(ctx.db, &group_id, group);
                    info!(
                        "Installed sender key from {} for group {:?} ({} members)",
                        source,
                        &group_id[..4],
                        group.member_count()
                    );
                }
                None => {
                    // An invitation: a peer we have a session with added us.
                    let mut group = SenderKeyGroup::new(group_id);
                    group.add_member(source, sender_key);
                    for m in &dist.members {
                        if *m != ctx.local_id {
                            group.add_pending_member(*m);
                        }
                    }
                    let _ = Self::persist_group_blob(ctx.db, &group_id, &group);
                    info!(
                        "Joined group {:?} via sender key from {} ({} members)",
                        &group_id[..4],
                        source,
                        group.member_count()
                    );
                    groups.insert(group_id, group);
                }
            }
        }

        // Reply with our key to anyone in the roster who has not got it.
        Self::distribute_sender_key(ctx, group_id, &[]).await;
    }

    pub async fn send_group_message(
        &self,
        group_id: [u8; 32],
        plaintext: &[u8],
        content_type: ContentType,
    ) -> Result<MessageId, NodeError> {
        let message_id = MessageId::random();
        let clock_val = {
            let mut clock = self.lamport_clock.write().await;
            clock.tick();
            clock.0
        };
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Encrypt with group sender key
        let (members, payload) = {
            let mut groups = self.groups.write().await;
            let group = groups
                .get_mut(&group_id)
                .ok_or_else(|| NodeError::RoutingFailed("group not found".into()))?;
            let group_msg = group.encrypt(plaintext)?;
            let payload = wire::serialize_group_message(
                &group_id,
                group_msg.iteration,
                content_type_to_byte(content_type),
                &group_msg.ciphertext,
            );
            // The sender-key chain has advanced in memory. If that advance
            // cannot be made durable we must not transmit: a restart would
            // reload the old iteration and re-use an AES-GCM nonce under the
            // same key. Fail the send instead — the ciphertext never left.
            Self::persist_group_blob(&self.db, &group_id, group)?;
            (group.members.clone(), payload)
        };

        // Store our sent message
        let record = MessageRecord {
            message_id,
            source: self.node_id,
            destination: NodeId::from_bytes(group_id), // Use group_id as destination
            content_type: content_type_str(content_type),
            plaintext: plaintext.to_vec(),
            lamport_clock: clock_val,
            device_timestamp: timestamp,
            status: "sent".to_string(),
            is_incoming: false,
        };
        let _ = self.db.insert_message(&record);

        // Send to each member
        for member in &members {
            let envelope = Envelope {
                source: self.node_id,
                destination: *member,
                message_id,
                ttl: 10,
                hop_count: 0,
                flags: MessageFlags::GROUP,
                lamport_clock: clock_val,
                device_timestamp: timestamp,
                protocol_version: ProtocolVersion::CURRENT,
                payload: payload.clone(),
            };
            let _ = self.route_and_send_envelope(envelope, message_id).await;
        }

        Ok(message_id)
    }

    /// Route an envelope and send it, handling DiscoveryPending.
    async fn route_and_send_envelope(
        &self,
        envelope: Envelope,
        message_id: MessageId,
    ) -> Result<(), NodeError> {
        Self::route_and_send(&self.send_ctx(), envelope, message_id).await
    }

    async fn route_and_send(
        ctx: &SendCtx<'_>,
        envelope: Envelope,
        message_id: MessageId,
    ) -> Result<(), NodeError> {
        let decision = {
            let r = ctx.routing.read().await;
            r.route_message(&envelope.destination)
        };

        info!(
            "route_and_send: msg={} dest={} decision={:?}",
            message_id, envelope.destination, decision
        );

        let serialized = envelope.serialize();

        match decision {
            RoutingDecision::SendRealtime { next_hop } => {
                match ctx.transport_manager.send(&next_hop, &serialized).await {
                    Ok(()) => {
                        info!(
                            "route_and_send: sent {} bytes via transport to {}",
                            serialized.len(),
                            next_hop
                        );
                        // Guarded: a `SessionReject` can mark this failed
                        // while the transport write is still in flight, and
                        // an unconditional write would claim success for a
                        // message that cannot arrive (T-35).
                        let _ = ctx.db.mark_message_sent(&message_id);
                    }
                    Err(e) => {
                        info!("route_and_send: transport send failed: {}", e);
                        return Err(e.into());
                    }
                }
            }
            RoutingDecision::DiscoveryPending => {
                let destination = envelope.destination;
                // Queue the envelope first, then decide whether this send has
                // to start a discovery of its own. Every envelope waiting on a
                // destination is waiting on the same route, so if one is
                // already queued a flood is already in flight and will serve
                // this one too. Starting one per envelope floods the mesh N
                // times for a single unreachable peer (ROADMAP T-10).
                let discovery_in_flight = {
                    let mut pr = ctx.pending_routes.write().await;
                    let in_flight = pr.contains_key(&destination);
                    pr.entry(destination)
                        .or_insert_with(PendingDiscovery::new)
                        .envelopes
                        .push(PendingRoute {
                            envelope_bytes: serialized,
                            message_id,
                        });
                    in_flight
                };

                if !discovery_in_flight {
                    let rreq = {
                        let mut r = ctx.routing.write().await;
                        r.initiate_discovery(destination)
                    };
                    Self::broadcast_aodv_static(&rreq, ctx.local_id, ctx.transport_manager).await;
                }
            }
            RoutingDecision::EnterDtn => {
                let mut r = ctx.routing.write().await;
                if r.fallback_to_dtn(message_id, envelope.destination, ctx.local_id, serialized)
                    .is_ok()
                {
                    if let Some(bundle) = r.dtn().get_bundle(&message_id) {
                        persist_dtn_bundle(ctx.db, bundle);
                    }
                }
                // Guarded, like every DTN transition: a message a rejection
                // already failed cannot be revived here (T-35).
                let _ = ctx.db.mark_message_dtn_pending(&message_id);
            }
            RoutingDecision::DeliverLocal => {
                return Err(NodeError::SendToSelf);
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn initiate_session_and_send(
        ctx: &SendCtx<'_>,
        destination: NodeId,
        bundle: &PrekeyBundle,
        plaintext: &[u8],
        content_type: ContentType,
        message_id: MessageId,
        clock_val: LamportClock,
        timestamp: u64,
    ) -> Result<(), NodeError> {
        let identity = identity_clone_for_prekeys(ctx.identity);

        // Note: the session is deliberately NOT persisted here. Storing it
        // before the first message is encrypted gains nothing — if we die
        // before encrypting we want no session at all — and a provisional row
        // whose cleanup DELETE later failed would be reloaded on restart and
        // used without the peer ever receiving SessionInit. One write, after
        // the encrypt, before the ciphertext can leave.
        //
        // If anything below fails the session must not be left installed:
        // `send_encrypted` would see `has_session()` and send a bare
        // EncryptedMessage to a peer that never received the handshake.
        let ad = build_ad(
            ctx.local_id,
            destination,
            content_type_to_byte(content_type),
        );

        // Choosing, initiating, encrypting and recording all happen under one
        // lock. Split apart, a second send to the same new peer could pass the
        // "no session" check, initiate again and replace the ratchet the first
        // had already encrypted under — stranding its message at both ends —
        // and an authenticated `SessionInit` accepted in the gap had its
        // clearing of this bookkeeping undone by the record that followed
        // (T-35). Everything in here is synchronous; the persist and the send
        // are outside it.
        let (payload, our_handshake) = {
            let mut sm = ctx.session_manager.write().await;
            if sm.has_session(&destination) {
                // Another send got here first. Use what it installed: a second
                // `initiate_session` would discard it.
                let (header, ciphertext) = sm.encrypt_for(&destination, plaintext, &ad)?;
                sm.record_unconfirmed_message(destination, message_id);
                let enc_payload = EncryptedPayload {
                    content_type: content_type_to_byte(content_type),
                    header: WireRatchetHeader {
                        dh_public: header.dh_public,
                        previous_chain_length: header.previous_chain_length,
                        message_number: header.message_number,
                    },
                    ciphertext,
                };
                (enc_payload.serialize(), None)
            } else {
                let init_result = sm.initiate_session(&identity, destination, bundle)?;
                let (header, ciphertext) = match sm.encrypt_for(&destination, plaintext, &ad) {
                    Ok(r) => r,
                    Err(e) => {
                        drop(sm);
                        Self::discard_unsent_session(ctx, &destination).await;
                        return Err(e.into());
                    }
                };
                let enc_payload = EncryptedPayload {
                    content_type: content_type_to_byte(content_type),
                    header: WireRatchetHeader {
                        dh_public: header.dh_public,
                        previous_chain_length: header.previous_chain_length,
                        message_number: header.message_number,
                    },
                    ciphertext,
                };
                let session_init = SessionInitPayload {
                    ephemeral_public: init_result.ephemeral_public,
                    identity_key: ctx.identity.public_key_bytes(),
                    signed_prekey_id: init_result.used_signed_prekey_id,
                    one_time_prekey_id: init_result.used_one_time_prekey_id,
                    encrypted_payload: enc_payload.serialize(),
                };
                let payload = session_init.serialize();
                // The transcript is over the body, which is what the responder
                // hashes: the type byte is the dispatcher's, not the payload's.
                let transcript = mycelium_crypto::reject::init_transcript(&payload[1..]);
                sm.mark_handshake_pending(destination, transcript, message_id);
                (payload, Some(transcript))
            }
        };

        // Persist the ratchet advance before the ciphertext can leave.
        if let Err(e) = Self::persist_session(ctx.session_manager, ctx.db, &destination).await {
            // Only tear down a session this call created, and only while it
            // is still the one outstanding.
            if let Some(transcript) = our_handshake {
                Self::discard_if_still_ours(ctx, &destination, transcript).await;
            }
            return Err(e.into());
        }

        let envelope = Envelope {
            source: ctx.local_id,
            destination,
            message_id,
            ttl: 10,
            hop_count: 0,
            flags: MessageFlags::NONE,
            lamport_clock: clock_val.0,
            device_timestamp: timestamp,
            protocol_version: ProtocolVersion::CURRENT,
            payload,
        };

        // Routing or the transport can still refuse this. If the SessionInit
        // never leaves, the session must not stay installed: later sends would
        // go out as bare EncryptedMessage to a peer that never saw the
        // handshake (round 5 finding #7).
        if let Err(e) = Self::route_and_send(ctx, envelope, message_id).await {
            if let Some(transcript) = our_handshake {
                Self::discard_if_still_ours(ctx, &destination, transcript).await;
            }
            return Err(e);
        }

        Ok(())
    }

    /// Broadcast an AODV message to all known peers.
    async fn broadcast_aodv_message(&self, msg: &AodvMessage, source: NodeId) {
        let payload = serialize_aodv_message(msg);
        let envelope = Envelope {
            source,
            destination: NodeId::ZERO, // broadcast
            message_id: MessageId::random(),
            ttl: 10,
            hop_count: 0,
            flags: MessageFlags::SYSTEM,
            lamport_clock: 0,
            device_timestamp: 0,
            protocol_version: ProtocolVersion::CURRENT,
            payload,
        };
        let data = envelope.serialize();
        let peers = self.transport_manager.known_peers().await;
        for peer in peers {
            let _ = self.transport_manager.send(&peer, &data).await;
        }
    }

    /// Route an envelope via the routing table (for use without &self).
    async fn route_envelope_static(
        envelope: &Envelope,
        routing: &RwLock<RoutingCoordinator>,
        transport_manager: &TransportManager,
    ) {
        let decision = {
            let r = routing.read().await;
            r.route_message(&envelope.destination)
        };
        match decision {
            RoutingDecision::SendRealtime { next_hop } => {
                let data = envelope.serialize();
                let _ = transport_manager.send(&next_hop, &data).await;
            }
            _ => {
                // Best effort — try direct send as fallback
                let data = envelope.serialize();
                let _ = transport_manager.send(&envelope.destination, &data).await;
            }
        }
    }

    /// Broadcast an AODV message without &self (for use in maintenance tasks).
    async fn broadcast_aodv_static(
        msg: &AodvMessage,
        source: NodeId,
        transport_manager: &TransportManager,
    ) {
        let payload = serialize_aodv_message(msg);
        let envelope = Envelope {
            source,
            destination: NodeId::ZERO,
            message_id: MessageId::random(),
            ttl: 10,
            hop_count: 0,
            flags: MessageFlags::SYSTEM,
            lamport_clock: 0,
            device_timestamp: 0,
            protocol_version: ProtocolVersion::CURRENT,
            payload,
        };
        let data = envelope.serialize();
        let peers = transport_manager.known_peers().await;
        for peer in peers {
            let _ = transport_manager.send(&peer, &data).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_transport_event(
        event: &TransportEvent,
        routing: &RwLock<RoutingCoordinator>,
        session_manager: &RwLock<SessionManager>,
        prekey_state: &RwLock<PrekeyState>,
        rate_limiter: &RwLock<RateLimiter>,
        trust_graph: &RwLock<TrustGraph>,
        groups: &RwLock<HashMap<[u8; 32], SenderKeyGroup>>,
        transport_manager: &TransportManager,
        db: &Database,
        identity: &Identity,
        local_id: NodeId,
        lamport_clock: &RwLock<LamportClock>,
        prekey_cache: &RwLock<HashMap<NodeId, (PrekeyBundle, Instant)>>,
        pending_messages: &RwLock<HashMap<NodeId, Vec<PendingMessage>>>,
        pending_routes: &RwLock<HashMap<NodeId, PendingDiscovery>>,
        battery: &RwLock<BatteryManager>,
        event_tx: &tokio::sync::broadcast::Sender<NodeEvent>,
        seen_channel_messages: &RwLock<HashSet<MessageId>>,
        local_group_hash: Option<[u8; 8]>,
        key_sent_to: &RwLock<HashMap<[u8; 32], HashSet<NodeId>>>,
    ) {
        let ctx = SendCtx {
            local_id,
            identity,
            db,
            transport_manager,
            routing,
            session_manager,
            prekey_cache,
            pending_messages,
            pending_routes,
            lamport_clock,
            groups,
            key_sent_to,
        };
        match event {
            TransportEvent::NeighborDiscovered { peer, transport } => {
                info!("Neighbor discovered: {} via {}", peer, transport);
                let dtn_actions = {
                    let mut r = routing.write().await;
                    r.on_neighbor_encountered(*peer)
                };

                // Execute DTN actions
                for action in dtn_actions {
                    match action {
                        DtnAction::SendToPeer {
                            peer: target,
                            bundle,
                        } => {
                            let ttl_secs = bundle
                                .expires_at
                                .saturating_duration_since(Instant::now())
                                .as_secs()
                                .min(u32::MAX as u64)
                                as u32;
                            let payload = wire::serialize_dtn_relay(&wire::DtnRelayPayload {
                                message_id: bundle.message_id,
                                copies_remaining: bundle.copies_remaining.max(1),
                                ttl_secs,
                                payload: bundle.payload.clone(),
                            });
                            let envelope = Envelope {
                                source: bundle.source,
                                destination: bundle.destination,
                                message_id: bundle.message_id,
                                ttl: 5,
                                hop_count: 0,
                                flags: MessageFlags::DTN,
                                lamport_clock: 0,
                                device_timestamp: 0,
                                protocol_version: ProtocolVersion::CURRENT,
                                payload,
                            };
                            let data = envelope.serialize();
                            match transport_manager.send(&target, &data).await {
                                Ok(()) => {
                                    if bundle.destination == target {
                                        // Sent directly to the destination — delivery complete,
                                        // remove bundle from both in-memory engine and DB.
                                        {
                                            let mut r = routing.write().await;
                                            r.dtn_mut().remove_bundle(&bundle.message_id);
                                        }
                                        let _ = db.remove_dtn_bundle(&bundle.message_id);
                                        debug!(
                                            "DTN delivered bundle {} to destination {}",
                                            bundle.message_id, target
                                        );
                                    } else {
                                        // Sprayed to a relay. The remaining
                                        // copies and the holder list must move
                                        // together: persisted apart, a failure
                                        // between them leaves a restart either
                                        // re-spraying a holder or spending a
                                        // copy it already spent.
                                        {
                                            let r = routing.read().await;
                                            if let Some(our) =
                                                r.dtn().get_bundle(&bundle.message_id)
                                            {
                                                let sprayed =
                                                    r.dtn().sprayed_to(&bundle.message_id).to_vec();
                                                if let Err(e) = db.update_dtn_spray_state(
                                                    &bundle.message_id,
                                                    our.copies_remaining,
                                                    &sprayed,
                                                ) {
                                                    // The copy has already gone
                                                    // out. Losing this write
                                                    // means a restart may spray
                                                    // this peer again, so say so
                                                    // rather than swallowing it.
                                                    warn!(
                                                        "Failed to persist spray state for {}: \
                                                         {} (a restart may re-spray)",
                                                        bundle.message_id, e
                                                    );
                                                }
                                            }
                                        }
                                        debug!(
                                            "DTN spray: sent bundle {} to relay {}",
                                            bundle.message_id, target
                                        );
                                    }
                                }
                                Err(e) => {
                                    debug!("DTN send to {} failed: {}, keeping bundle", target, e);
                                }
                            }
                        }
                        DtnAction::DeliverLocal { bundle } => {
                            debug!("DTN deliver local: bundle {}", bundle.message_id);
                            Self::handle_dtn_local_delivery(&bundle, event_tx, &ctx).await;
                            // Remove delivered bundle from DB
                            let _ = db.remove_dtn_bundle(&bundle.message_id);
                        }
                        DtnAction::None => {}
                    }
                }

                // Flush any pending route envelopes for this neighbor.
                // Messages queued via route_and_send_envelope() before the
                // AODV route existed can now be sent directly.
                let pending = {
                    let mut pr = pending_routes.write().await;
                    pr.remove(peer).map(|d| d.envelopes).unwrap_or_default()
                };
                if !pending.is_empty() {
                    debug!(
                        "Flushing {} pending route envelopes for newly discovered neighbor {}",
                        pending.len(),
                        peer
                    );
                    for route in pending {
                        let _ = transport_manager.send(peer, &route.envelope_bytes).await;
                    }
                }

                let _ = event_tx.send(NodeEvent::PeerDiscovered {
                    peer_id: *peer,
                    transport: transport.to_string(),
                });
            }
            TransportEvent::NeighborLost { peer, transport } => {
                info!("Neighbor lost: {} via {}", peer, transport);
                let rerr = {
                    let mut r = routing.write().await;
                    r.report_link_break(*peer)
                };
                if let Some(rerr_msg) = rerr {
                    let payload = serialize_aodv_message(&rerr_msg);
                    let envelope = Envelope {
                        source: local_id,
                        destination: NodeId::ZERO,
                        message_id: MessageId::random(),
                        ttl: 10,
                        hop_count: 0,
                        flags: MessageFlags::SYSTEM,
                        lamport_clock: 0,
                        device_timestamp: 0,
                        protocol_version: ProtocolVersion::CURRENT,
                        payload,
                    };
                    let data = envelope.serialize();
                    let peers = transport_manager.known_peers().await;
                    for p in peers {
                        let _ = transport_manager.send(&p, &data).await;
                    }
                }

                let _ = event_tx.send(NodeEvent::PeerLost {
                    peer_id: *peer,
                    transport: transport.to_string(),
                });
            }
            TransportEvent::DataReceived { peer, data, .. } => {
                // Deserialize envelope first so we can exempt protocol messages
                // from rate limiting (AODV, prekey, session init are required
                // for establishing connectivity with new peers).
                let envelope = match Envelope::deserialize(data) {
                    Ok(env) => env,
                    Err(e) => {
                        debug!("Failed to deserialize envelope from {}: {}", peer, e);
                        return;
                    }
                };

                // Merge lamport clock
                {
                    let mut clock = lamport_clock.write().await;
                    clock.merge(LamportClock(envelope.lamport_clock));
                }

                // Refresh the direct neighbor route on every received packet
                // so the route stays alive as long as the BLE connection is active.
                {
                    let mut r = routing.write().await;
                    r.aodv_mut().refresh_neighbor_route(*peer);
                }

                // If the envelope was forwarded (source != peer), learn a reverse
                // route back to the source via the peer who relayed it to us.
                if envelope.source != *peer && envelope.source != local_id && envelope.hop_count > 0
                {
                    let mut r = routing.write().await;
                    r.aodv_mut().update_route(
                        envelope.source,
                        *peer,
                        envelope.hop_count.saturating_add(1),
                        0,
                    );
                }

                if envelope.payload.is_empty() {
                    debug!("Empty payload from {}", peer);
                    return;
                }

                let payload_type = match WirePayloadType::from_byte(envelope.payload[0]) {
                    Some(t) => t,
                    None => {
                        debug!(
                            "Unknown payload type 0x{:02x} from {}",
                            envelope.payload[0], peer
                        );
                        return;
                    }
                };

                let body = &envelope.payload[1..];

                // Exempt protocol messages (AODV, prekey, session init, DTN relay,
                // beacon) from rate limiting — these are required for mesh
                // infrastructure and establishing sessions with new peers.
                let is_protocol_message = matches!(
                    payload_type,
                    WirePayloadType::AodvRreq
                        | WirePayloadType::AodvRrep
                        | WirePayloadType::AodvRerr
                        | WirePayloadType::PrekeyRequest
                        | WirePayloadType::PrekeyResponse
                        | WirePayloadType::SessionInit
                        | WirePayloadType::Beacon
                        | WirePayloadType::DtnRelay
                );

                if !is_protocol_message {
                    let trust_hops = {
                        let tg = trust_graph.read().await;
                        let score = tg.trust_score(&local_id, peer);
                        if score.value > 0.0 {
                            score.hops
                        } else {
                            u8::MAX
                        }
                    };
                    let mut rl = rate_limiter.write().await;
                    if rl.is_blacklisted(peer) {
                        debug!("Dropping data from blacklisted peer {}", peer);
                        return;
                    }
                    if !rl.check_message(peer, trust_hops) {
                        if rl.record_violation(peer) {
                            warn!(
                                "Auto-blacklisted peer {} after repeated rate violations",
                                peer
                            );
                        } else {
                            debug!("Rate limited peer {} (trust_hops={})", peer, trust_hops);
                        }
                        return;
                    }
                }

                // For non-AODV messages not addressed to us, forward via routing
                let is_aodv = matches!(
                    payload_type,
                    WirePayloadType::AodvRreq
                        | WirePayloadType::AodvRrep
                        | WirePayloadType::AodvRerr
                );
                let is_broadcast = envelope.destination == NodeId::ZERO;
                if !is_aodv
                    && !is_broadcast
                    && envelope.destination != local_id
                    // EncryptedMessage has its own forwarding logic
                    && payload_type != WirePayloadType::EncryptedMessage
                    // DtnRelay for another node is store-and-carry: the relay
                    // handler keeps the bundle when no route exists.
                    && payload_type != WirePayloadType::DtnRelay
                {
                    // Check battery policy
                    {
                        let batt = battery.read().await;
                        if !batt.should_relay() {
                            debug!("Battery too low to relay, dropping forward");
                            return;
                        }
                    }
                    if envelope.ttl == 0 {
                        debug!("Dropping forwarded message with TTL=0");
                        return;
                    }
                    let decision = {
                        let r = routing.read().await;
                        r.route_message(&envelope.destination)
                    };
                    // Opportunistically cache prekey responses passing through,
                    // but only when the bundle's identity key really belongs to
                    // the claimed source (NodeId = SHA-256(identity key)).
                    if payload_type == WirePayloadType::PrekeyResponse {
                        if let Some(bp) =
                            PrekeyBundlePayload::deserialize_body(body)
                                .ok()
                                .filter(|bp| {
                                    node_id_from_public_key(&bp.identity_key) == envelope.source
                                })
                        {
                            let bundle = PrekeyBundle {
                                identity_key: bp.identity_key,
                                signed_prekey: bp.signed_prekey,
                                signed_prekey_signature: bp.signed_prekey_signature.clone(),
                                signed_prekey_id: bp.signed_prekey_id,
                                one_time_prekey: bp.one_time_prekey,
                                one_time_prekey_id: bp.one_time_prekey_id,
                            };
                            {
                                let mut cache = prekey_cache.write().await;
                                cache.insert(envelope.source, (bundle, Instant::now()));
                            }
                            let serialized = bp.serialize();
                            let _ = db
                                .cache_prekey_bundle(envelope.source.as_bytes(), &serialized[1..]);
                            debug!(
                                "Cached prekey bundle from {} while forwarding",
                                envelope.source
                            );
                        }
                    }

                    if let RoutingDecision::SendRealtime { next_hop } = decision {
                        let mut fwd = envelope.clone();
                        fwd.forward();
                        let data = fwd.serialize();
                        let _ = transport_manager.send(&next_hop, &data).await;
                        debug!(
                            "Forwarded {:?} message toward {} via {}",
                            payload_type, envelope.destination, next_hop
                        );
                    } else {
                        debug!(
                            "No route to forward {:?} for {}, dropping",
                            payload_type, envelope.destination
                        );
                    }
                    return;
                }

                // Rate-limit user data messages based on the *originator's*
                // trust distance. A direct neighbor was already counted by the
                // previous-hop gate above, so do not charge it twice. DTN relay
                // quota is enforced by handle_dtn_relay when a bundle is stored.
                let is_user_data = matches!(
                    payload_type,
                    WirePayloadType::EncryptedMessage
                        | WirePayloadType::GroupMessage
                        | WirePayloadType::ChannelMessage
                );
                if is_user_data && envelope.source != *peer {
                    let trust_hops = {
                        let tg = trust_graph.read().await;
                        tg.trust_score(&local_id, &envelope.source).hops
                    };
                    let allowed = {
                        let mut rl = rate_limiter.write().await;
                        rl.check_message(&envelope.source, trust_hops)
                    };
                    if !allowed {
                        debug!(
                            "Rate-limited {:?} from {} (trust_hops={})",
                            payload_type, envelope.source, trust_hops
                        );
                        let mut rl = rate_limiter.write().await;
                        let blacklisted = rl.record_violation(&envelope.source);
                        if blacklisted {
                            warn!(
                                "Auto-blacklisted {} after repeated rate violations",
                                envelope.source
                            );
                        }
                        return;
                    }
                }

                match payload_type {
                    WirePayloadType::AodvRreq => {
                        Self::handle_aodv_rreq(
                            body,
                            *peer,
                            routing,
                            transport_manager,
                            local_id,
                            pending_routes,
                        )
                        .await;
                    }
                    WirePayloadType::AodvRrep => {
                        Self::handle_aodv_rrep(
                            body,
                            *peer,
                            routing,
                            transport_manager,
                            local_id,
                            pending_routes,
                        )
                        .await;
                    }
                    WirePayloadType::AodvRerr => {
                        Self::handle_aodv_rerr(body, *peer, routing, transport_manager, local_id)
                            .await;
                    }
                    WirePayloadType::EncryptedMessage => {
                        Self::handle_encrypted_message(
                            &envelope,
                            body,
                            routing,
                            session_manager,
                            transport_manager,
                            db,
                            local_id,
                            lamport_clock,
                            battery,
                            event_tx,
                            &ctx,
                        )
                        .await;
                    }
                    WirePayloadType::SessionInit => {
                        Self::handle_session_init(
                            &envelope,
                            body,
                            session_manager,
                            prekey_state,
                            db,
                            local_id,
                            lamport_clock,
                            event_tx,
                            &ctx,
                        )
                        .await;
                    }
                    WirePayloadType::PrekeyRequest => {
                        Self::handle_prekey_request(
                            &envelope,
                            prekey_state,
                            routing,
                            transport_manager,
                            identity,
                            local_id,
                            lamport_clock,
                            db,
                        )
                        .await;
                    }
                    WirePayloadType::PrekeyResponse => {
                        Self::handle_prekey_response(
                            &envelope,
                            body,
                            prekey_cache,
                            pending_messages,
                            session_manager,
                            transport_manager,
                            routing,
                            db,
                            identity,
                            local_id,
                            lamport_clock,
                        )
                        .await;
                    }
                    WirePayloadType::SessionReject => {
                        Self::handle_session_reject(
                            &envelope,
                            body,
                            prekey_cache,
                            session_manager,
                            db,
                            local_id,
                        )
                        .await;
                    }
                    WirePayloadType::DtnRelay => {
                        Self::handle_dtn_relay(
                            &envelope,
                            body,
                            routing,
                            session_manager,
                            prekey_state,
                            rate_limiter,
                            trust_graph,
                            transport_manager,
                            db,
                            local_id,
                            lamport_clock,
                            event_tx,
                            &ctx,
                        )
                        .await;
                    }
                    WirePayloadType::Beacon => {
                        Self::handle_beacon(
                            &envelope,
                            *peer,
                            body,
                            db,
                            lamport_clock,
                            trust_graph,
                            routing,
                            local_id,
                            local_group_hash,
                            identity.public_key_bytes(),
                        )
                        .await;
                    }
                    WirePayloadType::Receipt => {
                        Self::handle_receipt(&envelope, body, db, local_id, event_tx);
                    }
                    WirePayloadType::GroupMessage => {
                        Self::handle_group_message(&envelope, body, groups, db, local_id).await;
                    }
                    WirePayloadType::SenderKeyDistribution => {
                        // Sender keys only travel inside pairwise-encrypted
                        // messages (see install_sender_key); a bare payload is
                        // unauthenticated and ignored.
                        debug!(
                            "Ignoring top-level SenderKeyDistribution from {}",
                            envelope.source
                        );
                    }
                    WirePayloadType::ChannelMessage => {
                        Self::handle_channel_message(
                            &envelope,
                            *peer,
                            body,
                            db,
                            transport_manager,
                            local_id,
                            seen_channel_messages,
                            event_tx,
                        )
                        .await;
                    }
                    WirePayloadType::ChannelSubscribe
                    | WirePayloadType::ChannelUnsubscribe
                    | WirePayloadType::ChannelModeration => {
                        debug!(
                            "Channel control message {:?} received, not yet handled",
                            payload_type
                        );
                    }
                    WirePayloadType::EmergencyBroadcast => {
                        Self::handle_emergency_broadcast(
                            &envelope,
                            *peer,
                            body,
                            trust_graph,
                            transport_manager,
                            local_id,
                            seen_channel_messages,
                            event_tx,
                            db,
                        )
                        .await;
                    }
                }
            }
            TransportEvent::LinkQualityChanged { peer, quality, .. } => {
                tracing::trace!(
                    "Link quality changed for {}: score={:.2}",
                    peer,
                    quality.score()
                );
            }
        }
    }

    // --- AODV handlers ---

    async fn handle_aodv_rreq(
        body: &[u8],
        received_from: NodeId,
        routing: &RwLock<RoutingCoordinator>,
        transport_manager: &TransportManager,
        local_id: NodeId,
        pending_routes: &RwLock<HashMap<NodeId, PendingDiscovery>>,
    ) {
        let (request_id, source, source_seq, destination, dest_seq, hop_count, ttl) =
            match wire::deserialize_aodv_rreq(body) {
                Ok(v) => v,
                Err(e) => {
                    debug!("Bad AODV RREQ: {}", e);
                    return;
                }
            };

        let rreq = RouteRequest {
            request_id,
            source,
            source_seq,
            destination,
            dest_seq,
            hop_count,
            ttl,
        };

        let action = {
            let mut r = routing.write().await;
            r.handle_aodv_message(AodvMessage::RouteRequest(rreq), received_from)
        };

        Self::execute_aodv_action(action, routing, transport_manager, local_id, pending_routes)
            .await;
    }

    async fn handle_aodv_rrep(
        body: &[u8],
        received_from: NodeId,
        routing: &RwLock<RoutingCoordinator>,
        transport_manager: &TransportManager,
        local_id: NodeId,
        pending_routes: &RwLock<HashMap<NodeId, PendingDiscovery>>,
    ) {
        let (request_id, source, destination, dest_seq, hop_count, lifetime_secs) =
            match wire::deserialize_aodv_rrep(body) {
                Ok(v) => v,
                Err(e) => {
                    debug!("Bad AODV RREP: {}", e);
                    return;
                }
            };

        let rrep = RouteReply {
            request_id,
            source,
            destination,
            dest_seq,
            hop_count,
            lifetime_secs,
        };

        let action = {
            let mut r = routing.write().await;
            r.handle_aodv_message(AodvMessage::RouteReply(rrep), received_from)
        };

        Self::execute_aodv_action(action, routing, transport_manager, local_id, pending_routes)
            .await;
    }

    async fn handle_aodv_rerr(
        body: &[u8],
        received_from: NodeId,
        routing: &RwLock<RoutingCoordinator>,
        transport_manager: &TransportManager,
        local_id: NodeId,
    ) {
        let (unreachable, source, dest_seq) = match wire::deserialize_aodv_rerr(body) {
            Ok(v) => v,
            Err(e) => {
                debug!("Bad AODV RERR: {}", e);
                return;
            }
        };

        let rerr = RouteError {
            unreachable,
            source,
            dest_seq,
        };

        let action = {
            let mut r = routing.write().await;
            r.handle_aodv_message(AodvMessage::RouteError(rerr), received_from)
        };

        // For RERR, we only care about BroadcastRerr. Never echo it back to
        // the hop we got it from.
        if let AodvAction::BroadcastRerr(rerr) = action {
            let payload = wire::serialize_aodv_rerr(&rerr.unreachable, &rerr.source, rerr.dest_seq);
            let envelope = Envelope {
                source: local_id,
                destination: NodeId::ZERO,
                message_id: MessageId::random(),
                ttl: 10,
                hop_count: 0,
                flags: MessageFlags::SYSTEM,
                lamport_clock: 0,
                device_timestamp: 0,
                protocol_version: ProtocolVersion::CURRENT,
                payload,
            };
            let data = envelope.serialize();
            let peers = transport_manager.known_peers().await;
            for p in peers {
                if p == received_from {
                    continue;
                }
                let _ = transport_manager.send(&p, &data).await;
            }
        }
    }

    async fn execute_aodv_action(
        action: AodvAction,
        _routing: &RwLock<RoutingCoordinator>,
        transport_manager: &TransportManager,
        local_id: NodeId,
        pending_routes: &RwLock<HashMap<NodeId, PendingDiscovery>>,
    ) {
        match action {
            AodvAction::BroadcastRreq(rreq) => {
                let payload = wire::serialize_aodv_rreq(
                    rreq.request_id,
                    &rreq.source,
                    rreq.source_seq,
                    &rreq.destination,
                    rreq.dest_seq,
                    rreq.hop_count,
                    rreq.ttl,
                );
                let envelope = Envelope {
                    source: local_id,
                    destination: NodeId::ZERO,
                    message_id: MessageId::random(),
                    ttl: rreq.ttl,
                    hop_count: 0,
                    flags: MessageFlags::SYSTEM,
                    lamport_clock: 0,
                    device_timestamp: 0,
                    protocol_version: ProtocolVersion::CURRENT,
                    payload,
                };
                let data = envelope.serialize();
                let peers = transport_manager.known_peers().await;
                for p in peers {
                    let _ = transport_manager.send(&p, &data).await;
                }
            }
            AodvAction::UnicastRrep { next_hop, rrep } => {
                let payload = wire::serialize_aodv_rrep(
                    rrep.request_id,
                    &rrep.source,
                    &rrep.destination,
                    rrep.dest_seq,
                    rrep.hop_count,
                    rrep.lifetime_secs,
                );
                let envelope = Envelope {
                    source: local_id,
                    destination: rrep.source,
                    message_id: MessageId::random(),
                    ttl: 10,
                    hop_count: 0,
                    flags: MessageFlags::SYSTEM,
                    lamport_clock: 0,
                    device_timestamp: 0,
                    protocol_version: ProtocolVersion::CURRENT,
                    payload,
                };
                let data = envelope.serialize();
                let _ = transport_manager.send(&next_hop, &data).await;
            }
            AodvAction::RouteFound {
                destination,
                next_hop,
            } => {
                // Flush pending route envelopes for this destination
                let pending = {
                    let mut pr = pending_routes.write().await;
                    pr.remove(&destination)
                        .map(|d| d.envelopes)
                        .unwrap_or_default()
                };
                for route in pending {
                    debug!(
                        "Sending queued envelope for {} via {}",
                        destination, next_hop
                    );
                    let _ = transport_manager
                        .send(&next_hop, &route.envelope_bytes)
                        .await;
                }
            }
            AodvAction::BroadcastRerr(rerr) => {
                let payload =
                    wire::serialize_aodv_rerr(&rerr.unreachable, &rerr.source, rerr.dest_seq);
                let envelope = Envelope {
                    source: local_id,
                    destination: NodeId::ZERO,
                    message_id: MessageId::random(),
                    ttl: 10,
                    hop_count: 0,
                    flags: MessageFlags::SYSTEM,
                    lamport_clock: 0,
                    device_timestamp: 0,
                    protocol_version: ProtocolVersion::CURRENT,
                    payload,
                };
                let data = envelope.serialize();
                let peers = transport_manager.known_peers().await;
                for p in peers {
                    let _ = transport_manager.send(&p, &data).await;
                }
            }
            AodvAction::None => {}
        }
    }

    // --- Message handlers ---

    #[allow(clippy::too_many_arguments)]
    async fn handle_encrypted_message(
        envelope: &Envelope,
        body: &[u8],
        routing: &RwLock<RoutingCoordinator>,
        session_manager: &RwLock<SessionManager>,
        transport_manager: &TransportManager,
        db: &Database,
        local_id: NodeId,
        _lamport_clock: &RwLock<LamportClock>,
        battery: &RwLock<BatteryManager>,
        event_tx: &tokio::sync::broadcast::Sender<NodeEvent>,
        ctx: &SendCtx<'_>,
    ) {
        let is_for_us = envelope.destination == local_id;

        if is_for_us {
            // Duplicate delivery (DTN multi-copy, relay replay) must not touch
            // the ratchet again; the receipt is re-sent so the sender learns
            // its message arrived even if the first receipt was lost.
            if db.get_message(&envelope.message_id).is_ok() {
                debug!(
                    "Duplicate message {} from {}, re-sending receipt",
                    envelope.message_id, envelope.source
                );
                Self::send_delivery_receipt(
                    envelope.message_id,
                    envelope.source,
                    local_id,
                    transport_manager,
                    routing,
                )
                .await;
                return;
            }

            // Decrypt locally
            let enc = match EncryptedPayload::deserialize_body(body) {
                Ok(e) => e,
                Err(e) => {
                    debug!("Bad encrypted payload: {}", e);
                    return;
                }
            };

            let ratchet_header = RatchetHeader {
                dh_public: enc.header.dh_public,
                previous_chain_length: enc.header.previous_chain_length,
                message_number: enc.header.message_number,
            };

            let ad = build_ad(envelope.source, envelope.destination, enc.content_type);
            let plaintext = {
                let mut sm = session_manager.write().await;
                match sm.decrypt_from(&envelope.source, &ratchet_header, &enc.ciphertext, &ad) {
                    Ok(pt) => pt,
                    Err(e) => {
                        debug!("Decryption failed from {}: {}", envelope.source, e);
                        return;
                    }
                }
            };

            // Persist session after ratchet state advance
            Self::persist_session_lossy(session_manager, db, &envelope.source).await;

            let record = MessageRecord {
                message_id: envelope.message_id,
                source: envelope.source,
                destination: local_id,
                content_type: content_type_from_byte(enc.content_type),
                plaintext,
                lamport_clock: envelope.lamport_clock,
                device_timestamp: envelope.device_timestamp,
                status: "received".to_string(),
                is_incoming: true,
            };
            debug!(
                "Received message {} from {}",
                envelope.message_id, envelope.source
            );
            Self::finalize_incoming_message(record, enc.content_type, event_tx, ctx).await;
        } else {
            // Forward — check battery policy first
            {
                let batt = battery.read().await;
                if !batt.should_relay() {
                    debug!(
                        "Battery too low to relay ({:?}), dropping forward for {}",
                        batt.battery_level(),
                        envelope.destination
                    );
                    return;
                }
            }

            if envelope.ttl == 0 {
                debug!("Dropping message with TTL=0 for {}", envelope.destination);
                return;
            }

            let decision = {
                let r = routing.read().await;
                r.route_message(&envelope.destination)
            };

            match decision {
                RoutingDecision::SendRealtime { next_hop } => {
                    let mut fwd = envelope.clone();
                    fwd.forward();
                    let data = fwd.serialize();
                    let _ = transport_manager.send(&next_hop, &data).await;
                    debug!(
                        "Forwarded message {} toward {} via {}",
                        envelope.message_id, envelope.destination, next_hop
                    );
                }
                _ => {
                    debug!(
                        "No route to forward message for {}, dropping",
                        envelope.destination
                    );
                }
            }
        }
    }

    /// Store a decrypted incoming message, notify API clients, and send the
    /// delivery receipt. Shared by the real-time, SessionInit and DTN paths so
    /// every delivery behaves the same regardless of how it arrived.
    async fn finalize_incoming_message(
        record: MessageRecord,
        content_type: u8,
        event_tx: &tokio::sync::broadcast::Sender<NodeEvent>,
        ctx: &SendCtx<'_>,
    ) {
        let db = ctx.db;
        let transport_manager = ctx.transport_manager;
        let routing = ctx.routing;
        let local_id = ctx.local_id;
        // System messages carry protocol payloads (sender keys), not chat.
        if content_type == content_type_to_byte(ContentType::System) {
            if record.plaintext.first() == Some(&(WirePayloadType::SenderKeyDistribution as u8)) {
                Self::install_sender_key(ctx, record.source, &record.plaintext[1..]).await;
            } else {
                debug!(
                    "Ignoring system message from {} with unknown inner type",
                    record.source
                );
            }
            return;
        }

        let _ = db.insert_message(&record);

        let _ = event_tx.send(NodeEvent::MessageReceived {
            source: record.source,
            message_id: record.message_id,
            data: record.plaintext.clone(),
            content_type,
            timestamp: record.device_timestamp,
        });

        Self::send_delivery_receipt(
            record.message_id,
            record.source,
            local_id,
            transport_manager,
            routing,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_session_init(
        envelope: &Envelope,
        body: &[u8],
        session_manager: &RwLock<SessionManager>,
        prekey_state: &RwLock<PrekeyState>,
        db: &Database,
        local_id: NodeId,
        _lamport_clock: &RwLock<LamportClock>,
        event_tx: &tokio::sync::broadcast::Sender<NodeEvent>,
        ctx: &SendCtx<'_>,
    ) {
        if envelope.destination != local_id {
            debug!("SessionInit not for us, ignoring");
            return;
        }

        // What a rejection of *this* attempt is bound to. The envelope's id
        // and source are cleartext, so they identify nothing an attacker
        // could not have chosen; the payload is what the initiator built.
        let init_transcript = mycelium_crypto::reject::init_transcript(body);

        // A replay of the init this session was accepted from is answered
        // with silence. Duplicate detection keys on the envelope's
        // `message_id`, which the transcript does not cover, so a relay can
        // re-deliver an accepted init under a fresh id; its one-time prekey is
        // spent and the ratchet has moved past its message, so it would fail
        // and we would sign a *valid* rejection of an init the peer really
        // sent — which the peer would act on, tearing down a live handshake
        // (ADR-012).
        if session_manager
            .read()
            .await
            .is_replayed_init(&envelope.source, &init_transcript)
        {
            debug!(
                "Ignoring a replayed SessionInit from {}: it is the one our session \
                 was accepted from",
                envelope.source
            );
            return;
        }

        let init = match SessionInitPayload::deserialize_body(body) {
            Ok(i) => i,
            Err(e) => {
                debug!("Bad SessionInit payload: {}", e);
                return;
            }
        };

        // A replayed SessionInit (same message id) must not touch session state.
        if db.get_message(&envelope.message_id).is_ok() {
            debug!(
                "Duplicate SessionInit {} from {}, ignoring",
                envelope.message_id, envelope.source
            );
            return;
        }

        // Parse the enclosed first message, if any, before touching state.
        let first_message = if !init.encrypted_payload.is_empty()
            && init.encrypted_payload[0] == WirePayloadType::EncryptedMessage as u8
        {
            match EncryptedPayload::deserialize_body(&init.encrypted_payload[1..]) {
                Ok(e) => Some(e),
                Err(e) => {
                    debug!("Bad encrypted payload in SessionInit: {}", e);
                    return;
                }
            }
        } else {
            None
        };

        let Some(enc) = first_message else {
            // Nothing to authenticate the initiator with. Only accept when we
            // have no session to lose; otherwise a forged SessionInit could
            // clobber a working session.
            let mut sm = session_manager.write().await;
            if sm.has_session(&envelope.source) {
                debug!(
                    "Refusing unauthenticated SessionInit from {}: session already exists",
                    envelope.source
                );
                return;
            }
            let mut ps = prekey_state.write().await;
            let mut reject = None;
            match sm.accept_session(
                &mut ps,
                envelope.source,
                &init.identity_key,
                &init.ephemeral_public,
                init.signed_prekey_id,
                init.one_time_prekey_id,
                init_transcript,
            ) {
                Ok((safety_number, superseded)) => {
                    info!(
                        "Accepted session from {}, safety number: {}",
                        envelope.source, safety_number
                    );
                    // See the message-carrying path below: accepting clears
                    // our own unconfirmed handshake, so what it recorded is
                    // reported here (T-35).
                    for message_id in &superseded {
                        let _ = db.mark_message_failed(message_id);
                    }
                }
                Err(e) => {
                    debug!("Failed to accept session from {}: {}", envelope.source, e);
                    reject = Some(session_reject_reason(&e));
                }
            }
            // Persist prekey state (a one-time prekey may have been consumed)
            let _ = db.save_prekey_state_blob(&zeroize::Zeroizing::new(ps.to_bytes()));
            drop(ps);
            drop(sm);
            Self::persist_session_lossy(session_manager, db, &envelope.source).await;
            // Sent after the locks are released: the initiator must learn its
            // bundle is dead or it retries against it forever (T-06).
            if let Some(reason) = reject {
                Self::send_session_reject(ctx, envelope.source, reason, init_transcript).await;
            }
            return;
        };

        let ratchet_header = RatchetHeader {
            dh_public: enc.header.dh_public,
            previous_chain_length: enc.header.previous_chain_length,
            message_number: enc.header.message_number,
        };
        let ad = build_ad(envelope.source, envelope.destination, enc.content_type);

        // Simultaneous initiation: if we also just initiated a session with
        // this peer, exactly one side must give way or the two sessions end
        // up mismatched. The lower NodeId keeps its own session and only
        // decrypts the peer's first message; the peer replaces its session
        // when our SessionInit arrives.
        let keep_ours = {
            let sm = session_manager.read().await;
            sm.initiated_recently(&envelope.source, SIMULTANEOUS_INIT_WINDOW)
                && local_id.as_bytes() < envelope.source.as_bytes()
        };

        // Build the candidate session and decrypt the first message with it;
        // the session is only installed if the message authenticates.
        let plaintext = {
            let mut sm = session_manager.write().await;
            let mut ps = prekey_state.write().await;
            let result = if keep_ours {
                SessionManager::decrypt_first_message_only(
                    &mut ps,
                    envelope.source,
                    &init.identity_key,
                    &init.ephemeral_public,
                    init.signed_prekey_id,
                    init.one_time_prekey_id,
                    &ratchet_header,
                    &enc.ciphertext,
                    &ad,
                )
                .map(|pt| (String::new(), pt, Vec::new()))
            } else {
                sm.accept_session_with_first_message(
                    &mut ps,
                    envelope.source,
                    &init.identity_key,
                    &init.ephemeral_public,
                    init.signed_prekey_id,
                    init.one_time_prekey_id,
                    &ratchet_header,
                    &enc.ciphertext,
                    &ad,
                    init_transcript,
                )
            };
            // Persist prekey state (a one-time prekey may have been consumed
            // even when the session was rejected)
            let _ = db.save_prekey_state_blob(&zeroize::Zeroizing::new(ps.to_bytes()));
            match result {
                Ok((safety_number, plaintext, _)) if keep_ours => {
                    let _ = safety_number;
                    info!(
                        "Simultaneous session initiation with {}: keeping ours (lower id wins)",
                        envelope.source
                    );
                    plaintext
                }
                Ok((safety_number, plaintext, superseded)) => {
                    info!(
                        "Accepted session from {}, safety number: {}",
                        envelope.source, safety_number
                    );
                    // Messages we had sent under the session this one
                    // replaced went to a session the peer never had. They are
                    // reported here because accepting clears the handshake
                    // that recorded them — which it must, or a forged
                    // `SessionReject` would pass the unconfirmed gate and
                    // delete the session we just authenticated (T-35).
                    if !superseded.is_empty() {
                        info!(
                            "Our own handshake with {} was superseded; failing {} message(s) \
                             sent under it",
                            envelope.source,
                            superseded.len()
                        );
                        for message_id in &superseded {
                            let _ = db.mark_message_failed(message_id);
                        }
                    }
                    plaintext
                }
                Err(e) => {
                    debug!(
                        "Rejected SessionInit from {}: {} (existing session untouched)",
                        envelope.source, e
                    );
                    let reason = session_reject_reason(&e);
                    drop(ps);
                    drop(sm);
                    // A node keeping its own session under ADR-007's tie-break
                    // does not reject: the initiator is the loser and will
                    // accept *ours*, so it needs no rejection — and a decrypt
                    // failure here is also what a replayed init looks like,
                    // which would have us sign a valid rejection of an init
                    // the peer really sent.
                    if !keep_ours {
                        Self::send_session_reject(ctx, envelope.source, reason, init_transcript)
                            .await;
                    }
                    return;
                }
            }
        };

        // Persist the accepted session (unchanged when we kept ours)
        if !keep_ours {
            Self::persist_session_lossy(session_manager, db, &envelope.source).await;
        }

        // Reaching here means `build_accepted_session` verified that
        // `init.identity_key` hashes to the envelope source, so the key is
        // proven and worth recording for co-signature verification
        // (ROADMAP T-05).
        if let Err(e) = db.set_contact_identity_key(&envelope.source, &init.identity_key) {
            debug!(
                "Could not record identity key for {}: {}",
                envelope.source, e
            );
        }

        let record = MessageRecord {
            message_id: envelope.message_id,
            source: envelope.source,
            destination: local_id,
            content_type: content_type_from_byte(enc.content_type),
            plaintext,
            lamport_clock: envelope.lamport_clock,
            device_timestamp: envelope.device_timestamp,
            status: "received".to_string(),
            is_incoming: true,
        };
        debug!(
            "Received first message {} via SessionInit from {}",
            envelope.message_id, envelope.source
        );
        Self::finalize_incoming_message(record, enc.content_type, event_tx, ctx).await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_prekey_request(
        envelope: &Envelope,
        prekey_state: &RwLock<PrekeyState>,
        routing: &RwLock<RoutingCoordinator>,
        transport_manager: &TransportManager,
        _identity: &Identity,
        local_id: NodeId,
        lamport_clock: &RwLock<LamportClock>,
        db: &Database,
    ) {
        if envelope.destination != local_id {
            return;
        }

        // issue_bundle() reserves the one-time prekey so two initiators never
        // receive the same OTP (the second X3DH would fail).
        let bundle = {
            let mut ps = prekey_state.write().await;
            let b = ps.issue_bundle();
            let _ = db.save_prekey_state_blob(&zeroize::Zeroizing::new(ps.to_bytes()));
            b
        };

        let bundle_payload = PrekeyBundlePayload {
            identity_key: bundle.identity_key,
            signed_prekey: bundle.signed_prekey,
            signed_prekey_signature: bundle.signed_prekey_signature,
            signed_prekey_id: bundle.signed_prekey_id,
            one_time_prekey: bundle.one_time_prekey,
            one_time_prekey_id: bundle.one_time_prekey_id,
        };

        let clock_val = {
            let mut clock = lamport_clock.write().await;
            clock.tick()
        };

        let response_envelope = Envelope {
            source: local_id,
            destination: envelope.source,
            message_id: MessageId::random(),
            ttl: 10,
            hop_count: 0,
            flags: MessageFlags::SYSTEM,
            lamport_clock: clock_val.0,
            device_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            protocol_version: ProtocolVersion::CURRENT,
            payload: bundle_payload.serialize(),
        };

        Self::route_envelope_static(&response_envelope, routing, transport_manager).await;
        debug!("Sent prekey bundle to {}", envelope.source);
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_prekey_response(
        envelope: &Envelope,
        body: &[u8],
        prekey_cache: &RwLock<HashMap<NodeId, (PrekeyBundle, Instant)>>,
        pending_messages: &RwLock<HashMap<NodeId, Vec<PendingMessage>>>,
        session_manager: &RwLock<SessionManager>,
        transport_manager: &TransportManager,
        routing: &RwLock<RoutingCoordinator>,
        db: &Database,
        identity: &Identity,
        local_id: NodeId,
        lamport_clock: &RwLock<LamportClock>,
    ) {
        if envelope.destination != local_id {
            return;
        }

        let bundle_payload = match PrekeyBundlePayload::deserialize_body(body) {
            Ok(b) => b,
            Err(e) => {
                debug!("Bad prekey response: {}", e);
                return;
            }
        };

        let bundle = PrekeyBundle {
            identity_key: bundle_payload.identity_key,
            signed_prekey: bundle_payload.signed_prekey,
            signed_prekey_signature: bundle_payload.signed_prekey_signature,
            signed_prekey_id: bundle_payload.signed_prekey_id,
            one_time_prekey: bundle_payload.one_time_prekey,
            one_time_prekey_id: bundle_payload.one_time_prekey_id,
        };

        let peer_id = envelope.source;

        // The bundle must belong to the node that claims to have sent it:
        // NodeId is SHA-256 of the identity key, so this is a free check that
        // stops a neighbor from answering a prekey request on someone's behalf.
        if node_id_from_public_key(&bundle.identity_key) != peer_id {
            warn!(
                "Prekey response from {} carries an identity key for a different node, dropping",
                peer_id
            );
            return;
        }

        // Cache the bundle in memory and DB
        {
            let mut cache = prekey_cache.write().await;
            cache.insert(peer_id, (bundle.clone(), Instant::now()));
        }

        // The binding check above proves this key hashes to `peer_id`, so it
        // is safe to record. Emergency co-signature verification needs it
        // (ROADMAP T-05).
        if let Err(e) = db.set_contact_identity_key(&peer_id, &bundle.identity_key) {
            debug!("Could not record identity key for {}: {}", peer_id, e);
        }
        // Persist to DB (store body without type byte for consistent deserialization)
        let cache_payload = PrekeyBundlePayload {
            identity_key: bundle.identity_key,
            signed_prekey: bundle.signed_prekey,
            signed_prekey_signature: bundle.signed_prekey_signature.clone(),
            signed_prekey_id: bundle.signed_prekey_id,
            one_time_prekey: bundle.one_time_prekey,
            one_time_prekey_id: bundle.one_time_prekey_id,
        };
        // serialize() includes type byte; store body only (skip first byte)
        let serialized = cache_payload.serialize();
        let _ = db.cache_prekey_bundle(peer_id.as_bytes(), &serialized[1..]);

        // Process any pending messages for this peer
        let pending = {
            let mut pm = pending_messages.write().await;
            pm.remove(&peer_id).unwrap_or_default()
        };

        if pending.is_empty() {
            return;
        }

        // Deliberately not persisted here, matching
        // `initiate_session_and_send`: a provisional write would leave a
        // session on disk whose SessionInit never reached the peer if we die
        // or fail before transmitting. The loop below persists each ratchet
        // advance before its ciphertext leaves.

        // Send first pending message as SessionInit, rest as EncryptedMessage
        let mut queue = pending.into_iter().enumerate();
        while let Some((i, msg)) = queue.next() {
            let clock_val = {
                let mut clock = lamport_clock.write().await;
                clock.tick()
            };
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let ad = build_ad(local_id, peer_id, content_type_to_byte(msg.content_type));

            // Initiating, encrypting, building the payload and recording
            // the message against the handshake happen under one lock. Split
            // apart, a concurrent send could land in the gap: it would find a
            // session but no handshake record, so its own bookkeeping was
            // silently dropped and its message kept claiming "sent" after a
            // rejection (T-35).
            let (payload, our_handshake) = {
                let mut sm = session_manager.write().await;
                // Only initiate when there is nothing to use. A concurrent
                // send may have installed a session after this bundle was
                // cached, and initiating over it would replace the ratchet it
                // had already encrypted under (T-35).
                let init_result = if i == 0 && !sm.has_session(&peer_id) {
                    match sm.initiate_session(identity, peer_id, &bundle) {
                        Ok(r) => Some(r),
                        Err(e) => {
                            debug!("Failed to initiate session with {}: {}", peer_id, e);
                            // Keep the messages queued for the next prekey
                            // response.
                            let mut rest = vec![msg];
                            rest.extend(queue.map(|(_, m)| m));
                            drop(sm);
                            pending_messages
                                .write()
                                .await
                                .entry(peer_id)
                                .or_default()
                                .extend(rest);
                            return;
                        }
                    }
                } else {
                    None
                };
                let (header, ciphertext) = match sm.encrypt_for(&peer_id, &msg.plaintext, &ad) {
                    Ok(r) => r,
                    Err(e) => {
                        debug!("Failed to encrypt for {}: {}", peer_id, e);
                        // Requeue this and every later message instead of
                        // silently dropping them.
                        let mut rest = vec![msg];
                        rest.extend(queue.map(|(_, m)| m));
                        drop(sm);
                        pending_messages
                            .write()
                            .await
                            .entry(peer_id)
                            .or_default()
                            .extend(rest);
                        return;
                    }
                };
                let enc_payload = EncryptedPayload {
                    content_type: content_type_to_byte(msg.content_type),
                    header: WireRatchetHeader {
                        dh_public: header.dh_public,
                        previous_chain_length: header.previous_chain_length,
                        message_number: header.message_number,
                    },
                    ciphertext,
                };
                if let Some(init_result) = init_result {
                    // First message: wrap in SessionInit
                    let session_init = SessionInitPayload {
                        ephemeral_public: init_result.ephemeral_public,
                        identity_key: identity.public_key_bytes(),
                        signed_prekey_id: init_result.used_signed_prekey_id,
                        one_time_prekey_id: init_result.used_one_time_prekey_id,
                        encrypted_payload: enc_payload.serialize(),
                    };
                    let payload = session_init.serialize();
                    let transcript = mycelium_crypto::reject::init_transcript(&payload[1..]);
                    sm.mark_handshake_pending(peer_id, transcript, msg.message_id);
                    (payload, Some(transcript))
                } else {
                    sm.record_unconfirmed_message(peer_id, msg.message_id);
                    (enc_payload.serialize(), None)
                }
            };

            // The chain has advanced. Make that durable before the ciphertext
            // leaves, or a restart re-uses this chain position (T-07). On
            // failure requeue this message and every later one, exactly as the
            // encrypt-failure path above does, and leave the rest for the next
            // attempt.
            if let Err(e) = Self::persist_session(session_manager, db, &peer_id).await {
                warn!(
                    "Not sending to {}: ratchet state could not be persisted: {}",
                    peer_id, e
                );
                if let Some(transcript) = our_handshake {
                    // The SessionInit that would have carried this message has
                    // not been transmitted, so the peer knows nothing of this
                    // session. Leaving it installed would make every later
                    // send a bare EncryptedMessage it cannot decrypt.
                    //
                    // Only this call's own handshake, and only under one lock:
                    // an accepted `SessionInit` or another sender's session
                    // must not be deleted here (T-35).
                    let dead = {
                        let mut sm = session_manager.write().await;
                        match sm.remove_if_handshake(&peer_id, &transcript) {
                            Some(dead) => {
                                let _ = db.delete_session(&peer_id);
                                Some(dead)
                            }
                            None => None,
                        }
                    };
                    if let Some(dead) = dead {
                        for message_id in &dead {
                            let _ = db.mark_message_failed(message_id);
                        }
                        warn!(
                            "Discarded unsent session with {}; the handshake will be \
                             retried, {} message(s) reported failed",
                            peer_id,
                            dead.len()
                        );
                    }
                }
                // Do not requeue: `pending_messages` is drained only by an
                // incoming PrekeyResponse, and a later send would take the
                // session or cached-bundle branch, so requeued messages would
                // wait forever while the caller had been told the send was
                // accepted. A storage fault is not retryable in memory, so
                // report it.
                for stranded in std::iter::once(msg).chain(queue.map(|(_, m)| m)) {
                    let _ = db.update_message_status(&stranded.message_id, "failed");
                }
                return;
            }

            let envelope = Envelope {
                source: local_id,
                destination: peer_id,
                message_id: msg.message_id,
                ttl: 10,
                hop_count: 0,
                flags: MessageFlags::NONE,
                lamport_clock: clock_val.0,
                device_timestamp: timestamp,
                protocol_version: ProtocolVersion::CURRENT,
                payload,
            };

            let serialized = envelope.serialize();

            let decision = {
                let r = routing.read().await;
                r.route_message(&peer_id)
            };

            let sent = match decision {
                RoutingDecision::SendRealtime { next_hop } => {
                    transport_manager.send(&next_hop, &serialized).await
                }
                _ => {
                    // Direct send to peer (since they just sent us a prekey response,
                    // they should be a neighbor)
                    transport_manager.send(&peer_id, &serialized).await
                }
            };

            if let Err(e) = sent {
                // The transport refused it. Reporting "sent" here left the
                // caller believing a message had gone out, and keeping the
                // session left every later send a bare `EncryptedMessage` the
                // peer could not read, because its `SessionInit` never
                // arrived (T-35).
                warn!("Could not send {} to {}: {}", msg.message_id, peer_id, e);
                let dead = match our_handshake {
                    Some(transcript) => {
                        // One lock for memory and storage, as above.
                        let mut sm = session_manager.write().await;
                        match sm.remove_if_handshake(&peer_id, &transcript) {
                            Some(dead) => {
                                let _ = db.delete_session(&peer_id);
                                Some(dead)
                            }
                            None => None,
                        }
                    }
                    None => None,
                };
                for stranded in dead
                    .unwrap_or_default()
                    .into_iter()
                    .chain(std::iter::once(msg.message_id))
                    .chain(queue.map(|(_, m)| m.message_id))
                {
                    let _ = db.mark_message_failed(&stranded);
                }
                return;
            }
            let _ = db.mark_message_sent(&msg.message_id);
        }

        // Each message above persisted its own advance before transmitting;
        // this is a belt-and-braces write for any non-ratchet session field.
        Self::persist_session_lossy(session_manager, db, &peer_id).await;
    }

    /// Tell an initiator its `SessionInit` could not be accepted, so it stops
    /// retrying against a bundle that can never work (ROADMAP T-06).
    ///
    /// Signed over the id of the `SessionInit` being refused and both NodeIds,
    /// so the initiator can tell this apart from a forgery and cannot have it
    /// replayed against a later handshake (T-35, ADR-012).
    async fn send_session_reject(
        ctx: &SendCtx<'_>,
        peer: NodeId,
        reason: wire::SessionRejectReason,
        init_transcript: [u8; 32],
    ) {
        let signature =
            mycelium_crypto::reject::sign_reject(ctx.identity, &init_transcript, &peer, reason);
        let payload = wire::serialize_session_reject(
            reason,
            &ctx.identity.public_key_bytes(),
            &init_transcript,
            &signature,
        );
        let envelope = Envelope {
            source: ctx.local_id,
            destination: peer,
            message_id: MessageId::random(),
            ttl: 10,
            hop_count: 0,
            flags: MessageFlags::SYSTEM,
            lamport_clock: 0,
            device_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            protocol_version: ProtocolVersion::CURRENT,
            payload,
        };
        let data = envelope.serialize();

        // A SessionInit can arrive over several hops, so a direct send would
        // silently fail to reach a non-neighbour originator (round 5 finding
        // #3). Use the AODV route when there is one, and fall back to a direct
        // send. Deliberately no route discovery and no DTN: a reject is only
        // worth anything promptly, and an unauthenticated control message must
        // not be able to make us flood RREQs or consume relay storage.
        let next_hop = {
            let r = ctx.routing.read().await;
            match r.route_message(&peer) {
                RoutingDecision::SendRealtime { next_hop } => Some(next_hop),
                _ => None,
            }
        };
        let target = next_hop.unwrap_or(peer);
        if let Err(e) = ctx.transport_manager.send(&target, &data).await {
            debug!("Could not send SessionReject to {}: {}", peer, e);
        }
    }

    /// A peer refused our `SessionInit`.
    ///
    /// Our cached prekey bundle for them can never work — typically it predates
    /// a signed-prekey rotation — so drop it and let the next send re-request a
    /// fresh one (ROADMAP T-06). Without this the initiator retries against the
    /// same dead bundle forever and the conversation is silently stuck.
    ///
    /// A reject is authenticated, and three checks have to pass before it is
    /// acted on (T-35, ADR-012):
    ///
    /// - the NodeId binding, as on the other handshake ingress paths: the
    ///   claimed identity key must hash to the envelope source;
    /// - the signature, over the refused `SessionInit`'s id and both NodeIds,
    ///   against that key — which X3DH already gave us for this peer;
    /// - the refused id must be one we actually sent under a handshake this
    ///   peer has not confirmed.
    ///
    /// A forgery therefore achieves nothing, where before it could discard an
    /// unconfirmed handshake and the cached bundle with it. ADR-009 reasoned
    /// that a reject could not be authenticated because no confirmed session
    /// exists yet; the responder's identity key is what that missed.
    async fn handle_session_reject(
        envelope: &Envelope,
        body: &[u8],
        prekey_cache: &RwLock<HashMap<NodeId, (PrekeyBundle, Instant)>>,
        session_manager: &RwLock<SessionManager>,
        db: &Database,
        local_id: NodeId,
    ) {
        let (reason, identity_key, init_transcript, signature) =
            match wire::deserialize_session_reject(body) {
                Ok(v) => v,
                Err(e) => {
                    debug!("Bad SessionReject payload: {}", e);
                    return;
                }
            };

        // Same binding rule as PrekeyResponse and SessionInit: the claimed
        // identity key must hash to the envelope source.
        if node_id_from_public_key(&identity_key) != envelope.source {
            debug!(
                "Dropping SessionReject from {}: identity key does not match the source",
                envelope.source
            );
            return;
        }

        if let Err(e) = mycelium_crypto::reject::verify_reject(
            &identity_key,
            &init_transcript,
            &local_id,
            &envelope.source,
            reason,
            &signature,
        ) {
            debug!(
                "Dropping SessionReject from {}: signature did not verify ({:?})",
                envelope.source, e
            );
            return;
        }

        // Act only on a handshake the peer has not confirmed.
        //
        // "We have a session" is not evidence the peer agrees: the initiator
        // installs its session optimistically. Confirmation is the first thing
        // we successfully decrypt from them, since only their ratchet could
        // have produced it. A time window was the first attempt here and was
        // wrong both ways — it let a forged reject kill a working session
        // established seconds earlier, and ignored a legitimate reject that
        // arrived late, which DTN handshakes routinely do (round 5 findings
        // #1, #2).
        let unconfirmed_messages = {
            let mut sm = session_manager.write().await;
            if sm.handshake_transcript(&envelope.source) != Some(init_transcript) {
                // Either there is no unconfirmed handshake with this peer, or
                // the reject names a `SessionInit` we did not send — a
                // captured reject replayed at a later handshake, or a genuine
                // rejection of an init an attacker fabricated under our name.
                None
            } else {
                // Take the message ids *first*: `remove_session` also clears
                // the unconfirmed-handshake entry, so taking them afterwards
                // always yielded an empty list and nothing was ever reported
                // failed.
                let dead = sm.take_unconfirmed_messages(&envelope.source);
                sm.remove_session(&envelope.source);
                Some(dead)
            }
        };

        let Some(dead_messages) = unconfirmed_messages else {
            debug!(
                "Ignoring SessionReject from {}: no unconfirmed handshake with that peer",
                envelope.source
            );
            return;
        };

        let _ = db.delete_session(&envelope.source);

        // Drop the bundle from memory *and* storage: a restart would otherwise
        // reload the stale entry and undo the recovery (round 5 finding #5).
        let dropped = prekey_cache
            .write()
            .await
            .remove(&envelope.source)
            .is_some();
        let _ = db.remove_cached_prekey_bundle(envelope.source.as_bytes());

        // The messages sent under this handshake were never delivered: the
        // peer discarded the SessionInit, and nothing was ever decrypted from
        // them, so no receipt can have arrived. Report them rather than
        // leaving rows that claim "sent" (round 5 finding #6).
        for message_id in &dead_messages {
            let _ = db.mark_message_failed(message_id);
        }

        info!(
            "Peer {} refused our SessionInit ({:?}); discarded the unconfirmed session, \
             {} cached bundle and failed {} message(s)",
            envelope.source,
            reason,
            if dropped { "the" } else { "no" },
            dead_messages.len()
        );
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_dtn_relay(
        envelope: &Envelope,
        body: &[u8],
        routing: &RwLock<RoutingCoordinator>,
        session_manager: &RwLock<SessionManager>,
        prekey_state: &RwLock<PrekeyState>,
        rate_limiter: &RwLock<RateLimiter>,
        trust_graph: &RwLock<TrustGraph>,
        transport_manager: &TransportManager,
        db: &Database,
        local_id: NodeId,
        _lamport_clock: &RwLock<LamportClock>,
        event_tx: &tokio::sync::broadcast::Sender<NodeEvent>,
        ctx: &SendCtx<'_>,
    ) {
        let relay = match wire::deserialize_dtn_relay(body) {
            Ok(v) => v,
            Err(e) => {
                debug!("Bad DTN relay payload: {}", e);
                return;
            }
        };
        let msg_id = relay.message_id;
        let payload = relay.payload;

        if envelope.destination == local_id {
            // We are the final destination — deliver locally.
            // The payload is the original serialized Envelope; deserialize it
            // to recover the inner encrypted payload and original metadata.
            debug!("DTN relay delivered locally: {}", msg_id);

            // Several copies of the same bundle may reach us; only the first
            // touches the ratchet. Re-send the receipt so the carrier learns
            // the bundle is delivered.
            if db.get_message(&msg_id).is_ok() {
                debug!(
                    "DTN bundle {} already delivered, re-sending receipt",
                    msg_id
                );
                Self::send_delivery_receipt(
                    msg_id,
                    envelope.source,
                    local_id,
                    transport_manager,
                    routing,
                )
                .await;
                return;
            }

            let inner_envelope = match Envelope::deserialize(&payload) {
                Ok(e) => e,
                Err(e) => {
                    debug!("DTN: failed to deserialize inner envelope: {}", e);
                    return;
                }
            };

            let inner = &inner_envelope.payload;
            if inner.is_empty() {
                return;
            }

            let payload_type = inner[0];
            let inner_body = &inner[1..];

            if payload_type == WirePayloadType::EncryptedMessage as u8 {
                let enc = match EncryptedPayload::deserialize_body(inner_body) {
                    Ok(e) => e,
                    Err(_) => return,
                };

                let ratchet_header = RatchetHeader {
                    dh_public: enc.header.dh_public,
                    previous_chain_length: enc.header.previous_chain_length,
                    message_number: enc.header.message_number,
                };

                let ad = build_ad(inner_envelope.source, local_id, enc.content_type);
                let plaintext = {
                    let mut sm = session_manager.write().await;
                    match sm.decrypt_from(
                        &inner_envelope.source,
                        &ratchet_header,
                        &enc.ciphertext,
                        &ad,
                    ) {
                        Ok(pt) => pt,
                        Err(e) => {
                            debug!("DTN decrypt failed: {}", e);
                            return;
                        }
                    }
                };

                // Persist session after ratchet state advance
                Self::persist_session_lossy(session_manager, db, &inner_envelope.source).await;

                let record = MessageRecord {
                    message_id: msg_id,
                    source: inner_envelope.source,
                    destination: local_id,
                    content_type: content_type_from_byte(enc.content_type),
                    plaintext,
                    lamport_clock: inner_envelope.lamport_clock,
                    device_timestamp: inner_envelope.device_timestamp,
                    status: "received".to_string(),
                    is_incoming: true,
                };
                Self::finalize_incoming_message(record, enc.content_type, event_tx, ctx).await;
            } else if payload_type == WirePayloadType::SessionInit as u8 {
                // DTN-delivered SessionInit: create session and decrypt first message
                debug!("DTN: processing SessionInit from {}", inner_envelope.source);
                Self::handle_session_init(
                    &inner_envelope,
                    inner_body,
                    session_manager,
                    prekey_state,
                    db,
                    local_id,
                    _lamport_clock,
                    event_tx,
                    ctx,
                )
                .await;
            }
        } else {
            // Check DTN relay quota before storing
            let relay_size = body.len();
            {
                let trust_hops = {
                    let tg = trust_graph.read().await;
                    let score = tg.trust_score(&local_id, &envelope.source);
                    if score.value > 0.0 {
                        score.hops
                    } else {
                        u8::MAX
                    }
                };
                let mut rl = rate_limiter.write().await;
                if !rl.check_dtn_relay(&envelope.source, trust_hops, relay_size) {
                    debug!(
                        "DTN relay quota exceeded for source {} (trust_hops={}), dropping relay",
                        envelope.source, trust_hops
                    );
                    return;
                }
            }

            // Store as relay with the copies the spraying node handed us and
            // the remaining lifetime it reported (bounded to the spec maximum
            // so a peer cannot pin a bundle in our storage forever).
            let ttl = Duration::from_secs(u64::from(relay.ttl_secs).min(72 * 3600));
            let mut r = routing.write().await;
            let bundle = DtnBundle {
                message_id: msg_id,
                destination: envelope.destination,
                source: envelope.source,
                payload,
                copies_remaining: relay.copies_remaining.max(1),
                expires_at: Instant::now() + ttl,
                created_at: Instant::now(),
                size: relay_size,
                is_local: false,
            };
            // Only persist when the engine actually took a new bundle. A
            // duplicate returns Ok without inserting, and re-persisting would
            // overwrite the spray history of the copy we already hold with an
            // empty list, so after a restart we would spray those peers again.
            let already_held = r.dtn().get_bundle(&msg_id).is_some();
            if r.dtn_mut().store_relay(bundle).is_ok() && !already_held {
                if let Some(b) = r.dtn().get_bundle(&msg_id) {
                    persist_dtn_bundle(db, b);
                }
            }
            debug!("Stored DTN relay for {}", envelope.destination);
        }
    }

    async fn handle_dtn_local_delivery(
        bundle: &DtnBundle,
        event_tx: &tokio::sync::broadcast::Sender<NodeEvent>,
        ctx: &SendCtx<'_>,
    ) {
        let session_manager = ctx.session_manager;
        let db = ctx.db;
        let local_id = ctx.local_id;
        if db.get_message(&bundle.message_id).is_ok() {
            debug!("DTN bundle {} already delivered", bundle.message_id);
            return;
        }

        // The bundle payload is the full serialized Envelope; deserialize it
        // to recover the inner encrypted payload and original metadata.
        let inner_envelope = match Envelope::deserialize(&bundle.payload) {
            Ok(e) => e,
            Err(e) => {
                debug!(
                    "DTN local delivery: failed to deserialize inner envelope: {}",
                    e
                );
                return;
            }
        };

        let inner = &inner_envelope.payload;
        if inner.is_empty() {
            return;
        }

        let payload_type = inner[0];
        let inner_body = &inner[1..];

        if payload_type == WirePayloadType::EncryptedMessage as u8 {
            let enc = match EncryptedPayload::deserialize_body(inner_body) {
                Ok(e) => e,
                Err(_) => return,
            };

            let ratchet_header = RatchetHeader {
                dh_public: enc.header.dh_public,
                previous_chain_length: enc.header.previous_chain_length,
                message_number: enc.header.message_number,
            };

            let ad = build_ad(inner_envelope.source, local_id, enc.content_type);
            let plaintext = {
                let mut sm = session_manager.write().await;
                match sm.decrypt_from(
                    &inner_envelope.source,
                    &ratchet_header,
                    &enc.ciphertext,
                    &ad,
                ) {
                    Ok(pt) => pt,
                    Err(e) => {
                        debug!("DTN local delivery decrypt failed: {}", e);
                        return;
                    }
                }
            };

            // Persist session after ratchet state advance
            Self::persist_session_lossy(session_manager, db, &inner_envelope.source).await;

            let record = MessageRecord {
                message_id: bundle.message_id,
                source: inner_envelope.source,
                destination: local_id,
                content_type: content_type_from_byte(enc.content_type),
                plaintext,
                lamport_clock: inner_envelope.lamport_clock,
                device_timestamp: inner_envelope.device_timestamp,
                status: "received".to_string(),
                is_incoming: true,
            };
            Self::finalize_incoming_message(record, enc.content_type, event_tx, ctx).await;
        }
    }

    // --- Session persistence ---

    /// Write the peer's ratchet state to storage.
    ///
    /// The caller must not transmit a ciphertext whose ratchet advance this
    /// call failed to persist: the chain has already moved forward in memory,
    /// so a restart would reload the old position and re-use an AES-GCM nonce
    /// under the same key. Outgoing paths therefore propagate the error and
    /// drop the send; receive paths only log, because their state advance is
    /// idempotent on replay and failing them would discard a decrypted
    /// message.
    async fn persist_session(
        session_manager: &RwLock<SessionManager>,
        db: &Database,
        peer_id: &NodeId,
    ) -> Result<(), StorageError> {
        let sm = session_manager.read().await;
        for (nid, session) in sm.all_sessions() {
            if nid == peer_id {
                // The serialized blob carries the root key and both chain
                // keys in the clear. Wipe our copy once SQLCipher has it.
                let mut record = SessionRecord {
                    peer_id: *nid,
                    session_data: SessionManager::serialize_session(session),
                    safety_number: Some(session.safety_number.clone()),
                    is_verified: session.is_verified,
                };
                let saved = db.save_session(&record);
                record.session_data.zeroize();
                saved?;
                break;
            }
        }
        Ok(())
    }

    /// Write a group's state blob, wiping our copy once SQLCipher has it.
    ///
    /// The blob carries our sender chain key and every member's chain key in
    /// the clear (ROADMAP T-07 key hygiene).
    fn persist_group_blob(
        db: &Database,
        group_id: &[u8; 32],
        group: &SenderKeyGroup,
    ) -> Result<(), StorageError> {
        let mut blob = zeroize::Zeroizing::new(group.to_bytes());
        let result = db.save_group_blob(group_id, &blob);
        blob.zeroize();
        result
    }

    /// Drop a session that was created for an outgoing handshake we never
    /// managed to send, from memory and from storage. Leaving it installed
    /// would make every later send use a ratchet the peer knows nothing about.
    async fn discard_unsent_session(ctx: &SendCtx<'_>, destination: &NodeId) {
        {
            // Memory and storage under one lock, so a replacement installed
            // by another sender cannot have its row deleted by this cleanup.
            let mut sm = ctx.session_manager.write().await;
            sm.remove_session(destination);
            let _ = ctx.db.delete_session(destination);
        }
        warn!(
            "Discarded unsent session with {}; the handshake will be retried",
            destination
        );
    }

    /// Discard a session this send created, unless it is no longer the one
    /// outstanding.
    ///
    /// An authenticated `SessionInit` accepted while the transport write was
    /// in flight replaces our session and clears our handshake record, so
    /// "we initiated" stops being true: tearing down on a late failure would
    /// delete the peer's live replacement (T-35). The outstanding transcript
    /// is the evidence — `install_accepted` is what clears it.
    async fn discard_if_still_ours(ctx: &SendCtx<'_>, destination: &NodeId, transcript: [u8; 32]) {
        // The stored row is deleted under the *same* lock. Released first,
        // another sender could install and persist a replacement in the gap
        // and have its durable state deleted by this cleanup (T-35).
        let dead = {
            let mut sm = ctx.session_manager.write().await;
            match sm.remove_if_handshake(destination, &transcript) {
                Some(dead) => {
                    let _ = ctx.db.delete_session(destination);
                    Some(dead)
                }
                None => None,
            }
        };
        let Some(dead) = dead else {
            debug!(
                "Not discarding the session with {}: it is no longer the handshake \
                 this send created",
                destination
            );
            return;
        };
        // Messages a concurrent send had already queued under this handshake
        // die with it: their ciphertext belongs to a ratchet that is gone.
        for message_id in &dead {
            let _ = ctx.db.mark_message_failed(message_id);
        }
        warn!(
            "Discarded unsent session with {}; the handshake will be retried, \
             {} message(s) reported failed",
            destination,
            dead.len()
        );
    }

    /// `persist_session` for the receive path: log and carry on.
    async fn persist_session_lossy(
        session_manager: &RwLock<SessionManager>,
        db: &Database,
        peer_id: &NodeId,
    ) {
        if let Err(e) = Self::persist_session(session_manager, db, peer_id).await {
            warn!("Failed to persist session with {}: {}", peer_id, e);
        }
    }

    // --- Group message handlers ---

    async fn handle_group_message(
        envelope: &Envelope,
        body: &[u8],
        groups: &RwLock<HashMap<[u8; 32], SenderKeyGroup>>,
        db: &Database,
        local_id: NodeId,
    ) {
        if envelope.destination != local_id {
            debug!("Group message not for us, ignoring");
            return;
        }

        let (group_id, iteration, content_type, ciphertext) =
            match wire::deserialize_group_message(body) {
                Ok(v) => v,
                Err(e) => {
                    debug!("Bad group message: {}", e);
                    return;
                }
            };

        let plaintext = {
            let mut grps = groups.write().await;
            let group = match grps.get_mut(&group_id) {
                Some(g) => g,
                None => {
                    debug!("Received group message for unknown group");
                    return;
                }
            };

            let group_msg = mycelium_crypto::group::GroupMessage {
                group_id,
                iteration,
                ciphertext,
            };

            match group.decrypt(&envelope.source, &group_msg) {
                Ok(pt) => {
                    // Persist group state after sender key advance
                    let _ = Self::persist_group_blob(db, &group_id, group);
                    pt
                }
                Err(e) => {
                    debug!("Failed to decrypt group message: {}", e);
                    return;
                }
            }
        };

        let record = MessageRecord {
            message_id: envelope.message_id,
            source: envelope.source,
            destination: NodeId::from_bytes(group_id), // group_id as destination
            content_type: content_type_from_byte(content_type),
            plaintext,
            lamport_clock: envelope.lamport_clock,
            device_timestamp: envelope.device_timestamp,
            status: "received".to_string(),
            is_incoming: true,
        };
        let _ = db.insert_message(&record);
        debug!(
            "Received group message {} from {} in group {:?}",
            envelope.message_id,
            envelope.source,
            &group_id[..4]
        );
    }

    // --- Beacon handler ---

    #[allow(clippy::too_many_arguments)]
    async fn handle_beacon(
        envelope: &Envelope,
        peer: NodeId,
        body: &[u8],
        db: &Database,
        lamport_clock: &RwLock<LamportClock>,
        trust_graph: &RwLock<TrustGraph>,
        routing: &RwLock<RoutingCoordinator>,
        local_id: NodeId,
        local_group_hash: Option<[u8; 8]>,
        local_identity_key: [u8; 32],
    ) {
        if envelope.source == local_id {
            return; // Ignore our own beacons
        }

        let beacon = match crate::beacon::Beacon::deserialize(body) {
            Some(b) => b,
            None => {
                debug!("Bad beacon from {}", envelope.source);
                return;
            }
        };

        // The beacon body names its node. It must be the node we actually
        // heard it from; otherwise any neighbor could rename other contacts,
        // register arbitrary nodes as supernodes or redirect the auto-vouch.
        if beacon.node_id != peer || envelope.source != peer {
            debug!(
                "Beacon from {} claims node_id {} (envelope source {}), dropping",
                peer, beacon.node_id, envelope.source
            );
            return;
        }

        debug!(
            "Beacon from {} ({}): battery={}, neighbors={}",
            beacon.display_name, beacon.node_id, beacon.battery_level, beacon.neighbor_count
        );

        // Merge lamport clock from beacon
        {
            let mut clock = lamport_clock.write().await;
            clock.merge(LamportClock(beacon.lamport_clock));
        }

        // Register supernodes for route preference
        if beacon.node_type == NodeType::Supernode {
            let mut r = routing.write().await;
            r.aodv_mut().register_supernode(beacon.node_id);
            debug!("Registered supernode: {}", beacon.node_id);
        }

        // Create or update contact from beacon
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        use mycelium_storage::contacts::ContactRecord;
        let contact = match db.get_contact(&beacon.node_id) {
            Ok(mut existing) => {
                // Update last_seen and display name
                existing.last_seen = Some(now_secs);
                if !beacon.display_name.is_empty() {
                    existing.display_name = beacon.display_name.clone();
                }
                existing
            }
            Err(_) => {
                // Auto-create contact from beacon
                ContactRecord {
                    node_id: beacon.node_id,
                    display_name: beacon.display_name.clone(),
                    // A beacon carries no identity key, only the NodeId, so
                    // we do not know one yet. Empty, not the NodeId: storing
                    // the id here is what made emergency co-signature
                    // verification impossible (ROADMAP T-05). The key is
                    // filled in by the ingress paths that verify it.
                    public_key: Vec::new(),
                    trust_score: 0.0,
                    is_verified: false,
                    last_seen: Some(now_secs),
                }
            }
        };

        let _ = db.save_contact(&contact);

        // Auto-trust peers with matching group discovery hash
        if let (Some(local_hash), Some(peer_hash)) = (local_group_hash, beacon.group_discovery_hash)
        {
            if local_hash == peer_hash {
                info!(
                    "Group discovery match with {} — auto-vouching",
                    beacon.node_id
                );
                let mut tg = trust_graph.write().await;
                tg.add_vouch(local_id, beacon.node_id);
                let vouch = mycelium_storage::vouches::VouchRecord {
                    voucher_id: local_id,
                    vouchee_id: beacon.node_id,
                    voucher_public_key: local_identity_key.to_vec(),
                    display_name: beacon.display_name.clone(),
                    signature: Vec::new(), // Auto-vouch, no cryptographic sig
                    timestamp: now_secs,
                };
                let _ = db.save_vouch(&vouch);
            }
        }
    }

    // --- Channel message handler ---

    /// Handle an incoming channel message: dedup, store if subscribed, flood to peers.
    #[allow(clippy::too_many_arguments)]
    async fn handle_channel_message(
        envelope: &Envelope,
        peer: NodeId,
        body: &[u8],
        db: &Database,
        transport_manager: &TransportManager,
        local_id: NodeId,
        seen: &RwLock<HashSet<MessageId>>,
        event_tx: &tokio::sync::broadcast::Sender<NodeEvent>,
    ) {
        let (channel_id, content_type, data) = match wire::deserialize_channel_message(body) {
            Ok(v) => v,
            Err(e) => {
                debug!("Bad channel message: {}", e);
                return;
            }
        };

        // Dedup: skip if we've already seen this message_id
        {
            let mut seen_set = seen.write().await;
            if !seen_set.insert(envelope.message_id) {
                debug!(
                    "Duplicate channel message {}, skipping",
                    envelope.message_id
                );
                return;
            }
            // Cap the dedup set to prevent unbounded growth
            if seen_set.len() > 10_000 {
                seen_set.clear();
            }
        }

        // Store if we're subscribed to this channel
        if db.is_subscribed(&channel_id).unwrap_or(false) {
            let msg_id = *envelope.message_id.as_bytes();
            let timestamp = if envelope.device_timestamp > 0 {
                envelope.device_timestamp
            } else {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            };
            let _ = db.store_channel_message(
                &msg_id,
                &channel_id,
                &envelope.source,
                &data,
                content_type,
                timestamp,
            );

            // Notify WebSocket clients
            let _ = event_tx.send(NodeEvent::MessageReceived {
                source: envelope.source,
                message_id: envelope.message_id,
                data,
                content_type,
                timestamp,
            });
        }

        // Flood to all connected peers except the originator and the hop
        // that just delivered it to us.
        if envelope.ttl > 0 {
            let mut fwd = envelope.clone();
            fwd.forward();
            let fwd_data = fwd.serialize();
            let peers = transport_manager.known_peers().await;
            for p in peers {
                if p != envelope.source && p != local_id && p != peer {
                    let _ = transport_manager.send(&p, &fwd_data).await;
                }
            }
        }
    }

    // --- Emergency broadcast handler ---

    #[allow(clippy::too_many_arguments)]
    async fn handle_emergency_broadcast(
        envelope: &Envelope,
        peer: NodeId,
        body: &[u8],
        trust_graph: &RwLock<TrustGraph>,
        transport_manager: &TransportManager,
        local_id: NodeId,
        seen: &RwLock<HashSet<MessageId>>,
        event_tx: &tokio::sync::broadcast::Sender<NodeEvent>,
        db: &Database,
    ) {
        let (level, message_bytes, cosigners) = match wire::deserialize_emergency_broadcast(body) {
            Ok(v) => v,
            Err(e) => {
                debug!("Bad emergency broadcast: {}", e);
                return;
            }
        };

        // Dedup
        {
            let mut seen_set = seen.write().await;
            if !seen_set.insert(envelope.message_id) {
                debug!(
                    "Duplicate emergency broadcast {}, skipping",
                    envelope.message_id
                );
                return;
            }
            if seen_set.len() > 10_000 {
                seen_set.clear();
            }
        }

        // Trust threshold checks
        let tg = trust_graph.read().await;
        let sender_trust = tg.trust_score(&local_id, &envelope.source).value;

        // Thresholds per spec §9.5: Priority > 0.3, Urgent > 0.6, Critical
        // needs 3+ co-signers above 0.8 whose signatures verify (ADR-010).
        let accepted = match level {
            wire::EmergencyLevel::Priority => sender_trust > 0.3,
            wire::EmergencyLevel::Urgent => sender_trust > 0.6,
            wire::EmergencyLevel::Critical => {
                if cosigners.len() < 3 {
                    debug!(
                        "Critical emergency from {} rejected: only {} cosigners (need 3+)",
                        envelope.source,
                        cosigners.len()
                    );
                    false
                } else {
                    // A co-signature counts only when it verifies against a
                    // key we hold for that id *and* the id is trusted above
                    // 0.8. Bare ids prove nothing: anyone can list three
                    // trusted NodeIds they do not control.
                    let mut seen: Vec<NodeId> = Vec::with_capacity(cosigners.len());
                    let mut valid = 0usize;
                    for cs in &cosigners {
                        if seen.contains(&cs.node_id) {
                            debug!("Duplicate emergency co-signer {}", cs.node_id);
                            continue;
                        }
                        seen.push(cs.node_id);

                        let key = db.get_contact_identity_key(&cs.node_id);
                        if let Err(reason) = mycelium_crypto::emergency::verify_cosigner(
                            cs,
                            key,
                            &envelope.message_id,
                            &envelope.source,
                            level,
                            &message_bytes,
                        ) {
                            debug!(
                                "Emergency co-signature from {} not counted: {:?}",
                                cs.node_id, reason
                            );
                            continue;
                        }
                        if tg.trust_score(&local_id, &cs.node_id).value <= 0.8 {
                            debug!(
                                "Emergency co-signer {} verified but not trusted above 0.8",
                                cs.node_id
                            );
                            continue;
                        }
                        valid += 1;
                    }
                    if valid < 3 {
                        debug!(
                            "Critical emergency from {} rejected: {} of {} co-signatures valid \
                             and trusted (need 3)",
                            envelope.source,
                            valid,
                            cosigners.len()
                        );
                    }
                    valid >= 3
                }
            }
        };
        drop(tg);

        if !accepted {
            debug!(
                "Emergency broadcast from {} rejected: level={:?}, sender_trust={:.2}",
                envelope.source, level, sender_trust
            );
            return;
        }

        let message_text = String::from_utf8_lossy(&message_bytes).to_string();
        info!(
            "Emergency broadcast accepted: level={:?}, from={}, msg={}",
            level, envelope.source, message_text
        );

        // Notify via event
        let _ = event_tx.send(NodeEvent::EmergencyBroadcast {
            source: envelope.source,
            level: level as u8,
            message: message_text,
        });

        // Flood to all peers (bypass AODV routing for all emergency levels),
        // never back to the hop it came from.
        if envelope.ttl > 0 {
            let mut fwd = envelope.clone();
            fwd.forward();
            let fwd_data = fwd.serialize();
            let peers = transport_manager.known_peers().await;
            for p in peers {
                if p != envelope.source && p != local_id && p != peer {
                    let _ = transport_manager.send(&p, &fwd_data).await;
                }
            }
        }
    }

    // --- Receipt handler ---

    fn handle_receipt(
        envelope: &Envelope,
        body: &[u8],
        db: &Database,
        local_id: NodeId,
        event_tx: &tokio::sync::broadcast::Sender<NodeEvent>,
    ) {
        debug!(
            "handle_receipt: from={}, msg_id={}, body_len={}",
            envelope.source,
            envelope.message_id,
            body.len()
        );
        if envelope.destination != local_id {
            info!(
                "Receipt not for us (dest={}), ignoring",
                envelope.destination
            );
            return;
        }

        let (msg_id, receipt_type) = match wire::deserialize_receipt(body) {
            Ok(v) => v,
            Err(e) => {
                info!("Bad receipt from {}: {}", envelope.source, e);
                return;
            }
        };

        let new_status = match receipt_type {
            ReceiptType::Delivered => "delivered",
            ReceiptType::Read => "read",
        };

        // Receipts are unauthenticated: accept one only from the node we sent
        // that message to, and never for messages we received ourselves
        // (otherwise a peer could mark our unread messages as read).
        match db.get_message(&msg_id) {
            Ok(msg) if !msg.is_incoming && msg.destination == envelope.source => {}
            Ok(_) => {
                debug!(
                    "Receipt from {} for message {} it is not the recipient of, ignoring",
                    envelope.source, msg_id
                );
                return;
            }
            Err(_) => {
                debug!(
                    "Receipt from {} for unknown message {}, ignoring",
                    envelope.source, msg_id
                );
                return;
            }
        }

        match db.update_message_status(&msg_id, new_status) {
            Ok(()) => {
                info!(
                    "Receipt: message {} marked as {} (from {})",
                    msg_id, new_status, envelope.source
                );
                let _ = event_tx.send(NodeEvent::ReceiptUpdated {
                    message_id: msg_id,
                    status: new_status.to_string(),
                });
            }
            Err(e) => info!(
                "Receipt: failed to update message {} to {}: {}",
                msg_id, new_status, e
            ),
        }
    }

    /// Send a delivery receipt back to the sender.
    async fn send_delivery_receipt(
        message_id: MessageId,
        to: NodeId,
        local_id: NodeId,
        transport_manager: &TransportManager,
        routing: &RwLock<RoutingCoordinator>,
    ) {
        debug!("send_delivery_receipt: msg_id={}, to={}", message_id, to);
        let payload = wire::serialize_receipt(&message_id, ReceiptType::Delivered);
        let envelope = Envelope {
            source: local_id,
            destination: to,
            message_id: MessageId::random(),
            ttl: 10,
            hop_count: 0,
            flags: MessageFlags::SYSTEM,
            lamport_clock: 0,
            device_timestamp: 0,
            protocol_version: ProtocolVersion::CURRENT,
            payload,
        };

        let decision = {
            let r = routing.read().await;
            r.route_message(&to)
        };

        match decision {
            RoutingDecision::SendRealtime { next_hop } => {
                let data = envelope.serialize();
                let _ = transport_manager.send(&next_hop, &data).await;
                info!(
                    "Delivery receipt for {} sent to {} via {}",
                    message_id, to, next_hop
                );
            }
            _ => {
                info!(
                    "Delivery receipt for {} to {} dropped (no route)",
                    message_id, to
                );
            }
        }
    }

    /// Mark messages from a peer as read and send read receipts.
    pub async fn mark_read_and_notify(&self, peer: NodeId) -> usize {
        let msg_ids = match self
            .db
            .mark_messages_read_returning_ids(&self.node_id, &peer)
        {
            Ok(ids) => ids,
            Err(e) => {
                info!("Failed to mark messages as read: {}", e);
                return 0;
            }
        };

        let count = msg_ids.len();
        for msg_id in msg_ids {
            Self::send_read_receipt(
                msg_id,
                peer,
                self.node_id,
                &self.transport_manager,
                &self.routing,
            )
            .await;
        }
        count
    }

    /// Send a read receipt for a specific message.
    async fn send_read_receipt(
        message_id: MessageId,
        to: NodeId,
        local_id: NodeId,
        transport_manager: &TransportManager,
        routing: &RwLock<RoutingCoordinator>,
    ) {
        debug!("send_read_receipt: msg_id={}, to={}", message_id, to);
        let payload = wire::serialize_receipt(&message_id, ReceiptType::Read);
        let envelope = Envelope {
            source: local_id,
            destination: to,
            message_id: MessageId::random(),
            ttl: 10,
            hop_count: 0,
            flags: MessageFlags::SYSTEM,
            lamport_clock: 0,
            device_timestamp: 0,
            protocol_version: ProtocolVersion::CURRENT,
            payload,
        };

        let decision = {
            let r = routing.read().await;
            r.route_message(&to)
        };

        match decision {
            RoutingDecision::SendRealtime { next_hop } => {
                let data = envelope.serialize();
                let _ = transport_manager.send(&next_hop, &data).await;
                info!(
                    "Read receipt for {} sent to {} via {}",
                    message_id, to, next_hop
                );
            }
            _ => {
                info!(
                    "Read receipt for {} to {} dropped (no route)",
                    message_id, to
                );
            }
        }
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Count of pending messages waiting for session establishment.
    pub async fn pending_messages_count(&self) -> usize {
        let pm = self.pending_messages.read().await;
        pm.values().map(|v| v.len()).sum()
    }

    /// Count of pending route discoveries.
    pub async fn pending_routes_count(&self) -> usize {
        let pr = self.pending_routes.read().await;
        pr.values().map(|d| d.envelopes.len()).sum()
    }

    /// Destinations with pending messages (awaiting session).
    pub async fn pending_message_destinations(&self) -> Vec<NodeId> {
        let pm = self.pending_messages.read().await;
        pm.keys().copied().collect()
    }

    /// Destinations with pending route discoveries.
    pub async fn pending_route_destinations(&self) -> Vec<NodeId> {
        let pr = self.pending_routes.read().await;
        pr.keys().copied().collect()
    }
}

// --- Helpers ---

/// Persist a DtnBundle to the database.
fn persist_dtn_bundle(db: &Database, bundle: &DtnBundle) {
    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Convert Instant-based expires_at to epoch seconds
    let remaining = bundle.expires_at.saturating_duration_since(Instant::now());
    let expires_epoch = now_epoch + remaining.as_secs();

    let record = DtnBundleRecord {
        message_id: bundle.message_id,
        destination: bundle.destination,
        source: bundle.source,
        payload: bundle.payload.clone(),
        copies_remaining: bundle.copies_remaining,
        expires_at: expires_epoch,
        size: bundle.size,
        is_local: bundle.is_local,
        // A bundle is persisted when it is first stored, before any spray.
        // Later sprays are recorded with `update_dtn_sprayed_to`.
        sprayed_to: Vec::new(),
    };
    let _ = db.store_dtn_bundle(&record);
}

/// Translate a session-accept failure into the reason put on the wire.
///
/// Deliberately coarse: the initiator only needs to know its bundle is dead,
/// and a finer breakdown would tell an attacker which prekeys we still hold.
fn session_reject_reason(e: &SessionError) -> wire::SessionRejectReason {
    match e {
        SessionError::X3dh(X3dhError::SignedPrekeyNotFound) => {
            wire::SessionRejectReason::StaleSignedPrekey
        }
        SessionError::X3dh(X3dhError::OneTimePrekeyNotFound) => {
            wire::SessionRejectReason::UnknownOneTimePrekey
        }
        _ => wire::SessionRejectReason::DecryptFailed,
    }
}

/// Build associated data for Double Ratchet from source + destination NodeIds.
/// The AEAD associated data for a pairwise message.
///
/// `content_type` is in here because it travels in the clear beside the
/// ciphertext. Unauthenticated, a relay could retype any message — text into
/// a GPS pin, say — and, because the altered copy still decrypted, it could
/// also be used to mint a second identity for the same `SessionInit`: accept
/// the retyped copy, then replay the original past the replay check and
/// collect a valid rejection of it (T-35, ADR-012).
fn build_ad(source: NodeId, destination: NodeId, content_type: u8) -> Vec<u8> {
    let mut ad = Vec::with_capacity(65);
    ad.extend_from_slice(source.as_bytes());
    ad.extend_from_slice(destination.as_bytes());
    ad.push(content_type);
    ad
}

#[allow(dead_code)]
fn content_type_str(ct: ContentType) -> String {
    match ct {
        ContentType::Text => "text".to_string(),
        ContentType::Image => "image".to_string(),
        ContentType::File => "file".to_string(),
        ContentType::GpsPin => "gps_pin".to_string(),
        ContentType::VoiceNote => "voice_note".to_string(),
        ContentType::Receipt => "receipt".to_string(),
        ContentType::System => "system".to_string(),
    }
}

fn content_type_to_byte(ct: ContentType) -> u8 {
    match ct {
        ContentType::Text => 0,
        ContentType::Image => 1,
        ContentType::File => 2,
        ContentType::GpsPin => 3,
        ContentType::VoiceNote => 4,
        ContentType::Receipt => 5,
        ContentType::System => 6,
    }
}

fn content_type_from_byte(b: u8) -> String {
    match b {
        0 => "text".to_string(),
        1 => "image".to_string(),
        2 => "file".to_string(),
        3 => "gps_pin".to_string(),
        4 => "voice_note".to_string(),
        5 => "receipt".to_string(),
        6 => "system".to_string(),
        _ => "unknown".to_string(),
    }
}

fn serialize_aodv_message(msg: &AodvMessage) -> Vec<u8> {
    match msg {
        AodvMessage::RouteRequest(rreq) => wire::serialize_aodv_rreq(
            rreq.request_id,
            &rreq.source,
            rreq.source_seq,
            &rreq.destination,
            rreq.dest_seq,
            rreq.hop_count,
            rreq.ttl,
        ),
        AodvMessage::RouteReply(rrep) => wire::serialize_aodv_rrep(
            rrep.request_id,
            &rrep.source,
            &rrep.destination,
            rrep.dest_seq,
            rrep.hop_count,
            rrep.lifetime_secs,
        ),
        AodvMessage::RouteError(rerr) => {
            wire::serialize_aodv_rerr(&rerr.unreachable, &rerr.source, rerr.dest_seq)
        }
    }
}

/// Helper to create a separate Identity for PrekeyState.
/// (Identity doesn't implement Clone, so we re-derive from bytes.)
fn identity_clone_for_prekeys(identity: &Identity) -> Identity {
    let bytes = identity.to_bytes();
    Identity::from_bytes(&bytes).expect("identity roundtrip failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The content type is inside the associated data, so retyping a message
    /// in flight breaks its decryption (T-35, ADR-012).
    ///
    /// It travels in the clear beside the ciphertext, so without this a relay
    /// could turn a text message into a GPS pin — and, because the altered
    /// copy would still decrypt, it could mint a second identity for the same
    /// `SessionInit` and replay the original past the replay check.
    ///
    /// `double_ratchet::tests::test_ratchet_wrong_ad_fails` is the other half:
    /// a different AD does not decrypt. The end-to-end path is not covered by
    /// an integration test, because the harness cannot replay the exact bytes
    /// a node put on the wire.
    #[test]
    fn test_the_associated_data_covers_the_content_type() {
        let a = NodeId::from_bytes([1u8; 32]);
        let b = NodeId::from_bytes([2u8; 32]);

        let text = build_ad(a, b, content_type_to_byte(ContentType::Text));
        let pin = build_ad(a, b, content_type_to_byte(ContentType::GpsPin));
        assert_ne!(
            text, pin,
            "a retyped message must not share associated data with the original"
        );
        assert_eq!(text.len(), 65, "source, destination, content type");
        assert_eq!(&text[..32], a.as_bytes());
        assert_eq!(&text[32..64], b.as_bytes());

        // Direction still matters, as it did before.
        assert_ne!(
            text,
            build_ad(b, a, content_type_to_byte(ContentType::Text))
        );
    }
}
