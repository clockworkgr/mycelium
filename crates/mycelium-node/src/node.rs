use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use mycelium_core::dtn::spray_and_wait::{DtnAction, DtnBundle, DtnConfig, DtnEngine};
use mycelium_core::routing::aodv::{
    AodvAction, AodvMessage, AodvRouter, RouteError, RouteReply, RouteRequest,
};
use mycelium_core::routing::coordinator::{RoutingCoordinator, RoutingDecision};
use mycelium_core::transport::manager::TransportManager;
use mycelium_core::transport::{TransportError, TransportEvent};
use mycelium_crypto::double_ratchet::RatchetHeader;
use mycelium_crypto::identity::Identity;
use mycelium_crypto::group::{GroupError, SenderKey, SenderKeyGroup};
use mycelium_crypto::session::{SessionError, SessionManager};
use mycelium_crypto::wot::TrustGraph;
use mycelium_crypto::x3dh::{PrekeyBundle, PrekeyState};
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
}

/// A message waiting for a session to be established.
#[derive(Debug)]
struct PendingMessage {
    plaintext: Vec<u8>,
    content_type: ContentType,
    message_id: MessageId,
}

/// A pending route discovery with queued envelope.
struct PendingRoute {
    envelope_bytes: Vec<u8>,
    message_id: MessageId,
    started_at: Instant,
    retries: u8,
}

/// Maximum number of AODV discovery retries before DTN fallback.
const MAX_DISCOVERY_RETRIES: u8 = 1;

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
    prekey_cache: Arc<RwLock<HashMap<NodeId, (PrekeyBundle, Instant)>>>,
    pending_messages: Arc<RwLock<HashMap<NodeId, Vec<PendingMessage>>>>,
    pending_routes: Arc<RwLock<HashMap<NodeId, Vec<PendingRoute>>>>,
    cancel: CancellationToken,
    /// Handle to BLE transport for platform FFI callbacks.
    pub ble_transport: Arc<RwLock<Option<Arc<mycelium_core::transport::ble::BleTransport>>>>,
    /// Handle to Wi-Fi Direct transport for platform FFI callbacks.
    pub wifi_transport: Arc<RwLock<Option<Arc<mycelium_core::transport::wifi_direct::WifiDirectTransport>>>>,
    /// Broadcast channel for node events (consumed by API server / WebSocket clients).
    pub event_tx: tokio::sync::broadcast::Sender<NodeEvent>,
    /// Dedup set for channel messages (prevents re-processing flooded messages).
    seen_channel_messages: Arc<RwLock<HashSet<MessageId>>>,
}

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

        Self {
            identity,
            node_id,
            config,
            transport_manager: Arc::new(TransportManager::new()),
            routing: Arc::new(RwLock::new(routing)),
            session_manager: Arc::new(RwLock::new(SessionManager::new())),
            prekey_state: Arc::new(RwLock::new(prekey_state)),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new())),
            battery: Arc::new(RwLock::new(BatteryManager::new())),
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
            event_tx,
            seen_channel_messages: Arc::new(RwLock::new(HashSet::new())),
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
                        let _ = self.db.save_prekey_state_blob(&prekey_state.to_bytes());
                    }
                }
                Err(_) => {
                    // No saved state; generate fresh prekeys and persist
                    prekey_state.generate_one_time_prekeys(100);
                    let _ = self.db.save_prekey_state_blob(&prekey_state.to_bytes());
                    info!("Generated fresh prekey state with 100 one-time prekeys");
                }
            }
        }

        // Load persisted sessions from database
        {
            let mut sm = self.session_manager.write().await;
            if let Ok(records) = self.db.list_sessions() {
                for record in records {
                    match SessionManager::deserialize_session(&record.session_data) {
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
                    let bundle = DtnBundle {
                        message_id: record.message_id,
                        destination: record.destination,
                        source: record.source,
                        payload: record.payload,
                        copies_remaining: record.copies_remaining,
                        expires_at: Instant::now() + Duration::from_secs(remaining_secs),
                        created_at: Instant::now(), // approximate
                        size: record.size,
                    };
                    let _ = routing.dtn_mut().store_relay(bundle);
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
                                ).await;
                            }
                            Err(e) => {
                                warn!("Event channel error: {}", e);
                            }
                        }
                    }
                }
            }
        });

        // Maintenance timer
        let routing_m = self.routing.clone();
        let pending_routes_m = self.pending_routes.clone();
        let prekey_state_m = self.prekey_state.clone();
        let prekey_cache_m = self.prekey_cache.clone();
        let rate_limiter_m = self.rate_limiter.clone();
        let transport_m = self.transport_manager.clone();
        let cancel_m = self.cancel.clone();
        let db_m = self.db.clone();
        let node_id_m = self.node_id;
        let mut spk_rotation_counter: u32 = 0;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = cancel_m.cancelled() => break,
                    _ = interval.tick() => {
                        // Run routing maintenance
                        let mut r = routing_m.write().await;
                        r.maintenance();

                        // Check for timed-out route discoveries
                        let disc_timeout = r.discovery_timeout();
                        let mut pr = pending_routes_m.write().await;
                        let mut timed_out: Vec<(NodeId, Vec<PendingRoute>)> = Vec::new();
                        pr.retain(|dest, routes| {
                            let (expired, remaining): (Vec<_>, Vec<_>) = routes
                                .drain(..)
                                .partition(|r| r.started_at.elapsed() > disc_timeout);
                            if !expired.is_empty() {
                                timed_out.push((*dest, expired));
                            }
                            *routes = remaining;
                            !routes.is_empty()
                        });

                        // Handle timed-out discoveries: retry or fall back to DTN
                        for (dest, expired_routes) in timed_out {
                            for mut route in expired_routes {
                                if route.retries < MAX_DISCOVERY_RETRIES {
                                    // Retry: re-initiate AODV discovery
                                    route.retries += 1;
                                    route.started_at = Instant::now();
                                    debug!(
                                        "Retrying AODV discovery for {} (attempt {})",
                                        dest, route.retries + 1
                                    );
                                    let rreq = r.initiate_discovery(dest);
                                    // Re-queue the route
                                    pr.entry(dest).or_default().push(route);
                                    // Broadcast the retry RREQ
                                    drop(pr);
                                    drop(r);
                                    Self::broadcast_aodv_static(
                                        &rreq,
                                        node_id_m,
                                        &transport_m,
                                    ).await;
                                    // Re-acquire locks for next iteration
                                    r = routing_m.write().await;
                                    pr = pending_routes_m.write().await;
                                } else {
                                    debug!("Route discovery for {} exhausted retries, falling back to DTN", dest);
                                    if r.fallback_to_dtn(
                                        route.message_id,
                                        dest,
                                        node_id_m,
                                        route.envelope_bytes,
                                    ).is_ok() {
                                        if let Some(bundle) = r.dtn().get_bundle(&route.message_id) {
                                            persist_dtn_bundle(&db_m, bundle);
                                        }
                                    }
                                    let _ = db_m.update_message_status(
                                        &route.message_id,
                                        "dtn_pending",
                                    );
                                }
                            }
                        }

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
                                let _ = db_m.save_prekey_state_blob(&ps.to_bytes());
                                debug!("Replenished {} one-time prekeys (had {})", to_generate, current_count);
                            }

                            // Signed prekey rotation: every ~24h (2880 ticks at 30s interval)
                            spk_rotation_counter += 1;
                            if spk_rotation_counter >= 2880 {
                                spk_rotation_counter = 0;
                                ps.rotate_signed_prekey();
                                let _ = db_m.save_prekey_state_blob(&ps.to_bytes());
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
                self.node_id,
                InternetConfig {
                    listen_addr: format!("0.0.0.0:{}", inet_cfg.listen_port)
                        .parse()
                        .unwrap(),
                    bootstrap_nodes: bootstrap,
                    max_connections: 64,
                },
            ));
            self.transport_manager.add_transport(internet).await;
            info!("Registered Internet transport on port {}", inet_cfg.listen_port);
        }
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
        if destination == self.node_id {
            return Err(NodeError::SendToSelf);
        }

        let message_id = MessageId::random();
        let clock_val = {
            let mut clock = self.lamport_clock.write().await;
            clock.tick()
        };
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Store outgoing message in DB
        let record = MessageRecord {
            message_id,
            source: self.node_id,
            destination,
            content_type: content_type_str(content_type),
            plaintext: plaintext.to_vec(),
            lamport_clock: clock_val.0,
            device_timestamp: timestamp,
            status: "pending".to_string(),
            is_incoming: false,
        };
        self.db.insert_message(&record)?;

        // Check if session exists
        let has_session = {
            let sm = self.session_manager.read().await;
            sm.has_session(&destination)
        };

        if !has_session {
            // Check prekey cache
            let has_prekey = {
                let cache = self.prekey_cache.read().await;
                cache.contains_key(&destination)
            };

            if has_prekey {
                // Initiate session from cached prekey bundle
                let bundle = {
                    let cache = self.prekey_cache.read().await;
                    cache.get(&destination).map(|(b, _)| b.clone()).unwrap()
                };
                self.initiate_and_send_session(
                    destination,
                    &bundle,
                    plaintext,
                    content_type,
                    message_id,
                    clock_val,
                    timestamp,
                )
                .await?;
            } else {
                // Queue message and send prekey request
                {
                    let mut pm = self.pending_messages.write().await;
                    pm.entry(destination).or_default().push(PendingMessage {
                        plaintext: plaintext.to_vec(),
                        content_type,
                        message_id,
                    });
                }

                // Send prekey request
                let prekey_req_payload =
                    wire::serialize_prekey_request(&self.identity.public_key_bytes());
                let envelope = Envelope {
                    source: self.node_id,
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
                self.route_and_send_envelope(envelope, message_id).await?;
            }

            return Ok(message_id);
        }

        // Session exists — encrypt and send
        let ad = build_ad(self.node_id, destination);
        let (header, ciphertext) = {
            let mut sm = self.session_manager.write().await;
            sm.encrypt_for(&destination, plaintext, &ad)?
        };

        // Persist session after ratchet state advance
        Self::persist_session(&self.session_manager, &self.db, &destination).await;

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
            source: self.node_id,
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

        self.route_and_send_envelope(envelope, message_id).await?;
        Ok(message_id)
    }

    /// Send a message to a group.
    ///
    /// The message is encrypted with the group's sender key and sent to
    /// each group member individually via existing routes.
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
            // Persist group state after sender key advance
            let _ = self.db.save_group_blob(&group_id, &group.to_bytes());
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
        let decision = {
            let r = self.routing.read().await;
            r.route_message(&envelope.destination)
        };

        let serialized = envelope.serialize();

        match decision {
            RoutingDecision::SendRealtime { next_hop } => {
                self.transport_manager.send(&next_hop, &serialized).await?;
                let _ = self.db.update_message_status(&message_id, "sent");
            }
            RoutingDecision::DiscoveryPending => {
                let destination = envelope.destination;
                // Initiate AODV discovery
                let rreq = {
                    let mut r = self.routing.write().await;
                    r.initiate_discovery(destination)
                };
                // Broadcast RREQ
                self.broadcast_aodv_message(&rreq, self.node_id).await;
                // Queue envelope for when route is found
                let mut pr = self.pending_routes.write().await;
                pr.entry(destination).or_default().push(PendingRoute {
                    envelope_bytes: serialized,
                    message_id,
                    started_at: Instant::now(),
                    retries: 0,
                });
            }
            RoutingDecision::EnterDtn => {
                let mut r = self.routing.write().await;
                if r.fallback_to_dtn(
                    message_id,
                    envelope.destination,
                    self.node_id,
                    serialized,
                ).is_ok() {
                    if let Some(bundle) = r.dtn().get_bundle(&message_id) {
                        persist_dtn_bundle(&self.db, bundle);
                    }
                }
                let _ = self.db.update_message_status(&message_id, "dtn_pending");
            }
            RoutingDecision::DeliverLocal => {
                return Err(NodeError::SendToSelf);
            }
        }

        Ok(())
    }

    /// Initiate a session and send SessionInit + first message.
    async fn initiate_and_send_session(
        &self,
        destination: NodeId,
        bundle: &PrekeyBundle,
        plaintext: &[u8],
        content_type: ContentType,
        message_id: MessageId,
        clock_val: LamportClock,
        timestamp: u64,
    ) -> Result<(), NodeError> {
        let identity = identity_clone_for_prekeys(&self.identity);
        let init_result = {
            let mut sm = self.session_manager.write().await;
            sm.initiate_session(&identity, destination, bundle)?
        };

        // Persist the new session
        Self::persist_session(&self.session_manager, &self.db, &destination).await;

        // Encrypt the first message with the new session
        let ad = build_ad(self.node_id, destination);
        let (header, ciphertext) = {
            let mut sm = self.session_manager.write().await;
            sm.encrypt_for(&destination, plaintext, &ad)?
        };

        // Persist session after encrypt
        Self::persist_session(&self.session_manager, &self.db, &destination).await;

        // Build the encrypted payload part (without type byte prefix)
        let enc_payload = EncryptedPayload {
            content_type: content_type_to_byte(content_type),
            header: WireRatchetHeader {
                dh_public: header.dh_public,
                previous_chain_length: header.previous_chain_length,
                message_number: header.message_number,
            },
            ciphertext,
        };
        let enc_bytes = enc_payload.serialize();

        let session_init = SessionInitPayload {
            ephemeral_public: init_result.ephemeral_public,
            identity_key: self.identity.public_key_bytes(),
            signed_prekey_id: init_result.used_signed_prekey_id,
            one_time_prekey_id: init_result.used_one_time_prekey_id,
            encrypted_payload: enc_bytes,
        };

        let envelope = Envelope {
            source: self.node_id,
            destination,
            message_id,
            ttl: 10,
            hop_count: 0,
            flags: MessageFlags::NONE,
            lamport_clock: clock_val.0,
            device_timestamp: timestamp,
            protocol_version: ProtocolVersion::CURRENT,
            payload: session_init.serialize(),
        };

        self.route_and_send_envelope(envelope, message_id).await
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
        pending_routes: &RwLock<HashMap<NodeId, Vec<PendingRoute>>>,
        battery: &RwLock<BatteryManager>,
        event_tx: &tokio::sync::broadcast::Sender<NodeEvent>,
        seen_channel_messages: &RwLock<HashSet<MessageId>>,
    ) {
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
                        DtnAction::SendToPeer { peer: target, bundle } => {
                            let payload = wire::serialize_dtn_relay(
                                &bundle.message_id,
                                &bundle.payload,
                            );
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
                                        debug!("DTN delivered bundle {} to destination {}", bundle.message_id, target);
                                    } else {
                                        // Sprayed to a relay — update copies_remaining
                                        {
                                            let r = routing.read().await;
                                            if let Some(our) = r.dtn().get_bundle(&bundle.message_id) {
                                                let _ = db.update_dtn_copies(&bundle.message_id, our.copies_remaining);
                                            }
                                        }
                                        debug!("DTN spray: sent bundle {} to relay {}", bundle.message_id, target);
                                    }
                                }
                                Err(e) => {
                                    debug!("DTN send to {} failed: {}, keeping bundle", target, e);
                                }
                            }
                        }
                        DtnAction::DeliverLocal { bundle } => {
                            debug!("DTN deliver local: bundle {}", bundle.message_id);
                            Self::handle_dtn_local_delivery(
                                &bundle,
                                session_manager,
                                db,
                                local_id,
                                lamport_clock,
                            )
                            .await;
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
                    pr.remove(peer).unwrap_or_default()
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
                if envelope.source != *peer
                    && envelope.source != local_id
                    && envelope.hop_count > 0
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
                            warn!("Auto-blacklisted peer {} after repeated rate violations", peer);
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
                        Self::handle_aodv_rerr(
                            body,
                            routing,
                            transport_manager,
                            local_id,
                        )
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
                        )
                        .await;
                    }
                    WirePayloadType::SessionInit => {
                        Self::handle_session_init(
                            &envelope,
                            body,
                            session_manager,
                            prekey_state,
                            transport_manager,
                            routing,
                            db,
                            local_id,
                            lamport_clock,
                            event_tx,
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
                        )
                        .await;
                    }
                    WirePayloadType::Beacon => {
                        Self::handle_beacon(
                            &envelope,
                            body,
                            db,
                            lamport_clock,
                            local_id,
                        )
                        .await;
                    }
                    WirePayloadType::Receipt => {
                        Self::handle_receipt(
                            &envelope,
                            body,
                            db,
                            local_id,
                            event_tx,
                        );
                    }
                    WirePayloadType::GroupMessage => {
                        Self::handle_group_message(
                            &envelope,
                            body,
                            groups,
                            db,
                            local_id,
                        )
                        .await;
                    }
                    WirePayloadType::SenderKeyDistribution => {
                        Self::handle_sender_key_distribution(
                            &envelope,
                            body,
                            groups,
                            db,
                            local_id,
                        )
                        .await;
                    }
                    WirePayloadType::ChannelMessage => {
                        Self::handle_channel_message(
                            &envelope,
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
                        debug!("Channel control message {:?} received, not yet handled", payload_type);
                    }
                    WirePayloadType::EmergencyBroadcast => {
                        Self::handle_emergency_broadcast(
                            &envelope,
                            body,
                            trust_graph,
                            transport_manager,
                            local_id,
                            seen_channel_messages,
                            event_tx,
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
        pending_routes: &RwLock<HashMap<NodeId, Vec<PendingRoute>>>,
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

        Self::execute_aodv_action(
            action,
            routing,
            transport_manager,
            local_id,
            pending_routes,
        )
        .await;
    }

    async fn handle_aodv_rrep(
        body: &[u8],
        received_from: NodeId,
        routing: &RwLock<RoutingCoordinator>,
        transport_manager: &TransportManager,
        local_id: NodeId,
        pending_routes: &RwLock<HashMap<NodeId, Vec<PendingRoute>>>,
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

        Self::execute_aodv_action(
            action,
            routing,
            transport_manager,
            local_id,
            pending_routes,
        )
        .await;
    }

    async fn handle_aodv_rerr(
        body: &[u8],
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
            r.handle_aodv_message(AodvMessage::RouteError(rerr), local_id)
        };

        // For RERR, we only care about BroadcastRerr
        if let AodvAction::BroadcastRerr(rerr) = action {
            let payload = wire::serialize_aodv_rerr(
                &rerr.unreachable,
                &rerr.source,
                rerr.dest_seq,
            );
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
    }

    async fn execute_aodv_action(
        action: AodvAction,
        _routing: &RwLock<RoutingCoordinator>,
        transport_manager: &TransportManager,
        local_id: NodeId,
        pending_routes: &RwLock<HashMap<NodeId, Vec<PendingRoute>>>,
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
                    pr.remove(&destination).unwrap_or_default()
                };
                for route in pending {
                    debug!(
                        "Sending queued envelope for {} via {}",
                        destination, next_hop
                    );
                    let _ = transport_manager.send(&next_hop, &route.envelope_bytes).await;
                }
            }
            AodvAction::BroadcastRerr(rerr) => {
                let payload = wire::serialize_aodv_rerr(
                    &rerr.unreachable,
                    &rerr.source,
                    rerr.dest_seq,
                );
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
    ) {
        let is_for_us = envelope.destination == local_id;

        if is_for_us {
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

            let ad = build_ad(envelope.source, envelope.destination);
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
            Self::persist_session(session_manager, db, &envelope.source).await;

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
            let _ = db.insert_message(&record);
            debug!(
                "Received message {} from {}",
                envelope.message_id, envelope.source
            );

            let _ = event_tx.send(NodeEvent::MessageReceived {
                source: envelope.source,
                message_id: envelope.message_id,
                data: record.plaintext.clone(),
                content_type: enc.content_type,
                timestamp: envelope.device_timestamp,
            });

            // Send delivery receipt back to sender
            Self::send_delivery_receipt(
                envelope.message_id,
                envelope.source,
                local_id,
                transport_manager,
                routing,
            )
            .await;
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

    async fn handle_session_init(
        envelope: &Envelope,
        body: &[u8],
        session_manager: &RwLock<SessionManager>,
        prekey_state: &RwLock<PrekeyState>,
        transport_manager: &TransportManager,
        routing: &RwLock<RoutingCoordinator>,
        db: &Database,
        local_id: NodeId,
        _lamport_clock: &RwLock<LamportClock>,
        event_tx: &tokio::sync::broadcast::Sender<NodeEvent>,
    ) {
        if envelope.destination != local_id {
            debug!("SessionInit not for us, ignoring");
            return;
        }

        let init = match SessionInitPayload::deserialize_body(body) {
            Ok(i) => i,
            Err(e) => {
                debug!("Bad SessionInit payload: {}", e);
                return;
            }
        };

        // Accept the session
        {
            let mut sm = session_manager.write().await;
            let mut ps = prekey_state.write().await;
            match sm.accept_session(
                &mut ps,
                envelope.source,
                &init.identity_key,
                &init.ephemeral_public,
                init.one_time_prekey_id,
            ) {
                Ok(safety_number) => {
                    info!(
                        "Accepted session from {}, safety number: {}",
                        envelope.source, safety_number
                    );
                    // Persist prekey state (a one-time prekey may have been consumed)
                    let _ = db.save_prekey_state_blob(&ps.to_bytes());
                }
                Err(e) => {
                    debug!("Failed to accept session from {}: {}", envelope.source, e);
                    return;
                }
            }
        }

        // Persist the accepted session
        Self::persist_session(session_manager, db, &envelope.source).await;

        // Decrypt the enclosed first message
        if !init.encrypted_payload.is_empty() && init.encrypted_payload[0] == WirePayloadType::EncryptedMessage as u8 {
            let enc = match EncryptedPayload::deserialize_body(&init.encrypted_payload[1..]) {
                Ok(e) => e,
                Err(e) => {
                    debug!("Bad encrypted payload in SessionInit: {}", e);
                    return;
                }
            };

            let ratchet_header = RatchetHeader {
                dh_public: enc.header.dh_public,
                previous_chain_length: enc.header.previous_chain_length,
                message_number: enc.header.message_number,
            };

            let ad = build_ad(envelope.source, envelope.destination);
            let plaintext = {
                let mut sm = session_manager.write().await;
                match sm.decrypt_from(&envelope.source, &ratchet_header, &enc.ciphertext, &ad) {
                    Ok(pt) => pt,
                    Err(e) => {
                        debug!(
                            "Failed to decrypt first message from {}: {}",
                            envelope.source, e
                        );
                        return;
                    }
                }
            };

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
            let _ = db.insert_message(&record);
            debug!(
                "Received first message {} via SessionInit from {}",
                envelope.message_id, envelope.source
            );

            let _ = event_tx.send(NodeEvent::MessageReceived {
                source: envelope.source,
                message_id: envelope.message_id,
                data: record.plaintext.clone(),
                content_type: enc.content_type,
                timestamp: envelope.device_timestamp,
            });

            // Send delivery receipt
            Self::send_delivery_receipt(
                envelope.message_id,
                envelope.source,
                local_id,
                transport_manager,
                routing,
            )
            .await;
        }
    }

    async fn handle_prekey_request(
        envelope: &Envelope,
        prekey_state: &RwLock<PrekeyState>,
        routing: &RwLock<RoutingCoordinator>,
        transport_manager: &TransportManager,
        _identity: &Identity,
        local_id: NodeId,
        lamport_clock: &RwLock<LamportClock>,
    ) {
        if envelope.destination != local_id {
            return;
        }

        let bundle = {
            let ps = prekey_state.read().await;
            ps.bundle()
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

        Self::route_envelope_static(
            &response_envelope,
            routing,
            transport_manager,
        )
        .await;
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

        // Cache the bundle in memory and DB
        {
            let mut cache = prekey_cache.write().await;
            cache.insert(peer_id, (bundle.clone(), Instant::now()));
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

        // Initiate session
        let init_result = {
            let mut sm = session_manager.write().await;
            match sm.initiate_session(identity, peer_id, &bundle) {
                Ok(r) => r,
                Err(e) => {
                    debug!("Failed to initiate session with {}: {}", peer_id, e);
                    return;
                }
            }
        };

        // Persist the new session
        Self::persist_session(session_manager, db, &peer_id).await;

        // Send first pending message as SessionInit, rest as EncryptedMessage
        for (i, msg) in pending.into_iter().enumerate() {
            let clock_val = {
                let mut clock = lamport_clock.write().await;
                clock.tick()
            };
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let ad = build_ad(local_id, peer_id);

            let (header, ciphertext) = {
                let mut sm = session_manager.write().await;
                match sm.encrypt_for(&peer_id, &msg.plaintext, &ad) {
                    Ok(r) => r,
                    Err(e) => {
                        debug!("Failed to encrypt for {}: {}", peer_id, e);
                        return;
                    }
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

            let payload = if i == 0 {
                // First message: wrap in SessionInit
                let session_init = SessionInitPayload {
                    ephemeral_public: init_result.ephemeral_public,
                    identity_key: identity.public_key_bytes(),
                    signed_prekey_id: init_result.used_signed_prekey_id,
                    one_time_prekey_id: init_result.used_one_time_prekey_id,
                    encrypted_payload: enc_payload.serialize(),
                };
                session_init.serialize()
            } else {
                enc_payload.serialize()
            };

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

            match decision {
                RoutingDecision::SendRealtime { next_hop } => {
                    let _ = transport_manager.send(&next_hop, &serialized).await;
                    let _ = db.update_message_status(&msg.message_id, "sent");
                }
                _ => {
                    // Direct send to peer (since they just sent us a prekey response,
                    // they should be a neighbor)
                    let _ = transport_manager.send(&peer_id, &serialized).await;
                    let _ = db.update_message_status(&msg.message_id, "sent");
                }
            }
        }

        // Persist session after all encrypts
        Self::persist_session(session_manager, db, &peer_id).await;
    }

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
    ) {
        let (msg_id, payload) = match wire::deserialize_dtn_relay(body) {
            Ok(v) => v,
            Err(e) => {
                debug!("Bad DTN relay payload: {}", e);
                return;
            }
        };

        if envelope.destination == local_id {
            // We are the final destination — deliver locally.
            // The payload is the original serialized Envelope; deserialize it
            // to recover the inner encrypted payload and original metadata.
            debug!("DTN relay delivered locally: {}", msg_id);

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

                let ad = build_ad(inner_envelope.source, local_id);
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
                Self::persist_session(session_manager, db, &inner_envelope.source).await;

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
                let _ = db.insert_message(&record);
            } else if payload_type == WirePayloadType::SessionInit as u8 {
                // DTN-delivered SessionInit: create session and decrypt first message
                debug!("DTN: processing SessionInit from {}", inner_envelope.source);
                Self::handle_session_init(
                    &inner_envelope,
                    inner_body,
                    session_manager,
                    prekey_state,
                    transport_manager,
                    routing,
                    db,
                    local_id,
                    _lamport_clock,
                    event_tx,
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
                    if score.value > 0.0 { score.hops } else { u8::MAX }
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

            // Store as relay
            let mut r = routing.write().await;
            let bundle = DtnBundle {
                message_id: msg_id,
                destination: envelope.destination,
                source: envelope.source,
                payload,
                copies_remaining: 1,
                expires_at: Instant::now() + Duration::from_secs(72 * 3600),
                created_at: Instant::now(),
                size: relay_size,
            };
            if r.dtn_mut().store_relay(bundle).is_ok() {
                if let Some(b) = r.dtn().get_bundle(&msg_id) {
                    persist_dtn_bundle(db, b);
                }
            }
            debug!("Stored DTN relay for {}", envelope.destination);
        }
    }

    async fn handle_dtn_local_delivery(
        bundle: &DtnBundle,
        session_manager: &RwLock<SessionManager>,
        db: &Database,
        local_id: NodeId,
        _lamport_clock: &RwLock<LamportClock>,
    ) {
        // The bundle payload is the full serialized Envelope; deserialize it
        // to recover the inner encrypted payload and original metadata.
        let inner_envelope = match Envelope::deserialize(&bundle.payload) {
            Ok(e) => e,
            Err(e) => {
                debug!("DTN local delivery: failed to deserialize inner envelope: {}", e);
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

            let ad = build_ad(inner_envelope.source, local_id);
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
            Self::persist_session(session_manager, db, &inner_envelope.source).await;

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
            let _ = db.insert_message(&record);
        }
    }

    // --- Session persistence ---

    async fn persist_session(
        session_manager: &RwLock<SessionManager>,
        db: &Database,
        peer_id: &NodeId,
    ) {
        let sm = session_manager.read().await;
        for (nid, session) in sm.all_sessions() {
            if nid == peer_id {
                let data = SessionManager::serialize_session(session);
                let record = SessionRecord {
                    peer_id: *nid,
                    session_data: data,
                    safety_number: Some(session.safety_number.clone()),
                    is_verified: session.is_verified,
                };
                let _ = db.save_session(&record);
                break;
            }
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
                    let _ = db.save_group_blob(&group_id, &group.to_bytes());
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

    async fn handle_sender_key_distribution(
        envelope: &Envelope,
        body: &[u8],
        groups: &RwLock<HashMap<[u8; 32], SenderKeyGroup>>,
        db: &Database,
        local_id: NodeId,
    ) {
        if envelope.destination != local_id {
            return;
        }

        let (group_id, chain_key, iteration) =
            match wire::deserialize_sender_key_distribution(body) {
                Ok(v) => v,
                Err(e) => {
                    debug!("Bad sender key distribution: {}", e);
                    return;
                }
            };

        let sender_key = SenderKey {
            chain_key,
            iteration,
        };

        let mut grps = groups.write().await;
        let group = grps
            .entry(group_id)
            .or_insert_with(|| SenderKeyGroup::new(group_id));
        group.add_member(envelope.source, sender_key);
        // Persist group state
        let _ = db.save_group_blob(&group_id, &group.to_bytes());
        debug!(
            "Added sender key from {} for group {:?}",
            envelope.source,
            &group_id[..4]
        );
    }

    // --- Beacon handler ---

    async fn handle_beacon(
        envelope: &Envelope,
        body: &[u8],
        db: &Database,
        lamport_clock: &RwLock<LamportClock>,
        local_id: NodeId,
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

        debug!(
            "Beacon from {} ({}): battery={}, neighbors={}",
            beacon.display_name, beacon.node_id, beacon.battery_level, beacon.neighbor_count
        );

        // Merge lamport clock from beacon
        {
            let mut clock = lamport_clock.write().await;
            clock.merge(LamportClock(beacon.lamport_clock));
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
                    existing.display_name = beacon.display_name;
                }
                existing
            }
            Err(_) => {
                // Auto-create contact from beacon
                ContactRecord {
                    node_id: beacon.node_id,
                    display_name: beacon.display_name,
                    public_key: beacon.node_id.as_bytes().to_vec(), // Use node_id as public key placeholder
                    trust_score: 0.0,
                    is_verified: false,
                    last_seen: Some(now_secs),
                }
            }
        };

        let _ = db.save_contact(&contact);
    }

    // --- Channel message handler ---

    /// Handle an incoming channel message: dedup, store if subscribed, flood to peers.
    async fn handle_channel_message(
        envelope: &Envelope,
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
                debug!("Duplicate channel message {}, skipping", envelope.message_id);
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

        // Flood to all connected peers (except the one who sent it)
        if envelope.ttl > 0 {
            let mut fwd = envelope.clone();
            fwd.forward();
            let fwd_data = fwd.serialize();
            let peers = transport_manager.known_peers().await;
            for p in peers {
                if p != envelope.source && p != local_id {
                    let _ = transport_manager.send(&p, &fwd_data).await;
                }
            }
        }
    }

    // --- Emergency broadcast handler ---

    async fn handle_emergency_broadcast(
        envelope: &Envelope,
        body: &[u8],
        trust_graph: &RwLock<TrustGraph>,
        transport_manager: &TransportManager,
        local_id: NodeId,
        seen: &RwLock<HashSet<MessageId>>,
        event_tx: &tokio::sync::broadcast::Sender<NodeEvent>,
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
                debug!("Duplicate emergency broadcast {}, skipping", envelope.message_id);
                return;
            }
            if seen_set.len() > 10_000 {
                seen_set.clear();
            }
        }

        // Trust threshold checks
        let tg = trust_graph.read().await;
        let sender_trust = tg.trust_score(&local_id, &envelope.source).value;

        let accepted = match level {
            wire::EmergencyLevel::Priority => sender_trust > 0.3,
            wire::EmergencyLevel::Urgent => sender_trust > 0.6,
            wire::EmergencyLevel::Critical => {
                // Need 3+ cosigners each with trust > 0.8
                if cosigners.len() < 3 {
                    debug!(
                        "Critical emergency from {} rejected: only {} cosigners (need 3+)",
                        envelope.source,
                        cosigners.len()
                    );
                    false
                } else {
                    let trusted_cosigners = cosigners
                        .iter()
                        .filter(|cs| {
                            let cs_id = NodeId::from_bytes(**cs);
                            tg.trust_score(&local_id, &cs_id).value > 0.8
                        })
                        .count();
                    trusted_cosigners >= 3
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

        // Flood to all peers (bypass AODV routing for all emergency levels)
        if envelope.ttl > 0 {
            let mut fwd = envelope.clone();
            fwd.forward();
            let fwd_data = fwd.serialize();
            let peers = transport_manager.known_peers().await;
            for p in peers {
                if p != envelope.source && p != local_id {
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
            envelope.source, envelope.message_id, body.len()
        );
        if envelope.destination != local_id {
            info!("Receipt not for us (dest={}), ignoring", envelope.destination);
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
                info!("Delivery receipt for {} sent to {} via {}", message_id, to, next_hop);
            }
            _ => {
                info!("Delivery receipt for {} to {} dropped (no route)", message_id, to);
            }
        }
    }

    /// Mark messages from a peer as read and send read receipts.
    pub async fn mark_read_and_notify(&self, peer: NodeId) -> usize {
        let msg_ids = match self.db.mark_messages_read_returning_ids(&self.node_id, &peer) {
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
                info!("Read receipt for {} sent to {} via {}", message_id, to, next_hop);
            }
            _ => {
                info!("Read receipt for {} to {} dropped (no route)", message_id, to);
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
        pr.values().map(|v| v.len()).sum()
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
    };
    let _ = db.store_dtn_bundle(&record);
}

/// Build associated data for Double Ratchet from source + destination NodeIds.
fn build_ad(source: NodeId, destination: NodeId) -> Vec<u8> {
    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(source.as_bytes());
    ad.extend_from_slice(destination.as_bytes());
    ad
}

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
