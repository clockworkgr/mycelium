use std::collections::HashMap;
use std::time::{Duration, Instant};

use mycelium_protocol::types::{MessageId, NodeId};
use tracing::{debug, trace};

/// A DTN bundle stored for spray-and-wait delivery.
#[derive(Debug, Clone)]
pub struct DtnBundle {
    pub message_id: MessageId,
    pub destination: NodeId,
    pub source: NodeId,
    /// Encrypted opaque blob — relay nodes cannot read this.
    pub payload: Vec<u8>,
    /// Number of remaining copies this node can spray.
    pub copies_remaining: u8,
    /// When this bundle expires.
    pub expires_at: Instant,
    /// When this bundle was created.
    pub created_at: Instant,
    /// Size in bytes for quota tracking.
    pub size: usize,
    /// True when this node is the originator, false when we are carrying it
    /// for someone else. Eviction must never discard the user's own outgoing
    /// mail to make room for relay traffic (ROADMAP T-11), so the distinction
    /// has to survive a restart and is persisted with the bundle.
    pub is_local: bool,
}

/// Configuration for the DTN engine.
#[derive(Debug, Clone)]
pub struct DtnConfig {
    /// Default number of spray copies (L parameter).
    pub spray_copies: u8,
    /// Default TTL for bundles.
    pub ttl: Duration,
    /// Maximum total storage in bytes.
    pub max_storage_bytes: usize,
    /// Maximum storage per source identity in bytes.
    pub per_identity_quota_bytes: usize,
}

impl Default for DtnConfig {
    fn default() -> Self {
        Self {
            spray_copies: 8,
            ttl: Duration::from_secs(72 * 3600),  // 72 hours
            max_storage_bytes: 256 * 1024 * 1024, // 256 MB (phone default)
            per_identity_quota_bytes: 10 * 1024 * 1024, // 10 MB per identity
        }
    }
}

impl DtnConfig {
    /// Supernode configuration with larger storage.
    pub fn supernode() -> Self {
        Self {
            max_storage_bytes: 2 * 1024 * 1024 * 1024,  // 2 GB
            per_identity_quota_bytes: 50 * 1024 * 1024, // 50 MB per identity
            ..Default::default()
        }
    }
}

/// Actions the DTN engine requests from the caller.
#[derive(Debug)]
pub enum DtnAction {
    /// Send this bundle to a specific peer (spray).
    SendToPeer { peer: NodeId, bundle: DtnBundle },
    /// Bundle delivered locally.
    DeliverLocal { bundle: DtnBundle },
    /// No action.
    None,
}

/// Spray-and-Wait DTN engine per spec Section 4.1 Layer 2.
pub struct DtnEngine {
    config: DtnConfig,
    /// All stored bundles, keyed by message ID.
    bundles: HashMap<MessageId, DtnBundle>,
    /// Track total stored bytes.
    total_stored_bytes: usize,
    /// Per-source storage tracking.
    per_source_bytes: HashMap<NodeId, usize>,
    /// Peers we've already sprayed a given bundle to (to avoid re-spraying).
    sprayed_to: HashMap<MessageId, Vec<NodeId>>,
}

impl DtnEngine {
    pub fn new(config: DtnConfig) -> Self {
        Self {
            config,
            bundles: HashMap::new(),
            total_stored_bytes: 0,
            per_source_bytes: HashMap::new(),
            sprayed_to: HashMap::new(),
        }
    }

    /// Store a new outgoing message for spray-and-wait delivery.
    pub fn store_outgoing(
        &mut self,
        message_id: MessageId,
        destination: NodeId,
        source: NodeId,
        payload: Vec<u8>,
    ) -> Result<(), DtnError> {
        // Storing the same message twice must not double-count its size.
        if self.bundles.contains_key(&message_id) {
            return Ok(());
        }

        let size = payload.len();

        // Check per-identity quota
        let source_used = self.per_source_bytes.get(&source).copied().unwrap_or(0);
        if source_used + size > self.config.per_identity_quota_bytes {
            return Err(DtnError::QuotaExceeded);
        }

        // Check total storage, evict if needed
        self.evict_if_needed(size)?;

        let bundle = DtnBundle {
            message_id,
            destination,
            source,
            payload,
            copies_remaining: self.config.spray_copies,
            expires_at: Instant::now() + self.config.ttl,
            created_at: Instant::now(),
            size,
            is_local: true,
        };

        self.total_stored_bytes += size;
        *self.per_source_bytes.entry(source).or_insert(0) += size;
        self.bundles.insert(message_id, bundle);

        debug!(
            "Stored DTN bundle {} for {} ({} bytes, {} copies)",
            message_id, destination, size, self.config.spray_copies
        );

        Ok(())
    }

    /// Store an incoming bundle received from another relay.
    ///
    /// Relay traffic can only displace other relay traffic: see
    /// [`Self::evict_if_needed`].
    pub fn store_relay(&mut self, bundle: DtnBundle) -> Result<(), DtnError> {
        let mut bundle = bundle;
        bundle.is_local = false;
        self.insert_bundle(bundle)
    }

    /// Re-insert a bundle loaded from storage, keeping its original origin and
    /// spray history. Restarting must not reclassify the user's own bundles as
    /// relay traffic, nor re-spray copies to peers that already hold one.
    pub fn store_restored(
        &mut self,
        bundle: DtnBundle,
        sprayed_to: Vec<NodeId>,
    ) -> Result<(), DtnError> {
        let message_id = bundle.message_id;
        self.insert_bundle(bundle)?;
        if !sprayed_to.is_empty() {
            self.sprayed_to.insert(message_id, sprayed_to);
        }
        Ok(())
    }

    fn insert_bundle(&mut self, bundle: DtnBundle) -> Result<(), DtnError> {
        if self.bundles.contains_key(&bundle.message_id) {
            return Ok(()); // Already have it
        }

        let size = bundle.size;
        let source = bundle.source;

        let source_used = self.per_source_bytes.get(&source).copied().unwrap_or(0);
        if source_used + size > self.config.per_identity_quota_bytes {
            return Err(DtnError::QuotaExceeded);
        }

        self.evict_if_needed(size)?;

        self.total_stored_bytes += size;
        *self.per_source_bytes.entry(source).or_insert(0) += size;
        self.bundles.insert(bundle.message_id, bundle);

        Ok(())
    }

    /// Peers a bundle has already been sprayed to, for persistence.
    pub fn sprayed_to(&self, message_id: &MessageId) -> &[NodeId] {
        self.sprayed_to
            .get(message_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Called when we encounter a neighbor. Returns bundles to spray/deliver.
    pub fn on_neighbor_encountered(
        &mut self,
        neighbor: NodeId,
        local_id: &NodeId,
    ) -> Vec<DtnAction> {
        let mut actions = Vec::new();

        // Collect bundle IDs first to avoid borrow issues
        let bundle_ids: Vec<MessageId> = self.bundles.keys().copied().collect();

        for msg_id in bundle_ids {
            let bundle = match self.bundles.get(&msg_id) {
                Some(b) => b,
                None => continue,
            };

            // Skip expired
            if bundle.expires_at < Instant::now() {
                continue;
            }

            // Is the neighbor the destination? Send the bundle directly to them.
            if bundle.destination == neighbor {
                let relay_bundle = bundle.clone();
                actions.push(DtnAction::SendToPeer {
                    peer: neighbor,
                    bundle: relay_bundle,
                });
                continue;
            }

            // Are we the destination?
            if bundle.destination == *local_id {
                continue; // Already local
            }

            // Spray phase: if we have copies remaining
            if bundle.copies_remaining > 1 {
                let already_sprayed = self
                    .sprayed_to
                    .get(&msg_id)
                    .map(|peers| peers.contains(&neighbor))
                    .unwrap_or(false);

                if !already_sprayed {
                    // Give half our copies to the relay
                    let copies_to_give = bundle.copies_remaining / 2;
                    let mut relay_bundle = bundle.clone();
                    relay_bundle.copies_remaining = copies_to_give;

                    actions.push(DtnAction::SendToPeer {
                        peer: neighbor,
                        bundle: relay_bundle,
                    });
                }
            }
        }

        // Now apply state changes
        for action in &actions {
            match action {
                DtnAction::SendToPeer { peer, bundle } => {
                    // Reduce our copies
                    if let Some(our_bundle) = self.bundles.get_mut(&bundle.message_id) {
                        our_bundle.copies_remaining -= bundle.copies_remaining;
                    }
                    self.sprayed_to
                        .entry(bundle.message_id)
                        .or_default()
                        .push(*peer);
                }
                DtnAction::DeliverLocal { bundle } => {
                    trace!(
                        "Bundle {} delivered to destination {}",
                        bundle.message_id,
                        bundle.destination
                    );
                }
                DtnAction::None => {}
            }
        }

        actions
    }

    /// Remove a bundle (e.g., after confirmed delivery).
    pub fn remove_bundle(&mut self, message_id: &MessageId) {
        if let Some(bundle) = self.bundles.remove(message_id) {
            self.total_stored_bytes = self.total_stored_bytes.saturating_sub(bundle.size);
            if let Some(used) = self.per_source_bytes.get_mut(&bundle.source) {
                *used = used.saturating_sub(bundle.size);
                if *used == 0 {
                    // Do not keep an entry per source ever seen.
                    self.per_source_bytes.remove(&bundle.source);
                }
            }
            self.sprayed_to.remove(message_id);
        }
    }

    /// Run periodic maintenance: expire old bundles.
    pub fn expire_bundles(&mut self) -> usize {
        let now = Instant::now();
        let expired: Vec<MessageId> = self
            .bundles
            .iter()
            .filter(|(_, b)| b.expires_at < now)
            .map(|(id, _)| *id)
            .collect();

        let count = expired.len();
        for id in expired {
            self.remove_bundle(&id);
        }
        count
    }

    /// Get current storage usage.
    pub fn storage_used(&self) -> usize {
        self.total_stored_bytes
    }

    /// Get number of stored bundles.
    pub fn bundle_count(&self) -> usize {
        self.bundles.len()
    }

    /// Get a stored bundle by ID (for local delivery).
    pub fn get_bundle(&self, message_id: &MessageId) -> Option<&DtnBundle> {
        self.bundles.get(message_id)
    }

    /// Return all stored bundles (for diagnostics).
    pub fn bundles(&self) -> &HashMap<MessageId, DtnBundle> {
        &self.bundles
    }

    /// Get maximum storage capacity in bytes.
    pub fn max_storage_bytes(&self) -> usize {
        self.config.max_storage_bytes
    }

    /// Evict bundles to make room for `needed_bytes`.
    ///
    /// Only relay traffic is ever evicted, oldest-first. A local bundle is a
    /// message the user composed and the node has not yet delivered; nothing
    /// may displace it, not even another local bundle. Once the store holds
    /// only local bundles it is full, and the caller gets `StorageFull` —
    /// a visible send failure, rather than silently deleting mail the user
    /// cannot re-create (ROADMAP T-11).
    fn evict_if_needed(&mut self, needed_bytes: usize) -> Result<(), DtnError> {
        // First expire anything past TTL
        self.expire_bundles();

        // Phase 1: relay traffic, oldest first.
        while self.total_stored_bytes + needed_bytes > self.config.max_storage_bytes {
            let oldest_relay = self
                .bundles
                .iter()
                .filter(|(_, b)| !b.is_local)
                .min_by_key(|(_, b)| b.created_at)
                .map(|(id, _)| *id);

            match oldest_relay {
                Some(id) => self.remove_bundle(&id),
                None => break,
            }
        }

        if self.total_stored_bytes + needed_bytes <= self.config.max_storage_bytes {
            return Ok(());
        }

        // Nothing but local bundles left. A local bundle is a message the user
        // composed and cannot re-create, so it is never evicted — not even for
        // another local bundle. The send fails visibly instead.
        Err(DtnError::StorageFull)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DtnError {
    #[error("per-identity storage quota exceeded")]
    QuotaExceeded,
    #[error("DTN storage is full")]
    StorageFull,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(byte: u8) -> NodeId {
        NodeId([byte; 32])
    }

    #[test]
    fn test_store_and_retrieve() {
        let mut engine = DtnEngine::new(DtnConfig::default());
        let msg_id = MessageId::random();

        engine
            .store_outgoing(msg_id, node(2), node(1), b"encrypted blob".to_vec())
            .unwrap();

        assert_eq!(engine.bundle_count(), 1);
        let bundle = engine.get_bundle(&msg_id).unwrap();
        assert_eq!(bundle.destination, node(2));
        assert_eq!(bundle.copies_remaining, 8);
    }

    #[test]
    fn test_store_outgoing_twice_does_not_double_count() {
        let mut engine = DtnEngine::new(DtnConfig::default());
        let msg_id = MessageId::random();
        engine
            .store_outgoing(msg_id, node(2), node(1), vec![0u8; 100])
            .unwrap();
        engine
            .store_outgoing(msg_id, node(2), node(1), vec![0u8; 100])
            .unwrap();
        assert_eq!(engine.bundle_count(), 1);
        assert_eq!(engine.storage_used(), 100);
        engine.remove_bundle(&msg_id);
        assert_eq!(engine.storage_used(), 0);
        assert!(engine.per_source_bytes.is_empty());
    }

    #[test]
    fn test_spray_to_relay() {
        let mut engine = DtnEngine::new(DtnConfig::default());
        let msg_id = MessageId::random();

        engine
            .store_outgoing(msg_id, node(3), node(1), b"blob".to_vec())
            .unwrap();

        // Encounter node 2 (a relay, not the destination)
        let actions = engine.on_neighbor_encountered(node(2), &node(1));
        let spray_actions: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, DtnAction::SendToPeer { .. }))
            .collect();
        assert_eq!(spray_actions.len(), 1);

        // Our copies should have decreased
        let bundle = engine.get_bundle(&msg_id).unwrap();
        assert_eq!(bundle.copies_remaining, 4); // Started with 8, gave 4

        // Encountering same relay again should NOT re-spray
        let actions = engine.on_neighbor_encountered(node(2), &node(1));
        let spray_actions: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, DtnAction::SendToPeer { .. }))
            .collect();
        assert_eq!(spray_actions.len(), 0);
    }

    #[test]
    fn test_deliver_to_destination() {
        let mut engine = DtnEngine::new(DtnConfig::default());
        let msg_id = MessageId::random();

        engine
            .store_outgoing(msg_id, node(3), node(1), b"blob".to_vec())
            .unwrap();

        // Encounter the actual destination — should SendToPeer, not DeliverLocal
        let actions = engine.on_neighbor_encountered(node(3), &node(1));
        let send_actions: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, DtnAction::SendToPeer { .. }))
            .collect();
        assert_eq!(send_actions.len(), 1);

        // Verify the bundle is sent to the destination peer
        if let DtnAction::SendToPeer { peer, bundle } = &send_actions[0] {
            assert_eq!(*peer, node(3));
            assert_eq!(bundle.destination, node(3));
        }
    }

    #[test]
    fn test_per_identity_quota() {
        let config = DtnConfig {
            per_identity_quota_bytes: 100,
            ..Default::default()
        };
        let mut engine = DtnEngine::new(config);

        // First store should work
        engine
            .store_outgoing(MessageId::random(), node(2), node(1), vec![0u8; 80])
            .unwrap();

        // Second store should fail (would exceed 100-byte quota)
        let result = engine.store_outgoing(MessageId::random(), node(2), node(1), vec![0u8; 30]);
        assert!(result.is_err());
    }

    /// Relay traffic is evicted oldest-first. (Local bundles are never
    /// evicted at all; see `test_local_bundle_does_not_evict_older_local_bundle`.)
    #[test]
    fn test_eviction_oldest_first() {
        let config = DtnConfig {
            max_storage_bytes: 100,
            per_identity_quota_bytes: 200, // Large enough to not be the limit
            ..Default::default()
        };
        let mut engine = DtnEngine::new(config);

        // Relay traffic: this is what eviction operates on. The test used to
        // store local bundles, which are no longer evictable at all.
        let first = relay_bundle(40, node(1));
        let second = relay_bundle(40, node(1));
        let (msg1, msg2) = (first.message_id, second.message_id);
        engine.store_relay(first).unwrap();
        engine.store_relay(second).unwrap();

        // This should evict msg1 (oldest) to make room
        engine.store_relay(relay_bundle(40, node(1))).unwrap();

        assert!(engine.get_bundle(&msg1).is_none());
        assert!(engine.get_bundle(&msg2).is_some());
    }

    fn relay_bundle(size: usize, source: NodeId) -> DtnBundle {
        DtnBundle {
            message_id: MessageId::random(),
            destination: node(9),
            source,
            payload: vec![0u8; size],
            copies_remaining: 4,
            expires_at: Instant::now() + Duration::from_secs(3600),
            created_at: Instant::now(),
            size,
            is_local: false,
        }
    }

    /// Relaying mail for other nodes must never delete the user's own.
    ///
    /// Regression test for ROADMAP T-11: eviction picked the globally oldest
    /// bundle, so a node that relays enough traffic silently dropped its own
    /// unsent messages — the one thing in the store the user cannot re-create.
    #[test]
    fn test_relay_traffic_never_evicts_local_bundles() {
        let config = DtnConfig {
            max_storage_bytes: 100,
            per_identity_quota_bytes: 10_000,
            ..Default::default()
        };
        let mut engine = DtnEngine::new(config);

        // Our own outgoing message, stored first so it is also the oldest.
        let ours = MessageId::random();
        engine
            .store_outgoing(ours, node(2), node(1), vec![0u8; 40])
            .unwrap();

        // Relay traffic that more than fills the rest of the store.
        let first_relay = relay_bundle(40, node(3));
        let first_relay_id = first_relay.message_id;
        engine.store_relay(first_relay).unwrap();

        let second_relay = relay_bundle(40, node(4));
        let second_relay_id = second_relay.message_id;
        engine.store_relay(second_relay).unwrap();

        // Our bundle survives; the oldest relay bundle was evicted for it.
        assert!(
            engine.get_bundle(&ours).is_some(),
            "the user's own bundle must survive relay pressure"
        );
        assert!(
            engine.get_bundle(&first_relay_id).is_none(),
            "the oldest relay bundle should have been evicted"
        );
        assert!(engine.get_bundle(&second_relay_id).is_some());
    }

    /// When only local bundles remain there is nothing a relay bundle may
    /// displace, so the store is full and the relay bundle is refused.
    #[test]
    fn test_relay_refused_when_store_holds_only_local_bundles() {
        let config = DtnConfig {
            max_storage_bytes: 100,
            per_identity_quota_bytes: 10_000,
            ..Default::default()
        };
        let mut engine = DtnEngine::new(config);

        let ours = MessageId::random();
        engine
            .store_outgoing(ours, node(2), node(1), vec![0u8; 90])
            .unwrap();

        let err = engine.store_relay(relay_bundle(40, node(3)));
        assert!(
            matches!(err, Err(DtnError::StorageFull)),
            "expected StorageFull, got {err:?}"
        );
        assert!(engine.get_bundle(&ours).is_some());
    }

    /// A local bundle does not displace an older local bundle either. The
    /// user's outbox is not a ring buffer: when it is full the new send fails
    /// visibly and the queued messages are kept.
    #[test]
    fn test_local_bundle_does_not_evict_older_local_bundle() {
        let config = DtnConfig {
            max_storage_bytes: 100,
            per_identity_quota_bytes: 10_000,
            ..Default::default()
        };
        let mut engine = DtnEngine::new(config);

        let older = MessageId::random();
        engine
            .store_outgoing(older, node(2), node(1), vec![0u8; 60])
            .unwrap();

        let err = engine.store_outgoing(MessageId::random(), node(2), node(1), vec![0u8; 60]);
        assert!(
            matches!(err, Err(DtnError::StorageFull)),
            "expected StorageFull, got {err:?}"
        );
        assert!(
            engine.get_bundle(&older).is_some(),
            "the already-queued message must be kept"
        );
    }

    /// A restored bundle keeps its spray history, so a restart does not hand a
    /// second copy to a peer that already holds one (ROADMAP T-11).
    #[test]
    fn test_restored_bundle_does_not_respray_known_holders() {
        let mut engine = DtnEngine::new(DtnConfig::default());

        let already_holds = node(5);
        let mut bundle = relay_bundle(16, node(1));
        bundle.copies_remaining = 4;
        let msg_id = bundle.message_id;

        engine.store_restored(bundle, vec![already_holds]).unwrap();
        assert_eq!(engine.sprayed_to(&msg_id), &[already_holds]);

        // Meeting that peer again must not produce another spray.
        let actions = engine.on_neighbor_encountered(already_holds, &node(1));
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, DtnAction::SendToPeer { peer, .. } if *peer == already_holds)),
            "must not re-spray to a peer recorded in the restored spray history"
        );

        // A peer with no recorded copy still gets one.
        let fresh_peer = node(6);
        let actions = engine.on_neighbor_encountered(fresh_peer, &node(1));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, DtnAction::SendToPeer { peer, .. } if *peer == fresh_peer)),
            "a peer that holds no copy should still be sprayed"
        );
    }

    /// `store_restored` keeps the origin flag; `store_relay` forces it off.
    #[test]
    fn test_restore_preserves_origin_but_store_relay_does_not() {
        let mut engine = DtnEngine::new(DtnConfig::default());

        let mut local = relay_bundle(16, node(1));
        local.is_local = true;
        let local_id = local.message_id;
        engine.store_restored(local, Vec::new()).unwrap();
        assert!(
            engine.get_bundle(&local_id).unwrap().is_local,
            "a restored local bundle must stay local"
        );

        let mut claims_local = relay_bundle(16, node(2));
        claims_local.is_local = true;
        let claimed_id = claims_local.message_id;
        engine.store_relay(claims_local).unwrap();
        assert!(
            !engine.get_bundle(&claimed_id).unwrap().is_local,
            "a bundle arriving from the wire is relay traffic whatever it claims"
        );
    }
}
