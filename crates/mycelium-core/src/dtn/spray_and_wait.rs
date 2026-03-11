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
            ttl: Duration::from_secs(72 * 3600), // 72 hours
            max_storage_bytes: 256 * 1024 * 1024, // 256 MB (phone default)
            per_identity_quota_bytes: 10 * 1024 * 1024, // 10 MB per identity
        }
    }
}

impl DtnConfig {
    /// Supernode configuration with larger storage.
    pub fn supernode() -> Self {
        Self {
            max_storage_bytes: 2 * 1024 * 1024 * 1024, // 2 GB
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
    pub fn store_relay(
        &mut self,
        bundle: DtnBundle,
    ) -> Result<(), DtnError> {
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
                    trace!("Bundle {} delivered to destination {}", bundle.message_id, bundle.destination);
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

    /// Evict oldest bundles to make room for `needed_bytes`.
    fn evict_if_needed(&mut self, needed_bytes: usize) -> Result<(), DtnError> {
        // First expire anything past TTL
        self.expire_bundles();

        while self.total_stored_bytes + needed_bytes > self.config.max_storage_bytes {
            // Find oldest bundle
            let oldest = self
                .bundles
                .iter()
                .min_by_key(|(_, b)| b.created_at)
                .map(|(id, _)| *id);

            match oldest {
                Some(id) => self.remove_bundle(&id),
                None => return Err(DtnError::StorageFull),
            }
        }

        Ok(())
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
            .store_outgoing(
                MessageId::random(),
                node(2),
                node(1),
                vec![0u8; 80],
            )
            .unwrap();

        // Second store should fail (would exceed 100-byte quota)
        let result = engine.store_outgoing(
            MessageId::random(),
            node(2),
            node(1),
            vec![0u8; 30],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_eviction_oldest_first() {
        let config = DtnConfig {
            max_storage_bytes: 100,
            per_identity_quota_bytes: 200, // Large enough to not be the limit
            ..Default::default()
        };
        let mut engine = DtnEngine::new(config);

        let msg1 = MessageId::random();
        let msg2 = MessageId::random();
        engine
            .store_outgoing(msg1, node(2), node(1), vec![0u8; 40])
            .unwrap();
        engine
            .store_outgoing(msg2, node(2), node(1), vec![0u8; 40])
            .unwrap();

        // This should evict msg1 (oldest) to make room
        engine
            .store_outgoing(MessageId::random(), node(2), node(1), vec![0u8; 40])
            .unwrap();

        assert!(engine.get_bundle(&msg1).is_none());
        assert!(engine.get_bundle(&msg2).is_some());
    }
}
