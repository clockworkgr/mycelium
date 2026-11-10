use std::collections::HashMap;
use std::time::{Duration, Instant};

use mycelium_protocol::types::NodeId;

/// Trust-distance-based rate limits per spec Section 11.
#[derive(Debug, Clone)]
pub struct RateLimitTier {
    pub messages_per_hour: u32,
    pub dtn_relay_quota_bytes: usize,
}

impl RateLimitTier {
    /// Get rate limit tier based on trust hop distance.
    pub fn for_trust_distance(hops: u8) -> Self {
        match hops {
            0 => Self {
                messages_per_hour: u32::MAX,
                dtn_relay_quota_bytes: 50 * 1024 * 1024,
            },
            1 => Self {
                messages_per_hour: u32::MAX,
                dtn_relay_quota_bytes: 50 * 1024 * 1024,
            },
            2 => Self {
                messages_per_hour: 500,
                dtn_relay_quota_bytes: 10 * 1024 * 1024,
            },
            3 => Self {
                messages_per_hour: 100,
                dtn_relay_quota_bytes: 2 * 1024 * 1024,
            },
            4 => Self {
                messages_per_hour: 20,
                dtn_relay_quota_bytes: 500 * 1024,
            },
            _ => Self {
                // Unknown / no trust path
                messages_per_hour: 5,
                dtn_relay_quota_bytes: 100 * 1024,
            },
        }
    }
}

/// Per-node rate tracking.
#[derive(Debug)]
struct NodeRateState {
    /// Message timestamps in the current window.
    message_times: Vec<Instant>,
    /// DTN relay bytes used in current window.
    dtn_bytes_used: usize,
    /// When the current window started.
    window_start: Instant,
}

impl NodeRateState {
    fn new() -> Self {
        Self {
            message_times: Vec::new(),
            dtn_bytes_used: 0,
            window_start: Instant::now(),
        }
    }

    fn reset_if_expired(&mut self) {
        let window = Duration::from_secs(3600);
        if self.window_start.elapsed() > window {
            self.message_times.clear();
            self.dtn_bytes_used = 0;
            self.window_start = Instant::now();
        }
    }
}

/// Trust-based rate limiter per spec Section 11.
pub struct RateLimiter {
    states: HashMap<NodeId, NodeRateState>,
    /// Temporarily blacklisted nodes.
    blacklist: HashMap<NodeId, Instant>,
    /// Blacklist duration.
    blacklist_duration: Duration,
    /// Rate violation counts for auto-blacklisting.
    violations: HashMap<NodeId, u32>,
    /// Number of violations before auto-blacklist.
    blacklist_threshold: u32,
    /// When the violation counters were last reset (they cover one hour).
    violations_reset_at: Instant,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            blacklist: HashMap::new(),
            blacklist_duration: Duration::from_secs(3600), // 1 hour
            violations: HashMap::new(),
            blacklist_threshold: 10, // Auto-blacklist after 10 violations per hour
            violations_reset_at: Instant::now(),
        }
    }

    /// Check if a message from this node should be allowed.
    /// Returns true if allowed, false if rate limited.
    pub fn check_message(&mut self, node: &NodeId, trust_hops: u8) -> bool {
        // Check blacklist
        if let Some(until) = self.blacklist.get(node) {
            if Instant::now() < *until {
                return false;
            }
            self.blacklist.remove(node);
        }

        let tier = RateLimitTier::for_trust_distance(trust_hops);

        let state = self.states.entry(*node).or_insert_with(NodeRateState::new);
        state.reset_if_expired();

        if state.message_times.len() as u32 >= tier.messages_per_hour {
            return false;
        }

        state.message_times.push(Instant::now());
        true
    }

    /// Check if DTN relay storage for a node is within quota.
    pub fn check_dtn_relay(
        &mut self,
        node: &NodeId,
        trust_hops: u8,
        additional_bytes: usize,
    ) -> bool {
        let tier = RateLimitTier::for_trust_distance(trust_hops);

        let state = self.states.entry(*node).or_insert_with(NodeRateState::new);
        state.reset_if_expired();

        if state.dtn_bytes_used + additional_bytes > tier.dtn_relay_quota_bytes {
            return false;
        }

        state.dtn_bytes_used += additional_bytes;
        true
    }

    /// Temporarily blacklist a node (persistent violator).
    pub fn blacklist_node(&mut self, node: NodeId) {
        self.blacklist
            .insert(node, Instant::now() + self.blacklist_duration);
    }

    /// Record a rate violation. Auto-blacklists after threshold is reached.
    /// Returns true if the node was auto-blacklisted.
    pub fn record_violation(&mut self, node: &NodeId) -> bool {
        let count = self.violations.entry(*node).or_insert(0);
        *count += 1;
        if *count >= self.blacklist_threshold {
            self.blacklist_node(*node);
            self.violations.remove(node);
            true
        } else {
            false
        }
    }

    /// Check if a node is blacklisted.
    pub fn is_blacklisted(&self, node: &NodeId) -> bool {
        self.blacklist
            .get(node)
            .map(|until| Instant::now() < *until)
            .unwrap_or(false)
    }

    /// Clean up expired state. Safe to call often: violation counters are
    /// only reset once per hour so the "10 violations per hour" threshold is
    /// meaningful regardless of the maintenance interval.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.blacklist.retain(|_, until| now < *until);
        self.states
            .retain(|_, s| s.window_start.elapsed() < Duration::from_secs(2 * 3600));
        if self.violations_reset_at.elapsed() >= Duration::from_secs(3600) {
            self.violations.clear();
            self.violations_reset_at = now;
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(byte: u8) -> NodeId {
        NodeId([byte; 32])
    }

    #[test]
    fn test_direct_trust_unlimited() {
        let mut rl = RateLimiter::new();
        let n = node(1);

        // Direct trust (1 hop) should allow many messages
        for _ in 0..1000 {
            assert!(rl.check_message(&n, 1));
        }
    }

    #[test]
    fn test_unknown_node_limited() {
        let mut rl = RateLimiter::new();
        let n = node(1);

        // Unknown node (255 hops) gets 5 messages per hour
        for _ in 0..5 {
            assert!(rl.check_message(&n, 255));
        }
        // 6th should be denied
        assert!(!rl.check_message(&n, 255));
    }

    #[test]
    fn test_dtn_quota() {
        let mut rl = RateLimiter::new();
        let n = node(1);

        // 3-hop trust: 2MB quota
        assert!(rl.check_dtn_relay(&n, 3, 1_000_000)); // 1MB ok
        assert!(rl.check_dtn_relay(&n, 3, 1_000_000)); // 2MB total ok
        assert!(!rl.check_dtn_relay(&n, 3, 500_000)); // 2.5MB would exceed
    }

    #[test]
    fn test_cleanup_keeps_violations_within_the_hour() {
        let mut rl = RateLimiter::new();
        let n = node(1);
        for _ in 0..5 {
            assert!(!rl.record_violation(&n));
        }
        rl.cleanup();
        // Five more within the same hour must reach the threshold of ten.
        let mut blacklisted = false;
        for _ in 0..5 {
            blacklisted |= rl.record_violation(&n);
        }
        assert!(blacklisted);
        assert!(rl.is_blacklisted(&n));
    }

    #[test]
    fn test_blacklist() {
        let mut rl = RateLimiter::new();
        let n = node(1);

        assert!(!rl.is_blacklisted(&n));
        rl.blacklist_node(n);
        assert!(rl.is_blacklisted(&n));
        assert!(!rl.check_message(&n, 1)); // Even direct trust blocked
    }
}
