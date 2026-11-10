use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use mycelium_protocol::types::NodeId;
use tracing::{debug, trace};

/// An entry in the AODV routing table.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub destination: NodeId,
    pub next_hop: NodeId,
    pub hop_count: u8,
    pub sequence_number: u32,
    pub lifetime: Instant,
    pub is_valid: bool,
}

/// Route Request record for deduplication.
#[derive(Debug, Clone)]
struct RreqRecord {
    source: NodeId,
    request_id: u32,
    received_at: Instant,
}

/// Upper bound on routing-table entries. Every RREQ from a new source and
/// every forwarded envelope inserts an entry, so the table must be capped
/// against network input.
const MAX_ROUTES: usize = 4096;

/// AODV reactive routing implementation per spec Section 4.1 Layer 1.
pub struct AodvRouter {
    /// Our node identity.
    local_id: NodeId,
    /// Routing table: destination -> route entry.
    routes: HashMap<NodeId, RouteEntry>,
    /// Our monotonic sequence number.
    sequence_number: u32,
    /// Next RREQ ID.
    next_rreq_id: u32,
    /// Recently seen RREQs for dedup (source + rreq_id).
    seen_rreqs: Vec<RreqRecord>,
    /// Route lifetime duration.
    route_lifetime: Duration,
    /// RREQ dedup window.
    rreq_dedup_window: Duration,
    /// Known supernode peers — routes via supernodes get preference.
    known_supernodes: HashSet<NodeId>,
}

/// AODV control messages.
#[derive(Debug, Clone)]
pub enum AodvMessage {
    RouteRequest(RouteRequest),
    RouteReply(RouteReply),
    RouteError(RouteError),
}

#[derive(Debug, Clone)]
pub struct RouteRequest {
    pub request_id: u32,
    pub source: NodeId,
    pub source_seq: u32,
    pub destination: NodeId,
    pub dest_seq: u32,
    pub hop_count: u8,
    pub ttl: u8,
}

#[derive(Debug, Clone)]
pub struct RouteReply {
    pub request_id: u32,
    pub source: NodeId,
    pub destination: NodeId,
    pub dest_seq: u32,
    pub hop_count: u8,
    pub lifetime_secs: u32,
}

#[derive(Debug, Clone)]
pub struct RouteError {
    pub unreachable: NodeId,
    pub source: NodeId,
    pub dest_seq: u32,
}

/// Result of processing an AODV message: actions the node should take.
#[derive(Debug)]
pub enum AodvAction {
    /// Broadcast this RREQ to all neighbors.
    BroadcastRreq(RouteRequest),
    /// Send this RREP unicast toward the source.
    UnicastRrep { next_hop: NodeId, rrep: RouteReply },
    /// Forward RERR to neighbors.
    BroadcastRerr(RouteError),
    /// Route found: data can be sent via this next hop.
    RouteFound {
        destination: NodeId,
        next_hop: NodeId,
    },
    /// No action needed (duplicate, etc).
    None,
}

impl AodvRouter {
    pub fn new(local_id: NodeId) -> Self {
        Self {
            local_id,
            routes: HashMap::new(),
            sequence_number: 0,
            next_rreq_id: 0,
            seen_rreqs: Vec::new(),
            route_lifetime: Duration::from_secs(300),
            rreq_dedup_window: Duration::from_secs(10),
            known_supernodes: HashSet::new(),
        }
    }

    /// Add a direct neighbor as a route (1 hop, neighbor is next_hop).
    ///
    /// A direct link is always preferred over a multi-hop route to the same
    /// node, so an existing valid multi-hop route is replaced. The last known
    /// sequence number is retained so the entry is not considered stale.
    pub fn add_neighbor_route(&mut self, neighbor: NodeId) {
        let (should_insert, sequence_number) = match self.routes.get(&neighbor) {
            None => (true, 0),
            Some(existing) => (
                !existing.is_valid
                    || existing.lifetime < Instant::now()
                    || existing.hop_count > 1
                    || existing.next_hop != neighbor,
                existing.sequence_number,
            ),
        };
        if should_insert {
            self.evict_if_full(&neighbor);
            self.routes.insert(
                neighbor,
                RouteEntry {
                    destination: neighbor,
                    next_hop: neighbor,
                    hop_count: 1,
                    sequence_number,
                    lifetime: Instant::now() + self.route_lifetime,
                    is_valid: true,
                },
            );
            debug!("Added direct neighbor route to {}", neighbor);
        }
    }

    /// Refresh an existing neighbor route lifetime (called periodically for active neighbors).
    pub fn refresh_neighbor_route(&mut self, neighbor: NodeId) {
        if let Some(entry) = self.routes.get_mut(&neighbor) {
            if entry.hop_count == 1 && entry.next_hop == neighbor {
                entry.lifetime = Instant::now() + self.route_lifetime;
                entry.is_valid = true;
            }
        }
    }

    /// Initiate route discovery for a destination. Returns RREQ to broadcast.
    pub fn initiate_route_discovery(&mut self, destination: NodeId) -> RouteRequest {
        self.sequence_number += 1;
        self.next_rreq_id += 1;

        let dest_seq = self
            .routes
            .get(&destination)
            .map(|r| r.sequence_number)
            .unwrap_or(0);

        let rreq = RouteRequest {
            request_id: self.next_rreq_id,
            source: self.local_id,
            source_seq: self.sequence_number,
            destination,
            dest_seq,
            hop_count: 0,
            ttl: 10,
        };

        // Record our own RREQ so its echo from a neighbor is treated as a
        // duplicate instead of installing a route to ourselves and being
        // rebroadcast.
        self.cleanup_seen_rreqs();
        self.seen_rreqs.push(RreqRecord {
            source: self.local_id,
            request_id: rreq.request_id,
            received_at: Instant::now(),
        });

        debug!(
            "Initiating route discovery for {} (rreq_id={})",
            destination, rreq.request_id
        );

        rreq
    }

    /// Look up a route to a destination.
    pub fn find_route(&self, destination: &NodeId) -> Option<&RouteEntry> {
        self.routes.get(destination).and_then(|entry| {
            if entry.is_valid && entry.lifetime > Instant::now() {
                Some(entry)
            } else {
                None
            }
        })
    }

    /// Process an incoming RREQ. Returns action to take.
    pub fn handle_rreq(&mut self, mut rreq: RouteRequest, received_from: NodeId) -> AodvAction {
        // Our own RREQ echoed back by a neighbor: never a route to ourselves.
        if rreq.source == self.local_id {
            return AodvAction::None;
        }

        // Dedup: have we seen this RREQ recently?
        self.cleanup_seen_rreqs();
        if self.is_duplicate_rreq(&rreq) {
            trace!(
                "Duplicate RREQ {} from {}, ignoring",
                rreq.request_id,
                rreq.source
            );
            return AodvAction::None;
        }

        // Record this RREQ
        self.seen_rreqs.push(RreqRecord {
            source: rreq.source,
            request_id: rreq.request_id,
            received_at: Instant::now(),
        });

        // Create/update reverse route to source
        self.update_route(
            rreq.source,
            received_from,
            rreq.hop_count.saturating_add(1),
            rreq.source_seq,
        );

        // Are we the destination?
        if rreq.destination == self.local_id {
            self.sequence_number += 1;
            let rrep = RouteReply {
                request_id: rreq.request_id,
                source: rreq.source,
                destination: self.local_id,
                dest_seq: self.sequence_number,
                hop_count: 0,
                lifetime_secs: self.route_lifetime.as_secs() as u32,
            };
            debug!(
                "We are the destination, sending RREP for rreq_id={}",
                rreq.request_id
            );
            return AodvAction::UnicastRrep {
                next_hop: received_from,
                rrep,
            };
        }

        // Do we have a fresh route to the destination? Never answer with a
        // route that points back through the requester or the previous hop:
        // that would create a two-node forwarding loop.
        if let Some(route) = self.routes.get(&rreq.destination) {
            if route.is_valid
                && route.lifetime > Instant::now()
                && route.sequence_number >= rreq.dest_seq
                && route.next_hop != received_from
                && route.next_hop != rreq.source
            {
                let rrep = RouteReply {
                    request_id: rreq.request_id,
                    source: rreq.source,
                    destination: rreq.destination,
                    dest_seq: route.sequence_number,
                    hop_count: route.hop_count,
                    lifetime_secs: route.lifetime.duration_since(Instant::now()).as_secs() as u32,
                };
                debug!(
                    "Intermediate reply for {} via cached route (rreq_id={})",
                    rreq.destination, rreq.request_id
                );
                return AodvAction::UnicastRrep {
                    next_hop: received_from,
                    rrep,
                };
            }
        }

        // Forward RREQ if TTL allows
        if rreq.ttl > 0 {
            rreq.hop_count = rreq.hop_count.saturating_add(1);
            rreq.ttl -= 1;
            AodvAction::BroadcastRreq(rreq)
        } else {
            AodvAction::None
        }
    }

    /// Process an incoming RREP. Returns action to take.
    pub fn handle_rrep(&mut self, mut rrep: RouteReply, received_from: NodeId) -> AodvAction {
        // Create/update forward route to destination
        self.update_route(
            rrep.destination,
            received_from,
            rrep.hop_count.saturating_add(1),
            rrep.dest_seq,
        );

        // Are we the source of the original RREQ?
        if rrep.source == self.local_id {
            debug!(
                "Route found to {} via {} ({} hops)",
                rrep.destination,
                received_from,
                rrep.hop_count.saturating_add(1)
            );
            return AodvAction::RouteFound {
                destination: rrep.destination,
                next_hop: received_from,
            };
        }

        // Forward RREP toward the source
        if let Some(route) = self.routes.get(&rrep.source) {
            let next_hop = route.next_hop;
            rrep.hop_count = rrep.hop_count.saturating_add(1);
            AodvAction::UnicastRrep { next_hop, rrep }
        } else {
            debug!("No reverse route to {}, dropping RREP", rrep.source);
            AodvAction::None
        }
    }

    /// Process an incoming RERR from `received_from`. Returns action to take.
    ///
    /// Invalidates routes that go through the unreachable node, and routes to
    /// the unreachable node whose next hop is the RERR sender (the upstream
    /// case: A→B→C where B reports C lost must invalidate A's route to C).
    /// Only a valid→invalid transition triggers a rebroadcast, so an RERR
    /// cannot ping-pong between neighbors indefinitely.
    pub fn handle_rerr(&mut self, rerr: RouteError, received_from: NodeId) -> AodvAction {
        let mut affected = false;
        for entry in self.routes.values_mut() {
            if !entry.is_valid {
                continue;
            }
            let via_unreachable = entry.next_hop == rerr.unreachable;
            let upstream = entry.destination == rerr.unreachable && entry.next_hop == received_from;
            if via_unreachable || upstream {
                entry.is_valid = false;
                affected = true;
            }
        }

        if affected {
            AodvAction::BroadcastRerr(rerr)
        } else {
            AodvAction::None
        }
    }

    /// Report a link break to a neighbor.
    pub fn report_link_break(&mut self, broken_neighbor: NodeId) -> Option<RouteError> {
        let mut any_invalidated = false;
        for entry in self.routes.values_mut() {
            if entry.next_hop == broken_neighbor && entry.is_valid {
                entry.is_valid = false;
                any_invalidated = true;
            }
        }

        if any_invalidated {
            self.sequence_number += 1;
            Some(RouteError {
                unreachable: broken_neighbor,
                source: self.local_id,
                dest_seq: self.sequence_number,
            })
        } else {
            None
        }
    }

    /// Expire stale routes and prune entries that have been invalid for a
    /// full lifetime, so the table does not grow without bound.
    pub fn expire_routes(&mut self) {
        let now = Instant::now();
        for entry in self.routes.values_mut() {
            if entry.is_valid && entry.lifetime < now {
                entry.is_valid = false;
            }
        }
        let grace = self.route_lifetime;
        self.routes
            .retain(|_, e| e.is_valid || e.lifetime + grace > now);
    }

    /// Make room for a new destination when the table is at capacity by
    /// dropping the entry with the earliest lifetime (invalid ones first).
    fn evict_if_full(&mut self, incoming: &NodeId) {
        if self.routes.len() < MAX_ROUTES || self.routes.contains_key(incoming) {
            return;
        }
        let victim = self
            .routes
            .values()
            .min_by_key(|e| (e.is_valid, e.lifetime))
            .map(|e| e.destination);
        if let Some(v) = victim {
            self.routes.remove(&v);
        }
    }

    pub fn update_route(
        &mut self,
        destination: NodeId,
        next_hop: NodeId,
        hop_count: u8,
        sequence_number: u32,
    ) {
        let lifetime = Instant::now() + self.route_lifetime;

        let should_update = match self.routes.get(&destination) {
            None => true,
            Some(existing) => {
                let existing_is_direct = existing.is_valid
                    && existing.lifetime > Instant::now()
                    && existing.hop_count == 1
                    && existing.next_hop == destination;
                if existing_is_direct && hop_count > 1 {
                    // A live direct link beats any learned multi-hop route.
                    // Keep the fresher sequence number so the entry is not
                    // considered stale by later comparisons.
                    if let Some(e) = self.routes.get_mut(&destination) {
                        e.sequence_number = e.sequence_number.max(sequence_number);
                    }
                    false
                } else if sequence_number > existing.sequence_number || !existing.is_valid {
                    true
                } else if sequence_number == existing.sequence_number {
                    if hop_count < existing.hop_count {
                        true
                    } else if hop_count == existing.hop_count {
                        // Same hops + same seq: prefer supernode next-hop
                        let new_via_supernode = self.known_supernodes.contains(&next_hop);
                        let old_via_supernode = self.known_supernodes.contains(&existing.next_hop);
                        new_via_supernode && !old_via_supernode
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        };

        if should_update {
            self.evict_if_full(&destination);
            self.routes.insert(
                destination,
                RouteEntry {
                    destination,
                    next_hop,
                    hop_count,
                    sequence_number,
                    lifetime,
                    is_valid: true,
                },
            );
        }
    }

    fn is_duplicate_rreq(&self, rreq: &RouteRequest) -> bool {
        self.seen_rreqs
            .iter()
            .any(|r| r.source == rreq.source && r.request_id == rreq.request_id)
    }

    /// Return all routes in the routing table (for diagnostics).
    pub fn routes(&self) -> &HashMap<NodeId, RouteEntry> {
        &self.routes
    }

    fn cleanup_seen_rreqs(&mut self) {
        let cutoff = Instant::now() - self.rreq_dedup_window;
        self.seen_rreqs.retain(|r| r.received_at > cutoff);
    }

    /// Register a peer as a supernode. Routes via supernodes get preference.
    pub fn register_supernode(&mut self, node_id: NodeId) {
        self.known_supernodes.insert(node_id);
    }

    /// Check if a peer is a known supernode.
    pub fn is_supernode(&self, node_id: &NodeId) -> bool {
        self.known_supernodes.contains(node_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(byte: u8) -> NodeId {
        NodeId([byte; 32])
    }

    #[test]
    fn test_route_discovery_and_reply() {
        let mut router_a = AodvRouter::new(node(1));
        let mut router_b = AodvRouter::new(node(2));
        let mut router_c = AodvRouter::new(node(3));

        // A wants to reach C: A->B->C
        let rreq = router_a.initiate_route_discovery(node(3));

        // B receives RREQ from A
        let action = router_b.handle_rreq(rreq.clone(), node(1));
        let forwarded_rreq = match action {
            AodvAction::BroadcastRreq(rreq) => rreq,
            _ => panic!("expected broadcast"),
        };

        // C receives RREQ from B — C is the destination
        let action = router_c.handle_rreq(forwarded_rreq, node(2));
        let (next_hop, rrep) = match action {
            AodvAction::UnicastRrep { next_hop, rrep } => (next_hop, rrep),
            _ => panic!("expected unicast rrep"),
        };
        assert_eq!(next_hop, node(2));

        // B receives RREP from C, forwards toward A
        let action = router_b.handle_rrep(rrep, node(3));
        let (next_hop, rrep) = match action {
            AodvAction::UnicastRrep { next_hop, rrep } => (next_hop, rrep),
            _ => panic!("expected unicast rrep forwarded to A"),
        };
        assert_eq!(next_hop, node(1));

        // A receives RREP
        let action = router_a.handle_rrep(rrep, node(2));
        match action {
            AodvAction::RouteFound {
                destination,
                next_hop,
            } => {
                assert_eq!(destination, node(3));
                assert_eq!(next_hop, node(2));
            }
            _ => panic!("expected route found"),
        }

        // A should now have a route to C via B
        let route = router_a.find_route(&node(3)).unwrap();
        assert_eq!(route.next_hop, node(2));
    }

    #[test]
    fn test_rreq_dedup() {
        let mut router = AodvRouter::new(node(2));
        let rreq = RouteRequest {
            request_id: 1,
            source: node(1),
            source_seq: 1,
            destination: node(3),
            dest_seq: 0,
            hop_count: 0,
            ttl: 10,
        };

        // First time: should forward
        let action = router.handle_rreq(rreq.clone(), node(1));
        assert!(matches!(action, AodvAction::BroadcastRreq(_)));

        // Second time: should ignore (duplicate)
        let action = router.handle_rreq(rreq, node(1));
        assert!(matches!(action, AodvAction::None));
    }

    #[test]
    fn test_link_break() {
        let mut router = AodvRouter::new(node(1));

        // Manually insert a route
        router.update_route(node(3), node(2), 2, 1);
        assert!(router.find_route(&node(3)).is_some());

        // Report link break to node 2
        let rerr = router.report_link_break(node(2));
        assert!(rerr.is_some());

        // Route should now be invalid
        assert!(router.find_route(&node(3)).is_none());
    }

    #[test]
    fn test_better_route_replaces_worse() {
        let mut router = AodvRouter::new(node(1));

        // Insert a 5-hop route
        router.update_route(node(5), node(2), 5, 1);
        assert_eq!(router.find_route(&node(5)).unwrap().hop_count, 5);

        // Insert a 2-hop route with same seq
        router.update_route(node(5), node(3), 2, 1);
        assert_eq!(router.find_route(&node(5)).unwrap().hop_count, 2);
        assert_eq!(router.find_route(&node(5)).unwrap().next_hop, node(3));
    }

    #[test]
    fn test_add_neighbor_route() {
        let mut router = AodvRouter::new(node(1));

        // No route initially
        assert!(router.find_route(&node(2)).is_none());

        // Add neighbor route
        router.add_neighbor_route(node(2));

        // Should now have a 1-hop direct route
        let route = router.find_route(&node(2)).unwrap();
        assert_eq!(route.next_hop, node(2));
        assert_eq!(route.hop_count, 1);
        assert!(route.is_valid);
    }

    #[test]
    fn test_neighbor_route_replaces_multihop_route() {
        let mut router = AodvRouter::new(node(1));

        // Insert a valid multi-hop route
        router.update_route(node(3), node(2), 2, 5);
        assert_eq!(router.find_route(&node(3)).unwrap().hop_count, 2);

        // A direct link is always better than a learned multi-hop route
        router.add_neighbor_route(node(3));
        let route = router.find_route(&node(3)).unwrap();
        assert_eq!(route.hop_count, 1);
        assert_eq!(route.next_hop, node(3));
        assert_eq!(route.sequence_number, 5); // freshness retained

        // A later RREP for a longer route must not displace the direct link
        router.update_route(node(3), node(2), 2, 7);
        let route = router.find_route(&node(3)).unwrap();
        assert_eq!(route.hop_count, 1);
        assert_eq!(route.sequence_number, 7);
    }

    #[test]
    fn test_rerr_invalidates_upstream_route_and_does_not_storm() {
        // A -> B -> C. B reports C unreachable to A.
        let mut router_a = AodvRouter::new(node(1));
        router_a.update_route(node(3), node(2), 2, 1);
        router_a.add_neighbor_route(node(2));

        let rerr = RouteError {
            unreachable: node(3),
            source: node(2),
            dest_seq: 1,
        };
        let action = router_a.handle_rerr(rerr.clone(), node(2));
        assert!(matches!(action, AodvAction::BroadcastRerr(_)));
        assert!(router_a.find_route(&node(3)).is_none());
        assert!(router_a.find_route(&node(2)).is_some()); // link to B intact

        // The same RERR echoed back must not trigger another rebroadcast.
        let action = router_a.handle_rerr(rerr, node(4));
        assert!(matches!(action, AodvAction::None));
    }

    #[test]
    fn test_own_rreq_echo_is_ignored() {
        let mut router = AodvRouter::new(node(1));
        let rreq = router.initiate_route_discovery(node(9));
        let action = router.handle_rreq(rreq, node(2));
        assert!(matches!(action, AodvAction::None));
        assert!(router.find_route(&node(1)).is_none());
    }

    #[test]
    fn test_hop_count_from_network_does_not_overflow() {
        let mut router = AodvRouter::new(node(2));
        let rreq = RouteRequest {
            request_id: 1,
            source: node(1),
            source_seq: 1,
            destination: node(3),
            dest_seq: 0,
            hop_count: u8::MAX,
            ttl: 10,
        };
        let action = router.handle_rreq(rreq, node(1));
        assert!(matches!(action, AodvAction::BroadcastRreq(_)));
        let rrep = RouteReply {
            request_id: 1,
            source: node(1),
            destination: node(3),
            dest_seq: 1,
            hop_count: u8::MAX,
            lifetime_secs: 10,
        };
        let _ = router.handle_rrep(rrep, node(3));
    }

    #[test]
    fn test_intermediate_reply_never_points_back_at_requester() {
        // B holds "C via A"; A asks B for C. B must not answer with that route.
        let mut router_b = AodvRouter::new(node(2));
        router_b.update_route(node(3), node(1), 2, 1);
        let rreq = RouteRequest {
            request_id: 1,
            source: node(1),
            source_seq: 1,
            destination: node(3),
            dest_seq: 0,
            hop_count: 0,
            ttl: 10,
        };
        let action = router_b.handle_rreq(rreq, node(1));
        assert!(matches!(action, AodvAction::BroadcastRreq(_)));
    }

    #[test]
    fn test_expire_routes_prunes_long_invalid_entries() {
        let mut router = AodvRouter::new(node(1));
        router.route_lifetime = Duration::from_millis(5);
        router.update_route(node(3), node(2), 2, 1);
        std::thread::sleep(Duration::from_millis(15));
        router.expire_routes();
        assert!(router.routes().is_empty());
    }

    #[test]
    fn test_refresh_neighbor_route() {
        let mut router = AodvRouter::new(node(1));

        // Add neighbor route
        router.add_neighbor_route(node(2));
        let original_lifetime = router.find_route(&node(2)).unwrap().lifetime;

        // Wait a tiny bit and refresh
        std::thread::sleep(Duration::from_millis(10));
        router.refresh_neighbor_route(node(2));

        // Lifetime should have been extended
        let refreshed_lifetime = router.find_route(&node(2)).unwrap().lifetime;
        assert!(refreshed_lifetime > original_lifetime);
    }

    #[test]
    fn test_expire_routes() {
        let mut router = AodvRouter::new(node(1));

        // Set a very short route lifetime for testing
        router.route_lifetime = Duration::from_millis(10);

        // Add neighbor route with short lifetime
        router.add_neighbor_route(node(2));
        assert!(router.find_route(&node(2)).is_some());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        // Route should still be in table but expired
        router.expire_routes();
        assert!(router.find_route(&node(2)).is_none());
    }

    #[test]
    fn test_supernode_route_preference() {
        let mut router = AodvRouter::new(node(1));

        // Register node(3) as a supernode
        router.register_supernode(node(3));
        assert!(router.is_supernode(&node(3)));
        assert!(!router.is_supernode(&node(2)));

        // Add a route through non-supernode (node 2), 2 hops, seq 5
        router.update_route(node(10), node(2), 2, 5);
        let route = router.find_route(&node(10)).unwrap();
        assert_eq!(route.next_hop, node(2));

        // Same seq, same hops, but via supernode → should replace
        router.update_route(node(10), node(3), 2, 5);
        let route = router.find_route(&node(10)).unwrap();
        assert_eq!(route.next_hop, node(3));

        // Non-supernode with same seq/hops should NOT replace supernode route
        router.update_route(node(10), node(4), 2, 5);
        let route = router.find_route(&node(10)).unwrap();
        assert_eq!(route.next_hop, node(3)); // still via supernode
    }
}
