use std::time::Duration;

use mycelium_protocol::types::{MessageId, NodeId};
use tracing::debug;

use crate::dtn::spray_and_wait::{DtnEngine, DtnError};
use crate::routing::aodv::{AodvAction, AodvMessage, AodvRouter};

/// Decision result from the routing coordinator.
#[derive(Debug)]
pub enum RoutingDecision {
    /// Send via real-time AODV route.
    SendRealtime { next_hop: NodeId },
    /// Enter DTN spray-and-wait mode.
    EnterDtn,
    /// Message delivered locally (we are the destination).
    DeliverLocal,
    /// Route discovery in progress, message queued.
    DiscoveryPending,
}

/// Coordinates between AODV real-time routing and DTN spray-and-wait.
///
/// Decision logic (spec Section 4.1):
/// 1. Try AODV route lookup (instant if cached)
/// 2. If no route, initiate AODV discovery (5s timeout)
/// 3. If discovery fails, fall back to DTN spray-and-wait
pub struct RoutingCoordinator {
    local_id: NodeId,
    aodv: AodvRouter,
    dtn: DtnEngine,
    /// Timeout for AODV route discovery before falling back to DTN.
    discovery_timeout: Duration,
}

impl RoutingCoordinator {
    pub fn new(
        local_id: NodeId,
        aodv: AodvRouter,
        dtn: DtnEngine,
    ) -> Self {
        Self {
            local_id,
            aodv,
            dtn,
            discovery_timeout: Duration::from_secs(5),
        }
    }

    /// Decide how to route a message.
    pub fn route_message(&self, destination: &NodeId) -> RoutingDecision {
        // Are we the destination?
        if *destination == self.local_id {
            return RoutingDecision::DeliverLocal;
        }

        // Check AODV routing table for an existing route
        if let Some(route) = self.aodv.find_route(destination) {
            return RoutingDecision::SendRealtime {
                next_hop: route.next_hop,
            };
        }

        // No route — will need discovery or DTN
        RoutingDecision::DiscoveryPending
    }

    /// Initiate AODV route discovery for a destination.
    pub fn initiate_discovery(&mut self, destination: NodeId) -> AodvMessage {
        let rreq = self.aodv.initiate_route_discovery(destination);
        AodvMessage::RouteRequest(rreq)
    }

    /// Fall back to DTN for a message after AODV discovery timeout.
    pub fn fallback_to_dtn(
        &mut self,
        message_id: MessageId,
        destination: NodeId,
        source: NodeId,
        encrypted_payload: Vec<u8>,
    ) -> Result<(), DtnError> {
        debug!(
            "AODV discovery failed for {}, falling back to DTN spray-and-wait",
            destination
        );
        self.dtn
            .store_outgoing(message_id, destination, source, encrypted_payload)
    }

    /// Handle an incoming AODV message.
    pub fn handle_aodv_message(
        &mut self,
        msg: AodvMessage,
        received_from: NodeId,
    ) -> AodvAction {
        match msg {
            AodvMessage::RouteRequest(rreq) => self.aodv.handle_rreq(rreq, received_from),
            AodvMessage::RouteReply(rrep) => self.aodv.handle_rrep(rrep, received_from),
            AodvMessage::RouteError(rerr) => self.aodv.handle_rerr(rerr),
        }
    }

    /// Notify the coordinator that a neighbor was encountered.
    /// Adds a direct AODV route and checks DTN bundles for the neighbor.
    pub fn on_neighbor_encountered(&mut self, neighbor: NodeId) -> Vec<crate::dtn::spray_and_wait::DtnAction> {
        // Add direct neighbor route in AODV
        self.aodv.add_neighbor_route(neighbor);

        // Check DTN for bundles destined to this neighbor
        self.dtn.on_neighbor_encountered(neighbor, &self.local_id)
    }

    /// Report a link break.
    pub fn report_link_break(&mut self, neighbor: NodeId) -> Option<AodvMessage> {
        self.aodv
            .report_link_break(neighbor)
            .map(AodvMessage::RouteError)
    }

    /// Run periodic maintenance.
    pub fn maintenance(&mut self) {
        self.aodv.expire_routes();
        let expired = self.dtn.expire_bundles();
        if expired > 0 {
            debug!("Expired {} DTN bundles", expired);
        }
    }

    pub fn aodv(&self) -> &AodvRouter {
        &self.aodv
    }

    pub fn aodv_mut(&mut self) -> &mut AodvRouter {
        &mut self.aodv
    }

    pub fn dtn(&self) -> &DtnEngine {
        &self.dtn
    }

    pub fn dtn_mut(&mut self) -> &mut DtnEngine {
        &mut self.dtn
    }

    /// Get the configured discovery timeout duration.
    pub fn discovery_timeout(&self) -> Duration {
        self.discovery_timeout
    }
}
