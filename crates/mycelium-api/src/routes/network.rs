//! Network diagnostics endpoints.

use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use mycelium_core::transport::Transport;

use crate::state::AppState;
use crate::types::{
    ApiError, DtnBundleResponse, NetworkStatusResponse, PeerResponse, PendingResponse,
    RouteEntryResponse, TransportInfo, TransportPeerInfo, TransportStatusResponse,
};

/// GET /v1/network/status — Network overview
pub async fn get_status(
    State(state): State<AppState>,
) -> Result<Json<NetworkStatusResponse>, (StatusCode, Json<ApiError>)> {
    let routing = state.node.routing.read().await;
    let now = Instant::now();

    let neighbor_count = routing
        .aodv()
        .routes()
        .values()
        .filter(|r| r.is_valid && r.hop_count == 1 && r.lifetime > now)
        .count();

    let dtn_queue_size = routing.dtn().bundle_count();
    let dtn_storage_used = routing.dtn().storage_used();
    let dtn_storage_max = routing.dtn().max_storage_bytes();

    let pending_messages = state.node.pending_messages_count().await;
    let pending_routes = state.node.pending_routes_count().await;

    Ok(Json(NetworkStatusResponse {
        neighbor_count,
        is_connected: neighbor_count > 0,
        dtn_queue_size,
        dtn_storage_used,
        dtn_storage_max,
        pending_messages,
        pending_routes,
    }))
}

/// GET /v1/network/routes — AODV routing table
pub async fn get_routes(
    State(state): State<AppState>,
) -> Json<Vec<RouteEntryResponse>> {
    let routing = state.node.routing.read().await;
    let now = Instant::now();

    let routes: Vec<RouteEntryResponse> = routing
        .aodv()
        .routes()
        .values()
        .map(|r| {
            let expires_in = if r.lifetime > now {
                r.lifetime.duration_since(now).as_secs() as i64
            } else {
                -(now.duration_since(r.lifetime).as_secs() as i64)
            };

            RouteEntryResponse {
                destination: hex::encode(r.destination.as_bytes()),
                next_hop: hex::encode(r.next_hop.as_bytes()),
                hop_count: r.hop_count,
                sequence_number: r.sequence_number,
                is_valid: r.is_valid && r.lifetime > now,
                expires_in_secs: expires_in,
            }
        })
        .collect();

    Json(routes)
}

/// GET /v1/network/dtn — DTN bundle queue
pub async fn get_dtn_bundles(
    State(state): State<AppState>,
) -> Json<Vec<DtnBundleResponse>> {
    let routing = state.node.routing.read().await;
    let now = Instant::now();

    let bundles: Vec<DtnBundleResponse> = routing
        .dtn()
        .bundles()
        .values()
        .map(|b| {
            let expires_in = if b.expires_at > now {
                b.expires_at.duration_since(now).as_secs() as i64
            } else {
                -(now.duration_since(b.expires_at).as_secs() as i64)
            };

            DtnBundleResponse {
                message_id: hex::encode(b.message_id.as_bytes()),
                destination: hex::encode(b.destination.as_bytes()),
                source: hex::encode(b.source.as_bytes()),
                copies_remaining: b.copies_remaining,
                size: b.size,
                expires_in_secs: expires_in,
            }
        })
        .collect();

    Json(bundles)
}

/// GET /v1/network/pending — Pending messages and route discoveries
pub async fn get_pending(State(state): State<AppState>) -> Json<PendingResponse> {
    let pm_count = state.node.pending_messages_count().await;
    let pm_dests = state.node.pending_message_destinations().await;
    let pr_count = state.node.pending_routes_count().await;
    let pr_dests = state.node.pending_route_destinations().await;

    Json(PendingResponse {
        pending_messages: pm_count,
        pending_message_destinations: pm_dests
            .iter()
            .map(|n| hex::encode(n.as_bytes()))
            .collect(),
        pending_routes: pr_count,
        pending_route_destinations: pr_dests
            .iter()
            .map(|n| hex::encode(n.as_bytes()))
            .collect(),
    })
}

/// GET /v1/network/transports — Per-transport status
pub async fn get_transports(State(state): State<AppState>) -> Json<TransportStatusResponse> {
    let mut transports = Vec::new();

    // BLE transport
    {
        let guard = state.node.ble_transport.read().await;
        if let Some(ref ble) = *guard {
            let peers = ble.connected_peers();
            let peer_infos: Vec<TransportPeerInfo> = peers
                .iter()
                .map(|p| {
                    let lq = ble.link_quality(p);
                    TransportPeerInfo {
                        node_id: hex::encode(p.as_bytes()),
                        rssi: lq.and_then(|q| q.rssi),
                        throughput_bps: lq.map(|q| q.throughput_bps).unwrap_or(0),
                        latency_ms: lq.map(|q| q.latency_ms).unwrap_or(0),
                    }
                })
                .collect();
            transports.push(TransportInfo {
                name: "ble".to_string(),
                registered: true,
                peer_count: peer_infos.len(),
                mtu: ble.mtu(),
                peers: peer_infos,
            });
        } else {
            transports.push(TransportInfo {
                name: "ble".to_string(),
                registered: false,
                peer_count: 0,
                peers: Vec::new(),
                mtu: 0,
            });
        }
    }

    // Wi-Fi Direct transport
    {
        let guard = state.node.wifi_transport.read().await;
        if let Some(ref wifi) = *guard {
            let peers = wifi.connected_peers();
            let peer_infos: Vec<TransportPeerInfo> = peers
                .iter()
                .map(|p| {
                    let lq = wifi.link_quality(p);
                    TransportPeerInfo {
                        node_id: hex::encode(p.as_bytes()),
                        rssi: lq.and_then(|q| q.rssi),
                        throughput_bps: lq.map(|q| q.throughput_bps).unwrap_or(0),
                        latency_ms: lq.map(|q| q.latency_ms).unwrap_or(0),
                    }
                })
                .collect();
            transports.push(TransportInfo {
                name: "wifi_direct".to_string(),
                registered: true,
                peer_count: peer_infos.len(),
                mtu: wifi.mtu(),
                peers: peer_infos,
            });
        } else {
            transports.push(TransportInfo {
                name: "wifi_direct".to_string(),
                registered: false,
                peer_count: 0,
                peers: Vec::new(),
                mtu: 0,
            });
        }
    }

    Json(TransportStatusResponse { transports })
}

/// GET /v1/network/peers — Unified peer list across all transports
pub async fn get_peers(State(state): State<AppState>) -> Json<Vec<PeerResponse>> {
    let mut peers = Vec::new();

    {
        let guard = state.node.ble_transport.read().await;
        if let Some(ref ble) = *guard {
            for p in ble.connected_peers() {
                let lq = ble.link_quality(&p);
                peers.push(PeerResponse {
                    node_id: hex::encode(p.as_bytes()),
                    transport: "ble".to_string(),
                    rssi: lq.and_then(|q| q.rssi),
                    throughput_bps: lq.map(|q| q.throughput_bps).unwrap_or(0),
                    latency_ms: lq.map(|q| q.latency_ms).unwrap_or(0),
                });
            }
        }
    }

    {
        let guard = state.node.wifi_transport.read().await;
        if let Some(ref wifi) = *guard {
            for p in wifi.connected_peers() {
                let lq = wifi.link_quality(&p);
                peers.push(PeerResponse {
                    node_id: hex::encode(p.as_bytes()),
                    transport: "wifi_direct".to_string(),
                    rssi: lq.and_then(|q| q.rssi),
                    throughput_bps: lq.map(|q| q.throughput_bps).unwrap_or(0),
                    latency_ms: lq.map(|q| q.latency_ms).unwrap_or(0),
                });
            }
        }
    }

    Json(peers)
}
