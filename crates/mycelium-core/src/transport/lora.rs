//! LoRa transport for long-range, low-bandwidth mesh communication.
//!
//! LoRa provides 1-15+ km range at very low data rates (0.3-50 kbps).
//! The transport adapts spreading factor (SF7-SF12) for range vs throughput
//! and enforces regional duty cycle limits.
//!
//! When adaptive data rate (ADR) is enabled, each peer starts at the
//! configured SF and the transport progressively tests lower SFs on
//! consecutive successes, falling back to higher SFs on failures.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

use mycelium_protocol::types::{LinkQuality, NodeId};

use super::{Transport, TransportError, TransportEvent, TransportType};

/// LoRa radio configuration.
#[derive(Debug, Clone)]
pub struct LoraConfig {
    /// Frequency in MHz (e.g., 915.0 for US ISM, 868.0 for EU).
    pub frequency_mhz: f32,
    /// Spreading factor (7-12). Higher = more range, less speed.
    pub spreading_factor: u8,
    /// Bandwidth in kHz (125, 250, or 500).
    pub bandwidth_khz: u16,
    /// Transmit power in dBm (typical: 2-20).
    pub tx_power_dbm: i8,
    /// Duty cycle limit (0.01 = 1% for EU ISM band).
    pub duty_cycle_limit: f32,
    /// Whether to use adaptive data rate (auto-negotiate SF).
    pub adaptive_data_rate: bool,
}

impl Default for LoraConfig {
    fn default() -> Self {
        Self {
            frequency_mhz: 915.0,
            spreading_factor: 10,
            bandwidth_khz: 125,
            tx_power_dbm: 14,
            duty_cycle_limit: 1.0, // No duty cycle limit (US ISM)
            adaptive_data_rate: true,
        }
    }
}

impl LoraConfig {
    /// EU ISM band preset (868 MHz, 1% duty cycle).
    pub fn eu_868() -> Self {
        Self {
            frequency_mhz: 868.0,
            duty_cycle_limit: 0.01,
            ..Default::default()
        }
    }

    /// US ISM band preset (915 MHz, no duty cycle limit).
    pub fn us_915() -> Self {
        Self::default()
    }

    /// Maximum payload bytes for a given SF/BW combination.
    pub fn max_payload_for_sf(sf: u8) -> usize {
        match sf {
            7 => 222,
            8 => 222,
            9 => 115,
            10 => 51,
            11 => 51,
            12 => 51,
            _ => 51,
        }
    }

    /// Maximum payload bytes for current SF/BW combination.
    pub fn max_payload(&self) -> usize {
        Self::max_payload_for_sf(self.spreading_factor)
    }

    /// Approximate airtime in ms for a given payload size at a given SF.
    pub fn airtime_ms_for_sf(&self, payload_bytes: usize, sf: u8) -> u64 {
        let sf_f = sf as f64;
        let bw = self.bandwidth_khz as f64 * 1000.0;
        let symbol_time = (2.0_f64).powf(sf_f) / bw;
        let preamble_time = (8.0 + 4.25) * symbol_time;
        let payload_symbols = (8.0
            + (8.0 * payload_bytes as f64 + 28.0 - 4.0 * sf_f + 16.0)
                .max(0.0)
                .ceil()
                / (4.0 * sf_f)
                * 5.0)
            .max(8.0);
        let payload_time = payload_symbols * symbol_time;
        ((preamble_time + payload_time) * 1000.0) as u64
    }

    /// Approximate airtime in ms for a given payload size at the configured SF.
    pub fn airtime_ms(&self, payload_bytes: usize) -> u64 {
        self.airtime_ms_for_sf(payload_bytes, self.spreading_factor)
    }

    /// Approximate data rate in bps for a given SF.
    pub fn data_rate_bps(sf: u8) -> u32 {
        match sf {
            7 => 5_470,
            8 => 3_125,
            9 => 1_760,
            10 => 980,
            11 => 440,
            12 => 250,
            _ => 250,
        }
    }
}

// --- Adaptive Data Rate ---

/// Consecutive successes before trying a lower SF.
const ADR_LOWER_THRESHOLD: u32 = 10;
/// Consecutive failures before raising SF.
const ADR_RAISE_THRESHOLD: u32 = 2;
/// Discovery/beacon spreading factor (maximum range).
const ADR_DISCOVERY_SF: u8 = 12;
/// Minimum allowed SF.
const ADR_MIN_SF: u8 = 7;
/// Maximum allowed SF.
const ADR_MAX_SF: u8 = 12;

/// Per-peer adaptive data rate state.
#[derive(Debug, Clone)]
struct PeerAdrState {
    /// Current negotiated spreading factor for this peer.
    current_sf: u8,
    /// Consecutive successful transmissions at current SF.
    consecutive_successes: u32,
    /// Consecutive failures at current SF.
    consecutive_failures: u32,
    /// Total successful transmissions.
    total_successes: u64,
    /// Total failed transmissions.
    total_failures: u64,
}

impl PeerAdrState {
    fn new(initial_sf: u8) -> Self {
        Self {
            current_sf: initial_sf.clamp(ADR_MIN_SF, ADR_MAX_SF),
            consecutive_successes: 0,
            consecutive_failures: 0,
            total_successes: 0,
            total_failures: 0,
        }
    }

    /// Record a successful transmission. Returns the new SF if it changed.
    fn record_success(&mut self) -> Option<u8> {
        self.consecutive_successes += 1;
        self.consecutive_failures = 0;
        self.total_successes += 1;

        // After enough successes, try lowering SF for more throughput
        if self.consecutive_successes >= ADR_LOWER_THRESHOLD && self.current_sf > ADR_MIN_SF {
            self.current_sf -= 1;
            self.consecutive_successes = 0;
            debug!(
                "ADR: lowered SF to {} after {} consecutive successes",
                self.current_sf, ADR_LOWER_THRESHOLD
            );
            Some(self.current_sf)
        } else {
            None
        }
    }

    /// Record a failed transmission. Returns the new SF if it changed.
    fn record_failure(&mut self) -> Option<u8> {
        self.consecutive_failures += 1;
        self.consecutive_successes = 0;
        self.total_failures += 1;

        // After too many failures, raise SF for more range
        if self.consecutive_failures >= ADR_RAISE_THRESHOLD && self.current_sf < ADR_MAX_SF {
            self.current_sf += 1;
            self.consecutive_failures = 0;
            warn!(
                "ADR: raised SF to {} after {} consecutive failures",
                self.current_sf, ADR_RAISE_THRESHOLD
            );
            Some(self.current_sf)
        } else {
            None
        }
    }

    /// Estimated packet loss ratio (0.0 - 1.0).
    fn packet_loss(&self) -> f32 {
        let total = self.total_successes + self.total_failures;
        if total == 0 {
            0.0
        } else {
            self.total_failures as f32 / total as f32
        }
    }
}

/// Adaptive data rate manager for all peers.
#[derive(Debug)]
struct AdaptiveDataRate {
    peers: HashMap<NodeId, PeerAdrState>,
    initial_sf: u8,
}

impl AdaptiveDataRate {
    fn new(initial_sf: u8) -> Self {
        Self {
            peers: HashMap::new(),
            initial_sf,
        }
    }

    /// Get the current SF for a peer, creating state if needed.
    fn sf_for_peer(&mut self, peer: &NodeId) -> u8 {
        self.peers
            .entry(*peer)
            .or_insert_with(|| PeerAdrState::new(self.initial_sf))
            .current_sf
    }

    /// Record success for a peer. Returns new SF if changed.
    fn record_success(&mut self, peer: &NodeId) -> Option<u8> {
        self.peers
            .entry(*peer)
            .or_insert_with(|| PeerAdrState::new(self.initial_sf))
            .record_success()
    }

    /// Record failure for a peer. Returns new SF if changed.
    fn record_failure(&mut self, peer: &NodeId) -> Option<u8> {
        self.peers
            .entry(*peer)
            .or_insert_with(|| PeerAdrState::new(self.initial_sf))
            .record_failure()
    }

    /// Get peer ADR state (for link quality reporting).
    fn peer_state(&self, peer: &NodeId) -> Option<&PeerAdrState> {
        self.peers.get(peer)
    }

    /// Remove state for a peer that has been lost.
    fn remove_peer(&mut self, peer: &NodeId) {
        self.peers.remove(peer);
    }
}

// --- LoRa Transport ---

/// LoRa transport for long-range mesh communication.
///
/// Characteristics:
/// - Range: 1-15+ km (line of sight)
/// - MTU: 51-222 bytes (depends on spreading factor)
/// - Power: Medium (short duty cycle bursts)
/// - Use: Long-range relay, rural coverage, emergency fallback
pub struct LoraTransport {
    config: LoraConfig,
    tx: broadcast::Sender<TransportEvent>,
    connected_peers: Arc<RwLock<Vec<NodeId>>>,
    started: Arc<RwLock<bool>>,
    /// Outbox queue for outgoing data. Platform polls via FFI.
    #[allow(clippy::type_complexity)]
    outbox: Arc<Mutex<VecDeque<(NodeId, Vec<u8>)>>>,
    /// Duty cycle tracking: total airtime used in current window (ms).
    duty_airtime_ms: Arc<Mutex<u64>>,
    /// Adaptive data rate state per peer.
    adr: Arc<Mutex<AdaptiveDataRate>>,
}

impl LoraTransport {
    pub fn new(config: LoraConfig) -> Self {
        let (tx, _) = broadcast::channel(64);
        let initial_sf = config.spreading_factor;
        Self {
            config,
            tx,
            connected_peers: Arc::new(RwLock::new(Vec::new())),
            started: Arc::new(RwLock::new(false)),
            outbox: Arc::new(Mutex::new(VecDeque::new())),
            duty_airtime_ms: Arc::new(Mutex::new(0)),
            adr: Arc::new(Mutex::new(AdaptiveDataRate::new(initial_sf))),
        }
    }

    /// Number of packets waiting in the outbox.
    pub fn outbox_len(&self) -> usize {
        self.outbox.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// Dequeue a pending send from the outbox.
    pub fn dequeue_send(&self) -> Option<(NodeId, Vec<u8>)> {
        self.outbox.lock().ok()?.pop_front()
    }

    /// Called by platform when a LoRa peer is discovered.
    pub async fn on_peer_discovered(&self, peer: NodeId) {
        let mut peers = self.connected_peers.write().await;
        if !peers.contains(&peer) {
            info!("LoRa peer discovered: {}", peer);
            peers.push(peer);
            let _ = self.tx.send(TransportEvent::NeighborDiscovered {
                peer,
                transport: TransportType::Lora,
            });
        }
    }

    /// Called by platform when a LoRa peer is lost.
    pub async fn on_peer_lost(&self, peer: NodeId) {
        let mut peers = self.connected_peers.write().await;
        peers.retain(|p| *p != peer);
        // Clean up ADR state for this peer
        if let Ok(mut adr) = self.adr.lock() {
            adr.remove_peer(&peer);
        }
        let _ = self.tx.send(TransportEvent::NeighborLost {
            peer,
            transport: TransportType::Lora,
        });
    }

    /// Called by platform when data arrives from a LoRa peer.
    pub async fn on_data_received(&self, peer: NodeId, data: Vec<u8>) {
        debug!("LoRa data received: {} bytes from {}", data.len(), peer);
        let _ = self.tx.send(TransportEvent::DataReceived {
            peer,
            data,
            transport: TransportType::Lora,
        });
    }

    /// Called by platform to report transmission success for a peer.
    /// Used by the ADR algorithm to negotiate lower spreading factors.
    pub fn report_tx_success(&self, peer: &NodeId) {
        if !self.config.adaptive_data_rate {
            return;
        }
        if let Ok(mut adr) = self.adr.lock() {
            if let Some(new_sf) = adr.record_success(peer) {
                info!("LoRa ADR: peer {} now using SF{}", peer, new_sf);
            }
        }
    }

    /// Called by platform to report transmission failure for a peer.
    /// Used by the ADR algorithm to fall back to higher spreading factors.
    pub fn report_tx_failure(&self, peer: &NodeId) {
        if !self.config.adaptive_data_rate {
            return;
        }
        if let Ok(mut adr) = self.adr.lock() {
            if let Some(new_sf) = adr.record_failure(peer) {
                warn!("LoRa ADR: peer {} raised to SF{}", peer, new_sf);
            }
        }
    }

    /// Get the current effective SF for a peer (ADR-adjusted or config default).
    pub fn effective_sf(&self, peer: &NodeId) -> u8 {
        if !self.config.adaptive_data_rate {
            return self.config.spreading_factor;
        }
        self.adr
            .lock()
            .map(|mut adr| adr.sf_for_peer(peer))
            .unwrap_or(self.config.spreading_factor)
    }

    /// Get the SF to use for discovery beacons (always SF12 for max range).
    pub fn discovery_sf(&self) -> u8 {
        ADR_DISCOVERY_SF
    }

    /// Check if sending would exceed duty cycle limit.
    fn check_duty_cycle(&self, payload_bytes: usize) -> bool {
        if self.config.duty_cycle_limit >= 1.0 {
            return true; // No limit
        }
        let airtime = self.config.airtime_ms(payload_bytes);
        let used = self.duty_airtime_ms.lock().map(|v| *v).unwrap_or(0);
        // Allow if total airtime is under limit (per 1-hour window = 3_600_000ms)
        let max_airtime = (3_600_000.0 * self.config.duty_cycle_limit as f64) as u64;
        used + airtime <= max_airtime
    }

    /// Get the current spreading factor from config.
    pub fn spreading_factor(&self) -> u8 {
        self.config.spreading_factor
    }

    /// Get the LoRa config.
    pub fn config(&self) -> &LoraConfig {
        &self.config
    }
}

#[async_trait::async_trait]
impl Transport for LoraTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Lora
    }

    async fn start(&self) -> Result<(), TransportError> {
        let mut started = self.started.write().await;
        if *started {
            return Err(TransportError::AlreadyStarted);
        }
        *started = true;
        info!(
            "LoRa transport started: {:.1} MHz, SF{}, {}kHz BW, ADR={}",
            self.config.frequency_mhz,
            self.config.spreading_factor,
            self.config.bandwidth_khz,
            self.config.adaptive_data_rate
        );
        Ok(())
    }

    async fn stop(&self) -> Result<(), TransportError> {
        let mut started = self.started.write().await;
        if !*started {
            return Err(TransportError::NotStarted);
        }
        *started = false;
        let mut peers = self.connected_peers.write().await;
        peers.clear();
        Ok(())
    }

    async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError> {
        let started = self.started.read().await;
        if !*started {
            return Err(TransportError::NotStarted);
        }

        // Use ADR-adjusted SF for MTU check
        let peer_sf = self.effective_sf(peer);
        let peer_mtu = LoraConfig::max_payload_for_sf(peer_sf);
        if data.len() > peer_mtu {
            return Err(TransportError::ExceedsMtu {
                size: data.len(),
                mtu: peer_mtu,
            });
        }

        if !self.check_duty_cycle(data.len()) {
            warn!("LoRa duty cycle limit reached, dropping send");
            return Err(TransportError::SendFailed(
                "duty cycle limit exceeded".to_string(),
            ));
        }

        debug!(
            "LoRa send: {} bytes to {} (SF{})",
            data.len(),
            peer,
            peer_sf
        );

        // Track airtime using the peer's effective SF
        let airtime = self.config.airtime_ms_for_sf(data.len(), peer_sf);
        if let Ok(mut used) = self.duty_airtime_ms.lock() {
            *used += airtime;
        }

        // Queue for platform polling
        if let Ok(mut outbox) = self.outbox.lock() {
            outbox.push_back((*peer, data.to_vec()));
            debug!(
                "LoRa outbox: queued, depth now {}, airtime ~{}ms (SF{})",
                outbox.len(),
                airtime,
                peer_sf
            );
        }

        Ok(())
    }

    fn events(&self) -> broadcast::Receiver<TransportEvent> {
        self.tx.subscribe()
    }

    fn link_quality(&self, peer: &NodeId) -> Option<LinkQuality> {
        let peers = self.connected_peers.try_read().ok()?;
        if peers.contains(peer) {
            let (sf, packet_loss) = self
                .adr
                .lock()
                .ok()
                .and_then(|adr| {
                    adr.peer_state(peer)
                        .map(|s| (s.current_sf, s.packet_loss()))
                })
                .unwrap_or((self.config.spreading_factor, 0.05));

            Some(LinkQuality {
                rssi: Some(-110), // Typical LoRa RSSI
                packet_loss,
                latency_ms: 500,
                throughput_bps: LoraConfig::data_rate_bps(sf),
            })
        } else {
            None
        }
    }

    fn connected_peers(&self) -> Vec<NodeId> {
        self.connected_peers
            .try_read()
            .map(|p| p.clone())
            .unwrap_or_default()
    }

    fn mtu(&self) -> usize {
        self.config.max_payload()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lora_config_defaults() {
        let config = LoraConfig::default();
        assert_eq!(config.frequency_mhz, 915.0);
        assert_eq!(config.spreading_factor, 10);
        assert_eq!(config.bandwidth_khz, 125);
        assert_eq!(config.max_payload(), 51);
    }

    #[test]
    fn test_lora_eu_preset() {
        let config = LoraConfig::eu_868();
        assert_eq!(config.frequency_mhz, 868.0);
        assert_eq!(config.duty_cycle_limit, 0.01);
    }

    #[test]
    fn test_max_payload_by_sf() {
        assert_eq!(LoraConfig::max_payload_for_sf(7), 222);
        assert_eq!(LoraConfig::max_payload_for_sf(12), 51);
    }

    #[test]
    fn test_airtime_calculation() {
        let config = LoraConfig::default();
        let airtime = config.airtime_ms(50);
        assert!(airtime > 0, "airtime should be positive");
        // SF10 with 50 bytes should take several hundred ms
        assert!(airtime > 100, "SF10 50-byte packet should take >100ms");
    }

    #[test]
    fn test_airtime_for_sf() {
        let config = LoraConfig::default();
        // Lower SF = shorter airtime for same payload
        let airtime_sf7 = config.airtime_ms_for_sf(50, 7);
        let airtime_sf12 = config.airtime_ms_for_sf(50, 12);
        assert!(
            airtime_sf7 < airtime_sf12,
            "SF7 airtime ({}) should be less than SF12 ({})",
            airtime_sf7,
            airtime_sf12
        );
    }

    #[tokio::test]
    async fn test_lora_send_mtu_check() {
        let transport = LoraTransport::new(LoraConfig::default());
        transport.start().await.unwrap();
        transport.on_peer_discovered(NodeId([0xAA; 32])).await;

        // MTU for SF10 is 51 bytes
        let result = transport.send(&NodeId([0xAA; 32]), &[0u8; 100]).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TransportError::ExceedsMtu { .. }
        ));
    }

    #[test]
    fn test_duty_cycle_enforcement() {
        let mut config = LoraConfig::eu_868();
        config.spreading_factor = 12; // Very long airtime per packet
        let transport = LoraTransport::new(config);

        // Initially should be allowed
        assert!(transport.check_duty_cycle(50));

        // Simulate heavy usage by setting high airtime
        if let Ok(mut used) = transport.duty_airtime_ms.lock() {
            *used = 35_000; // 35 seconds out of 36 allowed (1% of 3600s)
        }
        // Should still pass for small packet
        assert!(transport.check_duty_cycle(10));

        // Set to near limit
        if let Ok(mut used) = transport.duty_airtime_ms.lock() {
            *used = 36_000; // At the limit
        }
        // Large packet should fail
        assert!(!transport.check_duty_cycle(50));
    }

    #[tokio::test]
    async fn test_lora_not_started() {
        let transport = LoraTransport::new(LoraConfig::default());
        let result = transport.send(&NodeId([0xBB; 32]), &[1, 2, 3]).await;
        assert!(matches!(result.unwrap_err(), TransportError::NotStarted));
    }

    // --- ADR tests ---

    #[test]
    fn test_adr_initial_sf() {
        let mut adr = AdaptiveDataRate::new(10);
        let peer = NodeId([0xAA; 32]);
        assert_eq!(adr.sf_for_peer(&peer), 10);
    }

    #[test]
    fn test_adr_lower_on_consecutive_success() {
        let mut adr = AdaptiveDataRate::new(10);
        let peer = NodeId([0xAA; 32]);

        // 9 successes: no change
        for _ in 0..ADR_LOWER_THRESHOLD - 1 {
            assert!(adr.record_success(&peer).is_none());
        }
        assert_eq!(adr.sf_for_peer(&peer), 10);

        // 10th success: lower to SF9
        let new_sf = adr.record_success(&peer);
        assert_eq!(new_sf, Some(9));
        assert_eq!(adr.sf_for_peer(&peer), 9);
    }

    #[test]
    fn test_adr_raise_on_consecutive_failure() {
        let mut adr = AdaptiveDataRate::new(9);
        let peer = NodeId([0xAA; 32]);

        // 1 failure: no change
        assert!(adr.record_failure(&peer).is_none());
        assert_eq!(adr.sf_for_peer(&peer), 9);

        // 2nd failure: raise to SF10
        let new_sf = adr.record_failure(&peer);
        assert_eq!(new_sf, Some(10));
        assert_eq!(adr.sf_for_peer(&peer), 10);
    }

    #[test]
    fn test_adr_clamp_at_boundaries() {
        let mut adr = AdaptiveDataRate::new(7);
        let peer = NodeId([0xAA; 32]);

        // At SF7, successes should not lower further
        for _ in 0..ADR_LOWER_THRESHOLD + 5 {
            assert!(adr.record_success(&peer).is_none());
        }
        assert_eq!(adr.sf_for_peer(&peer), 7);

        // Now test upper boundary
        let mut adr = AdaptiveDataRate::new(12);
        // At SF12, failures should not raise further
        for _ in 0..ADR_RAISE_THRESHOLD + 5 {
            assert!(adr.record_failure(&peer).is_none());
        }
        assert_eq!(adr.sf_for_peer(&peer), 12);
    }

    #[test]
    fn test_adr_failure_resets_success_counter() {
        let mut adr = AdaptiveDataRate::new(10);
        let peer = NodeId([0xAA; 32]);

        // 8 successes
        for _ in 0..8 {
            adr.record_success(&peer);
        }
        // 1 failure resets consecutive_successes
        adr.record_failure(&peer);

        // 9 more successes should NOT lower (need 10 consecutive)
        for _ in 0..9 {
            assert!(adr.record_success(&peer).is_none());
        }
        // 10th consecutive success lowers
        assert_eq!(adr.record_success(&peer), Some(9));
    }

    #[test]
    fn test_adr_per_peer_independence() {
        let mut adr = AdaptiveDataRate::new(10);
        let peer_a = NodeId([0xAA; 32]);
        let peer_b = NodeId([0xBB; 32]);

        // Lower peer_a to SF9
        for _ in 0..ADR_LOWER_THRESHOLD {
            adr.record_success(&peer_a);
        }
        assert_eq!(adr.sf_for_peer(&peer_a), 9);
        // peer_b unchanged
        assert_eq!(adr.sf_for_peer(&peer_b), 10);
    }

    #[test]
    fn test_adr_packet_loss_tracking() {
        let mut adr = AdaptiveDataRate::new(10);
        let peer = NodeId([0xAA; 32]);

        adr.record_success(&peer);
        adr.record_success(&peer);
        adr.record_failure(&peer);

        let state = adr.peer_state(&peer).unwrap();
        // 1 failure out of 3 total
        let loss = state.packet_loss();
        assert!((loss - 1.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_adr_remove_peer() {
        let mut adr = AdaptiveDataRate::new(10);
        let peer = NodeId([0xAA; 32]);
        adr.sf_for_peer(&peer);
        assert!(adr.peer_state(&peer).is_some());
        adr.remove_peer(&peer);
        assert!(adr.peer_state(&peer).is_none());
    }

    #[tokio::test]
    async fn test_transport_effective_sf() {
        let config = LoraConfig {
            adaptive_data_rate: true,
            spreading_factor: 10,
            ..Default::default()
        };
        let transport = LoraTransport::new(config);
        let peer = NodeId([0xAA; 32]);

        // Initial SF matches config
        assert_eq!(transport.effective_sf(&peer), 10);

        // After enough successes, SF should lower
        for _ in 0..ADR_LOWER_THRESHOLD {
            transport.report_tx_success(&peer);
        }
        assert_eq!(transport.effective_sf(&peer), 9);
    }

    #[tokio::test]
    async fn test_transport_adr_disabled() {
        let config = LoraConfig {
            adaptive_data_rate: false,
            spreading_factor: 10,
            ..Default::default()
        };
        let transport = LoraTransport::new(config);
        let peer = NodeId([0xAA; 32]);

        // ADR disabled: successes/failures ignored
        for _ in 0..ADR_LOWER_THRESHOLD + 5 {
            transport.report_tx_success(&peer);
        }
        assert_eq!(transport.effective_sf(&peer), 10);
    }

    #[test]
    fn test_discovery_sf() {
        let transport = LoraTransport::new(LoraConfig::default());
        assert_eq!(transport.discovery_sf(), 12);
    }

    #[tokio::test]
    async fn test_link_quality_uses_adr_sf() {
        let config = LoraConfig {
            adaptive_data_rate: true,
            spreading_factor: 10,
            ..Default::default()
        };
        let transport = LoraTransport::new(config);
        transport.start().await.unwrap();
        let peer = NodeId([0xAA; 32]);
        transport.on_peer_discovered(peer).await;

        // Initial link quality uses SF10
        let lq = transport.link_quality(&peer).unwrap();
        assert_eq!(lq.throughput_bps, 980); // SF10 rate

        // Lower to SF9
        for _ in 0..ADR_LOWER_THRESHOLD {
            transport.report_tx_success(&peer);
        }
        let lq = transport.link_quality(&peer).unwrap();
        assert_eq!(lq.throughput_bps, 1_760); // SF9 rate
    }
}
