//! LoRa transport for long-range, low-bandwidth mesh communication.
//!
//! LoRa provides 1-15+ km range at very low data rates (0.3-50 kbps).
//! The transport adapts spreading factor (SF7-SF12) for range vs throughput
//! and enforces regional duty cycle limits.

use std::collections::VecDeque;
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

    /// Maximum payload bytes for current SF/BW combination.
    pub fn max_payload(&self) -> usize {
        match self.spreading_factor {
            7 => 222,
            8 => 222,
            9 => 115,
            10 => 51,
            11 => 51,
            12 => 51,
            _ => 51,
        }
    }

    /// Approximate airtime in ms for a given payload size.
    pub fn airtime_ms(&self, payload_bytes: usize) -> u64 {
        // Simplified LoRa airtime calculation
        let sf = self.spreading_factor as f64;
        let bw = self.bandwidth_khz as f64 * 1000.0;
        let symbol_time = (2.0_f64).powf(sf) / bw;
        let preamble_time = (8.0 + 4.25) * symbol_time;
        let payload_symbols = (8.0
            + (8.0 * payload_bytes as f64 + 28.0 - 4.0 * sf + 16.0)
                .max(0.0)
                .ceil()
                / (4.0 * sf)
                * 5.0)
            .max(8.0);
        let payload_time = payload_symbols * symbol_time;
        ((preamble_time + payload_time) * 1000.0) as u64
    }
}

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
    outbox: Arc<Mutex<VecDeque<(NodeId, Vec<u8>)>>>,
    /// Duty cycle tracking: total airtime used in current window (ms).
    duty_airtime_ms: Arc<Mutex<u64>>,
}

impl LoraTransport {
    pub fn new(config: LoraConfig) -> Self {
        let (tx, _) = broadcast::channel(64);
        Self {
            config,
            tx,
            connected_peers: Arc::new(RwLock::new(Vec::new())),
            started: Arc::new(RwLock::new(false)),
            outbox: Arc::new(Mutex::new(VecDeque::new())),
            duty_airtime_ms: Arc::new(Mutex::new(0)),
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

    /// Get the current spreading factor.
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
            "LoRa transport started: {:.1} MHz, SF{}, {}kHz BW",
            self.config.frequency_mhz, self.config.spreading_factor, self.config.bandwidth_khz
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

        if data.len() > self.mtu() {
            return Err(TransportError::ExceedsMtu {
                size: data.len(),
                mtu: self.mtu(),
            });
        }

        if !self.check_duty_cycle(data.len()) {
            warn!("LoRa duty cycle limit reached, dropping send");
            return Err(TransportError::SendFailed(
                "duty cycle limit exceeded".to_string(),
            ));
        }

        debug!("LoRa send: {} bytes to {}", data.len(), peer);

        // Track airtime
        let airtime = self.config.airtime_ms(data.len());
        if let Ok(mut used) = self.duty_airtime_ms.lock() {
            *used += airtime;
        }

        // Queue for platform polling
        if let Ok(mut outbox) = self.outbox.lock() {
            outbox.push_back((*peer, data.to_vec()));
            debug!(
                "LoRa outbox: queued, depth now {}, airtime ~{}ms",
                outbox.len(),
                airtime
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
            // LoRa has high latency but very long range
            Some(LinkQuality {
                rssi: Some(-110), // Typical LoRa RSSI
                packet_loss: 0.05,
                latency_ms: 500,
                throughput_bps: match self.config.spreading_factor {
                    7 => 5_470,
                    8 => 3_125,
                    9 => 1_760,
                    10 => 980,
                    11 => 440,
                    12 => 250,
                    _ => 250,
                },
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
        let mut config = LoraConfig::default();
        config.spreading_factor = 7;
        assert_eq!(config.max_payload(), 222);
        config.spreading_factor = 12;
        assert_eq!(config.max_payload(), 51);
    }

    #[test]
    fn test_airtime_calculation() {
        let config = LoraConfig::default();
        let airtime = config.airtime_ms(50);
        assert!(airtime > 0, "airtime should be positive");
        // SF10 with 50 bytes should take several hundred ms
        assert!(airtime > 100, "SF10 50-byte packet should take >100ms");
    }

    #[tokio::test]
    async fn test_lora_send_mtu_check() {
        let transport = LoraTransport::new(LoraConfig::default());
        transport.start().await.unwrap();
        transport.on_peer_discovered(NodeId([0xAA; 32])).await;

        // MTU for SF10 is 51 bytes
        let result = transport.send(&NodeId([0xAA; 32]), &[0u8; 100]).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TransportError::ExceedsMtu { .. }));
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
}
