//! LoRa transport for long-range, low-bandwidth mesh communication.
//!
//! LoRa provides 1-15+ km range at very low data rates (0.3-50 kbps).
//! The transport adapts spreading factor (SF7-SF12) for range vs throughput
//! and enforces regional duty cycle limits.
//!
//! When adaptive data rate (ADR) is enabled, each peer starts at the
//! configured SF and the transport progressively tests lower SFs on
//! consecutive successes, falling back to higher SFs on failures.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

use mycelium_protocol::types::{LinkQuality, NodeId};

use super::fragment::{fragment, Reassembler};
use super::{
    PriorityOutbox, SendPriority, Transport, TransportError, TransportEvent, TransportType,
};

// --- LoRa BLE GATT Bridge UUIDs ---
//
// When connecting to an external LoRa module (e.g. ESP32+SX1276) over BLE,
// the phone acts as a GATT client and the LoRa module exposes this service.
//
// Service UUID: a1b2c3d4-e5f6-7890-abcd-ef12345678a0
// ├─ Data TX    (78a1) Write      — Phone writes outgoing mesh packets
// ├─ Data RX    (78a2) Notify     — LoRa module notifies phone of received packets
// ├─ Config     (78a3) Read/Write — Radio config: frequency, SF, BW, TX power
// └─ Status     (78a4) Read/Notify — Radio status: RSSI, SNR, duty cycle, error count

/// LoRa GATT service UUID.
pub const LORA_SERVICE_UUID: &str = "a1b2c3d4-e5f6-7890-abcd-ef12345678a0";
/// Phone → LoRa module: write outgoing mesh packets.
pub const LORA_DATA_TX_UUID: &str = "a1b2c3d4-e5f6-7890-abcd-ef12345678a1";
/// LoRa module → phone: notify with received mesh packets.
pub const LORA_DATA_RX_UUID: &str = "a1b2c3d4-e5f6-7890-abcd-ef12345678a2";
/// Radio configuration (frequency, SF, BW, TX power) — read/write.
pub const LORA_CONFIG_UUID: &str = "a1b2c3d4-e5f6-7890-abcd-ef12345678a3";
/// Radio status (RSSI, SNR, duty cycle, error count) — read/notify.
pub const LORA_STATUS_UUID: &str = "a1b2c3d4-e5f6-7890-abcd-ef12345678a4";

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

/// Length of the duty-cycle accounting window.
const DUTY_CYCLE_WINDOW: Duration = Duration::from_secs(3600);

/// Maximum packets queued in the outbox while the platform is not polling.
const MAX_OUTBOX: usize = 256;

/// A LoRa peer that has been silent this long is reported lost. The radio is
/// a broadcast medium with no link-layer sessions, so presence is inferred
/// from traffic (beacons every 30 s by default).
pub const LORA_PEER_TIMEOUT: Duration = Duration::from_secs(300);

/// Largest reassembled message the transport accepts.
pub const LORA_MAX_MESSAGE: usize = 2048;

/// The source NodeId of a reassembled message: every Mycelium envelope
/// starts with the 32-byte source id. Returns `None` for shorter data.
fn source_from_message(message: &[u8]) -> Option<NodeId> {
    if message.len() < 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&message[..32]);
    Some(NodeId::from_bytes(id))
}

/// Airtime accounting that resets every [`DUTY_CYCLE_WINDOW`].
struct DutyCycleWindow {
    window_start: Instant,
    airtime_ms: u64,
}

impl DutyCycleWindow {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            airtime_ms: 0,
        }
    }

    fn roll(&mut self) {
        if self.window_start.elapsed() >= DUTY_CYCLE_WINDOW {
            self.window_start = Instant::now();
            self.airtime_ms = 0;
        }
    }

    fn used_ms(&mut self) -> u64 {
        self.roll();
        self.airtime_ms
    }

    fn charge(&mut self, airtime_ms: u64) {
        self.roll();
        self.airtime_ms = self.airtime_ms.saturating_add(airtime_ms);
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
    outbox: Arc<Mutex<PriorityOutbox>>,
    /// Duty cycle tracking for the current one-hour window.
    duty_cycle: Arc<Mutex<DutyCycleWindow>>,
    /// Adaptive data rate state per peer.
    adr: Arc<Mutex<AdaptiveDataRate>>,
    /// Next outgoing fragment id.
    next_frag_id: Arc<Mutex<u16>>,
    /// Random tag identifying this radio's fragments to receivers.
    sender_tag: u16,
    /// In-progress reassemblies keyed by (sender tag, fragment id).
    reassembly: Arc<Mutex<Reassembler>>,
    /// When each peer was last heard from (for silent-peer expiry).
    last_seen: Arc<Mutex<HashMap<NodeId, Instant>>>,
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
            outbox: Arc::new(Mutex::new(PriorityOutbox::new(MAX_OUTBOX))),
            duty_cycle: Arc::new(Mutex::new(DutyCycleWindow::new())),
            adr: Arc::new(Mutex::new(AdaptiveDataRate::new(initial_sf))),
            next_frag_id: Arc::new(Mutex::new(0)),
            sender_tag: rand::random(),
            reassembly: Arc::new(Mutex::new(Reassembler::new(LORA_MAX_MESSAGE, "LoRa"))),
            last_seen: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Report peers that have been silent longer than [`LORA_PEER_TIMEOUT`]
    /// as lost. Called on every received frame; the platform may also call
    /// `on_peer_lost` directly.
    async fn expire_silent_peers(&self) {
        let now = Instant::now();
        let expired: Vec<NodeId> = match self.last_seen.lock() {
            Ok(mut seen) => {
                let gone: Vec<NodeId> = seen
                    .iter()
                    .filter(|(_, t)| now.duration_since(**t) > LORA_PEER_TIMEOUT)
                    .map(|(p, _)| *p)
                    .collect();
                for p in &gone {
                    seen.remove(p);
                }
                gone
            }
            Err(_) => Vec::new(),
        };
        for peer in expired {
            info!("LoRa peer {} silent for too long, marking lost", peer);
            self.on_peer_lost(peer).await;
        }
    }

    /// Record traffic from `peer`, announcing it as a neighbour on first
    /// contact. LoRa has no link-layer discovery: hearing a node is
    /// discovering it.
    async fn note_peer_heard(&self, peer: NodeId) {
        if let Ok(mut seen) = self.last_seen.lock() {
            seen.insert(peer, Instant::now());
        }
        self.on_peer_discovered(peer).await;
    }

    /// Number of incomplete reassemblies currently held.
    pub fn pending_reassemblies(&self) -> usize {
        self.reassembly.lock().map(|r| r.pending()).unwrap_or(0)
    }

    /// Feed one received frame into reassembly. Returns the complete message
    /// once every fragment has arrived.
    fn reassemble(&self, frame: &[u8]) -> Option<Vec<u8>> {
        // The radio exposes no link-layer address, so every sender shares one
        // scope and the random sender tag in the header is what separates
        // them (§8.4, ADR-022).
        self.reassembly.lock().ok()?.push(NodeId::ZERO, frame)
    }

    /// Number of packets waiting in the outbox.
    pub fn outbox_len(&self) -> usize {
        self.outbox.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// Dequeue a pending send from the outbox.
    pub fn dequeue_send(&self) -> Option<(NodeId, Vec<u8>)> {
        self.outbox.lock().ok()?.pop()
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
    /// Called by the platform for every frame the radio receives. The radio
    /// has no link-layer address, so the platform passes `NodeId::ZERO` and
    /// the peer is taken from the reassembled envelope's source field; a
    /// non-zero hint (e.g. from a bridge that knows the sender) is honoured.
    pub async fn on_data_received(&self, peer_hint: NodeId, data: Vec<u8>) {
        debug!("LoRa frame received: {} bytes", data.len());
        self.expire_silent_peers().await;
        let Some(message) = self.reassemble(&data) else {
            return;
        };
        let peer = if peer_hint != NodeId::ZERO {
            peer_hint
        } else {
            match source_from_message(&message) {
                Some(src) if src != NodeId::ZERO => src,
                _ => {
                    debug!("LoRa: reassembled message carries no source id, dropping");
                    return;
                }
            }
        };
        self.note_peer_heard(peer).await;
        debug!(
            "LoRa message reassembled: {} bytes from {}",
            message.len(),
            peer
        );
        let _ = self.tx.send(TransportEvent::DataReceived {
            peer,
            data: message,
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

    /// Check if `airtime_ms` more airtime would exceed the duty cycle limit
    /// for the current one-hour window (regulatory limits such as EU 1% are
    /// per hour).
    /// Whether `airtime_ms` fits the remaining allowance, given a window the
    /// caller already holds.
    ///
    /// Takes the guard rather than locking, so a caller can check, admit and
    /// charge without releasing it: two sends that each check against the same
    /// remaining allowance and then both charge exceed the duty cycle.
    fn airtime_fits(&self, window: &mut DutyCycleWindow, airtime_ms: u64) -> bool {
        if self.config.duty_cycle_limit >= 1.0 {
            return true; // No limit
        }
        let max_airtime =
            (DUTY_CYCLE_WINDOW.as_millis() as f64 * self.config.duty_cycle_limit as f64) as u64;
        window.used_ms() + airtime_ms <= max_airtime
    }

    /// Airtime charged so far in the current duty-cycle window (ms).
    pub fn duty_cycle_used_ms(&self) -> u64 {
        self.duty_cycle.lock().map(|mut w| w.used_ms()).unwrap_or(0)
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
        self.send_with_priority(peer, data, SendPriority::Normal)
            .await
    }

    /// An `Alert` frame is queued ahead of ordinary traffic, and kept in
    /// preference to it when the outbox is full: this outbox is where spec
    /// §9.5's "boosted priority in relay queues" actually happens (ADR-014).
    async fn send_with_priority(
        &self,
        peer: &NodeId,
        data: &[u8],
        priority: SendPriority,
    ) -> Result<(), TransportError> {
        let started = self.started.read().await;
        if !*started {
            return Err(TransportError::NotStarted);
        }

        // Unknown peers must fail so TransportManager's fallback does not
        // report success for an unreachable node. `NodeId::ZERO` is the
        // radio broadcast (see `supports_broadcast`).
        let is_broadcast = *peer == NodeId::ZERO;
        if !is_broadcast && !self.connected_peers.read().await.contains(peer) {
            return Err(TransportError::PeerNotConnected(*peer));
        }

        if data.len() > LORA_MAX_MESSAGE {
            return Err(TransportError::ExceedsMtu {
                size: data.len(),
                mtu: LORA_MAX_MESSAGE,
            });
        }

        // Split into radio frames sized for the peer's ADR-adjusted SF
        // (broadcasts use the discovery SF so every radio can decode them).
        let peer_sf = if is_broadcast {
            self.config.spreading_factor.max(ADR_DISCOVERY_SF.min(12))
        } else {
            self.effective_sf(peer)
        };
        let frame_mtu = LoraConfig::max_payload_for_sf(peer_sf);
        let frag_id = {
            let mut next = self
                .next_frag_id
                .lock()
                .map_err(|_| TransportError::Other("fragment id lock".into()))?;
            let id = *next;
            *next = next.wrapping_add(1);
            id
        };
        let frames = fragment(data, frame_mtu, self.sender_tag, frag_id)?;

        let fragment_count = frames.len();

        // Duty cycle: charge the airtime of every frame, not the payload.
        let airtime: u64 = frames
            .iter()
            .map(|f| self.config.airtime_ms_for_sf(f.len(), peer_sf))
            .sum();
        debug!(
            "LoRa send: {} bytes to {} as {} frame(s) (SF{}, ~{}ms airtime)",
            data.len(),
            peer,
            frames.len(),
            peer_sf,
            airtime
        );

        // Queue frames for platform polling. Airtime is charged only once
        // they are admitted: an ordinary send refused by an outbox full of
        // alerts transmits nothing, and charging it anyway would let retries
        // spend the hourly allowance and block the very alerts that filled
        // the queue.
        // The duty-cycle lock is held across the check, the admission and the
        // charge. Separate acquisitions let two concurrent sends both pass
        // against the same remaining allowance and exceed it, and the charge
        // has to come after admission — a send the outbox refuses transmits
        // nothing, so charging it would let retries spend the hourly budget
        // and block the alerts that filled the queue.
        let mut window = self
            .duty_cycle
            .lock()
            .map_err(|_| TransportError::Other("duty cycle lock".into()))?;
        if !self.airtime_fits(&mut window, airtime) {
            warn!("LoRa duty cycle limit reached, dropping send");
            return Err(TransportError::SendFailed(
                "duty cycle limit exceeded".to_string(),
            ));
        }

        if let Ok(mut outbox) = self.outbox.lock() {
            // All the fragments or none: a message missing one cannot be
            // reassembled, and reporting success for a half-queued batch stops
            // the manager trying another transport.
            if outbox.push_batch(*peer, frames, priority).is_err() {
                warn!(
                    "LoRa outbox has no room for {} fragment(s) without displacing alerts",
                    fragment_count
                );
                return Err(TransportError::SendFailed(
                    "outbox is full of emergency traffic".to_string(),
                ));
            }
            debug!("LoRa outbox depth now {}", outbox.len());
        }
        window.charge(airtime);

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
        // Messages are fragmented into radio frames, so the transport-level
        // MTU is the largest reassembled message, not one frame.
        LORA_MAX_MESSAGE
    }

    fn supports_broadcast(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    /// A fragmented send must not evict its own earlier fragments to fit:
    /// with the outbox nearly full, admitting some and dropping others left a
    /// message that could never be reassembled, reported as a success — so the
    /// manager never tried another transport (ADR-014).
    #[tokio::test]
    async fn test_a_fragmented_send_is_refused_rather_than_part_queued() {
        use crate::transport::SendPriority;

        let transport = LoraTransport::new(LoraConfig::default());
        transport.start().await.expect("start");
        let peer = NodeId([2u8; 32]);
        transport.on_peer_discovered(peer).await;

        // A message that fragments into three frames, as the fragmentation
        // test above establishes.
        let mut multi = NodeId([0xBB; 32]).as_bytes().to_vec();
        multi.extend((0..78u8).collect::<Vec<u8>>());

        // Fill the outbox with alerts but for two slots, so a three-fragment
        // ordinary send cannot fit and has only alerts to displace.
        let mut alert = NodeId([0xCC; 32]).as_bytes().to_vec();
        alert.extend_from_slice(b"alert");
        while transport.outbox_len() < MAX_OUTBOX - 2 {
            transport
                .send_with_priority(&peer, &alert, SendPriority::Alert)
                .await
                .expect("alerts are admitted");
        }
        let depth = transport.outbox_len();

        let refused = transport.send(&peer, &multi).await;
        assert!(
            refused.is_err(),
            "three fragments cannot be admitted without displacing alerts"
        );
        assert_eq!(
            transport.outbox_len(),
            depth,
            "and a refusal must leave the outbox untouched"
        );
    }

    /// Airtime is a scarce hourly budget, and a send the outbox refuses
    /// transmits nothing. Charging it anyway would let ordinary retries spend
    /// the allowance and block the very alerts that filled the queue
    /// (ADR-014).
    #[tokio::test]
    async fn test_a_refused_send_does_not_spend_airtime() {
        use crate::transport::SendPriority;

        let transport = LoraTransport::new(LoraConfig::default());
        transport.start().await.expect("start");
        let peer = NodeId([2u8; 32]);
        transport.on_peer_discovered(peer).await;

        // Fill the outbox with alerts, so ordinary traffic has nowhere to go.
        // A message looks like an envelope: it starts with the 32-byte source.
        let mut alert = NodeId([0xBB; 32]).as_bytes().to_vec();
        alert.extend_from_slice(b"alert");
        while transport.outbox_len() < MAX_OUTBOX {
            transport
                .send_with_priority(&peer, &alert, SendPriority::Alert)
                .await
                .expect("an alert is always admitted");
        }
        let spent = transport.duty_cycle_used_ms();

        let mut ordinary = NodeId([0xCC; 32]).as_bytes().to_vec();
        ordinary.extend_from_slice(b"ordinary");
        let refused = transport.send(&peer, &ordinary).await;
        assert!(refused.is_err(), "an outbox full of alerts refuses it");
        assert_eq!(
            transport.duty_cycle_used_ms(),
            spent,
            "a send that transmitted nothing must not have spent airtime"
        );
    }

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
    async fn test_lora_send_fragments_and_reassembles() {
        let sender = LoraTransport::new(LoraConfig::default());
        sender.start().await.unwrap();
        let peer = NodeId([0xAA; 32]);
        sender.on_peer_discovered(peer).await;

        // A message looks like an envelope: it starts with the 32-byte source.
        // 110 bytes at SF10 (51-byte frames, 45 payload each) → 3 frames.
        let src = NodeId([0xBB; 32]);
        let mut message: Vec<u8> = src.as_bytes().to_vec();
        message.extend((0..78u8).collect::<Vec<u8>>());
        sender.send(&peer, &message).await.unwrap();
        assert_eq!(sender.outbox_len(), 3);
        let mut frames = Vec::new();
        while let Some((to, frame)) = sender.dequeue_send() {
            assert_eq!(to, peer);
            assert!(frame.len() <= LoraConfig::max_payload_for_sf(10));
            frames.push(frame);
        }

        // Receiver reassembles them even when they arrive out of order and
        // learns the peer from the envelope source (platform passes ZERO).
        let receiver = LoraTransport::new(LoraConfig::default());
        let mut events = receiver.events();
        receiver
            .on_data_received(NodeId::ZERO, frames[2].clone())
            .await;
        receiver
            .on_data_received(NodeId::ZERO, frames[0].clone())
            .await;
        assert_eq!(receiver.pending_reassemblies(), 1);
        assert!(
            events.try_recv().is_err(),
            "incomplete message must not be delivered"
        );
        receiver
            .on_data_received(NodeId::ZERO, frames[1].clone())
            .await;
        match events.try_recv() {
            Ok(TransportEvent::NeighborDiscovered { peer: p, .. }) => assert_eq!(p, src),
            other => panic!("expected NeighborDiscovered first, got {:?}", other),
        }
        match events.try_recv() {
            Ok(TransportEvent::DataReceived { peer: p, data, .. }) => {
                assert_eq!(p, src);
                assert_eq!(data, message);
            }
            other => panic!("expected reassembled DataReceived, got {:?}", other),
        }
        assert_eq!(receiver.pending_reassemblies(), 0);
        assert!(receiver.connected_peers().contains(&src));

        // A late duplicate of a consumed fragment just opens a new partial.
        receiver
            .on_data_received(NodeId::ZERO, frames[1].clone())
            .await;
        assert_eq!(receiver.pending_reassemblies(), 1);
    }

    /// Beacons must go out before any peer is known: ZERO is the radio
    /// broadcast address.
    #[tokio::test]
    async fn test_lora_broadcast_without_peers() {
        let transport = LoraTransport::new(LoraConfig::default());
        transport.start().await.unwrap();
        assert!(transport.supports_broadcast());
        let msg = [0x11u8; 60];
        transport.send(&NodeId::ZERO, &msg).await.unwrap();
        assert!(transport.outbox_len() >= 2);
        let (to, _) = transport.dequeue_send().unwrap();
        assert_eq!(to, NodeId::ZERO);
    }

    /// A peer that stops transmitting is reported lost.
    #[tokio::test]
    async fn test_lora_silent_peer_expires() {
        let transport = LoraTransport::new(LoraConfig::default());
        let mut events = transport.events();
        let src = NodeId([0xCC; 32]);
        let mut message: Vec<u8> = src.as_bytes().to_vec();
        message.push(1);
        let frame = fragment(&message, 51, 7, 1).unwrap().remove(0);
        transport
            .on_data_received(NodeId::ZERO, frame.clone())
            .await;
        assert!(matches!(
            events.try_recv(),
            Ok(TransportEvent::NeighborDiscovered { .. })
        ));
        let _ = events.try_recv(); // DataReceived

        // Age the peer past the timeout, then any received frame prunes it.
        if let Ok(mut seen) = transport.last_seen.lock() {
            seen.insert(
                src,
                Instant::now() - LORA_PEER_TIMEOUT - Duration::from_secs(1),
            );
        }
        let other = NodeId([0xDD; 32]);
        let mut m2: Vec<u8> = other.as_bytes().to_vec();
        m2.push(2);
        let f2 = fragment(&m2, 51, 8, 1).unwrap().remove(0);
        transport.on_data_received(NodeId::ZERO, f2).await;
        match events.try_recv() {
            Ok(TransportEvent::NeighborLost { peer, .. }) => assert_eq!(peer, src),
            other => panic!("expected NeighborLost, got {:?}", other),
        }
        assert!(!transport.connected_peers().contains(&src));
    }

    #[tokio::test]
    async fn test_lora_send_exceeds_max_message() {
        let transport = LoraTransport::new(LoraConfig::default());
        transport.start().await.unwrap();
        let peer = NodeId([0xAA; 32]);
        transport.on_peer_discovered(peer).await;
        let result = transport.send(&peer, &[0u8; LORA_MAX_MESSAGE + 1]).await;
        assert!(matches!(result, Err(TransportError::ExceedsMtu { .. })));
        assert_eq!(transport.outbox_len(), 0);
    }

    #[tokio::test]
    async fn test_lora_reassembly_rejects_garbage() {
        let transport = LoraTransport::new(LoraConfig::default());
        let mut events = transport.events();
        let src = NodeId([0xBB; 32]);
        transport.on_data_received(src, vec![1, 2]).await; // too short
        transport
            .on_data_received(src, vec![0, 0, 0, 0, 5, 3, 9])
            .await; // index >= count
        transport
            .on_data_received(src, vec![0, 0, 0, 0, 0, 0, 9])
            .await; // count 0
                    // Complete single frame but too short to carry a source id, no hint
        transport
            .on_data_received(NodeId::ZERO, vec![0, 0, 7, 0, 0, 1, 42, 43])
            .await;
        assert!(events.try_recv().is_err());
        assert_eq!(transport.pending_reassemblies(), 0);

        // Single-frame message with a peer hint is delivered directly.
        transport
            .on_data_received(src, vec![0, 0, 7, 0, 0, 1, 42, 43])
            .await;
        let _ = events.try_recv(); // NeighborDiscovered(src)
        match events.try_recv() {
            Ok(TransportEvent::DataReceived { data, .. }) => assert_eq!(data, vec![42, 43]),
            other => panic!("expected DataReceived, got {:?}", other),
        }
    }

    #[test]
    fn test_duty_cycle_enforcement() {
        let mut config = LoraConfig::eu_868();
        config.spreading_factor = 12; // Very long airtime per packet
        let transport = LoraTransport::new(config);

        let airtime = |bytes: usize| transport.config.airtime_ms(bytes);
        // Initially should be allowed
        assert!(transport.airtime_fits(&mut transport.duty_cycle.lock().unwrap(), airtime(50)));

        // Simulate heavy usage by setting high airtime
        if let Ok(mut w) = transport.duty_cycle.lock() {
            w.airtime_ms = 35_000; // 35 seconds out of 36 allowed (1% of 3600s)
        }
        // Should still pass for small packet
        assert!(transport.airtime_fits(&mut transport.duty_cycle.lock().unwrap(), airtime(10)));

        // Set to near limit
        if let Ok(mut w) = transport.duty_cycle.lock() {
            w.airtime_ms = 36_000; // At the limit
        }
        // Large packet should fail
        assert!(!transport.airtime_fits(&mut transport.duty_cycle.lock().unwrap(), airtime(50)));

        // Once the hour window has elapsed the budget is available again.
        if let Ok(mut w) = transport.duty_cycle.lock() {
            w.window_start = Instant::now() - DUTY_CYCLE_WINDOW - Duration::from_secs(1);
        }
        assert!(transport.airtime_fits(&mut transport.duty_cycle.lock().unwrap(), airtime(50)));
        assert_eq!(transport.duty_cycle_used_ms(), 0);
    }

    #[tokio::test]
    async fn test_lora_send_unknown_peer_fails() {
        let transport = LoraTransport::new(LoraConfig::default());
        transport.start().await.unwrap();
        let result = transport.send(&NodeId([0xCC; 32]), &[1, 2, 3]).await;
        assert!(matches!(result, Err(TransportError::PeerNotConnected(_))));
        assert_eq!(transport.outbox_len(), 0);
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
