//! Authenticated links for transports whose frames come from a platform
//! bridge (BLE and Wi-Fi Direct).
//!
//! These transports used to install a peer from an id the platform layer
//! reported: BLE read a 32-byte NodeId from a GATT characteristic and Wi-Fi
//! Direct exchanged one in a `Hello`, with no key, no signature and nothing
//! bound to the connection. Anything in radio range could claim a
//! neighbour's id, and `TransportManager` would install a route for it, so
//! that node's traffic was delivered to the claimant and dropped (ROADMAP
//! T-34, spec §22).
//!
//! This module replaces the assertion with ADR-011's proof, run over the
//! shared fragmentation layer exactly as ADR-021 decided. The bridge no
//! longer knows, or reports, who is on the other end: it reports **links**,
//! named by whatever address it already has (a BLE device address, a
//! CoreBluetooth peripheral id, a Wi-Fi socket endpoint), and relays opaque
//! frames. A peer exists here only once it has signed a fresh ephemeral key
//! and sealed a frame under the channel that key produced, and its NodeId is
//! derived from the key it proved — nothing installs an id it was handed.
//!
//! What is different from the internet transport, and why:
//!
//! - **Frames carry their counter.** See [`DatagramCipher`]: a sealed frame
//!   crossing BLE is split into 512-byte fragments that nothing retries, so
//!   an implicit counter would turn one lost fragment into a dead link.
//! - **A frame is sealed as it leaves, not as it is queued.** The outbox
//!   puts an emergency ahead of ordinary traffic (§9.5, ADR-014), so sealing
//!   on the way in would hand the peer counters in a different order from
//!   the frames, and everything the alert overtook would be refused as
//!   stale. The counter is therefore assigned where the order is decided:
//!   at the dequeue. Handshake frames are queued as alerts so that nothing
//!   can overtake the confirmation, which must be the first sealed frame.
//! - **A frame that fails to open is dropped, not fatal.** On TCP a failed
//!   open means the stream is desynchronised and the connection is finished.
//!   Here it means a frame was forged, truncated or replayed; tearing the
//!   link down would hand anything in radio range a way to kill established
//!   links by injecting noise.
//! - **A peer may hold several links.** BLE is dual-role, so two devices
//!   connect to each other in both directions and both handshakes complete.
//!   The newest established link carries what we send; a peer is reported
//!   lost only when its last link goes.
//! - **There is no background task.** Nothing here awaits, and the table is
//!   swept on every call, so an unfinished handshake is reaped by the next
//!   event — in practice the app's 50 ms outbox poll.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use mycelium_crypto::channel::{DatagramCipher, AEAD_TAG_LEN};
use mycelium_crypto::identity::Identity;
use mycelium_protocol::types::NodeId;

use super::channel::{discriminant_name, Channel, ChannelHandshakeDriver};
use super::fragment::{fragment, Reassembler};
use super::{PriorityOutbox, SendPriority, TransportError, TransportEvent, TransportType};
use crate::dht::rpc::{
    deserialize_wire_message, encode_body, ChannelWireMessage, MESH_DATA_OVERHEAD,
};

/// How a link is named. Whatever the platform layer already calls it, kept
/// opaque: Rust never parses it, and it is never trusted for identity.
pub type LinkAddr = Arc<str>;

/// Longest platform address accepted, **including the NUL terminator a C
/// caller needs**, so a buffer of this size can always carry one back out.
/// A BLE MAC is 17 characters and an IPv6 endpoint 47; this is room to spare
/// and a bound on what a bridge can make us store per link.
pub const MAX_LINK_ADDR: usize = 64;

/// Take a link address from a caller, or refuse it.
///
/// Refused rather than truncated: a shortened address names a different
/// link, which is the one mistake this layer must not make.
fn checked_addr(addr: &str) -> Option<LinkAddr> {
    if addr.is_empty() || addr.len() + 1 > MAX_LINK_ADDR {
        return None;
    }
    Some(Arc::from(addr))
}

/// Bytes a sealed mesh frame spends on framing: the counter it carries, the
/// `MeshData` header and the AEAD tag.
pub const SEALED_FRAME_OVERHEAD: usize = COUNTER_LEN + MESH_DATA_OVERHEAD + AEAD_TAG_LEN;

/// The frame counter travels ahead of the ciphertext, little-endian as
/// everything else on the wire is.
const COUNTER_LEN: usize = 8;

/// A link has this long to finish its handshake before it is reaped. The
/// same bound the internet transport puts on its own (`HANDSHAKE_TIMEOUT`).
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

/// What the platform layer must do with a link. Authentication is decided
/// here; closing sockets is the bridge's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkDirective {
    /// The handshake completed. The bridge can stop retrying this address.
    Established,
    /// Close it and do not immediately redial: the handshake failed, timed
    /// out, named us, or there was no room for it. Nothing was installed.
    Close,
}

/// Static per-transport sizing.
#[derive(Debug, Clone, Copy)]
pub struct LinkConfig {
    /// Reported on every event, so the routing layer knows which link type
    /// found the peer.
    pub transport: TransportType,
    /// Names the transport in log lines.
    pub label: &'static str,
    /// Bytes one frame carries, fragment header included.
    pub frame_mtu: usize,
    /// Largest sealed frame reassembled from fragments.
    pub max_frame: usize,
    /// Links held at once, in any stage.
    pub max_links: usize,
    /// Frames queued for the platform layer to collect.
    pub outbox_capacity: usize,
}

impl LinkConfig {
    /// The largest message a caller may send: what is left of a reassembled
    /// frame once the counter, the `MeshData` header and the AEAD tag are
    /// paid for.
    pub fn mtu(&self) -> usize {
        self.max_frame.saturating_sub(SEALED_FRAME_OVERHEAD)
    }
}

/// Where a link has got to.
enum Stage {
    /// Our hello is queued. `hello_seen` records whether the peer's has
    /// arrived, which is what says whether the next frame must be a hello or
    /// the sealed confirmation.
    Handshaking {
        driver: ChannelHandshakeDriver,
        hello_seen: bool,
    },
    /// Proved. The NodeId was derived from the key the peer signed.
    Established {
        peer: NodeId,
        /// Which establishment this was, counted across the table. A peer
        /// may hold several links, and the newest is the one we send on
        /// (ADR-021); after a link goes, the newest *survivor* takes over,
        /// which needs an order and not a `HashMap`'s.
        sequence: u64,
        send: DatagramCipher,
        recv: DatagramCipher,
    },
}

struct Link {
    stage: Stage,
    opened: Instant,
}

impl Link {
    fn peer(&self) -> Option<NodeId> {
        match self.stage {
            Stage::Established { peer, .. } => Some(peer),
            Stage::Handshaking { .. } => None,
        }
    }

    fn sequence(&self) -> u64 {
        match self.stage {
            Stage::Established { sequence, .. } => sequence,
            Stage::Handshaking { .. } => 0,
        }
    }
}

/// What one received frame leads to, decided while the link is borrowed and
/// applied once it is not.
enum Outcome {
    /// Queue this frame back to the peer (our sealed confirmation).
    Reply(Vec<u8>),
    /// The handshake completed.
    Establish(Box<Channel>),
    /// Hand the opened payload to the node.
    Deliver(NodeId, Vec<u8>),
    /// Drop the frame and keep the link.
    Ignore,
    /// Close the link. Nothing was installed.
    Close(String),
}

struct LinkState {
    config: LinkConfig,
    links: HashMap<LinkAddr, Link>,
    /// Whether new links are being taken at all. False while the transport is
    /// stopped, so a bridge still delivering frames cannot install a peer on
    /// a transport that has gone.
    accepting: bool,
    /// The link each proved peer is sent on: the most recently established.
    peers: HashMap<NodeId, LinkAddr>,
    /// Keyed by link, not by peer: a frame arrives before the peer behind it
    /// is proved, and two links must never pool their fragments.
    reassembly: Reassembler<LinkAddr>,
    /// `MeshData` bodies still to be sealed, so that a frame's counter is
    /// taken in the order frames leave rather than the order they were
    /// queued.
    outbox: PriorityOutbox<LinkAddr, Vec<u8>>,
    /// Handshake frames, drained before the outbox and never evicted.
    ///
    /// They cannot share the outbox: a full outbox makes room for an alert by
    /// dropping the oldest entry of its own class (§9.5, ADR-014), so a flood
    /// of emergencies on one link could silently discard another link's
    /// confirmation — after which our data frames would reach a peer still
    /// waiting for it, and it would close a link we think is good. At most a
    /// hello and a confirmation per link wait here.
    handshakes: VecDeque<(LinkAddr, Vec<u8>)>,
    /// The fragments of the frame currently going out, drained before the
    /// next frame is taken. Two frames interleaved on one link would be
    /// reassembled in whichever order they completed, and the one that lost
    /// would then be refused as stale.
    ///
    /// Each carries whether it belongs to a handshake frame. The platform
    /// layer gives a handshake priority and refuses to evict it, and it
    /// cannot work that out for itself: a link is established here the
    /// moment the peer's confirmation arrives, which can be before our own
    /// confirmation has left, so "is this link established" is the wrong
    /// question by exactly the margin that matters.
    fragments: VecDeque<(LinkAddr, Vec<u8>, bool)>,
    /// At most one per link, newest kept: what the bridge must do with it
    /// now, not the history of what it was told.
    directives: VecDeque<(LinkAddr, LinkDirective)>,
    /// Random per instance, so two senders' fragment ids cannot collide into
    /// one reassembly.
    sender_tag: u16,
    next_frag_id: u16,
    /// Counts establishments, so "the most recently established link" is a
    /// fact rather than whatever a hash map happens to yield first.
    next_sequence: u64,
}

impl LinkState {
    /// Queue a handshake frame, which goes on the wire exactly as it is.
    ///
    /// Its own queue, not the outbox: see `handshakes`. Refused rather than
    /// evicting anything, so a link that cannot be handshaked fails now
    /// instead of appearing to work and dying at the reaper.
    fn queue_handshake(&mut self, addr: &LinkAddr, body: Vec<u8>) -> Result<(), TransportError> {
        // Two per link is all the handshake has: a hello and a confirmation.
        let cap = self.config.max_links.saturating_mul(2).max(4);
        if self.handshakes.len() >= cap {
            return Err(TransportError::SendFailed(
                "handshake queue is full".to_string(),
            ));
        }
        self.handshakes.push_back((addr.clone(), body));
        Ok(())
    }

    /// Queue a `MeshData` body to be sealed on its way out.
    fn queue_sealed(
        &mut self,
        addr: &LinkAddr,
        body: Vec<u8>,
        priority: SendPriority,
    ) -> Result<(), TransportError> {
        if self.outbox.push(addr.clone(), body, priority).is_err() {
            return Err(TransportError::SendFailed(
                "outbox is full of emergency traffic".to_string(),
            ));
        }
        Ok(())
    }

    /// Seal a queued body for `addr`, taking the next counter on its channel.
    fn seal(&mut self, addr: &LinkAddr, body: &[u8]) -> Result<Vec<u8>, TransportError> {
        let link = self
            .links
            .get_mut(addr)
            .ok_or_else(|| TransportError::Other("link is gone".to_string()))?;
        let Stage::Established { send, .. } = &mut link.stage else {
            return Err(TransportError::Other("link is not established".to_string()));
        };
        let (counter, sealed) = send
            .seal(body)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        let mut frame = Vec::with_capacity(COUNTER_LEN + sealed.len());
        frame.extend_from_slice(&counter.to_le_bytes());
        frame.extend_from_slice(&sealed);
        Ok(frame)
    }

    /// Split one frame into fragments ready for the platform layer.
    fn spread(
        &mut self,
        addr: &LinkAddr,
        frame: &[u8],
        handshake: bool,
    ) -> Result<(), TransportError> {
        let frag_id = self.next_frag_id;
        self.next_frag_id = self.next_frag_id.wrapping_add(1);
        for piece in fragment(frame, self.config.frame_mtu, self.sender_tag, frag_id)? {
            self.fragments.push_back((addr.clone(), piece, handshake));
        }
        Ok(())
    }

    /// Queue what the bridge must do with a link.
    ///
    /// One entry per link, newest kept: the bridge needs the link's current
    /// state, not every transition it went through, and repeated frames on an
    /// unknown link must not be able to push real work out of the queue.
    ///
    /// When there is no room at all, an `Established` is dropped before a
    /// `Close`. `Established` only tells the bridge to stop retrying; a lost
    /// `Close` leaves a socket open that this layer has already forgotten, so
    /// it counts against neither `max_links` here nor the platform's own
    /// limit — the one outcome worth protecting.
    ///
    /// A queue of nothing but closes can still overflow, and then the oldest
    /// is dropped. That needs more distinct refused links between two polls
    /// than the platform can open, and it is not the only safety net: the
    /// bridges close a link of their own accord once it has been announced
    /// for twenty seconds without becoming established, because a socket's
    /// lifetime is theirs to bound rather than something to learn from a
    /// queue they poll.
    fn direct(&mut self, addr: &LinkAddr, directive: LinkDirective) {
        self.directives.retain(|(held, _)| held != addr);
        let cap = self.config.max_links.saturating_mul(4).max(8);
        if self.directives.len() >= cap {
            // An entry for a link that still exists is never the victim:
            // either it is a `Close` for a socket this layer has forgotten,
            // or it is the `Established` the bridge needs in order to stop
            // its own stale-link sweep from closing a proved peer. Both are
            // bounded by `max_links`; what is not bounded is closes for
            // addresses we never held, so those go first and oldest-first.
            let victim = self
                .directives
                .iter()
                .position(|(held, _)| !self.links.contains_key(held))
                .or_else(|| {
                    self.directives
                        .iter()
                        .position(|(_, d)| *d == LinkDirective::Established)
                })
                .unwrap_or(0);
            warn!(
                "{}: directive queue full, dropping {:?} for {}",
                self.config.label, self.directives[victim].1, self.directives[victim].0
            );
            self.directives.remove(victim);
        }
        self.directives.push_back((addr.clone(), directive));
    }

    /// Drop any directive still waiting for a link.
    ///
    /// Called when an address comes up again: a directive nobody has
    /// collected is about the connection that *was* there, and a `Close` the
    /// bridge polls after the reconnect would close the replacement.
    fn forget_directives(&mut self, addr: &LinkAddr) {
        self.directives.retain(|(held, _)| held != addr);
    }

    /// Forget a link. Returns the peer to report lost, if this was its last.
    fn forget(&mut self, addr: &LinkAddr) -> Option<NodeId> {
        // Before anything else, and whether or not the link is still here: a
        // directive nobody collected is about a link that no longer exists.
        // An `Established` delivered after the link went would mark it live
        // in the bridge's own bookkeeping, and a replacement with the same
        // name would then slip past the bridge's stale-link sweep. `Close` is
        // queued after this call, by the paths that mean it.
        self.forget_directives(addr);
        self.reassembly.forget(addr);
        // Frames for a dead link are not just wasted writes: a BLE address
        // comes back, and a frame sealed under the old link's channel would
        // be written to whoever holds it next.
        self.outbox.retain(|dest| dest != addr);
        self.handshakes.retain(|(dest, _)| dest != addr);
        self.fragments.retain(|(dest, _, _)| dest != addr);
        let peer = self.links.remove(addr)?.peer()?;

        // Another established link to the same peer keeps it connected: BLE
        // runs both roles, so losing one direction is not losing the peer.
        if self
            .peers
            .get(&peer)
            .is_some_and(|selected| selected != addr)
        {
            // The link that went was not the one we send on, so the
            // selection stands.
            return None;
        }
        let replacement = self
            .links
            .iter()
            .filter(|(_, other)| other.peer() == Some(peer))
            .max_by_key(|(_, other)| other.sequence())
            .map(|(other_addr, _)| other_addr.clone());
        match replacement {
            // The newest survivor, not an arbitrary one: ADR-021's rule is
            // that the most recently established link carries what we send.
            Some(other) => {
                self.peers.insert(peer, other);
                None
            }
            None => {
                self.peers.remove(&peer);
                Some(peer)
            }
        }
    }
}

/// The link table and the handshake that fills it.
pub struct AuthenticatedLinks {
    identity: Arc<Identity>,
    local_id: NodeId,
    config: LinkConfig,
    events: broadcast::Sender<TransportEvent>,
    state: Mutex<LinkState>,
}

impl AuthenticatedLinks {
    pub fn new(
        identity: Arc<Identity>,
        config: LinkConfig,
        events: broadcast::Sender<TransportEvent>,
    ) -> Self {
        Self {
            local_id: identity.node_id(),
            identity,
            config,
            events,
            state: Mutex::new(LinkState {
                config,
                links: HashMap::new(),
                accepting: false,
                peers: HashMap::new(),
                reassembly: Reassembler::new(config.max_frame, config.label),
                outbox: PriorityOutbox::new(config.outbox_capacity),
                handshakes: VecDeque::new(),
                fragments: VecDeque::new(),
                directives: VecDeque::new(),
                sender_tag: rand::random(),
                next_frag_id: 0,
                next_sequence: 0,
            }),
        }
    }

    pub fn config(&self) -> &LinkConfig {
        &self.config
    }

    /// Largest message `send` accepts.
    pub fn mtu(&self) -> usize {
        self.config.mtu()
    }

    fn lock(&self) -> Option<std::sync::MutexGuard<'_, LinkState>> {
        match self.state.lock() {
            Ok(guard) => Some(guard),
            Err(_) => {
                warn!("{}: link table lock poisoned", self.config.label);
                None
            }
        }
    }

    /// Reap links that never finished their handshake.
    ///
    /// Called from every entry point rather than from a timer: these
    /// transports are driven by a platform bridge that polls, so there is
    /// always a next call, and a task would have to be owned, started and
    /// stopped by a transport whose lifecycle is the app's.
    fn sweep(state: &mut LinkState, now: Instant) {
        let expired: Vec<LinkAddr> = state
            .links
            .iter()
            .filter(|(_, link)| {
                matches!(link.stage, Stage::Handshaking { .. })
                    && now.saturating_duration_since(link.opened) >= HANDSHAKE_DEADLINE
            })
            .map(|(addr, _)| addr.clone())
            .collect();
        for addr in expired {
            debug!(
                "{}: link {} never finished its handshake",
                state.config.label, addr
            );
            // Unestablished, so `forget` can have no peer to report.
            state.forget(&addr);
            state.direct(&addr, LinkDirective::Close);
        }
    }

    /// Open the transport: links may be taken from now on.
    pub fn open(&self) {
        if let Some(mut state) = self.lock() {
            state.accepting = true;
        }
    }

    /// The platform layer brought a link up. Queues our hello.
    pub fn link_up(&self, addr: &str) {
        let Some(addr) = checked_addr(addr) else {
            warn!("{}: refusing an unusable link address", self.config.label);
            return;
        };
        let Some(mut state) = self.lock() else { return };
        Self::sweep(&mut state, Instant::now());

        if !state.accepting {
            debug!(
                "{}: link {} arrived while stopped, closing it",
                self.config.label, addr
            );
            state.direct(&addr, LinkDirective::Close);
            return;
        }
        if state.links.contains_key(&addr) {
            // The bridge reported the same link twice. Restarting the
            // handshake here would let a repeat announcement displace a
            // proved peer, so the existing link stands; one that never
            // completes is reaped at its deadline and may then be reopened.
            debug!("{}: link {} is already open", self.config.label, addr);
            return;
        }
        if state.links.len() >= self.config.max_links {
            // Refused, never evicted: a stranger opening links must not be
            // able to drop a peer that has already proved itself.
            warn!(
                "{}: no room for link {} ({} open)",
                self.config.label,
                addr,
                state.links.len()
            );
            state.direct(&addr, LinkDirective::Close);
            return;
        }

        // A directive nobody has collected is about the connection that was
        // there before this one; polled after the reconnect, a stale `Close`
        // would close the replacement.
        state.forget_directives(&addr);

        let (driver, hello) = ChannelHandshakeDriver::start(&self.identity, 0);
        state.links.insert(
            addr.clone(),
            Link {
                stage: Stage::Handshaking {
                    driver,
                    hello_seen: false,
                },
                opened: Instant::now(),
            },
        );
        if let Err(e) = state.queue_handshake(&addr, hello) {
            warn!(
                "{}: cannot send a hello on {}: {}",
                self.config.label, addr, e
            );
            state.forget(&addr);
            state.direct(&addr, LinkDirective::Close);
        }
    }

    /// The platform layer lost a link.
    pub fn link_down(&self, addr: &str) {
        let Some(addr) = checked_addr(addr) else {
            return;
        };
        let Some(mut state) = self.lock() else { return };
        Self::sweep(&mut state, Instant::now());
        if let Some(peer) = state.forget(&addr) {
            info!("{}: peer {} disconnected", self.config.label, peer);
            // Under the lock, as the internet transport does it: a reconnect
            // that discovers the same peer must not overtake this loss and
            // have the routing layer drop the live link it just installed.
            let _ = self.events.send(TransportEvent::NeighborLost {
                peer,
                transport: self.config.transport,
            });
        }
    }

    /// One frame arrived on a link.
    pub fn link_data(&self, addr: &str, frame: &[u8]) {
        let Some(addr) = checked_addr(addr) else {
            return;
        };
        let Some(mut state) = self.lock() else { return };
        Self::sweep(&mut state, Instant::now());

        if !state.links.contains_key(&addr) {
            // Only the bridge's own announcement opens a link. Letting a
            // frame open one would mean a link we had just closed could
            // reopen itself with whatever was still in flight.
            debug!(
                "{}: frame on unknown link {}, closing it",
                self.config.label, addr
            );
            state.direct(&addr, LinkDirective::Close);
            return;
        }

        let Some(body) = state.reassembly.push(addr.clone(), frame) else {
            return;
        };

        let outcome = self.classify(&mut state, &addr, &body);
        self.apply(&mut state, &addr, outcome);
    }

    /// Decide what a reassembled frame means, with the link borrowed.
    fn classify(&self, state: &mut LinkState, addr: &LinkAddr, body: &[u8]) -> Outcome {
        let label = self.config.label;
        let Some(link) = state.links.get_mut(addr) else {
            return Outcome::Ignore;
        };
        match &mut link.stage {
            Stage::Handshaking { driver, hello_seen } if !*hello_seen => {
                match driver.accept_hello(body) {
                    Ok(confirm) => {
                        *hello_seen = true;
                        Outcome::Reply(confirm)
                    }
                    Err(e) => Outcome::Close(e.to_string()),
                }
            }
            Stage::Handshaking { driver, .. } => match driver.accept_confirm(body) {
                Ok(channel) => Outcome::Establish(Box::new(channel)),
                Err(e) => Outcome::Close(e.to_string()),
            },
            Stage::Established { peer, recv, .. } => {
                if body.len() < COUNTER_LEN {
                    return Outcome::Ignore;
                }
                let mut counter_bytes = [0u8; COUNTER_LEN];
                counter_bytes.copy_from_slice(&body[..COUNTER_LEN]);
                let counter = u64::from_le_bytes(counter_bytes);
                let opened = match recv.open(counter, &body[COUNTER_LEN..]) {
                    Ok(opened) => opened,
                    Err(e) => {
                        // Dropped, not fatal: a forged or replayed frame must
                        // not give anything in range a way to kill the link.
                        debug!("{}: dropping a frame from {}: {}", label, peer, e);
                        return Outcome::Ignore;
                    }
                };
                match deserialize_wire_message(&opened) {
                    // The sender id in the frame is ignored: the peer is
                    // whoever holds this channel's key.
                    Ok(ChannelWireMessage::MeshData { data, .. }) => Outcome::Deliver(*peer, data),
                    Ok(ChannelWireMessage::Hello { .. })
                    | Ok(ChannelWireMessage::Confirm { .. }) => {
                        // The handshake is over; a repeat must never
                        // re-authenticate an established link.
                        debug!("{}: ignoring a late handshake frame from {}", label, peer);
                        Outcome::Ignore
                    }
                    Ok(other) => {
                        debug!(
                            "{}: {} is not carried on a local link, dropping it",
                            label,
                            discriminant_name(&other)
                        );
                        Outcome::Ignore
                    }
                    Err(e) => {
                        debug!("{}: undecodable frame from {}: {}", label, peer, e);
                        Outcome::Ignore
                    }
                }
            }
        }
    }

    /// Apply what `classify` decided, with the link no longer borrowed.
    ///
    /// Events go out from here, while the state lock is still held, so the
    /// order the routing layer sees is the order the links changed in.
    fn apply(&self, state: &mut LinkState, addr: &LinkAddr, outcome: Outcome) {
        match outcome {
            Outcome::Ignore => {}
            Outcome::Reply(body) => {
                if let Err(e) = state.queue_handshake(addr, body) {
                    warn!(
                        "{}: cannot confirm the channel on {}: {}",
                        self.config.label, addr, e
                    );
                    state.forget(addr);
                    state.direct(addr, LinkDirective::Close);
                }
            }
            Outcome::Establish(channel) => {
                let peer = channel.peer.node_id;
                if peer == self.local_id {
                    // Our own identity on the far end: a loopback the
                    // platform could not recognise, since it no longer sees
                    // an id. Nothing is installed.
                    debug!(
                        "{}: link {} proved our own identity, closing it",
                        self.config.label, addr
                    );
                    state.forget(addr);
                    state.direct(addr, LinkDirective::Close);
                    return;
                }
                let sequence = state.next_sequence;
                let Some(link) = state.links.get_mut(addr) else {
                    return;
                };
                link.stage = Stage::Established {
                    peer,
                    sequence,
                    send: channel.send.into_datagram(),
                    recv: channel.recv.into_datagram(),
                };
                state.next_sequence = sequence.saturating_add(1);
                // The newest established link is the one we send on; any
                // earlier one stays readable until it drops.
                state.peers.insert(peer, addr.clone());
                state.direct(addr, LinkDirective::Established);
                info!(
                    "{}: peer {} proved its identity on {}",
                    self.config.label, peer, addr
                );
                let _ = self.events.send(TransportEvent::NeighborDiscovered {
                    peer,
                    transport: self.config.transport,
                });
            }
            Outcome::Deliver(peer, data) => {
                let _ = self.events.send(TransportEvent::DataReceived {
                    peer,
                    data,
                    transport: self.config.transport,
                });
            }
            Outcome::Close(reason) => {
                debug!("{}: closing link {}: {}", self.config.label, addr, reason);
                // An unproved link cannot report a peer lost; a proved one
                // does not reach here, because a bad frame is dropped.
                if let Some(peer) = state.forget(addr) {
                    let _ = self.events.send(TransportEvent::NeighborLost {
                        peer,
                        transport: self.config.transport,
                    });
                }
                state.direct(addr, LinkDirective::Close);
            }
        }
    }

    /// Seal a message for a proved peer and queue it.
    pub fn send(
        &self,
        peer: &NodeId,
        data: &[u8],
        priority: SendPriority,
    ) -> Result<(), TransportError> {
        if data.len() > self.mtu() {
            return Err(TransportError::ExceedsMtu {
                size: data.len(),
                mtu: self.mtu(),
            });
        }
        let mut state = self
            .lock()
            .ok_or_else(|| TransportError::Other("link table lock".to_string()))?;
        Self::sweep(&mut state, Instant::now());

        let addr = state
            .peers
            .get(peer)
            .cloned()
            .ok_or(TransportError::PeerNotConnected(*peer))?;
        if !matches!(
            state.links.get(&addr).map(|link| &link.stage),
            Some(Stage::Established { .. })
        ) {
            return Err(TransportError::PeerNotConnected(*peer));
        }
        let body = encode_body(&ChannelWireMessage::MeshData {
            sender_id: self.local_id,
            data: data.to_vec(),
        });
        state.queue_sealed(&addr, body, priority)
    }

    /// Take the next frame the platform layer should write, with the link to
    /// write it on.
    /// Returns the link to write on, the fragment, and whether it belongs to
    /// a handshake frame — which the platform layer must neither delay nor
    /// evict, and cannot identify for itself.
    pub fn dequeue_send(&self) -> Option<(LinkAddr, Vec<u8>, bool)> {
        let mut state = self.lock()?;
        Self::sweep(&mut state, Instant::now());
        loop {
            if let Some(next) = state.fragments.pop_front() {
                return Some(next);
            }
            // Handshake frames before traffic: a link that has not finished
            // proving itself is on a ten-second deadline, and its frames
            // cannot be evicted to make room for anything.
            // A handshake frame is already what should go on the wire; a
            // queued message is sealed here, where its place in the order is
            // finally known.
            let (addr, frame, handshake) = match state.handshakes.pop_front() {
                Some((addr, frame)) => (addr, frame, true),
                None => {
                    let (addr, body) = state.outbox.pop()?;
                    match state.seal(&addr, &body) {
                        Ok(frame) => (addr, frame, false),
                        Err(e) => {
                            // The link went away, or its counter is spent.
                            // The message is dropped here rather than
                            // earlier because this is where it was due to
                            // leave.
                            debug!(
                                "{}: dropping a queued message for {}: {}",
                                self.config.label, addr, e
                            );
                            continue;
                        }
                    }
                }
            };
            if let Err(e) = state.spread(&addr, &frame, handshake) {
                debug!(
                    "{}: cannot fragment a frame for {}: {}",
                    self.config.label, addr, e
                );
                continue;
            }
        }
    }

    /// Take the next thing the platform layer must do with a link.
    pub fn next_directive(&self) -> Option<(LinkAddr, LinkDirective)> {
        let mut state = self.lock()?;
        Self::sweep(&mut state, Instant::now());
        state.directives.pop_front()
    }

    /// Frames waiting for the platform layer.
    pub fn outbox_len(&self) -> usize {
        self.lock()
            .map(|s| s.outbox.len() + s.handshakes.len() + s.fragments.len())
            .unwrap_or(0)
    }

    /// Links held, in any stage.
    pub fn link_count(&self) -> usize {
        self.lock().map(|s| s.links.len()).unwrap_or(0)
    }

    /// Peers that have proved their identity.
    pub fn connected_peers(&self) -> Vec<NodeId> {
        self.lock()
            .map(|s| s.peers.keys().copied().collect())
            .unwrap_or_default()
    }

    pub fn is_connected(&self, peer: &NodeId) -> bool {
        self.lock()
            .map(|s| s.peers.contains_key(peer))
            .unwrap_or(false)
    }

    /// Seal an arbitrary body for a proved peer, bypassing `send`'s framing.
    ///
    /// Only a test needs this: it is how a frame the public API cannot
    /// produce — a DHT request on a radio link — is put on the wire by a
    /// genuine peer on a genuine channel, which is the case worth refusing
    /// explicitly.
    #[cfg(test)]
    pub fn send_raw_for_test(&self, peer: &NodeId, body: &[u8]) -> Result<(), TransportError> {
        let mut state = self
            .lock()
            .ok_or_else(|| TransportError::Other("link table lock".to_string()))?;
        let addr = state
            .peers
            .get(peer)
            .cloned()
            .ok_or(TransportError::PeerNotConnected(*peer))?;
        state.queue_sealed(&addr, body.to_vec(), SendPriority::Normal)
    }

    /// Run the sweep as if every handshake deadline had passed.
    #[cfg(test)]
    pub fn expire_handshakes_for_test(&self) {
        if let Some(mut state) = self.lock() {
            Self::sweep(&mut state, Instant::now() + HANDSHAKE_DEADLINE);
        }
    }

    /// Drop every link, reporting each proved peer lost.
    ///
    /// The routing layer learns the peers are gone; staying silent would
    /// leave routes pointing at a transport that has stopped.
    pub fn clear(&self) {
        let Some(mut state) = self.lock() else { return };
        let lost: Vec<NodeId> = state.peers.keys().copied().collect();
        // No new links until the transport is started again: a bridge that
        // keeps delivering frames must not be able to install a peer on a
        // transport that has stopped.
        state.accepting = false;
        state.links.clear();
        state.peers.clear();
        state.outbox.clear();
        state.handshakes.clear();
        state.fragments.clear();
        state.directives.clear();
        state.reassembly.clear();
        for peer in lost {
            // Under the lock, with the table already empty, so nothing can
            // discover a peer between the clear and its loss.
            let _ = self.events.send(TransportEvent::NeighborLost {
                peer,
                transport: self.config.transport,
            });
        }
    }
}
