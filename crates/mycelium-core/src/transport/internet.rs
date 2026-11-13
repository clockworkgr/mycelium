//! Internet TCP transport for long-range mesh connectivity.
//!
//! Nodes reach each other over TCP and find each other through the Kademlia
//! DHT in [`crate::dht`].
//!
//! Every connection is a **keyed, mutually authenticated channel** before any
//! state is installed (ROADMAP T-09, ADR-011). Both ends sign a fresh X25519
//! ephemeral public key with their identity key, derive directional AES-256-GCM
//! keys from the resulting shared secret, and prove possession of those keys
//! with a `Confirm` frame before the peer is installed. Every later frame is
//! sealed, so TCP's lack of integrity cannot be used to inject or alter one.
//!
//! Signing an ephemeral key rather than exchanged nonces is what closes the
//! relay: an attacker can forward a victim's signed `Hello`, but it holds no
//! ephemeral secret for it, so it cannot produce the `Confirm` frame, let alone
//! speak on the channel. A handshake that does not complete costs the peer its
//! socket: no `connections` entry, no DHT contact, no `NeighborDiscovered`, and
//! therefore no route in `TransportManager`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use mycelium_crypto::channel::{channel_hello_payload, ChannelHandshake, FrameCipher};
use mycelium_crypto::identity::{node_id_from_public_key, verify_signature_bytes, Identity};
use mycelium_protocol::types::{LinkQuality, NodeId};

use super::{SendPriority, Transport, TransportError, TransportEvent, TransportType};
use crate::dht::record::{DhtRecord, RECORD_TTL_SECS};
use crate::dht::rpc::{
    deserialize_wire_message, encode_body, DhtReply, DhtRequest, DhtRequestBody,
    InternetWireMessage, CONFIRM_FRAME_LEN, MAX_HANDSHAKE_FRAME, MAX_MESH_PAYLOAD,
    MAX_WIRE_MESSAGE,
};
use crate::dht::{AddrSource, DhtConfig, DhtEngine, DhtRpc, PeerInfo, REQUEST_TIMEOUT};

/// Bound on the whole handshake, so an idle or stalling peer cannot hold a
/// task, a socket and a connection slot indefinitely.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often we re-sign and re-offer our own address record. A third of the
/// record TTL, so a peer always holds an unexpired record for us even if one
/// republish is lost.
const RECORD_REPUBLISH_INTERVAL: Duration = Duration::from_secs(RECORD_TTL_SECS / 3);

/// How long `stop()` waits for its tasks, and then for every connection to
/// release its slot, before giving up and logging. Connections are cancelled
/// first, so reaching this means a task is wedged.
const STOP_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Frames that may be queued for one peer before sends start failing. Same
/// shape as the other transports' outboxes: a bounded queue, and a failed send
/// the node's DTN layer can fall back on.
const OUTBOX_CAPACITY: usize = 128;

/// Frames queued for the alert channel of one connection.
///
/// Smaller than the ordinary outbox: an emergency is rare, and a queue deep
/// enough to hold many of them would only delay the newest behind the oldest.
const ALERT_OUTBOX_CAPACITY: usize = 16;

/// How long one frame may take to reach the socket before the channel is
/// considered dead. Bounds a peer that stops reading.
const FRAME_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for a TCP connect, dialled or bootstrap.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Configuration for the Internet transport.
#[derive(Debug, Clone)]
pub struct InternetConfig {
    /// Address to listen on for incoming connections.
    pub listen_addr: SocketAddr,
    /// Bootstrap DHT nodes to connect to initially.
    pub bootstrap_nodes: Vec<SocketAddr>,
    /// Maximum number of simultaneous TCP connections, inbound and outbound,
    /// counted from the moment a socket is accepted or dialled.
    pub max_connections: usize,
}

impl Default for InternetConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:9736".parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            max_connections: 64,
        }
    }
}

/// The sealed write half of a channel.
struct SealedWriter {
    writer: tokio::io::WriteHalf<TcpStream>,
    cipher: FrameCipher,
}

impl SealedWriter {
    /// Seal and write one frame.
    ///
    /// Only ever called from the connection's own writer task. Sealing
    /// advances the frame counter, so a caller that could be cancelled between
    /// the seal and the write would leave a truncated frame on the wire and
    /// every later frame mis-numbered — which is why no other code may call
    /// this directly.
    async fn send(&mut self, msg: &InternetWireMessage) -> Result<(), TransportError> {
        let body = encode_body(msg);
        let sealed = self
            .cipher
            .seal(&body)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        write_framed(&mut self.writer, &sealed).await
    }

    async fn shutdown(&mut self) {
        let _ = self.writer.shutdown().await;
    }
}

/// Owns the sealed write half for one connection.
///
/// Every frame is sealed and written here, in one task that no *caller* can
/// cancel mid-frame. Senders only queue, so a cancelled send can lose a
/// message but can never corrupt the channel.
///
/// The write itself is inside the cancellation select, because a peer that
/// stops reading would otherwise keep a live socket for the write timeout
/// after `stop()` returned. Abandoning a half-written frame is safe here and
/// only here: the task immediately cancels the connection and closes the
/// socket, so nothing further is ever sealed for that channel.
///
/// Holds a share of the connection's permit, so the slot comes back only once
/// both this task and the read loop are gone.
async fn writer_task(
    mut writer: SealedWriter,
    mut outbox: mpsc::Receiver<InternetWireMessage>,
    mut alerts: mpsc::Receiver<InternetWireMessage>,
    cancel: CancellationToken,
    _permit: Arc<OwnedSemaphorePermit>,
) {
    loop {
        // Alerts first, and the select is biased so a steady stream of
        // ordinary traffic cannot starve them: this channel is where spec
        // §9.5's "boosted priority in relay queues" happens for the internet
        // transport (ADR-014).
        let msg = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            msg = alerts.recv() => match msg {
                Some(msg) => msg,
                // The alert channel closing means the connection is going
                // away; the ordinary one is handled the same way below.
                None => break,
            },
            msg = outbox.recv() => match msg {
                Some(msg) => msg,
                None => break,
            },
        };
        let written = tokio::select! {
            _ = cancel.cancelled() => break,
            result = tokio::time::timeout(FRAME_WRITE_TIMEOUT, writer.send(&msg)) => result,
        };
        match written {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                debug!("Internet: write failed, closing the channel: {}", e);
                break;
            }
            Err(_) => {
                debug!("Internet: peer stopped reading, closing the channel");
                break;
            }
        }
    }
    // A connection we can no longer write to is useless, and leaving its entry
    // in place would block a reconnect while the peer keeps its own direction
    // open. Cancelling tears the read loop down with us.
    cancel.cancel();
    // Close the write half so the peer sees EOF rather than a half-written
    // frame it would try to parse.
    writer.shutdown().await;
}

/// The sealed read half of a channel.
struct SealedReader {
    reader: tokio::io::ReadHalf<TcpStream>,
    cipher: FrameCipher,
}

impl SealedReader {
    async fn recv(&mut self) -> Result<InternetWireMessage, TransportError> {
        let sealed = read_framed(&mut self.reader, MAX_WIRE_MESSAGE).await?;
        let body = self
            .cipher
            .open(&sealed)
            .map_err(|e| TransportError::Other(e.to_string()))?;
        deserialize_wire_message(&body).map_err(|e| TransportError::Other(e.to_string()))
    }
}

/// Active connection to an authenticated peer.
struct PeerConnection {
    /// The socket address this connection runs over.
    socket_addr: SocketAddr,
    /// The peer's dialable address: its socket IP with its *signed* listen
    /// port. For an inbound connection the socket's port is ephemeral and
    /// useless for dialling back.
    dialable_addr: SocketAddr,
    /// True when we dialled `dialable_addr` ourselves, so it is proven
    /// reachable rather than derived from the peer's own claim.
    dialled: bool,
    connected_at: Instant,
    /// This channel's transcript, used to order two connections to the same
    /// peer identically at both ends.
    transcript: [u8; 32],
    /// Cancels just this connection, without stopping the transport. A child
    /// of the transport's lifetime token, so `stop()` still reaches it.
    cancel: CancellationToken,
    /// Queue into the connection's writer task.
    outbox: mpsc::Sender<InternetWireMessage>,
    /// Queue for emergency alerts, which the writer drains first.
    ///
    /// A separate channel rather than a priority flag, because an `mpsc` is
    /// first-in-first-out: an alert queued behind a hundred ordinary frames
    /// would leave last however it was labelled.
    alerts: mpsc::Sender<InternetWireMessage>,
    /// In-flight DHT requests on *this* connection, awaiting their replies.
    ///
    /// Per connection, not global: with one shared map any authenticated peer
    /// could answer a request addressed to another by guessing its id.
    pending: std::sync::Mutex<HashMap<u64, oneshot::Sender<DhtReply>>>,
}

impl PeerConnection {
    /// Queue a frame for transmission.
    ///
    /// Synchronous on purpose: there is no await to be cancelled, so a caller
    /// that goes away cannot leave the channel half-written. A full outbox
    /// means the peer is not draining, which the caller should treat as a
    /// failed send.
    fn enqueue(&self, msg: InternetWireMessage) -> Result<(), TransportError> {
        self.enqueue_with_priority(msg, SendPriority::Normal)
    }

    /// `enqueue`, choosing the queue the writer drains first for an alert.
    fn enqueue_with_priority(
        &self,
        msg: InternetWireMessage,
        priority: SendPriority,
    ) -> Result<(), TransportError> {
        let queue = match priority {
            SendPriority::Alert => &self.alerts,
            SendPriority::Normal => &self.outbox,
        };
        queue.try_send(msg).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => {
                TransportError::SendFailed("peer is not draining its outbox".to_string())
            }
            mpsc::error::TrySendError::Closed(_) => {
                TransportError::SendFailed("connection is closed".to_string())
            }
        })
    }

    /// This connection as a DHT contact.
    ///
    /// The address is only *proven* when we dialled it. An inbound
    /// connection's is derived from its socket IP and the listen port the
    /// peer signed, which is the peer's claim — and a claim must not replace
    /// an endpoint we reached, or a peer behind a port forward becomes
    /// undialable.
    fn contact(&self, peer_id: NodeId) -> PeerInfo {
        PeerInfo {
            node_id: peer_id,
            addr: self.dialable_addr,
            last_seen: Instant::now(),
            addr_source: if self.dialled {
                AddrSource::Dialled
            } else {
                AddrSource::Claimed
            },
            // When *this* channel proved the address, not now: every DHT
            // request this connection answers refreshes the contact, and
            // dating those refreshes `now` let a long-lived channel keep
            // reinstating its own endpoint over one a later dial proved.
            addr_proved_at: self.connected_at,
        }
    }

    fn resolve_pending(&self, reply: DhtReply) {
        let waiter = self
            .pending
            .lock()
            .map(|mut p| p.remove(&reply.request_id))
            .unwrap_or(None);
        match waiter {
            Some(tx) => {
                let _ = tx.send(reply);
            }
            None => debug!(
                "Internet: dropping an unmatched DHT reply {}",
                reply.request_id
            ),
        }
    }

    fn forget_pending(&self, request_id: u64) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&request_id);
        }
    }
}

/// Leaves the transport in a usable stopped state however `stop()` ends.
///
/// The drains it brackets can be abandoned safely: the connections being
/// drained have already been cancelled, so their read loops remove their own
/// entries and their permits come back without anyone waiting for them. What
/// cannot be left behind is the shutdown flag or the cancelled lifetime
/// token, because nothing later would repair either — dials would be refused
/// for good, and a `start()` would hand its tasks a token that is already
/// cancelled.
///
/// The replacement token is published here, which is *after* the drain in the
/// ordinary case, so a dial still cannot attach to it and outlive the
/// shutdown.
struct StopState<'a> {
    stopping: &'a std::sync::atomic::AtomicBool,
    lifetime: &'a std::sync::Mutex<CancellationToken>,
    started: &'a mut bool,
}

impl Drop for StopState<'_> {
    fn drop(&mut self) {
        if let Ok(mut token) = self.lifetime.lock() {
            *token = CancellationToken::new();
        }
        self.stopping
            .store(false, std::sync::atomic::Ordering::SeqCst);
        *self.started = false;
    }
}

/// Clears a pending entry however `request` ends, including cancellation.
///
/// A dropped future never reaches its cleanup code, so without this a lookup
/// that times out leaves its slot in the map for the connection's lifetime.
struct PendingGuard<'a> {
    conn: &'a PeerConnection,
    request_id: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.conn.forget_pending(self.request_id);
    }
}

/// What a connection task needs, so inbound and outbound connections run the
/// same code instead of two copies that drift apart.
struct Shared {
    identity: Arc<Identity>,
    local_id: NodeId,
    listen_addr: SocketAddr,
    dht: Arc<DhtEngine>,
    event_tx: broadcast::Sender<TransportEvent>,
    connections: RwLock<HashMap<NodeId, Arc<PeerConnection>>>,
    /// One permit per allowed connection; held for the connection's lifetime.
    slots: Arc<Semaphore>,
    /// The permit count the semaphore was actually built with, so `stop()`
    /// drains exactly as many as exist.
    connection_limit: usize,
}

/// Internet transport using TCP connections and Kademlia DHT for discovery.
pub struct InternetTransport {
    shared: Arc<Shared>,
    config: InternetConfig,
    started: RwLock<bool>,
    /// Parent of every connection's and task's token.
    ///
    /// Replaced — not just cancelled — by `stop()`, so the transport can be
    /// restarted. Everything takes a child or clone of whatever this holds at
    /// the time, including connections opened by `connect_to` before `start()`:
    /// those used to attach to a token `start()` then replaced without
    /// cancelling, so a later `stop()` never reached them.
    lifetime: std::sync::Mutex<CancellationToken>,
    /// Background tasks, so `stop()` can wait for the listener to close and
    /// for every connection to release its slot.
    tasks: Mutex<JoinSet<()>>,
    /// Set for the duration of `stop()`. A dial that began before it is
    /// cancelled through the old token; one that arrives during it is refused,
    /// because it would otherwise attach to the replacement token, survive
    /// cancellation, and have its map entry cleared out from under it while
    /// its socket and permit stayed alive.
    stopping: std::sync::atomic::AtomicBool,
}

/// A peer that has proved possession of the identity key behind its NodeId
/// *and* of the channel key derived from the ephemeral key it signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    pub node_id: NodeId,
    pub identity_key: [u8; 32],
    /// The port the peer says it accepts connections on, covered by its
    /// signature so a man in the middle cannot redirect later dials.
    pub listen_port: u16,
}

/// Read one length-prefixed frame body, capped at `max`.
async fn read_framed<R: AsyncRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| TransportError::Other(e.to_string()))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max {
        return Err(TransportError::Other(format!(
            "frame of {} bytes exceeds the {} byte cap",
            len, max
        )));
    }
    let mut data = vec![0u8; len];
    reader
        .read_exact(&mut data)
        .await
        .map_err(|e| TransportError::Other(e.to_string()))?;
    Ok(data)
}

/// Write one length-prefixed frame body.
async fn write_framed<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> Result<(), TransportError> {
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(body);
    writer
        .write_all(&frame)
        .await
        .map_err(|e| TransportError::SendFailed(e.to_string()))
}

/// The result of a completed handshake: who the peer is, and the channel.
pub struct Channel {
    pub peer: AuthenticatedPeer,
    /// Identifies this channel. Both ends derive the same value, and it
    /// differs per connection, which is what makes it a usable tie-break when
    /// two connections to one peer exist at once.
    pub transcript: [u8; 32],
    send: FrameCipher,
    recv: FrameCipher,
}

/// Run the mutual handshake. Symmetric: the same code serves both ends.
///
/// Returns only once the peer has proved it holds the channel key, so a
/// caller that gets a `Channel` is talking to the node it names.
pub async fn handshake<R, W>(
    identity: &Identity,
    listen_port: u16,
    reader: &mut R,
    writer: &mut W,
) -> Result<Channel, TransportError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let exchange = ChannelHandshake::new();
    let ephemeral_public = exchange.public_key();
    let identity_key = identity.public_key_bytes();
    let signature = identity
        .sign(&channel_hello_payload(
            &ephemeral_public,
            &identity_key,
            listen_port,
        ))
        .to_bytes();

    write_framed(
        writer,
        &encode_body(&InternetWireMessage::Hello {
            identity_key,
            ephemeral_public,
            listen_port,
            signature,
        }),
    )
    .await?;

    let body = read_framed(reader, MAX_HANDSHAKE_FRAME).await?;
    let peer =
        match deserialize_wire_message(&body).map_err(|e| TransportError::Other(e.to_string()))? {
            InternetWireMessage::Hello {
                identity_key,
                ephemeral_public,
                listen_port,
                signature,
            } => (identity_key, ephemeral_public, listen_port, signature),
            other => {
                return Err(TransportError::Other(format!(
                    "expected a hello, got {}",
                    discriminant_name(&other)
                )))
            }
        };
    let (peer_identity_key, peer_ephemeral, peer_port, peer_signature) = peer;

    verify_signature_bytes(
        &peer_identity_key,
        &channel_hello_payload(&peer_ephemeral, &peer_identity_key, peer_port),
        &peer_signature,
    )
    .map_err(|_| TransportError::Other("hello signature did not verify".to_string()))?;

    let mut keys = exchange
        .complete(&peer_ephemeral, &identity_key, &peer_identity_key)
        .map_err(|e| TransportError::Other(e.to_string()))?;

    // Key confirmation. Without it a relay that forwarded someone else's
    // hello would install itself as a peer that silently drops everything.
    let confirm = InternetWireMessage::Confirm {
        transcript: keys.transcript,
    };
    let sealed = keys
        .send
        .seal(&encode_body(&confirm))
        .map_err(|e| TransportError::SendFailed(e.to_string()))?;
    write_framed(writer, &sealed).await?;

    // The peer has not yet proved it holds the channel key, so this frame gets
    // its own exact cap rather than the 1 MiB data-frame cap.
    let sealed = read_framed(reader, CONFIRM_FRAME_LEN).await?;
    let opened = keys
        .recv
        .open(&sealed)
        .map_err(|_| TransportError::Other("peer could not prove the channel key".to_string()))?;
    match deserialize_wire_message(&opened).map_err(|e| TransportError::Other(e.to_string()))? {
        InternetWireMessage::Confirm { transcript } if transcript == keys.transcript => {}
        InternetWireMessage::Confirm { .. } => {
            return Err(TransportError::Other(
                "peer confirmed a different transcript".to_string(),
            ))
        }
        other => {
            return Err(TransportError::Other(format!(
                "expected a confirmation, got {}",
                discriminant_name(&other)
            )))
        }
    }

    Ok(Channel {
        peer: AuthenticatedPeer {
            node_id: node_id_from_public_key(&peer_identity_key),
            identity_key: peer_identity_key,
            listen_port: peer_port,
        },
        transcript: keys.transcript,
        send: keys.send,
        recv: keys.recv,
    })
}

fn discriminant_name(msg: &InternetWireMessage) -> &'static str {
    match msg {
        InternetWireMessage::MeshData { .. } => "mesh data",
        InternetWireMessage::Dht(_) => "dht request",
        InternetWireMessage::DhtReply(_) => "dht reply",
        InternetWireMessage::Hello { .. } => "hello",
        InternetWireMessage::Confirm { .. } => "confirmation",
    }
}

impl Shared {
    /// Whether our configured listen address is worth telling anyone about.
    ///
    /// A record for `0.0.0.0` would be signed, valid and useless, so we
    /// neither store nor publish one. Learning the address peers actually see
    /// us on is ROADMAP T-31.
    fn has_publishable_address(&self) -> bool {
        !self.listen_addr.ip().is_unspecified()
    }

    /// Authenticate a fresh socket and install the connection.
    ///
    /// On any failure nothing is installed and no event is emitted, so an
    /// unverified peer never reaches the routing layer.
    async fn establish(
        &self,
        stream: TcpStream,
        socket_addr: SocketAddr,
        cancel: &CancellationToken,
        expected: Option<NodeId>,
        // For an outbound connection, the address we dialled. `None` for an
        // inbound one, where the peer's dialable address has to be derived.
        dialled: Option<SocketAddr>,
        permit: Arc<OwnedSemaphorePermit>,
    ) -> Result<(NodeId, Arc<PeerConnection>, SealedReader, CancellationToken), TransportError>
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let channel = tokio::select! {
            _ = cancel.cancelled() => {
                return Err(TransportError::Other("transport stopped".to_string()));
            }
            result = tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                handshake(&self.identity, self.listen_addr.port(), &mut reader, &mut writer),
            ) => result
                .map_err(|_| TransportError::Other("handshake timed out".to_string()))??,
        };

        if channel.peer.node_id == self.local_id {
            return Err(TransportError::Other(
                "peer proved our own identity".to_string(),
            ));
        }
        // Checked before anything is installed: a dial made to reach a
        // particular node, from a referral that turned out to be stale or
        // dishonest, must not leave an unrelated peer holding a slot.
        if let Some(expected) = expected {
            if channel.peer.node_id != expected {
                return Err(TransportError::Other(format!(
                    "{} answered at {}, expected {}",
                    channel.peer.node_id, socket_addr, expected
                )));
            }
        }
        if cancel.is_cancelled() {
            return Err(TransportError::Other("transport stopped".to_string()));
        }

        let peer_id = channel.peer.node_id;
        // An outbound connection already proves a working endpoint, so keep
        // it. Substituting the signed listen port would break a peer behind a
        // port forward: `public:443 -> internal:9736` would be recorded as
        // `public:9736`, which nothing can reach. The substitution exists for
        // *inbound* connections, whose source port is ephemeral and was never
        // dialable.
        let dialable_addr =
            dialled.unwrap_or_else(|| SocketAddr::new(socket_addr.ip(), channel.peer.listen_port));
        let conn_cancel = cancel.child_token();
        let (outbox, outbox_rx) = mpsc::channel(OUTBOX_CAPACITY);
        // Its own capacity, so ordinary traffic filling the outbox cannot
        // leave an alert with nowhere to go.
        let (alerts, alerts_rx) = mpsc::channel(ALERT_OUTBOX_CAPACITY);
        let conn = Arc::new(PeerConnection {
            socket_addr,
            dialable_addr,
            dialled: dialled.is_some(),
            connected_at: Instant::now(),
            transcript: channel.transcript,
            cancel: conn_cancel.clone(),
            outbox,
            alerts,
            pending: std::sync::Mutex::new(HashMap::new()),
        });
        let sealed_reader = SealedReader {
            reader,
            cipher: channel.recv,
        };
        tokio::spawn(writer_task(
            SealedWriter {
                writer,
                cipher: channel.send,
            },
            outbox_rx,
            alerts_rx,
            conn_cancel.clone(),
            permit,
        ));

        // A completed dial proves its endpoint whatever happens to this
        // channel next, so the contact is recorded here rather than in the
        // read loop: a dial that loses the transcript tie-break is closed
        // without a read loop, and throwing the proven address away there
        // left an unreachable claim cached for a peer we had just reached.
        // Only the dialled case belongs here — an inbound connection's
        // address is a claim, and recording a claim before the duplicate is
        // resolved is what put a closed channel's address in the table.
        if dialled.is_some() {
            self.dht.add_peer(conn.contact(peer_id)).await;
        }

        // Everything from here on is synchronous, deliberately: once the
        // connection is in the map, the caller must reach `read_loop` without
        // an await in between. A cancellation in that gap would leave a peer
        // installed with nothing reading from it and its slot released.
        // The lock is held across the insert *and* the event, so discovery
        // and loss are totally ordered with respect to the map. Emitting
        // either after unlocking lets a reconnect's loss arrive after the
        // replacement's discovery and strip the live peer's routes.
        let displaced = {
            let mut conns = self.connections.write().await;
            let displaced = match conns.get(&peer_id) {
                Some(existing) => {
                    // Two connections to one peer exist whenever both ends
                    // dial at once, or two lookups dial the same peer. Both
                    // ends must pick the *same* one: if they pick differently,
                    // each closes the one the other kept and both are lost.
                    //
                    // The transcript is the only value that orders them
                    // correctly. It is identical at both ends of a given
                    // connection and different between connections, so
                    // "keep the lower transcript" is a total order both ends
                    // compute without reference to local arrival order or to
                    // who dialled — neither of which distinguishes two
                    // connections opened by the same node.
                    if conn.transcript >= existing.transcript {
                        return Err(TransportError::Other(format!(
                            "{} is already connected on a channel that wins the tie",
                            peer_id
                        )));
                    }
                    let displaced = existing.cancel.clone();
                    conns.insert(peer_id, conn.clone());
                    Some(displaced)
                }
                None => {
                    conns.insert(peer_id, conn.clone());
                    None
                }
            };
            let _ = self.event_tx.send(TransportEvent::NeighborDiscovered {
                peer: peer_id,
                transport: TransportType::InternetTunnel,
            });
            displaced
        };
        if let Some(displaced) = displaced {
            debug!(
                "Internet: replacing the connection to {} with a lower-transcript channel",
                peer_id
            );
            displaced.cancel();
        }

        info!(
            "Internet: peer {} authenticated on {} (listens on {})",
            peer_id, socket_addr, dialable_addr
        );

        Ok((peer_id, conn, sealed_reader, conn_cancel))
    }

    /// Offer our own signed address record to one peer.
    fn offer_self_record(&self, conn: &PeerConnection) {
        if !self.has_publishable_address() {
            debug!(
                "Internet: not publishing a DHT record for wildcard address {}",
                self.listen_addr
            );
            return;
        }
        let record: DhtRecord = self.dht.self_record(self.listen_addr);
        let msg = InternetWireMessage::Dht(DhtRequest {
            request_id: self.dht.next_request_id(),
            body: DhtRequestBody::Store { record },
        });
        if let Err(e) = conn.enqueue(msg) {
            debug!("Internet: could not publish our record: {}", e);
        }
    }

    /// Re-sign our record and offer it to every connected peer.
    ///
    /// Records expire, so publishing only at connection setup would make a
    /// node with a long-lived connection unresolvable after the TTL.
    pub(crate) async fn republish_self_record(&self) {
        if !self.has_publishable_address() {
            return;
        }
        self.dht.store_self(self.listen_addr).await;
        let peers: Vec<Arc<PeerConnection>> = {
            let conns = self.connections.read().await;
            conns.values().cloned().collect()
        };
        for conn in peers {
            self.offer_self_record(&conn);
        }
    }

    /// Serve one authenticated connection until it closes or is cancelled.
    async fn read_loop(
        self: Arc<Self>,
        peer_id: NodeId,
        conn: Arc<PeerConnection>,
        mut reader: SealedReader,
        cancel: CancellationToken,
        _permit: Arc<OwnedSemaphorePermit>,
    ) {
        // Only an admitted connection becomes a DHT contact. Done in
        // `establish`, this ran before the duplicate was resolved, so a
        // connection that lost the tie-break and was closed still rewrote the
        // contact for a peer we were keeping another channel to.
        self.dht.add_peer(conn.contact(peer_id)).await;
        self.offer_self_record(&conn);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                result = reader.recv() => {
                    match result {
                        Ok(InternetWireMessage::MeshData { data, .. }) => {
                            // The sender id in the frame is ignored: the peer
                            // is whoever holds this channel's key.
                            let _ = self.event_tx.send(TransportEvent::DataReceived {
                                peer: peer_id,
                                data,
                                transport: TransportType::InternetTunnel,
                            });
                        }
                        Ok(InternetWireMessage::Dht(request)) => {
                            let reply = self
                                .dht
                                // Carries the address provenance, or
                                // answering one request would undo it: the
                                // engine refreshes the contact for whoever
                                // asked.
                                .handle_request(conn.contact(peer_id), request)
                                .await;
                            // Queued, not written here: a write in this
                            // branch would sit outside the cancellation
                            // select and let a peer that stops reading hold
                            // its connection slot past `stop()`.
                            if let Err(e) = conn.enqueue(InternetWireMessage::DhtReply(reply)) {
                                debug!("Internet: cannot answer {}: {}", peer_id, e);
                                break;
                            }
                        }
                        Ok(InternetWireMessage::DhtReply(reply)) => {
                            conn.resolve_pending(reply);
                        }
                        Ok(InternetWireMessage::Hello { .. })
                        | Ok(InternetWireMessage::Confirm { .. }) => {
                            // The handshake is over; a repeat must never
                            // re-authenticate an established channel.
                            debug!("Internet: ignoring a late handshake frame from {}", peer_id);
                        }
                        Err(e) => {
                            debug!("Internet: connection to {} ended: {}", peer_id, e);
                            break;
                        }
                    }
                }
            }
        }

        // Takes the writer task down with us, so its permit share is released
        // and the socket closes instead of lingering.
        cancel.cancel();
        // The DHT contact is deliberately kept: its address is what lets this
        // peer be dialled again. Pruning contacts that have gone for good
        // needs bucket liveness checks (ROADMAP T-32).
        let was_current = {
            // Only remove the entry if it is still ours: a reconnect that
            // replaced it must not be torn down by this task's exit. The event
            // goes out under the same lock, so it cannot overtake the
            // discovery of a connection that replaced us.
            let mut conns = self.connections.write().await;
            if conns
                .get(&peer_id)
                .is_some_and(|existing| Arc::ptr_eq(existing, &conn))
            {
                conns.remove(&peer_id);
                let _ = self.event_tx.send(TransportEvent::NeighborLost {
                    peer: peer_id,
                    transport: TransportType::InternetTunnel,
                });
                true
            } else {
                false
            }
        };
        if was_current {
            info!("Internet: peer {} disconnected", peer_id);
        } else {
            // A displaced connection must stay silent. Reporting a loss here
            // would make the routing layer drop the peer and its routes while
            // the replacement connection is live.
            debug!(
                "Internet: a displaced connection to {} closed; the peer is still connected",
                peer_id
            );
        }
    }
}

impl InternetTransport {
    /// Create a new Internet transport.
    ///
    /// Takes the node's identity rather than its NodeId: the handshake has to
    /// sign with it, and deriving the id here means the two cannot disagree.
    pub fn new(identity: Arc<Identity>, config: InternetConfig) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        let dht_config = DhtConfig {
            bootstrap_nodes: config.bootstrap_nodes.clone(),
            ..DhtConfig::default()
        };
        let dht = Arc::new(DhtEngine::new(identity.clone(), dht_config));
        // Clamped to what a single `acquire_many` can ask for *and* to what
        // the semaphore accepts — `Semaphore::MAX_PERMITS` is below `u32::MAX`
        // on 32-bit targets, where a larger value would panic here. The same
        // effective value is what `stop()` drains.
        let permits = config
            .max_connections
            .clamp(1, Semaphore::MAX_PERMITS.min(u32::MAX as usize));

        Self {
            shared: Arc::new(Shared {
                local_id: identity.node_id(),
                identity,
                listen_addr: config.listen_addr,
                dht,
                event_tx,
                connections: RwLock::new(HashMap::new()),
                slots: Arc::new(Semaphore::new(permits)),
                connection_limit: permits,
            }),
            config,
            started: RwLock::new(false),
            lifetime: std::sync::Mutex::new(CancellationToken::new()),
            tasks: Mutex::new(JoinSet::new()),
            stopping: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Get a reference to the DHT engine.
    pub fn dht(&self) -> &Arc<DhtEngine> {
        &self.shared.dht
    }

    /// The local node id, derived from the identity this transport signs with.
    pub fn local_id(&self) -> NodeId {
        self.shared.local_id
    }

    /// How many connection slots are still free.
    pub fn available_slots(&self) -> usize {
        self.shared.slots.available_permits()
    }

    /// The token everything spawned right now should hang off.
    fn lifetime_token(&self) -> CancellationToken {
        self.lifetime.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// Re-sign our address record and offer it to every connected peer.
    pub async fn republish_self_record(&self) {
        self.shared.republish_self_record().await;
    }

    /// Connect to a peer at the given address and authenticate it.
    pub async fn connect_to(&self, addr: SocketAddr) -> Result<NodeId, TransportError> {
        self.connect_expecting(addr, None).await
    }

    /// Dial `addr`, refusing the connection unless the peer proves it is
    /// `expected` (when given).
    pub async fn connect_expecting(
        &self,
        addr: SocketAddr,
        expected: Option<NodeId>,
    ) -> Result<NodeId, TransportError> {
        let cancel = self.begin_dial()?;
        self.dial_with(cancel, addr, expected).await
    }

    /// The cancellation token a dial must run under, refusing it outright
    /// while a `stop()` is in progress.
    ///
    /// The token is taken **before** the shutdown flag is read, and both
    /// before anything that can wait. A dial that read the flag first could
    /// be descheduled in between for long enough that an entire `stop()`
    /// passes — flag set, token cancelled, permits drained, a fresh token
    /// published, flag cleared — and would then take the *new* token and
    /// install a live connection on a transport whose `stop()` had already
    /// returned, with nothing left to cancel it. Taking the token first puts
    /// every dial unambiguously on one side: either its token is the one
    /// `stop()` cancels, or it is a dial after the stop, which is a
    /// supported use of `connect_to` on a stopped transport.
    fn begin_dial(&self) -> Result<CancellationToken, TransportError> {
        let cancel = self.lifetime_token();
        if self.stopping.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(TransportError::Other("transport is stopping".to_string()));
        }
        Ok(cancel)
    }

    /// Dial under a token taken earlier by `begin_dial`.
    async fn dial_with(
        &self,
        cancel: CancellationToken,
        addr: SocketAddr,
        expected: Option<NodeId>,
    ) -> Result<NodeId, TransportError> {
        // After the token, so a dial that lost its race with `stop()` does
        // not even take a slot.
        let permit = Arc::new(self.shared.slots.clone().try_acquire_owned().map_err(|_| {
            TransportError::Other(format!(
                "connection limit of {} reached",
                self.shared.connection_limit
            ))
        })?);

        let stream = tokio::select! {
            _ = cancel.cancelled() => {
                return Err(TransportError::Other("transport stopped".to_string()));
            }
            result = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(addr)) => {
                match result {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(e)) => {
                        return Err(TransportError::Other(format!("connect to {}: {}", addr, e)))
                    }
                    Err(_) => {
                        return Err(TransportError::Other(format!("connect to {} timed out", addr)))
                    }
                }
            }
        };

        let (peer_id, conn, reader, conn_cancel) = self
            .shared
            .establish(stream, addr, &cancel, expected, Some(addr), permit.clone())
            .await?;
        tokio::spawn(
            self.shared
                .clone()
                .read_loop(peer_id, conn, reader, conn_cancel, permit),
        );
        Ok(peer_id)
    }

    /// Resolve a peer's address through the DHT, asking the network if needed.
    pub async fn resolve(self: &Arc<Self>, target: &NodeId) -> Option<SocketAddr> {
        let rpc: Arc<dyn DhtRpc> = self.clone();
        self.shared
            .dht
            .iterative_find_value(rpc, target)
            .await
            .map(|record| record.addr)
    }

    /// Diagnostics: how long a peer has been connected, and over what socket.
    pub async fn connection_info(&self, peer: &NodeId) -> Option<(SocketAddr, Duration)> {
        let conns = self.shared.connections.read().await;
        let conn = conns.get(peer)?;
        Some((conn.socket_addr, conn.connected_at.elapsed()))
    }
}

#[async_trait::async_trait]
impl DhtRpc for InternetTransport {
    async fn request(&self, peer: PeerInfo, request: DhtRequest) -> Option<DhtReply> {
        let existing = {
            let conns = self.shared.connections.read().await;
            conns.get(&peer.node_id).cloned()
        };
        let conn = match existing {
            Some(conn) => conn,
            None => {
                // The dial names the peer it is for, so a stale referral that
                // leads to a different node is refused before it is installed.
                if let Err(e) = self.connect_expecting(peer.addr, Some(peer.node_id)).await {
                    debug!("Internet: cannot reach {}: {}", peer.node_id, e);
                }
                // Re-read the map either way: a concurrent lookup may have
                // dialled the same peer and won the race, in which case our
                // own dial was refused as a duplicate and the connection is
                // perfectly usable.
                let conns = self.shared.connections.read().await;
                conns.get(&peer.node_id).cloned()?
            }
        };

        let request_id = request.request_id;
        let (tx, rx) = oneshot::channel();
        match conn.pending.lock() {
            Ok(mut pending) => {
                pending.insert(request_id, tx);
            }
            Err(_) => return None,
        }
        // Cleared on every exit path, cancellation included.
        let _guard = PendingGuard {
            conn: &conn,
            request_id,
        };

        if let Err(e) = conn.enqueue(InternetWireMessage::Dht(request)) {
            debug!("Internet: cannot query {}: {}", peer.node_id, e);
            return None;
        }

        tokio::time::timeout(REQUEST_TIMEOUT, rx).await.ok()?.ok()
    }
}

#[async_trait::async_trait]
impl Transport for InternetTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::InternetTunnel
    }

    async fn start(&self) -> Result<(), TransportError> {
        // Hold the started lock across bind so a bind failure leaves the
        // transport stopped (and restartable) instead of stuck "started".
        let mut started = self.started.write().await;
        if *started {
            return Err(TransportError::AlreadyStarted);
        }

        // `stop()` leaves a fresh, uncancelled lifetime token behind, so the
        // accept loop can simply hang off whatever is current.
        let cancel = self.lifetime_token();

        let listen_addr = self.config.listen_addr;
        let listener = TcpListener::bind(listen_addr)
            .await
            .map_err(|e| TransportError::Other(format!("bind {}: {}", listen_addr, e)))?;
        info!("Internet transport listening on {}", listen_addr);

        // `started` is set at the end, and the guard is held until then.
        //
        // Releasing the guard right after the bind let a `stop()` run to
        // completion in the gap: it cancelled the token this call had already
        // captured, joined a task set the accept task was not in yet, drained
        // the permits and returned — while `start()` still held a bound
        // listener it was about to hand to a task attached to that cancelled
        // token, so the port was still bound when `stop()` returned.
        //
        // Setting the flag before the awaits below was its own defect: a
        // caller that walked away during one of them dropped the listener
        // along with the future and left the transport marked started with no
        // accept task, so every later `start()` returned `AlreadyStarted`.

        // Publish our own address, if it is one anyone could dial.
        if self.shared.has_publishable_address() {
            self.shared.dht.store_self(listen_addr).await;
        }

        let mut tasks = self.tasks.lock().await;

        let shared = self.shared.clone();
        let accept_cancel = cancel.clone();
        tasks.spawn(async move {
            loop {
                tokio::select! {
                    _ = accept_cancel.cancelled() => break,
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                // The slot is taken before the handshake, so
                                // connections that never finish one still
                                // count against the limit.
                                let Ok(permit) = shared.slots.clone().try_acquire_owned() else {
                                    debug!(
                                        "Internet: refusing {} — all connection slots are in use",
                                        addr
                                    );
                                    drop(stream);
                                    continue;
                                };
                                let shared = shared.clone();
                                let cancel = accept_cancel.clone();
                                // Detached: the accept loop must not take a
                                // lock `stop()` holds, and a connection task
                                // can itself dial out. `stop()` waits for
                                // these by waiting for their permits instead.
                                let permit = Arc::new(permit);
                                tokio::spawn(async move {
                                    match shared
                                        .establish(
                                            stream,
                                            addr,
                                            &cancel,
                                            None,
                                            None,
                                            permit.clone(),
                                        )
                                        .await
                                    {
                                        Ok((peer_id, conn, reader, conn_cancel)) => {
                                            shared
                                                .read_loop(
                                                    peer_id, conn, reader, conn_cancel, permit,
                                                )
                                                .await;
                                        }
                                        Err(e) => {
                                            debug!(
                                                "Internet: handshake with {} failed: {}",
                                                addr, e
                                            );
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("Internet: accept error: {}", e);
                            }
                        }
                    }
                }
            }
        });

        for addr in &self.config.bootstrap_nodes {
            let addr = *addr;
            let shared = self.shared.clone();
            let cancel = cancel.clone();
            tasks.spawn(async move {
                let Ok(permit) = shared.slots.clone().try_acquire_owned() else {
                    debug!("Internet: no slot free for bootstrap node {}", addr);
                    return;
                };
                // Cancellable and bounded: an unreachable bootstrap host
                // would otherwise keep stop() waiting for the OS timeout.
                let connected = tokio::select! {
                    _ = cancel.cancelled() => return,
                    result = tokio::time::timeout(
                        DIAL_TIMEOUT,
                        TcpStream::connect(addr),
                    ) => match result {
                        Ok(result) => result,
                        Err(_) => {
                            warn!("Internet: bootstrap connect to {} timed out", addr);
                            return;
                        }
                    },
                };
                let permit = Arc::new(permit);
                match connected {
                    Ok(stream) => match shared
                        .establish(stream, addr, &cancel, None, Some(addr), permit.clone())
                        .await
                    {
                        Ok((peer_id, conn, reader, conn_cancel)) => {
                            info!("Internet: bootstrapped from {} ({})", addr, peer_id);
                            tokio::spawn(shared.read_loop(
                                peer_id,
                                conn,
                                reader,
                                conn_cancel,
                                permit,
                            ));
                        }
                        Err(e) => {
                            warn!("Internet: bootstrap handshake with {} failed: {}", addr, e)
                        }
                    },
                    Err(e) => warn!("Internet: bootstrap connect to {} failed: {}", addr, e),
                }
            });
        }

        // Keep our record alive for peers that stay connected past its TTL.
        if self.shared.has_publishable_address() {
            let shared = self.shared.clone();
            let republish_cancel = cancel.clone();
            tasks.spawn(async move {
                let mut ticker = tokio::time::interval(RECORD_REPUBLISH_INTERVAL);
                ticker.tick().await; // the first tick is immediate
                loop {
                    tokio::select! {
                        _ = republish_cancel.cancelled() => break,
                        _ = ticker.tick() => shared.republish_self_record().await,
                    }
                }
            });
        }

        // Every task is registered, so the transport is started and a
        // concurrent `stop()` — which needs this guard — will reach them all.
        *started = true;
        Ok(())
    }

    /// Stop listening and drop all connections. Idempotent: outbound
    /// connections made via `connect_to` work without `start()`, so stop must
    /// clean them up even when the listener was never started.
    ///
    /// Waits for its tasks to finish, so the listener is closed and every
    /// connection slot released before it returns. Without that wait, a
    /// `start()` immediately after a `stop()` raced the old accept loop and
    /// failed to bind, and a stalled handshake kept its slot.
    async fn stop(&self) -> Result<(), TransportError> {
        let mut started = self.started.write().await;
        // Refuse dials for the duration, then cancel. The fresh token is not
        // published until the drain is over, so nothing can attach to it and
        // escape the shutdown.
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.lifetime_token().cancel();
        let _restore = StopState {
            stopping: &self.stopping,
            lifetime: &self.lifetime,
            started: &mut started,
        };
        // What the transport looks like after this call is restored by a
        // guard, not by the tail of this function: everything below can be
        // abandoned by a caller that stops awaiting mid-drain, and left to
        // the tail that published no replacement token and never cleared the
        // shutdown flag — refusing every later dial for good and leaving
        // `start()` reporting `AlreadyStarted`.
        {
            // The listener lives in the accept task, so a restart cannot bind
            // until that task has dropped it. Bounded: a task that ignores
            // cancellation must not make stop() hang.
            let mut tasks = self.tasks.lock().await;
            if tokio::time::timeout(STOP_DRAIN_TIMEOUT, async {
                while tasks.join_next().await.is_some() {}
            })
            .await
            .is_err()
            {
                warn!(
                    "Internet: a background task did not stop in time; the listener \
                     may still hold its port"
                );
            }
        }
        // Then wait for every connection slot to come back. Connection tasks
        // are detached (one can dial out, so joining them from here would
        // deadlock), and their permits are the observable proof that they are
        // gone — including handshakes that had stalled.
        let permits = self.shared.connection_limit as u32;
        if tokio::time::timeout(STOP_DRAIN_TIMEOUT, self.shared.slots.acquire_many(permits))
            .await
            .is_err()
        {
            warn!("Internet: a connection did not release its slot within the stop timeout");
        }
        self.shared.connections.write().await.clear();
        info!("Internet transport stopped");
        Ok(())
    }

    async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError> {
        self.send_with_priority(peer, data, SendPriority::Normal)
            .await
    }

    /// An `Alert` frame goes to the channel the writer drains first.
    async fn send_with_priority(
        &self,
        peer: &NodeId,
        data: &[u8],
        priority: SendPriority,
    ) -> Result<(), TransportError> {
        if data.len() > MAX_MESH_PAYLOAD {
            return Err(TransportError::ExceedsMtu {
                size: data.len(),
                mtu: MAX_MESH_PAYLOAD,
            });
        }

        let conn = {
            let conns = self.shared.connections.read().await;
            conns
                .get(peer)
                .ok_or(TransportError::PeerNotConnected(*peer))?
                .clone()
        };

        conn.enqueue_with_priority(
            InternetWireMessage::MeshData {
                sender_id: self.shared.local_id,
                data: data.to_vec(),
            },
            priority,
        )
    }

    fn events(&self) -> broadcast::Receiver<TransportEvent> {
        self.shared.event_tx.subscribe()
    }

    fn link_quality(&self, peer: &NodeId) -> Option<LinkQuality> {
        let conns = self.shared.connections.try_read().ok()?;
        if conns.contains_key(peer) {
            Some(LinkQuality {
                rssi: None,
                throughput_bps: 1_000_000,
                packet_loss: 0.0,
                latency_ms: 50,
            })
        } else {
            None
        }
    }

    fn connected_peers(&self) -> Vec<NodeId> {
        match self.shared.connections.try_read() {
            Ok(conns) => conns.keys().copied().collect(),
            Err(_) => Vec::new(),
        }
    }

    fn mtu(&self) -> usize {
        // The frame cap minus the AEAD tag and what MeshData framing costs, so
        // a send at the advertised MTU is exactly one frame the receiver
        // accepts.
        MAX_MESH_PAYLOAD
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::rpc::MESH_DATA_OVERHEAD;
    use mycelium_crypto::channel::{ChannelKeys, AEAD_TAG_LEN};
    use tokio::time::{sleep, timeout};

    fn config_on(port: u16) -> InternetConfig {
        InternetConfig {
            listen_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            max_connections: 64,
        }
    }

    fn transport(port: u16) -> (Arc<Identity>, InternetTransport) {
        let identity = Arc::new(Identity::generate());
        let t = InternetTransport::new(identity.clone(), config_on(port));
        (identity, t)
    }

    /// A port that was free a moment ago. Binding to port 0 and reading back
    /// the assigned port is the only portable way to get one.
    async fn free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    async fn wait_for_peer(t: &InternetTransport, peer: &NodeId) -> bool {
        for _ in 0..100 {
            if t.connected_peers().contains(peer) {
                return true;
            }
            sleep(Duration::from_millis(20)).await;
        }
        false
    }

    /// The address our routing table holds for a peer, if any.
    async fn contact_addr(t: &InternetTransport, peer: &NodeId) -> Option<SocketAddr> {
        t.dht()
            .all_peers()
            .await
            .into_iter()
            .find(|p| p.node_id == *peer)
            .map(|p| p.addr)
    }

    /// The contact is recorded by the connection's read loop, which starts
    /// just after the handshake returns.
    async fn wait_for_contact(t: &InternetTransport, peer: &NodeId) -> Option<SocketAddr> {
        for _ in 0..100 {
            if let Some(addr) = contact_addr(t, peer).await {
                return Some(addr);
            }
            sleep(Duration::from_millis(20)).await;
        }
        None
    }

    async fn next_data_event(
        events: &mut broadcast::Receiver<TransportEvent>,
    ) -> Option<(NodeId, Vec<u8>)> {
        for _ in 0..20 {
            match timeout(Duration::from_secs(10), events.recv()).await {
                Ok(Ok(TransportEvent::DataReceived { peer, data, .. })) => {
                    return Some((peer, data))
                }
                Ok(Ok(_)) => continue,
                _ => return None,
            }
        }
        None
    }

    #[tokio::test]
    async fn test_transport_type() {
        let (_, t) = transport(0);
        assert_eq!(t.transport_type(), TransportType::InternetTunnel);
    }

    #[tokio::test]
    async fn test_mtu_leaves_room_for_framing_and_the_aead_tag() {
        let (_, t) = transport(0);
        assert_eq!(t.mtu(), MAX_MESH_PAYLOAD);
        assert_eq!(
            t.mtu() + MESH_DATA_OVERHEAD + AEAD_TAG_LEN,
            MAX_WIRE_MESSAGE,
            "an MTU-sized send must land exactly on the receiver's frame cap"
        );
    }

    #[tokio::test]
    async fn test_two_nodes_authenticate_and_exchange_data() {
        let port = free_port().await;
        let (a_identity, a) = transport(port);
        a.start().await.unwrap();

        let (b_identity, b) = transport(free_port().await);
        let mut b_events = b.events();

        let connected = b
            .connect_to(format!("127.0.0.1:{}", port).parse().unwrap())
            .await
            .unwrap();
        assert_eq!(connected, a_identity.node_id());

        assert!(
            wait_for_peer(&a, &b_identity.node_id()).await,
            "A learns B only from B's signed hello and proven channel key"
        );
        assert!(b.connected_peers().contains(&a_identity.node_id()));

        a.send(&b_identity.node_id(), b"hello from A")
            .await
            .unwrap();
        let (peer, data) = next_data_event(&mut b_events).await.expect("no data event");
        assert_eq!(peer, a_identity.node_id());
        assert_eq!(data, b"hello from A");

        a.stop().await.unwrap();
        b.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_a_payload_at_the_advertised_mtu_round_trips() {
        let port = free_port().await;
        let (a_identity, a) = transport(port);
        a.start().await.unwrap();
        let (b_identity, b) = transport(free_port().await);
        let mut b_events = b.events();
        b.connect_to(format!("127.0.0.1:{}", port).parse().unwrap())
            .await
            .unwrap();
        assert!(wait_for_peer(&a, &b_identity.node_id()).await);

        let payload = vec![0x5Au8; a.mtu()];
        a.send(&b_identity.node_id(), &payload).await.unwrap();
        let (peer, data) = next_data_event(&mut b_events).await.expect("no data event");
        assert_eq!(peer, a_identity.node_id());
        assert_eq!(data.len(), payload.len());
        assert_eq!(data, payload);

        a.stop().await.unwrap();
        b.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_a_send_above_the_mtu_is_refused_before_transmission() {
        let port = free_port().await;
        let (_, a) = transport(port);
        a.start().await.unwrap();
        let (b_identity, b) = transport(free_port().await);
        b.connect_to(format!("127.0.0.1:{}", port).parse().unwrap())
            .await
            .unwrap();
        assert!(wait_for_peer(&a, &b_identity.node_id()).await);

        let err = a
            .send(&b_identity.node_id(), &vec![0u8; a.mtu() + 1])
            .await
            .expect_err("a payload over the MTU must be refused");
        assert!(
            matches!(err, TransportError::ExceedsMtu { .. }),
            "{:?}",
            err
        );

        a.stop().await.unwrap();
        b.stop().await.unwrap();
    }

    /// Drive the client half of the handshake by hand, so a test can present a
    /// `Hello` the real implementation would never produce. Returns the socket,
    /// which the caller must keep alive while it inspects the server.
    ///
    /// `hello_ephemeral` is the key put in the hello; `confirm_with` is the
    /// exchange actually used to derive the confirmation. A relay is exactly
    /// the case where those two disagree.
    async fn raw_client(
        port: u16,
        identity: &Identity,
        sign_correctly: bool,
        relay: bool,
    ) -> TcpStream {
        raw_client_announcing(port, identity, sign_correctly, relay, 7000).await
    }

    /// As `raw_client`, with the listen port the hello announces — the port a
    /// server records as the peer's dialable one.
    async fn raw_client_announcing(
        port: u16,
        identity: &Identity,
        sign_correctly: bool,
        relay: bool,
        listen_port: u16,
    ) -> TcpStream {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let _ = raw_handshake(&mut stream, identity, sign_correctly, relay, listen_port).await;
        stream
    }

    /// A client that completes the handshake and then asks a DHT question on
    /// the channel, which is what makes the server refresh its contact.
    async fn raw_client_pinging(port: u16, identity: &Identity, listen_port: u16) -> TcpStream {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let mut keys = raw_handshake(&mut stream, identity, true, false, listen_port)
            .await
            .expect("the handshake must complete");
        let (_, mut writer) = tokio::io::split(&mut stream);
        let sealed = keys
            .send
            .seal(&encode_body(&InternetWireMessage::Dht(DhtRequest {
                request_id: 1,
                body: DhtRequestBody::Ping,
            })))
            .unwrap();
        write_framed(&mut writer, &sealed).await.unwrap();
        stream
    }

    /// The client half of the handshake, returning the channel keys so a
    /// caller can keep sending on it. `None` if the server hung up.
    async fn raw_handshake(
        stream: &mut TcpStream,
        identity: &Identity,
        sign_correctly: bool,
        relay: bool,
        listen_port: u16,
    ) -> Option<ChannelKeys> {
        {
            let (mut reader, mut writer) = tokio::io::split(stream);
            // The exchange whose secret we hold.
            let mine = ChannelHandshake::new();
            // A relay puts a key it does *not* hold the secret for in the
            // hello — which is what forwarding someone else's hello amounts to.
            let other = ChannelHandshake::new();
            let hello_ephemeral = if relay {
                other.public_key()
            } else {
                mine.public_key()
            };
            let identity_key = identity.public_key_bytes();
            // Signing a different key is what a stale or forged hello looks like.
            let signed_ephemeral = if sign_correctly {
                hello_ephemeral
            } else {
                [0xAAu8; 32]
            };
            let signature = identity
                .sign(&channel_hello_payload(
                    &signed_ephemeral,
                    &identity_key,
                    listen_port,
                ))
                .to_bytes();
            write_framed(
                &mut writer,
                &encode_body(&InternetWireMessage::Hello {
                    identity_key,
                    ephemeral_public: hello_ephemeral,
                    listen_port,
                    signature,
                }),
            )
            .await
            .unwrap();

            let Ok(body) = read_framed(&mut reader, MAX_HANDSHAKE_FRAME).await else {
                // The server hung up on the hello; nothing left to confirm.
                return None;
            };
            let (server_key, server_ephemeral) = match deserialize_wire_message(&body).unwrap() {
                InternetWireMessage::Hello {
                    identity_key,
                    ephemeral_public,
                    ..
                } => (identity_key, ephemeral_public),
                other => panic!("expected a hello, got {}", discriminant_name(&other)),
            };
            let mut keys = mine
                .complete(&server_ephemeral, &identity_key, &server_key)
                .unwrap();
            let sealed = keys
                .send
                .seal(&encode_body(&InternetWireMessage::Confirm {
                    transcript: keys.transcript,
                }))
                .unwrap();
            let _ = write_framed(&mut writer, &sealed).await;
            Some(keys)
        }
    }

    #[tokio::test]
    async fn test_a_hello_whose_signature_does_not_verify_installs_no_state() {
        let port = free_port().await;
        let (_, a) = transport(port);
        a.start().await.unwrap();
        let mut a_events = a.events();

        let impostor = Identity::generate();
        let _socket = raw_client(port, &impostor, false, false).await;

        sleep(Duration::from_millis(300)).await;
        assert!(
            !a.connected_peers().contains(&impostor.node_id()),
            "a peer whose signature does not verify must not be connected"
        );
        assert_eq!(
            a.dht().peer_count().await,
            0,
            "nor reach the DHT routing table"
        );
        assert!(
            matches!(
                a_events.try_recv(),
                Err(broadcast::error::TryRecvError::Empty)
            ),
            "nor produce any event — a NeighborDiscovered here would install a route"
        );

        a.stop().await.unwrap();
    }

    /// The control for the two refusal tests: the identical exchange, done
    /// properly, must be accepted. Without it, those tests could pass because
    /// of a framing mistake rather than the check they claim to exercise.
    #[tokio::test]
    async fn test_the_same_exchange_done_correctly_is_accepted() {
        let port = free_port().await;
        let (_, a) = transport(port);
        a.start().await.unwrap();

        let peer = Identity::generate();
        let _socket = raw_client(port, &peer, true, false).await;

        assert!(
            wait_for_peer(&a, &peer.node_id()).await,
            "a correctly signed hello with a proven channel key must authenticate"
        );
        assert_eq!(a.dht().peer_count().await, 1);

        a.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_a_relayed_hello_cannot_impersonate_its_signer() {
        // The attack a nonce-signature handshake cannot stop: the attacker
        // forwards a victim's genuinely signed hello as its own. The signature
        // verifies — and the connection still fails, because the key comes
        // from an ephemeral secret the attacker does not hold.
        let port = free_port().await;
        let (_, a) = transport(port);
        a.start().await.unwrap();
        let mut a_events = a.events();

        let victim = Identity::generate();
        let _socket = raw_client(port, &victim, true, true).await;

        sleep(Duration::from_millis(300)).await;
        assert!(
            !a.connected_peers().contains(&victim.node_id()),
            "relaying a victim's hello must not authenticate as the victim"
        );
        assert_eq!(a.dht().peer_count().await, 0);
        assert!(
            matches!(
                a_events.try_recv(),
                Err(broadcast::error::TryRecvError::Empty)
            ),
            "and must install no route"
        );

        a.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_a_full_outbox_fails_the_send_instead_of_blocking() {
        // `enqueue` must never await: a caller that is cancelled mid-write
        // would advance the frame counter without the bytes reaching the
        // socket, and every later frame would be mis-numbered.
        let (outbox, _rx) = mpsc::channel(1);
        let conn = PeerConnection {
            socket_addr: "127.0.0.1:1".parse().unwrap(),
            dialable_addr: "127.0.0.1:1".parse().unwrap(),
            dialled: true,
            connected_at: Instant::now(),
            transcript: [0u8; 32],
            cancel: CancellationToken::new(),
            outbox,
            alerts: mpsc::channel(1).0,
            pending: std::sync::Mutex::new(HashMap::new()),
        };
        let frame = || InternetWireMessage::Confirm {
            transcript: [0u8; 32],
        };
        assert!(conn.enqueue(frame()).is_ok());
        let err = conn
            .enqueue(frame())
            .expect_err("a full outbox must fail the send");
        assert!(matches!(err, TransportError::SendFailed(_)), "{:?}", err);
        assert!(err.to_string().contains("draining"), "{}", err);
    }

    #[tokio::test]
    async fn test_a_frame_over_its_cap_is_refused_before_allocating() {
        let (mut client, mut server) = tokio::io::duplex(64);
        // A length prefix claiming a megabyte, read with the confirmation cap.
        tokio::spawn(async move {
            let _ = client
                .write_all(&(MAX_WIRE_MESSAGE as u32).to_le_bytes())
                .await;
        });
        let err = read_framed(&mut server, CONFIRM_FRAME_LEN)
            .await
            .expect_err("a frame over the cap must be refused");
        assert!(
            err.to_string().contains(&CONFIRM_FRAME_LEN.to_string()),
            "{}",
            err
        );
    }

    #[tokio::test]
    async fn test_a_cancelled_request_leaves_the_channel_usable() {
        // Sends are queued, not written, by the caller, so abandoning one
        // mid-flight cannot desynchronise the frame counter. This checks the
        // observable consequence: the channel still carries data afterwards.
        let port = free_port().await;
        let (a_identity, a) = transport(port);
        a.start().await.unwrap();
        let (b_identity, b) = transport(free_port().await);
        let mut b_events = b.events();
        b.connect_to(format!("127.0.0.1:{}", port).parse().unwrap())
            .await
            .unwrap();
        assert!(wait_for_peer(&a, &b_identity.node_id()).await);

        // B never answers a DHT request for an unknown key, so this request is
        // still in flight when the timeout drops it.
        let pending = PeerInfo {
            node_id: b_identity.node_id(),
            addr: format!("127.0.0.1:{}", port).parse().unwrap(),
            last_seen: Instant::now(),
            addr_source: AddrSource::Dialled,
            addr_proved_at: Instant::now(),
        };
        let request = DhtRequest {
            request_id: 4242,
            body: DhtRequestBody::FindNode {
                target: Identity::generate().node_id(),
            },
        };
        let _ = timeout(Duration::from_millis(1), a.request(pending, request)).await;

        a.send(&b_identity.node_id(), b"still intact")
            .await
            .unwrap();
        let (peer, data) = next_data_event(&mut b_events).await.expect("no data event");
        assert_eq!(peer, a_identity.node_id());
        assert_eq!(data, b"still intact");

        a.stop().await.unwrap();
        b.stop().await.unwrap();
    }

    /// A transport with a proven contact for a peer that is no longer
    /// connected: `a` dials `b`, then `b` goes away. Contacts outlive the
    /// connection (the stored address is what allows a redial), and with no
    /// live connection left the tests below exercise the address rule rather
    /// than which of two concurrent channels won.
    async fn proven_contact_then_disconnect(a: &InternetTransport) -> (Arc<Identity>, SocketAddr) {
        let b_port = free_port().await;
        let (b_identity, b) = transport(b_port);
        b.start().await.unwrap();
        let b_addr: SocketAddr = format!("127.0.0.1:{}", b_port).parse().unwrap();
        a.connect_to(b_addr).await.unwrap();
        assert_eq!(
            wait_for_contact(a, &b_identity.node_id()).await,
            Some(b_addr),
            "the address we dialled is the contact"
        );

        b.stop().await.unwrap();
        for _ in 0..100 {
            if !a.connected_peers().contains(&b_identity.node_id()) {
                return (b_identity, b_addr);
            }
            sleep(Duration::from_millis(20)).await;
        }
        panic!("a never noticed b going away");
    }

    #[tokio::test]
    async fn test_an_inbound_connection_keeps_the_address_we_dialled() {
        // The peer comes back inbound, announcing the port it listens on
        // inside its own network. That claim must not replace the address we
        // proved: for a peer behind a port forward it turns a working
        // `public:443` into an unreachable `public:9736`.
        let a_port = free_port().await;
        let (_, a) = transport(a_port);
        a.start().await.unwrap();
        let (b_identity, b_addr) = proven_contact_then_disconnect(&a).await;

        let _inbound = raw_client_announcing(a_port, &b_identity, true, false, 9736).await;
        assert!(wait_for_peer(&a, &b_identity.node_id()).await);
        sleep(Duration::from_millis(100)).await;

        assert_eq!(
            contact_addr(&a, &b_identity.node_id()).await,
            Some(b_addr),
            "an inbound hello must not overwrite an address we dialled"
        );

        a.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_a_dht_request_from_an_inbound_peer_keeps_the_proven_address() {
        // Answering a request refreshes the asker's contact, so the address
        // provenance has to travel with it. Without that, the first DHT frame
        // on an inbound channel undid the rule the test above checks.
        let a_port = free_port().await;
        let (_, a) = transport(a_port);
        a.start().await.unwrap();
        let (b_identity, b_addr) = proven_contact_then_disconnect(&a).await;

        let _inbound = raw_client_pinging(a_port, &b_identity, 9736).await;
        assert!(wait_for_peer(&a, &b_identity.node_id()).await);
        sleep(Duration::from_millis(200)).await;

        assert_eq!(
            contact_addr(&a, &b_identity.node_id()).await,
            Some(b_addr),
            "answering a DHT request must not replace an address we dialled"
        );

        a.stop().await.unwrap();
    }

    /// A peer that answers one dial, keeps the channel, and pings on demand.
    /// Returns the address to dial and the trigger for its DHT request.
    async fn fake_peer(
        identity: Arc<Identity>,
        claims_port: u16,
    ) -> (SocketAddr, oneshot::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (mut reader, mut writer) = tokio::io::split(stream);
            let Ok(mut channel) = handshake(&identity, claims_port, &mut reader, &mut writer).await
            else {
                return;
            };
            if rx.await.is_ok() {
                let sealed = channel
                    .send
                    .seal(&encode_body(&InternetWireMessage::Dht(DhtRequest {
                        request_id: 7,
                        body: DhtRequestBody::Ping,
                    })))
                    .unwrap();
                let _ = write_framed(&mut writer, &sealed).await;
            }
            sleep(Duration::from_secs(5)).await;
        });
        (addr, tx)
    }

    #[tokio::test]
    async fn test_a_live_channel_does_not_restore_the_endpoint_it_was_dialled_on() {
        // Every DHT request a connection answers refreshes its contact. A
        // long-lived channel's refresh therefore kept reinstating the address
        // it was dialled on, undoing a later dial that had proved a different
        // endpoint — so the contact could go back to one that no longer
        // reaches the peer.
        let a_port = free_port().await;
        let (_, a) = transport(a_port);
        a.start().await.unwrap();

        for _ in 0..20 {
            let peer = Arc::new(Identity::generate());
            let (first_addr, ping_first) = fake_peer(peer.clone(), 9736).await;
            a.connect_to(first_addr).await.unwrap();
            assert_eq!(
                wait_for_contact(&a, &peer.node_id()).await,
                Some(first_addr)
            );

            // A second endpoint for the same peer, proved later. The channel
            // it opens has to lose the transcript tie-break for the case
            // under test, so retry until it does.
            let (second_addr, _ping_second) = fake_peer(peer.clone(), 9736).await;
            match a.connect_to(second_addr).await {
                Err(e) if e.to_string().contains("wins the tie") => {}
                _ => continue,
            }
            assert_eq!(
                contact_addr(&a, &peer.node_id()).await,
                Some(second_addr),
                "the later dial proved a newer endpoint"
            );

            // The first channel is still live. Let it answer a DHT request.
            ping_first.send(()).unwrap();
            sleep(Duration::from_millis(300)).await;

            assert_eq!(
                contact_addr(&a, &peer.node_id()).await,
                Some(second_addr),
                "answering on an older channel must not restore its endpoint"
            );
            a.stop().await.unwrap();
            return;
        }
        panic!("no second dial lost the tie-break in 20 tries");
    }

    #[tokio::test]
    async fn test_a_dial_that_loses_the_tie_break_still_records_its_endpoint() {
        // The dial completed, so its address is reachable from here whatever
        // happens to the channel. Recording contacts only in the read loop
        // threw that away when the dial lost the transcript tie-break, and
        // left the inbound channel's unreachable claim cached instead.
        let a_port = free_port().await;
        let (_, a) = transport(a_port);
        a.start().await.unwrap();

        let peer = Arc::new(Identity::generate());
        let mut sockets = Vec::new();
        let mut refused = None;
        // Which of two channels wins is decided by the transcript, so retry
        // until the dial is the one refused.
        for _ in 0..20 {
            if !a.connected_peers().contains(&peer.node_id()) {
                sockets.push(raw_client_announcing(a_port, &peer, true, false, 9736).await);
                assert!(wait_for_peer(&a, &peer.node_id()).await);
            }
            // The same identity, now answering a dial on a port it never
            // announces — the port-forward case.
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dialled = listener.local_addr().unwrap();
            let server = peer.clone();
            tokio::spawn(async move {
                if let Ok((stream, _)) = listener.accept().await {
                    let (mut reader, mut writer) = tokio::io::split(stream);
                    let _ = handshake(&server, 9736, &mut reader, &mut writer).await;
                    sleep(Duration::from_secs(5)).await;
                }
            });
            match a.connect_to(dialled).await {
                Err(e) if e.to_string().contains("wins the tie") => {
                    refused = Some(dialled);
                    break;
                }
                _ => continue,
            }
        }

        let dialled = refused.expect("no dial lost the tie-break in 20 tries");
        assert_eq!(
            contact_addr(&a, &peer.node_id()).await,
            Some(dialled),
            "a completed dial proves its endpoint even when its channel is closed"
        );

        a.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_a_refused_duplicate_leaves_the_dht_contact_alone() {
        // The contact used to be recorded before the duplicate was resolved,
        // so a second connection that lost the transcript tie-break — and was
        // closed — still rewrote the address of the peer whose other channel
        // we kept.
        let a_port = free_port().await;
        let (_, a) = transport(a_port);
        a.start().await.unwrap();

        let first_addr: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        // Which of two connections wins is decided by the channel transcript,
        // so retry until the second one is the refused one.
        for _ in 0..20 {
            let peer = Identity::generate();
            let first = raw_client_announcing(a_port, &peer, true, false, 1111).await;
            if !wait_for_peer(&a, &peer.node_id()).await {
                continue;
            }
            let first_transcript = {
                let conns = a.shared.connections.read().await;
                conns.get(&peer.node_id()).map(|c| c.transcript)
            };
            assert_eq!(
                wait_for_contact(&a, &peer.node_id()).await,
                Some(first_addr)
            );

            let second = raw_client_announcing(a_port, &peer, true, false, 2222).await;
            sleep(Duration::from_millis(300)).await;
            let kept = {
                let conns = a.shared.connections.read().await;
                conns.get(&peer.node_id()).map(|c| c.transcript)
            };
            if kept != first_transcript {
                // The second connection won; this attempt says nothing.
                drop(first);
                drop(second);
                continue;
            }

            assert_eq!(
                contact_addr(&a, &peer.node_id()).await,
                Some(first_addr),
                "a connection that lost the tie-break must not rewrite the contact"
            );
            drop(first);
            drop(second);
            a.stop().await.unwrap();
            return;
        }
        panic!("no attempt produced a refused duplicate");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_stop_waits_for_a_start_that_is_still_registering_tasks() {
        // start() used to publish `started = true` and release the lock before
        // spawning its accept task, so a stop() in that gap joined an empty
        // task set and returned while the listener was still bound.
        let port = free_port().await;
        let (_, t) = transport(port);
        let t = Arc::new(t);

        // Park start() between its bind and the registration of its tasks: it
        // publishes our own record in there, which needs this lock.
        let held = t.shared.dht.hold_store_for_test().await;
        let starting = {
            let t = t.clone();
            tokio::spawn(async move { t.start().await })
        };

        // A successful connect proves the listener is bound, so there is no
        // sleep to guess at: start() is at or past the parked publish.
        let addr = format!("127.0.0.1:{}", port);
        let mut bound = false;
        for _ in 0..200 {
            if TcpStream::connect(&addr).await.is_ok() {
                bound = true;
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert!(bound, "start() never bound its listener");

        assert!(
            timeout(Duration::from_millis(250), t.stop()).await.is_err(),
            "stop() must not finish while start() still has tasks to register"
        );

        drop(held);
        starting.await.unwrap().unwrap();
        t.stop().await.unwrap();
    }

    /// Two connections to one peer must be ordered by something both ends
    /// compute the same way. Who dialled does not distinguish them when the
    /// same node opened both, and local arrival order can differ at the two
    /// ends — either way each side keeps a different connection and both are
    /// lost. The transcript is identical at both ends of a connection and
    /// differs between connections, which is exactly what is needed.
    #[tokio::test]
    async fn test_a_duplicate_connection_is_resolved_by_transcript() {
        let port = free_port().await;
        let (_, a) = transport(port);
        a.start().await.unwrap();

        // Two connections from the same identity, so the peer id and the
        // direction are identical and only the transcript separates them.
        let peer = Identity::generate();
        let first = raw_client(port, &peer, true, false).await;
        assert!(wait_for_peer(&a, &peer.node_id()).await);
        let first_transcript = {
            let conns = a.shared.connections.read().await;
            conns.get(&peer.node_id()).unwrap().transcript
        };

        let second = raw_client(port, &peer, true, false).await;
        sleep(Duration::from_millis(300)).await;

        let kept = {
            let conns = a.shared.connections.read().await;
            conns.get(&peer.node_id()).map(|c| c.transcript)
        };
        let kept = kept.expect("the peer must still be connected");
        assert!(
            kept <= first_transcript,
            "the lower transcript must win, whichever connection arrived first"
        );

        drop(first);
        drop(second);
        a.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_a_displaced_connection_does_not_report_the_peer_lost() {
        // A replaced connection closing must stay silent: a NeighborLost here
        // makes the routing layer drop the peer and its routes while the
        // replacement is live.
        let port = free_port().await;
        let (_, a) = transport(port);
        a.start().await.unwrap();

        // An identity whose second connection displaces its first.
        let (peer, _first) = loop {
            let candidate = Identity::generate();
            let socket = raw_client(port, &candidate, true, false).await;
            if !wait_for_peer(&a, &candidate.node_id()).await {
                continue;
            }
            break (candidate, socket);
        };

        let mut events = a.events();
        let _second = raw_client(port, &peer, true, false).await;
        sleep(Duration::from_millis(400)).await;

        assert!(
            a.connected_peers().contains(&peer.node_id()),
            "one of the two connections must survive"
        );
        let mut lost = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let TransportEvent::NeighborLost { peer, .. } = event {
                lost.push(peer);
            }
        }
        assert!(
            !lost.contains(&peer.node_id()),
            "a peer that is still connected must not be reported lost"
        );

        a.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_a_connection_made_before_start_is_still_stopped() {
        // Those connections used to attach to a token that start() replaced
        // without cancelling, so stop() never reached them: the socket and its
        // slot survived shutdown.
        let port = free_port().await;
        let (server_identity, server) = transport(port);
        server.start().await.unwrap();

        let client = InternetTransport::new(
            Arc::new(Identity::generate()),
            InternetConfig {
                listen_addr: format!("127.0.0.1:{}", free_port().await).parse().unwrap(),
                bootstrap_nodes: Vec::new(),
                max_connections: 4,
            },
        );
        client
            .connect_to(format!("127.0.0.1:{}", port).parse().unwrap())
            .await
            .unwrap();
        assert_eq!(client.available_slots(), 3);

        client.start().await.unwrap();
        assert!(
            client
                .connected_peers()
                .contains(&server_identity.node_id()),
            "starting must not drop a connection made before it"
        );

        client.stop().await.unwrap();
        assert_eq!(
            client.available_slots(),
            4,
            "stop() must reclaim the slot of a connection made before start()"
        );
        assert!(client.connected_peers().is_empty());

        server.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_a_dial_for_the_wrong_peer_installs_nothing() {
        let port = free_port().await;
        let (server_identity, server) = transport(port);
        server.start().await.unwrap();

        let (_, client) = transport(free_port().await);
        let mut client_events = client.events();
        let wrong = Identity::generate().node_id();
        let err = client
            .connect_expecting(format!("127.0.0.1:{}", port).parse().unwrap(), Some(wrong))
            .await
            .expect_err("a dial naming the wrong peer must fail");
        assert!(err.to_string().contains("expected"), "{}", err);

        assert!(
            !client
                .connected_peers()
                .contains(&server_identity.node_id()),
            "a stale referral must not leave an unrelated peer holding a slot"
        );
        assert_eq!(client.available_slots(), 64);
        assert!(
            matches!(
                client_events.try_recv(),
                Err(broadcast::error::TryRecvError::Empty)
            ),
            "and must emit no discovery event"
        );

        server.stop().await.unwrap();
        client.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_stop_releases_the_slot_of_a_peer_that_stopped_reading() {
        // A peer that completes the handshake and then never reads keeps the
        // writer blocked. The write sits inside the cancellation select, so
        // stop() must still get the slot back.
        let port = free_port().await;
        let a = InternetTransport::new(
            Arc::new(Identity::generate()),
            InternetConfig {
                listen_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
                bootstrap_nodes: Vec::new(),
                max_connections: 2,
            },
        );
        a.start().await.unwrap();

        let peer = Identity::generate();
        let socket = raw_client(port, &peer, true, false).await;
        assert!(wait_for_peer(&a, &peer.node_id()).await);

        // Queue more than the socket and outbox can absorb without being read.
        for _ in 0..OUTBOX_CAPACITY + 8 {
            let _ = a.send(&peer.node_id(), &vec![0u8; a.mtu()]).await;
        }

        a.stop().await.unwrap();
        assert_eq!(
            a.available_slots(),
            2,
            "stop() must reclaim the slot even while a write is blocked"
        );
        drop(socket);
    }

    #[tokio::test]
    async fn test_an_outbound_contact_keeps_the_address_that_worked() {
        // A peer behind a port forward signs the port it listens on inside its
        // own network, not the one we reached it on. Substituting it would
        // turn a working `public:443` into an unreachable `public:9736`.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reachable_port = listener.local_addr().unwrap().port();
        let server = Identity::generate();
        let server_id = server.node_id();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(stream);
            // Claims a port it is not reachable on from here.
            let _ = handshake(&server, 9999, &mut reader, &mut writer).await;
            sleep(Duration::from_secs(5)).await;
        });

        let (_, client) = transport(free_port().await);
        let addr: SocketAddr = format!("127.0.0.1:{}", reachable_port).parse().unwrap();
        assert_eq!(client.connect_to(addr).await.unwrap(), server_id);

        let contact = wait_for_contact(&client, &server_id)
            .await
            .expect("the peer should be a DHT contact");
        assert_eq!(
            contact, addr,
            "an outbound contact must keep the endpoint that actually worked"
        );

        client.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_an_inbound_contact_uses_the_signed_listen_port() {
        // The mirror of the test above: an inbound socket's source port is
        // ephemeral, so the signed listen port is the only dialable one.
        let port = free_port().await;
        let (_, a) = transport(port);
        a.start().await.unwrap();

        let peer = Identity::generate();
        let _socket = raw_client(port, &peer, true, false).await;
        assert!(wait_for_peer(&a, &peer.node_id()).await);

        let contact = wait_for_contact(&a, &peer.node_id())
            .await
            .expect("the peer should be a DHT contact");
        // `raw_client` signs listen_port 7000.
        assert_eq!(contact.port(), 7000);

        a.stop().await.unwrap();
    }

    /// `start()` again until it binds, failing immediately if the transport
    /// has been left marked started instead.
    async fn start_again(t: &InternetTransport) {
        let mut last = None;
        for _ in 0..50 {
            match t.start().await {
                Ok(()) => return,
                Err(e) => {
                    assert!(
                        !matches!(e, TransportError::AlreadyStarted),
                        "the transport was left marked started: {}",
                        e
                    );
                    last = Some(e);
                    sleep(Duration::from_millis(20)).await;
                }
            }
        }
        panic!("start() never succeeded: {:?}", last);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_a_cancelled_start_leaves_the_transport_startable() {
        // A caller that walks away mid-startup drops the listener with the
        // future. Marking the transport started before that point left it
        // with no accept task and no way back: every later `start()` returned
        // `AlreadyStarted`.
        let port = free_port().await;
        let (_, t) = transport(port);
        let t = Arc::new(t);

        let held = t.shared.dht.hold_store_for_test().await;
        let starting = {
            let t = t.clone();
            tokio::spawn(async move { t.start().await })
        };
        let addr = format!("127.0.0.1:{}", port);
        let mut bound = false;
        for _ in 0..200 {
            if TcpStream::connect(&addr).await.is_ok() {
                bound = true;
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert!(bound, "start() never bound its listener");

        starting.abort();
        let _ = starting.await;
        drop(held);

        start_again(&t).await;
        t.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_a_cancelled_stop_does_not_wedge_the_transport() {
        // The shutdown flag and the replacement token used to be set in the
        // tail of `stop()`, so a caller that stopped awaiting during a drain
        // left the flag set and the cancelled token in place: every later
        // dial was refused and `start()` could not run.
        let port = free_port().await;
        let (_, t) = transport(port);
        t.start().await.unwrap();

        // Hold a slot so the permit drain cannot finish, then walk away.
        let hog = t.shared.slots.clone().try_acquire_owned().unwrap();
        assert!(
            timeout(Duration::from_millis(150), t.stop()).await.is_err(),
            "the drain must still have been waiting"
        );
        drop(hog);

        assert!(
            !t.stopping.load(std::sync::atomic::Ordering::SeqCst),
            "a cancelled stop must not leave dials refused"
        );
        assert!(t.begin_dial().is_ok(), "dials must be accepted again");
        start_again(&t).await;
        t.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_a_dial_that_overlapped_a_stop_cannot_install_afterwards() {
        // The dial takes its token, and is then overtaken by an entire
        // `stop()`: the flag is set and cleared again, the permits drained
        // and a fresh token published. Nothing it could consult afterwards
        // says a shutdown happened — so a dial that took its token *after*
        // reading the flag adopted the new one and installed a live
        // connection on a stopped transport, with nothing left to cancel it.
        let port = free_port().await;
        let (_, server) = transport(port);
        server.start().await.unwrap();

        let client = InternetTransport::new(
            Arc::new(Identity::generate()),
            InternetConfig {
                listen_addr: format!("127.0.0.1:{}", free_port().await).parse().unwrap(),
                bootstrap_nodes: Vec::new(),
                max_connections: 4,
            },
        );

        let cancel = client
            .begin_dial()
            .expect("the transport is not stopping yet");
        client.stop().await.unwrap();

        let err = client
            .dial_with(cancel, format!("127.0.0.1:{}", port).parse().unwrap(), None)
            .await
            .expect_err("a dial from before the stop must not install after it");
        assert!(err.to_string().contains("stopped"), "{}", err);
        assert!(client.connected_peers().is_empty());
        assert_eq!(
            client.available_slots(),
            4,
            "a refused dial must not keep a slot"
        );

        server.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_a_dial_during_shutdown_is_refused() {
        // A dial that attached to the token `stop()` used to publish *before*
        // draining survived cancellation, had its map entry cleared, and kept
        // its socket and permit for good. The gate is what closes that window;
        // publishing the replacement token only after the drain is the second
        // half, and is not separately observable because `start()` serialises
        // against `stop()` on the `started` lock.
        //
        // Driven by setting the flag directly, because the real window — the
        // inside of `stop()`'s drain — is too narrow to land in reliably, and
        // a test that only sometimes exercises the bug is worse than none.
        let port = free_port().await;
        let (server_identity, server) = transport(port);
        server.start().await.unwrap();

        let (_, client) = transport(free_port().await);
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

        client
            .stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let err = client
            .connect_to(addr)
            .await
            .expect_err("a dial during shutdown must be refused");
        assert!(err.to_string().contains("stopping"), "{}", err);
        assert_eq!(
            client.available_slots(),
            64,
            "a refused dial must not have taken a permit"
        );

        // Control: the same dial succeeds once the shutdown is over, so the
        // refusal above is the gate and not something unrelated.
        client
            .stopping
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            client.connect_to(addr).await.unwrap(),
            server_identity.node_id()
        );

        client.stop().await.unwrap();
        assert_eq!(client.available_slots(), 64);
        server.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_max_connections_is_enforced() {
        let port = free_port().await;
        let a = InternetTransport::new(
            Arc::new(Identity::generate()),
            InternetConfig {
                listen_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
                bootstrap_nodes: Vec::new(),
                max_connections: 1,
            },
        );
        a.start().await.unwrap();

        let (first_id, first) = transport(free_port().await);
        first
            .connect_to(format!("127.0.0.1:{}", port).parse().unwrap())
            .await
            .unwrap();
        assert!(wait_for_peer(&a, &first_id.node_id()).await);
        assert_eq!(a.available_slots(), 0, "the one slot is taken");

        // The second connection is accepted by the OS and then dropped
        // without a handshake, so the client sees EOF rather than a hello.
        let mut second = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let mut buf = [0u8; 1];
        let read = timeout(Duration::from_secs(5), second.read(&mut buf))
            .await
            .expect("the server must not leave an over-limit socket open");
        assert_eq!(
            read.unwrap(),
            0,
            "an over-limit connection must be closed, not served"
        );
        assert_eq!(a.connected_peers().len(), 1);

        a.stop().await.unwrap();
        first.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_an_outbound_connection_respects_the_limit() {
        let port = free_port().await;
        let (_, server) = transport(port);
        server.start().await.unwrap();

        let client = InternetTransport::new(
            Arc::new(Identity::generate()),
            InternetConfig {
                listen_addr: format!("127.0.0.1:{}", free_port().await).parse().unwrap(),
                bootstrap_nodes: Vec::new(),
                max_connections: 1,
            },
        );
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        client.connect_to(addr).await.unwrap();
        let err = client
            .connect_to(addr)
            .await
            .expect_err("a second outbound connection must not exceed the limit");
        assert!(err.to_string().contains("connection limit"), "{}", err);

        server.stop().await.unwrap();
        client.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_stop_releases_every_connection_slot() {
        let port = free_port().await;
        let a = InternetTransport::new(
            Arc::new(Identity::generate()),
            InternetConfig {
                listen_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
                bootstrap_nodes: Vec::new(),
                max_connections: 4,
            },
        );
        a.start().await.unwrap();

        let (peer_id, peer) = transport(free_port().await);
        peer.connect_to(format!("127.0.0.1:{}", port).parse().unwrap())
            .await
            .unwrap();
        assert!(wait_for_peer(&a, &peer_id.node_id()).await);
        assert_eq!(a.available_slots(), 3);

        a.stop().await.unwrap();
        assert_eq!(
            a.available_slots(),
            4,
            "stop() must not return while a connection still holds a slot"
        );
        assert!(a.connected_peers().is_empty());

        peer.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_restart_after_stop_still_authenticates() {
        let port = free_port().await;
        let (a_identity, a) = transport(port);
        a.start().await.unwrap();
        a.stop().await.unwrap();
        a.start().await.unwrap();

        let (_, b) = transport(free_port().await);
        let connected = b
            .connect_to(format!("127.0.0.1:{}", port).parse().unwrap())
            .await
            .unwrap();
        assert_eq!(connected, a_identity.node_id());

        a.stop().await.unwrap();
        b.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_our_signed_record_reaches_a_connected_peer() {
        let port = free_port().await;
        let (a_identity, a) = transport(port);
        a.start().await.unwrap();

        let (b_identity, b) = transport(free_port().await);
        b.connect_to(format!("127.0.0.1:{}", port).parse().unwrap())
            .await
            .unwrap();
        assert!(wait_for_peer(&a, &b_identity.node_id()).await);

        // Republishing is what keeps a record alive past its TTL on a
        // long-lived connection; it must reach the peer the same way.
        a.republish_self_record().await;

        let mut found = None;
        for _ in 0..100 {
            if let Some(addr) = b.dht().lookup(&a_identity.node_id()).await {
                found = Some(addr);
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            found,
            Some(format!("127.0.0.1:{}", port).parse().unwrap()),
            "a peer should end up holding our signed address record"
        );

        a.stop().await.unwrap();
        b.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_a_wildcard_listen_address_is_never_published() {
        let port = free_port().await;
        let a = InternetTransport::new(
            Arc::new(Identity::generate()),
            InternetConfig {
                listen_addr: format!("0.0.0.0:{}", port).parse().unwrap(),
                bootstrap_nodes: Vec::new(),
                max_connections: 64,
            },
        );
        let a_id = a.local_id();
        a.start().await.unwrap();

        let (b_identity, b) = transport(free_port().await);
        b.connect_to(format!("127.0.0.1:{}", port).parse().unwrap())
            .await
            .unwrap();
        assert!(wait_for_peer(&a, &b_identity.node_id()).await);
        a.republish_self_record().await;
        sleep(Duration::from_millis(200)).await;

        assert!(
            a.dht().lookup(&a_id).await.is_none(),
            "a record for 0.0.0.0 would be signed, valid and useless; it must not be stored"
        );
        assert!(
            b.dht().lookup(&a_id).await.is_none(),
            "nor served to a peer that asks for it"
        );

        a.stop().await.unwrap();
        b.stop().await.unwrap();
    }
}
