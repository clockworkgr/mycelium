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
use tokio::sync::{broadcast, oneshot, Mutex, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use mycelium_crypto::channel::{channel_hello_payload, ChannelHandshake, FrameCipher};
use mycelium_crypto::identity::{node_id_from_public_key, verify_signature_bytes, Identity};
use mycelium_protocol::types::{LinkQuality, NodeId};

use super::{Transport, TransportError, TransportEvent, TransportType};
use crate::dht::record::{DhtRecord, RECORD_TTL_SECS};
use crate::dht::rpc::{
    deserialize_wire_message, encode_body, DhtReply, DhtRequest, DhtRequestBody,
    InternetWireMessage, MAX_HANDSHAKE_FRAME, MAX_MESH_PAYLOAD, MAX_WIRE_MESSAGE,
};
use crate::dht::{DhtConfig, DhtEngine, DhtRpc, PeerInfo, REQUEST_TIMEOUT};

/// Bound on the whole handshake, so an idle or stalling peer cannot hold a
/// task, a socket and a connection slot indefinitely.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often we re-sign and re-offer our own address record. A third of the
/// record TTL, so a peer always holds an unexpired record for us even if one
/// republish is lost.
const RECORD_REPUBLISH_INTERVAL: Duration = Duration::from_secs(RECORD_TTL_SECS / 3);

/// How long `stop()` waits for every connection to release its slot before
/// giving up and logging. Connections are cancelled first, so reaching this
/// means a task is wedged.
const STOP_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

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
    async fn send(&mut self, msg: &InternetWireMessage) -> Result<(), TransportError> {
        let body = encode_body(msg);
        let sealed = self
            .cipher
            .seal(&body)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        write_framed(&mut self.writer, &sealed).await
    }
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
    connected_at: Instant,
    writer: Mutex<SealedWriter>,
    /// In-flight DHT requests on *this* connection, awaiting their replies.
    ///
    /// Per connection, not global: with one shared map any authenticated peer
    /// could answer a request addressed to another by guessing its id.
    pending: std::sync::Mutex<HashMap<u64, oneshot::Sender<DhtReply>>>,
}

impl PeerConnection {
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
}

/// Internet transport using TCP connections and Kademlia DHT for discovery.
pub struct InternetTransport {
    shared: Arc<Shared>,
    config: InternetConfig,
    started: RwLock<bool>,
    /// Replaced on every start() so the transport can be restarted after stop().
    cancel: std::sync::Mutex<CancellationToken>,
    /// Background tasks, so `stop()` can wait for the listener to close and
    /// for every connection to release its slot.
    tasks: Mutex<JoinSet<()>>,
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

    let sealed = read_framed(reader, MAX_WIRE_MESSAGE).await?;
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
    ) -> Result<(NodeId, Arc<PeerConnection>, SealedReader), TransportError> {
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
        if cancel.is_cancelled() {
            return Err(TransportError::Other("transport stopped".to_string()));
        }

        let peer_id = channel.peer.node_id;
        let dialable_addr = SocketAddr::new(socket_addr.ip(), channel.peer.listen_port);
        let conn = Arc::new(PeerConnection {
            socket_addr,
            dialable_addr,
            connected_at: Instant::now(),
            writer: Mutex::new(SealedWriter {
                writer,
                cipher: channel.send,
            }),
            pending: std::sync::Mutex::new(HashMap::new()),
        });
        let sealed_reader = SealedReader {
            reader,
            cipher: channel.recv,
        };

        {
            // A second connection claiming an already-connected peer is
            // refused: accepting it would overwrite the live entry, and its
            // later teardown would evict the real peer.
            let mut conns = self.connections.write().await;
            if conns.contains_key(&peer_id) {
                return Err(TransportError::Other(format!(
                    "{} is already connected",
                    peer_id
                )));
            }
            conns.insert(peer_id, conn.clone());
        }

        self.dht
            .add_peer(PeerInfo {
                node_id: peer_id,
                addr: dialable_addr,
                last_seen: Instant::now(),
            })
            .await;

        let _ = self.event_tx.send(TransportEvent::NeighborDiscovered {
            peer: peer_id,
            transport: TransportType::InternetTunnel,
        });

        info!(
            "Internet: peer {} authenticated on {} (listens on {})",
            peer_id, socket_addr, dialable_addr
        );

        self.offer_self_record(&conn).await;
        Ok((peer_id, conn, sealed_reader))
    }

    /// Offer our own signed address record to one peer.
    async fn offer_self_record(&self, conn: &PeerConnection) {
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
        let mut guard = conn.writer.lock().await;
        if let Err(e) = guard.send(&msg).await {
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
            self.offer_self_record(&conn).await;
        }
    }

    /// Serve one authenticated connection until it closes or is cancelled.
    async fn read_loop(
        self: Arc<Self>,
        peer_id: NodeId,
        conn: Arc<PeerConnection>,
        mut reader: SealedReader,
        cancel: CancellationToken,
        _permit: OwnedSemaphorePermit,
    ) {
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
                                .handle_request(
                                    PeerInfo {
                                        node_id: peer_id,
                                        addr: conn.dialable_addr,
                                        last_seen: Instant::now(),
                                    },
                                    request,
                                )
                                .await;
                            let mut guard = conn.writer.lock().await;
                            if guard
                                .send(&InternetWireMessage::DhtReply(reply))
                                .await
                                .is_err()
                            {
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

        {
            // Only remove the entry if it is still ours: a reconnect that
            // replaced it must not be torn down by this task's exit.
            let mut conns = self.connections.write().await;
            if conns
                .get(&peer_id)
                .is_some_and(|existing| Arc::ptr_eq(existing, &conn))
            {
                conns.remove(&peer_id);
            }
        }
        // The DHT contact is deliberately kept: its address is what lets this
        // peer be dialled again. Pruning contacts that have gone for good
        // needs bucket liveness checks (ROADMAP T-32).
        let _ = self.event_tx.send(TransportEvent::NeighborLost {
            peer: peer_id,
            transport: TransportType::InternetTunnel,
        });
        info!("Internet: peer {} disconnected", peer_id);
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
        let permits = config.max_connections.clamp(1, Semaphore::MAX_PERMITS);

        Self {
            shared: Arc::new(Shared {
                local_id: identity.node_id(),
                identity,
                listen_addr: config.listen_addr,
                dht,
                event_tx,
                connections: RwLock::new(HashMap::new()),
                slots: Arc::new(Semaphore::new(permits)),
            }),
            config,
            started: RwLock::new(false),
            cancel: std::sync::Mutex::new(CancellationToken::new()),
            tasks: Mutex::new(JoinSet::new()),
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

    fn current_cancel(&self) -> CancellationToken {
        self.cancel.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// Re-sign our address record and offer it to every connected peer.
    pub async fn republish_self_record(&self) {
        self.shared.republish_self_record().await;
    }

    /// Connect to a peer at the given address and authenticate it.
    pub async fn connect_to(&self, addr: SocketAddr) -> Result<NodeId, TransportError> {
        let permit = self.shared.slots.clone().try_acquire_owned().map_err(|_| {
            TransportError::Other(format!(
                "connection limit of {} reached",
                self.config.max_connections
            ))
        })?;

        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| TransportError::Other(format!("connect to {}: {}", addr, e)))?;

        let cancel = self.current_cancel();
        let (peer_id, conn, reader) = self.shared.establish(stream, addr, &cancel).await?;
        tokio::spawn(
            self.shared
                .clone()
                .read_loop(peer_id, conn, reader, cancel, permit),
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
            None => match self.connect_to(peer.addr).await {
                Ok(id) if id == peer.node_id => {
                    let conns = self.shared.connections.read().await;
                    conns.get(&peer.node_id).cloned()?
                }
                Ok(other) => {
                    debug!(
                        "Internet: {} answered at {}, expected {}",
                        other, peer.addr, peer.node_id
                    );
                    return None;
                }
                Err(e) => {
                    debug!("Internet: cannot reach {}: {}", peer.node_id, e);
                    return None;
                }
            },
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

        let sent = {
            let mut guard = conn.writer.lock().await;
            guard.send(&InternetWireMessage::Dht(request)).await.is_ok()
        };
        if !sent {
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

        // Fresh token per start: a cancelled token from a previous stop()
        // would make the new accept loop exit immediately.
        let cancel = CancellationToken::new();
        if let Ok(mut guard) = self.cancel.lock() {
            *guard = cancel.clone();
        }

        let listen_addr = self.config.listen_addr;
        let listener = TcpListener::bind(listen_addr)
            .await
            .map_err(|e| TransportError::Other(format!("bind {}: {}", listen_addr, e)))?;
        info!("Internet transport listening on {}", listen_addr);

        *started = true;
        drop(started);

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
                                tokio::spawn(async move {
                                    match shared.establish(stream, addr, &cancel).await {
                                        Ok((peer_id, conn, reader)) => {
                                            shared
                                                .read_loop(peer_id, conn, reader, cancel, permit)
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
                match TcpStream::connect(addr).await {
                    Ok(stream) => match shared.establish(stream, addr, &cancel).await {
                        Ok((peer_id, conn, reader)) => {
                            info!("Internet: bootstrapped from {} ({})", addr, peer_id);
                            tokio::spawn(shared.read_loop(peer_id, conn, reader, cancel, permit));
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
        if let Ok(guard) = self.cancel.lock() {
            guard.cancel();
        }
        {
            // The listener lives in the accept task, so a restart cannot bind
            // until that task has dropped it.
            let mut tasks = self.tasks.lock().await;
            while tasks.join_next().await.is_some() {}
        }
        // Then wait for every connection slot to come back. Connection tasks
        // are detached (one can dial out, so joining them from here would
        // deadlock), and their permits are the observable proof that they are
        // gone — including handshakes that had stalled.
        let permits = u32::try_from(self.config.max_connections.clamp(1, Semaphore::MAX_PERMITS))
            .unwrap_or(u32::MAX);
        if tokio::time::timeout(STOP_DRAIN_TIMEOUT, self.shared.slots.acquire_many(permits))
            .await
            .is_err()
        {
            warn!("Internet: a connection did not release its slot within the stop timeout");
        }
        self.shared.connections.write().await.clear();
        *started = false;
        info!("Internet transport stopped");
        Ok(())
    }

    async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError> {
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

        let msg = InternetWireMessage::MeshData {
            sender_id: self.shared.local_id,
            data: data.to_vec(),
        };
        let mut guard = conn.writer.lock().await;
        guard.send(&msg).await
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
    use mycelium_crypto::channel::AEAD_TAG_LEN;
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
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        {
            let (mut reader, mut writer) = tokio::io::split(&mut stream);
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
                    7000,
                ))
                .to_bytes();
            write_framed(
                &mut writer,
                &encode_body(&InternetWireMessage::Hello {
                    identity_key,
                    ephemeral_public: hello_ephemeral,
                    listen_port: 7000,
                    signature,
                }),
            )
            .await
            .unwrap();

            let Ok(body) = read_framed(&mut reader, MAX_HANDSHAKE_FRAME).await else {
                // The server hung up on the hello; nothing left to confirm.
                return stream;
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
        }
        stream
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
