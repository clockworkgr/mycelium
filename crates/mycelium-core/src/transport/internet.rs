//! Internet TCP transport for long-range mesh connectivity.
//!
//! Enables nodes to communicate over the internet using TCP connections.
//! Integrates with the Kademlia DHT for peer discovery.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex, RwLock};
use tracing::{debug, info, warn};

use mycelium_protocol::types::{LinkQuality, NodeId};

use super::{Transport, TransportError, TransportEvent, TransportType};
use crate::dht::rpc::{deserialize_wire_message, serialize_wire_message, InternetWireMessage};
use crate::dht::{DhtConfig, DhtEngine, PeerInfo};

/// Configuration for the Internet transport.
#[derive(Debug, Clone)]
pub struct InternetConfig {
    /// Address to listen on for incoming connections.
    pub listen_addr: SocketAddr,
    /// Bootstrap DHT nodes to connect to initially.
    pub bootstrap_nodes: Vec<SocketAddr>,
    /// Maximum number of simultaneous TCP connections.
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

/// Active TCP connection to a peer.
struct PeerConnection {
    _addr: SocketAddr,
    writer: tokio::io::WriteHalf<TcpStream>,
    _connected_at: Instant,
}

/// Internet transport using TCP connections and Kademlia DHT for discovery.
pub struct InternetTransport {
    local_id: NodeId,
    config: InternetConfig,
    dht: Arc<DhtEngine>,
    event_tx: broadcast::Sender<TransportEvent>,
    connections: Arc<RwLock<HashMap<NodeId, Arc<Mutex<PeerConnection>>>>>,
    started: Arc<RwLock<bool>>,
    cancel: tokio_util::sync::CancellationToken,
}

impl InternetTransport {
    /// Create a new Internet transport.
    pub fn new(local_id: NodeId, config: InternetConfig) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        let dht_config = DhtConfig {
            bootstrap_nodes: config.bootstrap_nodes.clone(),
            ..DhtConfig::default()
        };
        let dht = Arc::new(DhtEngine::new(local_id, dht_config));

        Self {
            local_id,
            config,
            dht,
            event_tx,
            connections: Arc::new(RwLock::new(HashMap::new())),
            started: Arc::new(RwLock::new(false)),
            cancel: tokio_util::sync::CancellationToken::new(),
        }
    }

    /// Get a reference to the DHT engine.
    pub fn dht(&self) -> &Arc<DhtEngine> {
        &self.dht
    }

    /// Handle an incoming TCP connection.
    async fn handle_connection(
        _local_id: NodeId,
        stream: TcpStream,
        addr: SocketAddr,
        dht: Arc<DhtEngine>,
        event_tx: broadcast::Sender<TransportEvent>,
        connections: Arc<RwLock<HashMap<NodeId, Arc<Mutex<PeerConnection>>>>>,
        cancel: tokio_util::sync::CancellationToken,
    ) {
        let (mut reader, writer) = tokio::io::split(stream);

        // Read hello message to learn peer's node ID
        let peer_id = match Self::read_message(&mut reader).await {
            Ok(InternetWireMessage::Hello { node_id, .. }) => node_id,
            Ok(_) => {
                debug!("Expected Hello from {}, got other message", addr);
                return;
            }
            Err(e) => {
                debug!("Failed to read Hello from {}: {}", addr, e);
                return;
            }
        };

        info!("Internet: peer {} connected from {}", peer_id, addr);

        // Store connection
        let conn = Arc::new(Mutex::new(PeerConnection {
            _addr: addr,
            writer,
            _connected_at: Instant::now(),
        }));
        {
            let mut conns = connections.write().await;
            conns.insert(peer_id, conn.clone());
        }

        // Add to DHT
        dht.add_peer(PeerInfo {
            node_id: peer_id,
            addr,
            last_seen: Instant::now(),
        })
        .await;

        // Notify neighbor discovered
        let _ = event_tx.send(TransportEvent::NeighborDiscovered {
            peer: peer_id,
            transport: TransportType::InternetTunnel,
        });

        // Read loop
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                result = Self::read_message(&mut reader) => {
                    match result {
                        Ok(InternetWireMessage::MeshData { data, .. }) => {
                            let _ = event_tx.send(TransportEvent::DataReceived {
                                peer: peer_id,
                                data,
                                transport: TransportType::InternetTunnel,
                            });
                        }
                        Ok(InternetWireMessage::Dht(msg)) => {
                            if let Some(resp) = dht.handle_message(msg).await {
                                let reply = InternetWireMessage::DhtReply(resp);
                                let bytes = serialize_wire_message(&reply);
                                let mut guard = conn.lock().await;
                                let _ = guard.writer.write_all(&bytes).await;
                            }
                        }
                        Ok(InternetWireMessage::DhtReply(_resp)) => {
                            // DHT responses handled inline for now
                        }
                        Ok(InternetWireMessage::Hello { .. }) => {
                            // Ignore duplicate hellos
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        // Cleanup
        {
            let mut conns = connections.write().await;
            conns.remove(&peer_id);
        }
        let _ = event_tx.send(TransportEvent::NeighborLost {
            peer: peer_id,
            transport: TransportType::InternetTunnel,
        });
        info!("Internet: peer {} disconnected", peer_id);
    }

    /// Read a length-prefixed message from a reader.
    async fn read_message(
        reader: &mut tokio::io::ReadHalf<TcpStream>,
    ) -> Result<InternetWireMessage, TransportError> {
        let mut len_buf = [0u8; 4];
        reader
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| TransportError::Other(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > 1_048_576 {
            return Err(TransportError::Other("Message too large".to_string()));
        }

        let mut data = vec![0u8; len];
        reader
            .read_exact(&mut data)
            .await
            .map_err(|e| TransportError::Other(e.to_string()))?;

        deserialize_wire_message(&data).map_err(|e| TransportError::Other(e.to_string()))
    }

    /// Connect to a peer at the given address.
    pub async fn connect_to(&self, addr: SocketAddr) -> Result<NodeId, TransportError> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| TransportError::Other(format!("Connect to {}: {}", addr, e)))?;

        // Send Hello
        let hello = InternetWireMessage::Hello {
            node_id: self.local_id,
            listen_port: self.config.listen_addr.port(),
        };
        let (mut reader, mut writer) = tokio::io::split(stream);
        let bytes = serialize_wire_message(&hello);
        writer
            .write_all(&bytes)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        // Read their Hello
        let mut len_buf = [0u8; 4];
        reader
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| TransportError::Other(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; len];
        reader
            .read_exact(&mut data)
            .await
            .map_err(|e| TransportError::Other(e.to_string()))?;

        let peer_id = match deserialize_wire_message(&data) {
            Ok(InternetWireMessage::Hello { node_id, .. }) => node_id,
            _ => return Err(TransportError::Other("Expected Hello response".to_string())),
        };

        // Store connection
        let conn = Arc::new(Mutex::new(PeerConnection {
            _addr: addr,
            writer,
            _connected_at: Instant::now(),
        }));

        {
            let mut conns = self.connections.write().await;
            conns.insert(peer_id, conn.clone());
        }

        // Add to DHT
        self.dht
            .add_peer(PeerInfo {
                node_id: peer_id,
                addr,
                last_seen: Instant::now(),
            })
            .await;

        // Notify
        let _ = self.event_tx.send(TransportEvent::NeighborDiscovered {
            peer: peer_id,
            transport: TransportType::InternetTunnel,
        });

        // Spawn read task for this connection
        let dht = self.dht.clone();
        let event_tx = self.event_tx.clone();
        let connections = self.connections.clone();
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = Self::read_message(&mut reader) => {
                        match result {
                            Ok(InternetWireMessage::MeshData { data, .. }) => {
                                let _ = event_tx.send(TransportEvent::DataReceived {
                                    peer: peer_id,
                                    data,
                                    transport: TransportType::InternetTunnel,
                                });
                            }
                            Ok(InternetWireMessage::Dht(msg)) => {
                                if let Some(resp) = dht.handle_message(msg).await {
                                    let reply = InternetWireMessage::DhtReply(resp);
                                    let bytes = serialize_wire_message(&reply);
                                    let mut guard = conn.lock().await;
                                    let _ = guard.writer.write_all(&bytes).await;
                                }
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                }
            }

            {
                let mut conns = connections.write().await;
                conns.remove(&peer_id);
            }
            let _ = event_tx.send(TransportEvent::NeighborLost {
                peer: peer_id,
                transport: TransportType::InternetTunnel,
            });
        });

        info!("Internet: connected to {} at {}", peer_id, addr);
        Ok(peer_id)
    }
}

#[async_trait::async_trait]
impl Transport for InternetTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::InternetTunnel
    }

    async fn start(&self) -> Result<(), TransportError> {
        {
            let mut s = self.started.write().await;
            if *s {
                return Err(TransportError::AlreadyStarted);
            }
            *s = true;
        }

        let listen_addr = self.config.listen_addr;
        let local_id = self.local_id;
        let dht = self.dht.clone();
        let event_tx = self.event_tx.clone();
        let connections = self.connections.clone();
        let cancel = self.cancel.clone();

        // Start TCP listener
        let listener = TcpListener::bind(listen_addr)
            .await
            .map_err(|e| TransportError::Other(format!("Bind {}: {}", listen_addr, e)))?;
        info!("Internet transport listening on {}", listen_addr);

        // Store our address in DHT
        self.dht.store_self(listen_addr).await;

        // Accept loop
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                // Send Hello to the connecting peer
                                let (reader, mut writer) = tokio::io::split(stream);
                                let hello = InternetWireMessage::Hello {
                                    node_id: local_id,
                                    listen_port: listen_addr.port(),
                                };
                                let bytes = serialize_wire_message(&hello);
                                if writer.write_all(&bytes).await.is_err() {
                                    continue;
                                }

                                // Reassemble into TcpStream for the handler
                                let stream = reader.unsplit(writer);
                                let dht = dht.clone();
                                let event_tx = event_tx.clone();
                                let connections = connections.clone();
                                let cancel = cancel.clone();
                                tokio::spawn(Self::handle_connection(
                                    local_id,
                                    stream,
                                    addr,
                                    dht,
                                    event_tx,
                                    connections,
                                    cancel,
                                ));
                            }
                            Err(e) => {
                                warn!("Internet: accept error: {}", e);
                            }
                        }
                    }
                }
            }
        });

        // Bootstrap: connect to known nodes
        for addr in &self.config.bootstrap_nodes {
            let addr = *addr;
            let this_dht = self.dht.clone();
            let this_event_tx = self.event_tx.clone();
            let this_connections = self.connections.clone();
            let this_cancel = self.cancel.clone();
            let this_local_id = self.local_id;
            let this_listen_addr = self.config.listen_addr;

            tokio::spawn(async move {
                match TcpStream::connect(addr).await {
                    Ok(stream) => {
                        info!("Internet: connected to bootstrap node {}", addr);
                        // Exchange hellos handled in handle_connection
                        // For simplicity, we handle it similarly
                        let (reader, mut writer) = tokio::io::split(stream);
                        let hello = InternetWireMessage::Hello {
                            node_id: this_local_id,
                            listen_port: this_listen_addr.port(),
                        };
                        let bytes = serialize_wire_message(&hello);
                        if writer.write_all(&bytes).await.is_ok() {
                            let stream = reader.unsplit(writer);
                            Self::handle_connection(
                                this_local_id,
                                stream,
                                addr,
                                this_dht,
                                this_event_tx,
                                this_connections,
                                this_cancel,
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        warn!("Internet: bootstrap connect to {} failed: {}", addr, e);
                    }
                }
            });
        }

        Ok(())
    }

    async fn stop(&self) -> Result<(), TransportError> {
        self.cancel.cancel();
        let mut conns = self.connections.write().await;
        conns.clear();
        let mut s = self.started.write().await;
        *s = false;
        info!("Internet transport stopped");
        Ok(())
    }

    async fn send(&self, peer: &NodeId, data: &[u8]) -> Result<(), TransportError> {
        let conns = self.connections.read().await;
        let conn = conns
            .get(peer)
            .ok_or(TransportError::PeerNotConnected(*peer))?
            .clone();
        drop(conns);

        let msg = InternetWireMessage::MeshData {
            sender_id: self.local_id,
            data: data.to_vec(),
        };
        let bytes = serialize_wire_message(&msg);
        let mut guard = conn.lock().await;
        guard
            .writer
            .write_all(&bytes)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        Ok(())
    }

    fn events(&self) -> broadcast::Receiver<TransportEvent> {
        self.event_tx.subscribe()
    }

    fn link_quality(&self, peer: &NodeId) -> Option<LinkQuality> {
        let conns = self.connections.try_read().ok()?;
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
        match self.connections.try_read() {
            Ok(conns) => conns.keys().copied().collect(),
            Err(_) => Vec::new(),
        }
    }

    fn mtu(&self) -> usize {
        // TCP has no real MTU limit, but we cap messages at 1MB
        1_048_576
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::time::{sleep, Duration};

    fn random_node_id() -> NodeId {
        use rand::Rng;
        NodeId::from_bytes(rand::thread_rng().gen())
    }

    fn make_config(port: u16) -> InternetConfig {
        InternetConfig {
            listen_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            bootstrap_nodes: Vec::new(),
            max_connections: 64,
        }
    }

    #[tokio::test]
    async fn test_transport_type() {
        let t = InternetTransport::new(random_node_id(), make_config(0));
        assert_eq!(t.transport_type(), TransportType::InternetTunnel);
    }

    #[tokio::test]
    async fn test_mtu() {
        let t = InternetTransport::new(random_node_id(), make_config(0));
        assert_eq!(t.mtu(), 1_048_576);
    }

    #[tokio::test]
    async fn test_two_nodes_connect_and_send() {
        let id_a = random_node_id();
        let id_b = random_node_id();

        // Node A listens on port 0 (OS assigns)
        let a_config = InternetConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            max_connections: 64,
        };
        let _a = InternetTransport::new(id_a, a_config);

        // Start A — need to get its actual port
        // We bind manually to get the port
        let a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_port = a_listener.local_addr().unwrap().port();
        drop(a_listener);

        let a = InternetTransport::new(
            id_a,
            InternetConfig {
                listen_addr: format!("127.0.0.1:{}", a_port).parse().unwrap(),
                bootstrap_nodes: Vec::new(),
                max_connections: 64,
            },
        );
        a.start().await.unwrap();

        // Node B connects to A
        let b = InternetTransport::new(
            id_b,
            InternetConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                bootstrap_nodes: Vec::new(),
                max_connections: 64,
            },
        );

        let mut b_events = b.events();

        // Connect B → A
        let b_addr: SocketAddr = format!("127.0.0.1:{}", a_port).parse().unwrap();
        let connected_id = b.connect_to(b_addr).await.unwrap();
        assert_eq!(connected_id, id_a);

        // Wait for A to process the connection
        sleep(Duration::from_millis(100)).await;

        // A should see B as a connected peer
        let a_peers = a.connected_peers();
        assert!(a_peers.contains(&id_b), "A should see B as connected");

        // B should see A
        let b_peers = b.connected_peers();
        assert!(b_peers.contains(&id_a), "B should see A as connected");

        // Send data from A → B
        let test_data = b"hello from A";
        a.send(&id_b, test_data).await.unwrap();

        // B should receive it
        let event = tokio::time::timeout(Duration::from_secs(2), b_events.recv())
            .await
            .expect("timeout waiting for event")
            .expect("event channel error");

        match event {
            TransportEvent::NeighborDiscovered { peer, .. } => {
                assert_eq!(peer, id_a);
                // Read the actual data event
                let data_event = tokio::time::timeout(Duration::from_secs(2), b_events.recv())
                    .await
                    .expect("timeout")
                    .expect("channel error");
                match data_event {
                    TransportEvent::DataReceived { data, peer, .. } => {
                        assert_eq!(peer, id_a);
                        assert_eq!(data, test_data);
                    }
                    other => panic!("Expected DataReceived, got {:?}", other),
                }
            }
            TransportEvent::DataReceived { data, peer, .. } => {
                assert_eq!(peer, id_a);
                assert_eq!(data, test_data);
            }
            other => panic!("Expected data event, got {:?}", other),
        }

        // Cleanup
        a.stop().await.unwrap();
        b.stop().await.unwrap();
    }
}
