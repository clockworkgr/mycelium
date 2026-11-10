//! Wire messages for the internet transport and its DHT.
//!
//! Framing is a 4-byte little-endian body length followed by a binary body
//! (little-endian throughout, as in §4). The previous encoding was JSON, which
//! writes a byte array as a list of decimal numbers and expanded mesh payloads
//! by about 5×: a send at the advertised 1 MiB MTU was rejected by the
//! receiver's 1 MiB frame cap, so the real ceiling was around 210 KB.
//!
//! Only the two `Hello` frames travel in the clear. Everything after them is
//! sealed by [`mycelium_crypto::channel`], so the body a frame carries is
//! ciphertext and the length prefix covers it including the AEAD tag.
//!
//! A DHT request carries no sender identity. The sender is whoever completed
//! the authenticated handshake on the connection the message arrived over, so
//! a self-asserted id in the body would only be an opportunity to poison the
//! routing table.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use mycelium_crypto::channel::AEAD_TAG_LEN;
use mycelium_protocol::types::NodeId;

use super::record::DhtRecord;

/// Maximum body size accepted for one frame, excluding the length prefix.
pub const MAX_WIRE_MESSAGE: usize = 1_048_576;

/// Cap on a cleartext handshake frame. A `Hello` body is 131 bytes; keeping
/// the pre-key limit small means a peer cannot make us allocate a megabyte
/// before it has proved anything.
pub const MAX_HANDSHAKE_FRAME: usize = 1024;

/// The exact size of a sealed `Confirm` frame: tag byte, transcript, AEAD tag.
///
/// Confirmation is read *before* the peer has proved it holds the channel key,
/// so it gets its own exact cap rather than the 1 MiB data-frame cap.
pub const CONFIRM_FRAME_LEN: usize = 1 + 32 + AEAD_TAG_LEN;

/// Largest plaintext that can be sealed into one frame.
pub const MAX_PLAINTEXT_FRAME: usize = MAX_WIRE_MESSAGE - AEAD_TAG_LEN;

/// Bytes a `MeshData` frame body spends on framing: tag, sender, payload length.
pub const MESH_DATA_OVERHEAD: usize = 1 + 32 + 4;

/// Largest mesh payload that fits in one frame once sealed.
pub const MAX_MESH_PAYLOAD: usize = MAX_PLAINTEXT_FRAME - MESH_DATA_OVERHEAD;

/// Cap on the node list in a `FoundNodes` reply, in both directions. Bounds
/// what a peer can make us allocate, and what we emit, independently of `k`.
pub const MAX_FOUND_NODES: usize = 64;

const TAG_MESH_DATA: u8 = 0x01;
const TAG_DHT_REQUEST: u8 = 0x02;
const TAG_DHT_REPLY: u8 = 0x03;
const TAG_HELLO: u8 = 0x05;
const TAG_CONFIRM: u8 = 0x06;

const REQ_PING: u8 = 0x01;
const REQ_FIND_NODE: u8 = 0x02;
const REQ_FIND_VALUE: u8 = 0x03;
const REQ_STORE: u8 = 0x04;

const REP_PONG: u8 = 0x01;
const REP_FOUND_NODES: u8 = 0x02;
const REP_FOUND_VALUE: u8 = 0x03;
const REP_STORED: u8 = 0x04;
const REP_REJECTED: u8 = 0x05;

/// A decoding failure. Every variant means the frame is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("frame ended early")]
    Truncated,
    #[error("frame has trailing bytes")]
    TrailingBytes,
    #[error("unknown tag {0:#04x}")]
    UnknownTag(u8),
    #[error("unknown address family {0}")]
    BadAddrFamily(u8),
    #[error("declared length exceeds the frame")]
    LengthOverflow,
}

/// A DHT request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtRequest {
    /// Correlates a reply with this request on the same connection.
    pub request_id: u64,
    pub body: DhtRequestBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtRequestBody {
    /// Liveness check.
    Ping,
    /// Ask for the K closest nodes to `target`.
    FindNode { target: NodeId },
    /// Ask for `key`'s record, or the closest nodes if it is not held.
    FindValue { key: NodeId },
    /// Offer a signed record for storage.
    Store { record: DhtRecord },
}

/// A DHT reply, echoing the request id it answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtReply {
    pub request_id: u64,
    pub body: DhtReplyBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtReplyBody {
    Pong,
    FoundNodes {
        nodes: Vec<(NodeId, SocketAddr)>,
    },
    FoundValue {
        record: DhtRecord,
    },
    Stored,
    /// A `Store` that failed verification or did not fit. The reason is a
    /// single opaque byte: a publisher only needs to know it was refused.
    Rejected,
}

/// Messages exchanged over an internet-transport connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InternetWireMessage {
    /// A mesh envelope being carried between nodes.
    MeshData {
        sender_id: NodeId,
        data: Vec<u8>,
    },
    Dht(DhtRequest),
    DhtReply(DhtReply),
    /// The cleartext handshake frame. The NodeId is derived from
    /// `identity_key` and never carried, so it cannot disagree with the key.
    /// The signature covers the ephemeral key, which is what the frame keys
    /// come from — so a relayed `Hello` yields a channel the relayer cannot
    /// speak on.
    Hello {
        identity_key: [u8; 32],
        ephemeral_public: [u8; 32],
        listen_port: u16,
        signature: [u8; 64],
    },
    /// The first sealed frame: proof the sender holds the channel key. It
    /// carries the transcript both sides must independently agree on.
    Confirm {
        transcript: [u8; 32],
    },
}

/// Encode a message body (no length prefix).
pub fn encode_body(msg: &InternetWireMessage) -> Vec<u8> {
    let mut out = Vec::new();
    match msg {
        InternetWireMessage::MeshData { sender_id, data } => {
            out.reserve(MESH_DATA_OVERHEAD + data.len());
            out.push(TAG_MESH_DATA);
            out.extend_from_slice(sender_id.as_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(data);
        }
        InternetWireMessage::Dht(req) => {
            out.push(TAG_DHT_REQUEST);
            out.extend_from_slice(&req.request_id.to_le_bytes());
            match &req.body {
                DhtRequestBody::Ping => out.push(REQ_PING),
                DhtRequestBody::FindNode { target } => {
                    out.push(REQ_FIND_NODE);
                    out.extend_from_slice(target.as_bytes());
                }
                DhtRequestBody::FindValue { key } => {
                    out.push(REQ_FIND_VALUE);
                    out.extend_from_slice(key.as_bytes());
                }
                DhtRequestBody::Store { record } => {
                    out.push(REQ_STORE);
                    encode_record(&mut out, record);
                }
            }
        }
        InternetWireMessage::DhtReply(reply) => {
            out.push(TAG_DHT_REPLY);
            out.extend_from_slice(&reply.request_id.to_le_bytes());
            match &reply.body {
                DhtReplyBody::Pong => out.push(REP_PONG),
                DhtReplyBody::FoundNodes { nodes } => {
                    out.push(REP_FOUND_NODES);
                    // Truncated rather than refused, so the encoder can never
                    // produce a frame the decoder would reject.
                    let count = nodes.len().min(MAX_FOUND_NODES);
                    out.extend_from_slice(&(count as u16).to_le_bytes());
                    for (id, addr) in nodes.iter().take(count) {
                        out.extend_from_slice(id.as_bytes());
                        out.extend_from_slice(&super::record::encode_addr(addr));
                    }
                }
                DhtReplyBody::FoundValue { record } => {
                    out.push(REP_FOUND_VALUE);
                    encode_record(&mut out, record);
                }
                DhtReplyBody::Stored => out.push(REP_STORED),
                DhtReplyBody::Rejected => out.push(REP_REJECTED),
            }
        }
        InternetWireMessage::Hello {
            identity_key,
            ephemeral_public,
            listen_port,
            signature,
        } => {
            out.push(TAG_HELLO);
            out.extend_from_slice(identity_key);
            out.extend_from_slice(ephemeral_public);
            out.extend_from_slice(&listen_port.to_le_bytes());
            out.extend_from_slice(signature);
        }
        InternetWireMessage::Confirm { transcript } => {
            out.push(TAG_CONFIRM);
            out.extend_from_slice(transcript);
        }
    }
    out
}

fn encode_record(out: &mut Vec<u8>, record: &DhtRecord) {
    out.extend_from_slice(&record.public_key);
    out.extend_from_slice(&super::record::encode_addr(&record.addr));
    out.extend_from_slice(&record.published_at.to_le_bytes());
    out.extend_from_slice(&record.signature);
}

/// Encode a message with its 4-byte little-endian length prefix.
pub fn serialize_wire_message(msg: &InternetWireMessage) -> Vec<u8> {
    let body = encode_body(msg);
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
    buf.extend_from_slice(&body);
    buf
}

/// Decode a message body (the bytes after the length prefix).
pub fn deserialize_wire_message(data: &[u8]) -> Result<InternetWireMessage, CodecError> {
    let mut r = Reader::new(data);
    let msg = match r.u8()? {
        TAG_MESH_DATA => {
            let sender_id = NodeId::from_bytes(r.array::<32>()?);
            let len = r.u32()? as usize;
            let data = r.take(len)?.to_vec();
            InternetWireMessage::MeshData { sender_id, data }
        }
        TAG_DHT_REQUEST => {
            let request_id = r.u64()?;
            let body = match r.u8()? {
                REQ_PING => DhtRequestBody::Ping,
                REQ_FIND_NODE => DhtRequestBody::FindNode {
                    target: NodeId::from_bytes(r.array::<32>()?),
                },
                REQ_FIND_VALUE => DhtRequestBody::FindValue {
                    key: NodeId::from_bytes(r.array::<32>()?),
                },
                REQ_STORE => DhtRequestBody::Store {
                    record: decode_record(&mut r)?,
                },
                tag => return Err(CodecError::UnknownTag(tag)),
            };
            InternetWireMessage::Dht(DhtRequest { request_id, body })
        }
        TAG_DHT_REPLY => {
            let request_id = r.u64()?;
            let body = match r.u8()? {
                REP_PONG => DhtReplyBody::Pong,
                REP_FOUND_NODES => {
                    let count = r.u16()? as usize;
                    if count > MAX_FOUND_NODES {
                        return Err(CodecError::LengthOverflow);
                    }
                    let mut nodes = Vec::with_capacity(count);
                    for _ in 0..count {
                        let id = NodeId::from_bytes(r.array::<32>()?);
                        nodes.push((id, decode_addr(&mut r)?));
                    }
                    DhtReplyBody::FoundNodes { nodes }
                }
                REP_FOUND_VALUE => DhtReplyBody::FoundValue {
                    record: decode_record(&mut r)?,
                },
                REP_STORED => DhtReplyBody::Stored,
                REP_REJECTED => DhtReplyBody::Rejected,
                tag => return Err(CodecError::UnknownTag(tag)),
            };
            InternetWireMessage::DhtReply(DhtReply { request_id, body })
        }
        TAG_HELLO => InternetWireMessage::Hello {
            identity_key: r.array::<32>()?,
            ephemeral_public: r.array::<32>()?,
            listen_port: r.u16()?,
            signature: r.array::<64>()?,
        },
        TAG_CONFIRM => InternetWireMessage::Confirm {
            transcript: r.array::<32>()?,
        },
        tag => return Err(CodecError::UnknownTag(tag)),
    };
    r.finish()?;
    Ok(msg)
}

fn decode_record(r: &mut Reader<'_>) -> Result<DhtRecord, CodecError> {
    Ok(DhtRecord {
        public_key: r.array::<32>()?,
        addr: decode_addr(r)?,
        published_at: r.u64()?,
        signature: r.array::<64>()?,
    })
}

fn decode_addr(r: &mut Reader<'_>) -> Result<SocketAddr, CodecError> {
    let ip = match r.u8()? {
        4 => IpAddr::V4(Ipv4Addr::from(r.array::<4>()?)),
        6 => IpAddr::V6(Ipv6Addr::from(r.array::<16>()?)),
        family => return Err(CodecError::BadAddrFamily(family)),
    };
    Ok(SocketAddr::new(ip, r.u16()?))
}

/// A bounds-checked cursor. Every length check subtracts on the trusted side
/// (`len - pos`, with `pos <= len` as an invariant), so no check can wrap.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.buf.len() - self.pos < n {
            return Err(CodecError::Truncated);
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        let b = self.take(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Ok(u64::from_le_bytes(arr))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let mut arr = [0u8; N];
        arr.copy_from_slice(self.take(N)?);
        Ok(arr)
    }

    fn finish(self) -> Result<(), CodecError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_crypto::identity::Identity;

    fn random_node_id() -> NodeId {
        use rand::Rng;
        NodeId::from_bytes(rand::thread_rng().gen())
    }

    fn roundtrip(msg: InternetWireMessage) {
        let framed = serialize_wire_message(&msg);
        let len = u32::from_le_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        assert_eq!(len, framed.len() - 4, "length prefix must match the body");
        assert_eq!(deserialize_wire_message(&framed[4..]).unwrap(), msg);
    }

    fn sample_record() -> DhtRecord {
        DhtRecord::new_signed(
            &Identity::generate(),
            "127.0.0.1:9736".parse().unwrap(),
            super::super::record::unix_now(),
        )
    }

    #[test]
    fn test_mesh_data_roundtrip() {
        roundtrip(InternetWireMessage::MeshData {
            sender_id: random_node_id(),
            data: vec![0xAB; 5000],
        });
    }

    #[test]
    fn test_hello_and_confirm_roundtrip() {
        roundtrip(InternetWireMessage::Hello {
            identity_key: [1u8; 32],
            ephemeral_public: [3u8; 32],
            listen_port: 9736,
            signature: [2u8; 64],
        });
        roundtrip(InternetWireMessage::Confirm {
            transcript: [7u8; 32],
        });
    }

    #[test]
    fn test_a_sealed_confirmation_is_exactly_the_declared_size() {
        let body = encode_body(&InternetWireMessage::Confirm {
            transcript: [7u8; 32],
        });
        assert_eq!(
            body.len() + AEAD_TAG_LEN,
            CONFIRM_FRAME_LEN,
            "the confirmation cap must match what sealing one actually produces"
        );
    }

    #[test]
    fn test_a_hello_fits_the_handshake_frame_cap() {
        let body = encode_body(&InternetWireMessage::Hello {
            identity_key: [1u8; 32],
            ephemeral_public: [3u8; 32],
            listen_port: 9736,
            signature: [2u8; 64],
        });
        assert!(body.len() <= MAX_HANDSHAKE_FRAME, "{} bytes", body.len());
    }

    #[test]
    fn test_every_dht_request_roundtrips() {
        for body in [
            DhtRequestBody::Ping,
            DhtRequestBody::FindNode {
                target: random_node_id(),
            },
            DhtRequestBody::FindValue {
                key: random_node_id(),
            },
            DhtRequestBody::Store {
                record: sample_record(),
            },
        ] {
            roundtrip(InternetWireMessage::Dht(DhtRequest {
                request_id: 0xDEAD_BEEF_CAFE_0001,
                body,
            }));
        }
    }

    #[test]
    fn test_every_dht_reply_roundtrips() {
        for body in [
            DhtReplyBody::Pong,
            DhtReplyBody::FoundNodes {
                nodes: vec![
                    (random_node_id(), "10.0.0.1:1".parse().unwrap()),
                    (random_node_id(), "[2001:db8::1]:65535".parse().unwrap()),
                ],
            },
            DhtReplyBody::FoundValue {
                record: sample_record(),
            },
            DhtReplyBody::Stored,
            DhtReplyBody::Rejected,
        ] {
            roundtrip(InternetWireMessage::DhtReply(DhtReply {
                request_id: 42,
                body,
            }));
        }
    }

    #[test]
    fn test_mesh_payload_at_the_cap_fits_one_sealed_frame() {
        let msg = InternetWireMessage::MeshData {
            sender_id: random_node_id(),
            data: vec![0u8; MAX_MESH_PAYLOAD],
        };
        let body = encode_body(&msg);
        assert_eq!(body.len(), MAX_PLAINTEXT_FRAME);
        assert_eq!(
            body.len() + AEAD_TAG_LEN,
            MAX_WIRE_MESSAGE,
            "sealing the largest payload must land exactly on the frame cap"
        );
        assert_eq!(deserialize_wire_message(&body).unwrap(), msg);
    }

    #[test]
    fn test_truncated_frame_is_refused() {
        let body = encode_body(&InternetWireMessage::Hello {
            identity_key: [1u8; 32],
            ephemeral_public: [3u8; 32],
            listen_port: 1,
            signature: [2u8; 64],
        });
        for cut in 0..body.len() {
            assert!(
                deserialize_wire_message(&body[..cut]).is_err(),
                "a {}-byte prefix must not decode",
                cut
            );
        }
    }

    #[test]
    fn test_trailing_bytes_are_refused() {
        let mut body = encode_body(&InternetWireMessage::Confirm {
            transcript: [0u8; 32],
        });
        body.push(0);
        assert_eq!(
            deserialize_wire_message(&body),
            Err(CodecError::TrailingBytes)
        );
    }

    #[test]
    fn test_declared_payload_length_cannot_exceed_the_frame() {
        // A MeshData header claiming 4 GiB of payload in a 37-byte frame.
        let mut body = vec![TAG_MESH_DATA];
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            deserialize_wire_message(&body),
            Err(CodecError::Truncated),
            "a declared length must be checked against the bytes actually present"
        );
    }

    #[test]
    fn test_found_nodes_count_is_capped() {
        let mut body = vec![TAG_DHT_REPLY];
        body.extend_from_slice(&1u64.to_le_bytes());
        body.push(REP_FOUND_NODES);
        body.extend_from_slice(&((MAX_FOUND_NODES + 1) as u16).to_le_bytes());
        assert_eq!(
            deserialize_wire_message(&body),
            Err(CodecError::LengthOverflow)
        );
    }

    #[test]
    fn test_encoder_truncates_an_oversized_node_list() {
        let nodes: Vec<(NodeId, SocketAddr)> = (0..MAX_FOUND_NODES + 10)
            .map(|i| {
                (
                    random_node_id(),
                    format!("10.0.0.1:{}", i + 1).parse().unwrap(),
                )
            })
            .collect();
        let body = encode_body(&InternetWireMessage::DhtReply(DhtReply {
            request_id: 1,
            body: DhtReplyBody::FoundNodes { nodes },
        }));
        match deserialize_wire_message(&body).unwrap() {
            InternetWireMessage::DhtReply(DhtReply {
                body: DhtReplyBody::FoundNodes { nodes },
                ..
            }) => assert_eq!(nodes.len(), MAX_FOUND_NODES),
            other => panic!("unexpected {:?}", other),
        }
    }

    #[test]
    fn test_unknown_tags_are_refused() {
        assert_eq!(
            deserialize_wire_message(&[0xFF]),
            Err(CodecError::UnknownTag(0xFF))
        );
        let mut body = vec![TAG_DHT_REQUEST];
        body.extend_from_slice(&0u64.to_le_bytes());
        body.push(0x7F);
        assert_eq!(
            deserialize_wire_message(&body),
            Err(CodecError::UnknownTag(0x7F))
        );
    }

    #[test]
    fn test_unknown_address_family_is_refused() {
        let mut body = vec![TAG_DHT_REPLY];
        body.extend_from_slice(&0u64.to_le_bytes());
        body.push(REP_FOUND_NODES);
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(9); // not 4 or 6
        body.extend_from_slice(&[0u8; 6]);
        assert_eq!(
            deserialize_wire_message(&body),
            Err(CodecError::BadAddrFamily(9))
        );
    }

    #[test]
    fn test_binary_framing_does_not_expand_payloads() {
        // The JSON encoding this replaces expanded a byte array about 5×.
        let data = vec![0xFFu8; 64 * 1024];
        let body = encode_body(&InternetWireMessage::MeshData {
            sender_id: random_node_id(),
            data: data.clone(),
        });
        assert_eq!(body.len(), data.len() + MESH_DATA_OVERHEAD);
    }
}
