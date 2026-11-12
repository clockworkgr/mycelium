//! Wire payload types and serialization for mesh message dispatch.
//!
//! The first byte of an Envelope's payload discriminates the message type.
//! Each payload type has its own binary format following that type byte.

use crate::codec::CodecError;
use crate::types::NodeId;

/// Payload type discriminator (first byte of Envelope payload).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WirePayloadType {
    EncryptedMessage = 0x10,
    SessionInit = 0x11,
    PrekeyRequest = 0x20,
    PrekeyResponse = 0x21,
    SessionReject = 0x22,
    AodvRreq = 0x30,
    AodvRrep = 0x31,
    AodvRerr = 0x32,
    DtnRelay = 0x40,
    Beacon = 0x50,
    Receipt = 0x60,
    GroupMessage = 0x70,
    SenderKeyDistribution = 0x71,
    ChannelMessage = 0x80,
    ChannelSubscribe = 0x81,
    ChannelUnsubscribe = 0x82,
    ChannelModeration = 0x83,
    EmergencyBroadcast = 0x90,
}

impl WirePayloadType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x10 => Some(Self::EncryptedMessage),
            0x11 => Some(Self::SessionInit),
            0x20 => Some(Self::PrekeyRequest),
            0x21 => Some(Self::PrekeyResponse),
            0x22 => Some(Self::SessionReject),
            0x30 => Some(Self::AodvRreq),
            0x31 => Some(Self::AodvRrep),
            0x32 => Some(Self::AodvRerr),
            0x40 => Some(Self::DtnRelay),
            0x50 => Some(Self::Beacon),
            0x60 => Some(Self::Receipt),
            0x70 => Some(Self::GroupMessage),
            0x71 => Some(Self::SenderKeyDistribution),
            0x80 => Some(Self::ChannelMessage),
            0x81 => Some(Self::ChannelSubscribe),
            0x82 => Some(Self::ChannelUnsubscribe),
            0x83 => Some(Self::ChannelModeration),
            0x90 => Some(Self::EmergencyBroadcast),
            _ => None,
        }
    }
}

/// Serialized ratchet header: 40 bytes.
/// Layout: dh_public(32) + previous_chain_length(4) + message_number(4)
#[derive(Debug, Clone)]
pub struct WireRatchetHeader {
    pub dh_public: [u8; 32],
    pub previous_chain_length: u32,
    pub message_number: u32,
}

impl WireRatchetHeader {
    pub const SIZE: usize = 40;

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.dh_public);
        buf.extend_from_slice(&self.previous_chain_length.to_le_bytes());
        buf.extend_from_slice(&self.message_number.to_le_bytes());
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() < Self::SIZE {
            return Err(CodecError::BufferTooShort {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }
        let mut dh_public = [0u8; 32];
        dh_public.copy_from_slice(&data[..32]);
        let previous_chain_length = u32::from_le_bytes(data[32..36].try_into().unwrap());
        let message_number = u32::from_le_bytes(data[36..40].try_into().unwrap());
        Ok(Self {
            dh_public,
            previous_chain_length,
            message_number,
        })
    }
}

/// Encrypted message payload.
/// Layout: type(1=0x10) + content_type(1) + ratchet_header(40) + ciphertext_len(4) + ciphertext
#[derive(Debug, Clone)]
pub struct EncryptedPayload {
    pub content_type: u8,
    pub header: WireRatchetHeader,
    pub ciphertext: Vec<u8>,
}

impl EncryptedPayload {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(1 + 1 + WireRatchetHeader::SIZE + 4 + self.ciphertext.len());
        buf.push(WirePayloadType::EncryptedMessage as u8);
        buf.push(self.content_type);
        self.header.serialize(&mut buf);
        buf.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Deserialize from payload bytes (after the type byte has already been read).
    pub fn deserialize_body(data: &[u8]) -> Result<Self, CodecError> {
        // data starts after the type byte: content_type(1) + header(40) + ct_len(4) + ct
        if data.len() < 1 + WireRatchetHeader::SIZE + 4 {
            return Err(CodecError::BufferTooShort {
                expected: 1 + WireRatchetHeader::SIZE + 4,
                actual: data.len(),
            });
        }
        let content_type = data[0];
        let header = WireRatchetHeader::deserialize(&data[1..1 + WireRatchetHeader::SIZE])?;
        let ct_len = u32::from_le_bytes(data[41..45].try_into().unwrap()) as usize;
        if data.len() - 45 != ct_len {
            // Exactly, for the same reason as `SessionInitPayload`: this blob
            // sits inside the init whose hash identifies the handshake.
            return Err(CodecError::PayloadLengthMismatch {
                header: ct_len,
                actual: data.len() - 45,
            });
        }
        let ciphertext = data[45..45 + ct_len].to_vec();
        Ok(Self {
            content_type,
            header,
            ciphertext,
        })
    }
}

/// Session init payload (X3DH initiation + first encrypted message).
/// Layout: type(1=0x11) + ephemeral_public(32) + identity_key(32)
///         + signed_prekey_id(4) + has_otp(1) + otp_id(4, if has_otp)
///         + encrypted_payload_len(4) + encrypted_payload_bytes
#[derive(Debug, Clone)]
pub struct SessionInitPayload {
    pub ephemeral_public: [u8; 32],
    pub identity_key: [u8; 32],
    pub signed_prekey_id: u32,
    pub one_time_prekey_id: Option<u32>,
    /// The encrypted first message (EncryptedPayload serialized without type byte prefix).
    pub encrypted_payload: Vec<u8>,
}

impl SessionInitPayload {
    pub fn serialize(&self) -> Vec<u8> {
        let otp_size = if self.one_time_prekey_id.is_some() {
            5
        } else {
            1
        };
        let mut buf =
            Vec::with_capacity(1 + 32 + 32 + 4 + otp_size + 4 + self.encrypted_payload.len());
        buf.push(WirePayloadType::SessionInit as u8);
        buf.extend_from_slice(&self.ephemeral_public);
        buf.extend_from_slice(&self.identity_key);
        buf.extend_from_slice(&self.signed_prekey_id.to_le_bytes());
        if let Some(otp_id) = self.one_time_prekey_id {
            buf.push(1);
            buf.extend_from_slice(&otp_id.to_le_bytes());
        } else {
            buf.push(0);
        }
        buf.extend_from_slice(&(self.encrypted_payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.encrypted_payload);
        buf
    }

    pub fn deserialize_body(data: &[u8]) -> Result<Self, CodecError> {
        // data starts after type byte
        let min_size = 32 + 32 + 4 + 1; // 69
        if data.len() < min_size {
            return Err(CodecError::BufferTooShort {
                expected: min_size,
                actual: data.len(),
            });
        }
        let mut offset = 0;

        let mut ephemeral_public = [0u8; 32];
        ephemeral_public.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut identity_key = [0u8; 32];
        identity_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let signed_prekey_id = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let has_otp = data[offset];
        if has_otp > 1 {
            // Canonical, because this payload's hash identifies the handshake
            // a `SessionReject` names: `2` parsed the same as `1` but hashed
            // differently, so an altered copy could be accepted under one
            // identity and the original replayed under another (T-35,
            // ADR-012).
            return Err(CodecError::InvalidDiscriminant { value: has_otp });
        }
        offset += 1;

        let one_time_prekey_id = if has_otp != 0 {
            if data.len() < offset + 4 {
                return Err(CodecError::BufferTooShort {
                    expected: offset + 4,
                    actual: data.len(),
                });
            }
            let id = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            offset += 4;
            Some(id)
        } else {
            None
        };

        if data.len() < offset + 4 {
            return Err(CodecError::BufferTooShort {
                expected: offset + 4,
                actual: data.len(),
            });
        }
        let payload_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if data.len() - offset != payload_len {
            // Exactly, not at least: trailing bytes are ignored by the parse
            // but change the payload's hash, and that hash is the identity a
            // `SessionReject` is bound to. A padded copy of an init would
            // otherwise be accepted under a different identity, leaving the
            // original free to be replayed past the replay check (T-35,
            // ADR-012).
            return Err(CodecError::PayloadLengthMismatch {
                header: payload_len,
                actual: data.len() - offset,
            });
        }
        let encrypted_payload = data[offset..offset + payload_len].to_vec();

        Ok(Self {
            ephemeral_public,
            identity_key,
            signed_prekey_id,
            one_time_prekey_id,
            encrypted_payload,
        })
    }
}

/// Prekey bundle payload for PrekeyRequest (empty body) and PrekeyResponse.
/// Layout for response: type(1=0x21) + identity_key(32) + signed_prekey(32)
///                       + sig_len(2) + signature(sig_len) + signed_prekey_id(4)
///                       + has_otp(1) + otp(32, if has) + otp_id(4, if has)
#[derive(Debug, Clone)]
pub struct PrekeyBundlePayload {
    pub identity_key: [u8; 32],
    pub signed_prekey: [u8; 32],
    pub signed_prekey_signature: Vec<u8>,
    pub signed_prekey_id: u32,
    pub one_time_prekey: Option<[u8; 32]>,
    pub one_time_prekey_id: Option<u32>,
}

impl PrekeyBundlePayload {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.push(WirePayloadType::PrekeyResponse as u8);
        buf.extend_from_slice(&self.identity_key);
        buf.extend_from_slice(&self.signed_prekey);
        buf.extend_from_slice(&(self.signed_prekey_signature.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.signed_prekey_signature);
        buf.extend_from_slice(&self.signed_prekey_id.to_le_bytes());
        if let Some(otp) = &self.one_time_prekey {
            buf.push(1);
            buf.extend_from_slice(otp);
            buf.extend_from_slice(&self.one_time_prekey_id.unwrap_or(0).to_le_bytes());
        } else {
            buf.push(0);
        }
        buf
    }

    pub fn deserialize_body(data: &[u8]) -> Result<Self, CodecError> {
        let min = 32 + 32 + 2; // 66
        if data.len() < min {
            return Err(CodecError::BufferTooShort {
                expected: min,
                actual: data.len(),
            });
        }
        let mut offset = 0;

        let mut identity_key = [0u8; 32];
        identity_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut signed_prekey = [0u8; 32];
        signed_prekey.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let sig_len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;

        if data.len() < offset + sig_len + 4 + 1 {
            return Err(CodecError::BufferTooShort {
                expected: offset + sig_len + 4 + 1,
                actual: data.len(),
            });
        }
        let signed_prekey_signature = data[offset..offset + sig_len].to_vec();
        offset += sig_len;

        let signed_prekey_id = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let has_otp = data[offset];
        offset += 1;

        let (one_time_prekey, one_time_prekey_id) = if has_otp != 0 {
            if data.len() < offset + 32 + 4 {
                return Err(CodecError::BufferTooShort {
                    expected: offset + 36,
                    actual: data.len(),
                });
            }
            let mut otp = [0u8; 32];
            otp.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            let otp_id = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            (Some(otp), Some(otp_id))
        } else {
            (None, None)
        };

        Ok(Self {
            identity_key,
            signed_prekey,
            signed_prekey_signature,
            signed_prekey_id,
            one_time_prekey,
            one_time_prekey_id,
        })
    }
}

// --- AODV message serialization ---

use crate::types::MessageId;

/// Serialize a prekey request payload (just the type byte + requesting node's identity key).
pub fn serialize_prekey_request(requester_identity_key: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(33);
    buf.push(WirePayloadType::PrekeyRequest as u8);
    buf.extend_from_slice(requester_identity_key);
    buf
}

/// Why a `SessionInit` was refused.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRejectReason {
    /// The signed prekey the initiator used is one we no longer hold: its
    /// cached bundle is older than our retention window.
    StaleSignedPrekey = 1,
    /// The one-time prekey the initiator used is not available.
    UnknownOneTimePrekey = 2,
    /// X3DH completed but the enclosed first message did not authenticate.
    DecryptFailed = 3,
}

impl SessionRejectReason {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::StaleSignedPrekey),
            2 => Some(Self::UnknownOneTimePrekey),
            3 => Some(Self::DecryptFailed),
            _ => None,
        }
    }
}

/// Session rejection wire format.
/// Layout: type(1=0x22) + reason(1) + identity_key(32)
///
/// Sent when a `SessionInit` cannot be accepted, so the initiator discards its
/// cached prekey bundle and re-requests instead of retrying forever against a
/// bundle that can never work (ROADMAP T-06).
///
/// A reject is necessarily unauthenticated — no session exists yet — so the
/// receiver must treat it as a hint only: drop the cached bundle and
/// re-request, never touch an established session. The `identity_key` lets the
/// receiver apply the same NodeId binding check as every other ingress path.
/// Body of a `SessionReject`, after the type byte.
///
/// `reason(1) ‖ identity_key(32) ‖ init_transcript(32) ‖ signature(64)`.
/// The transcript identifies the `SessionInit` being refused — the envelope's
/// id and source are both forgeable, so they identify nothing — and the
/// signature covers it, so a reject can be neither forged nor replayed
/// against another handshake (ROADMAP T-35).
pub const SESSION_REJECT_BODY_LEN: usize = 1 + 32 + 32 + 64;

pub fn serialize_session_reject(
    reason: SessionRejectReason,
    identity_key: &[u8; 32],
    init_transcript: &[u8; 32],
    signature: &[u8; 64],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + SESSION_REJECT_BODY_LEN);
    buf.push(WirePayloadType::SessionReject as u8);
    buf.push(reason as u8);
    buf.extend_from_slice(identity_key);
    buf.extend_from_slice(init_transcript);
    buf.extend_from_slice(signature);
    buf
}

/// Deserialize a session rejection from body bytes (after the type byte).
#[allow(clippy::type_complexity)]
pub fn deserialize_session_reject(
    data: &[u8],
) -> Result<(SessionRejectReason, [u8; 32], [u8; 32], [u8; 64]), CodecError> {
    if data.len() < SESSION_REJECT_BODY_LEN {
        return Err(CodecError::BufferTooShort {
            expected: SESSION_REJECT_BODY_LEN,
            actual: data.len(),
        });
    }
    let reason = SessionRejectReason::from_byte(data[0])
        .ok_or(CodecError::InvalidDiscriminant { value: data[0] })?;
    let mut identity_key = [0u8; 32];
    identity_key.copy_from_slice(&data[1..33]);
    let mut init_transcript = [0u8; 32];
    init_transcript.copy_from_slice(&data[33..65]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[65..129]);
    Ok((reason, identity_key, init_transcript, signature))
}

/// AODV Route Request wire format.
/// Layout: type(1=0x30) + request_id(4) + source(32) + source_seq(4) + destination(32) + dest_seq(4) + hop_count(1) + ttl(1)
pub fn serialize_aodv_rreq(
    request_id: u32,
    source: &NodeId,
    source_seq: u32,
    destination: &NodeId,
    dest_seq: u32,
    hop_count: u8,
    ttl: u8,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(79);
    buf.push(WirePayloadType::AodvRreq as u8);
    buf.extend_from_slice(&request_id.to_le_bytes());
    buf.extend_from_slice(source.as_bytes());
    buf.extend_from_slice(&source_seq.to_le_bytes());
    buf.extend_from_slice(destination.as_bytes());
    buf.extend_from_slice(&dest_seq.to_le_bytes());
    buf.push(hop_count);
    buf.push(ttl);
    buf
}

/// Deserialize AODV RREQ from body bytes (after type byte).
#[allow(clippy::type_complexity)]
pub fn deserialize_aodv_rreq(
    data: &[u8],
) -> Result<(u32, NodeId, u32, NodeId, u32, u8, u8), CodecError> {
    if data.len() < 78 {
        return Err(CodecError::BufferTooShort {
            expected: 78,
            actual: data.len(),
        });
    }
    let request_id = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let mut source = [0u8; 32];
    source.copy_from_slice(&data[4..36]);
    let source_seq = u32::from_le_bytes(data[36..40].try_into().unwrap());
    let mut dest = [0u8; 32];
    dest.copy_from_slice(&data[40..72]);
    let dest_seq = u32::from_le_bytes(data[72..76].try_into().unwrap());
    let hop_count = data[76];
    let ttl = data[77];
    Ok((
        request_id,
        NodeId::from_bytes(source),
        source_seq,
        NodeId::from_bytes(dest),
        dest_seq,
        hop_count,
        ttl,
    ))
}

/// AODV Route Reply wire format.
/// Layout: type(1=0x31) + request_id(4) + source(32) + destination(32) + dest_seq(4) + hop_count(1) + lifetime_secs(4)
pub fn serialize_aodv_rrep(
    request_id: u32,
    source: &NodeId,
    destination: &NodeId,
    dest_seq: u32,
    hop_count: u8,
    lifetime_secs: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(78);
    buf.push(WirePayloadType::AodvRrep as u8);
    buf.extend_from_slice(&request_id.to_le_bytes());
    buf.extend_from_slice(source.as_bytes());
    buf.extend_from_slice(destination.as_bytes());
    buf.extend_from_slice(&dest_seq.to_le_bytes());
    buf.push(hop_count);
    buf.extend_from_slice(&lifetime_secs.to_le_bytes());
    buf
}

/// Deserialize AODV RREP from body bytes (after type byte).
pub fn deserialize_aodv_rrep(
    data: &[u8],
) -> Result<(u32, NodeId, NodeId, u32, u8, u32), CodecError> {
    if data.len() < 77 {
        return Err(CodecError::BufferTooShort {
            expected: 77,
            actual: data.len(),
        });
    }
    let request_id = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let mut source = [0u8; 32];
    source.copy_from_slice(&data[4..36]);
    let mut dest = [0u8; 32];
    dest.copy_from_slice(&data[36..68]);
    let dest_seq = u32::from_le_bytes(data[68..72].try_into().unwrap());
    let hop_count = data[72];
    let lifetime_secs = u32::from_le_bytes(data[73..77].try_into().unwrap());
    Ok((
        request_id,
        NodeId::from_bytes(source),
        NodeId::from_bytes(dest),
        dest_seq,
        hop_count,
        lifetime_secs,
    ))
}

/// AODV Route Error wire format.
/// Layout: type(1=0x32) + unreachable(32) + source(32) + dest_seq(4)
pub fn serialize_aodv_rerr(unreachable: &NodeId, source: &NodeId, dest_seq: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(69);
    buf.push(WirePayloadType::AodvRerr as u8);
    buf.extend_from_slice(unreachable.as_bytes());
    buf.extend_from_slice(source.as_bytes());
    buf.extend_from_slice(&dest_seq.to_le_bytes());
    buf
}

/// Deserialize AODV RERR from body bytes (after type byte).
pub fn deserialize_aodv_rerr(data: &[u8]) -> Result<(NodeId, NodeId, u32), CodecError> {
    if data.len() < 68 {
        return Err(CodecError::BufferTooShort {
            expected: 68,
            actual: data.len(),
        });
    }
    let mut unreachable = [0u8; 32];
    unreachable.copy_from_slice(&data[0..32]);
    let mut source = [0u8; 32];
    source.copy_from_slice(&data[32..64]);
    let dest_seq = u32::from_le_bytes(data[64..68].try_into().unwrap());
    Ok((
        NodeId::from_bytes(unreachable),
        NodeId::from_bytes(source),
        dest_seq,
    ))
}

/// A DTN bundle handed to a relay (spray-and-wait).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtnRelayPayload {
    pub message_id: MessageId,
    /// Spray copies the relay now owns (binary spray gives away half).
    pub copies_remaining: u8,
    /// Seconds until the bundle expires, from the sender's point of view.
    pub ttl_secs: u32,
    /// The opaque, end-to-end encrypted inner payload.
    pub payload: Vec<u8>,
}

impl DtnRelayPayload {
    /// Fixed body size before the variable payload.
    pub const HEADER_SIZE: usize = 16 + 1 + 4 + 4;
}

/// Serialize a DTN relay payload.
/// Layout: type(1=0x40) + message_id(16) + copies_remaining(1) + ttl_secs(4)
///       + payload_len(4) + payload
pub fn serialize_dtn_relay(relay: &DtnRelayPayload) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + DtnRelayPayload::HEADER_SIZE + relay.payload.len());
    buf.push(WirePayloadType::DtnRelay as u8);
    buf.extend_from_slice(relay.message_id.as_bytes());
    buf.push(relay.copies_remaining);
    buf.extend_from_slice(&relay.ttl_secs.to_le_bytes());
    buf.extend_from_slice(&(relay.payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(&relay.payload);
    buf
}

/// Deserialize DTN relay body (after type byte).
pub fn deserialize_dtn_relay(data: &[u8]) -> Result<DtnRelayPayload, CodecError> {
    const H: usize = DtnRelayPayload::HEADER_SIZE;
    if data.len() < H {
        return Err(CodecError::BufferTooShort {
            expected: H,
            actual: data.len(),
        });
    }
    let mut msg_id = [0u8; 16];
    msg_id.copy_from_slice(&data[0..16]);
    let copies_remaining = data[16];
    let ttl_secs = u32::from_le_bytes(data[17..21].try_into().unwrap());
    let payload_len = u32::from_le_bytes(data[21..25].try_into().unwrap()) as usize;
    if data.len() - H < payload_len {
        return Err(CodecError::PayloadLengthMismatch {
            header: payload_len,
            actual: data.len() - H,
        });
    }
    let payload = data[H..H + payload_len].to_vec();
    Ok(DtnRelayPayload {
        message_id: MessageId::from_bytes(msg_id),
        copies_remaining,
        ttl_secs,
        payload,
    })
}

// --- Group message serialization ---

/// Serialize a group message payload.
/// Layout: type(1=0x70) + group_id(32) + iteration(4) + content_type(1) + ciphertext
pub fn serialize_group_message(
    group_id: &[u8; 32],
    iteration: u32,
    content_type: u8,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 32 + 4 + 1 + ciphertext.len());
    buf.push(WirePayloadType::GroupMessage as u8);
    buf.extend_from_slice(group_id);
    buf.extend_from_slice(&iteration.to_le_bytes());
    buf.push(content_type);
    buf.extend_from_slice(ciphertext);
    buf
}

/// Deserialize group message body (after type byte).
/// Returns: (group_id, iteration, content_type, ciphertext)
pub fn deserialize_group_message(data: &[u8]) -> Result<([u8; 32], u32, u8, Vec<u8>), CodecError> {
    if data.len() < 37 {
        return Err(CodecError::BufferTooShort {
            expected: 37,
            actual: data.len(),
        });
    }
    let mut group_id = [0u8; 32];
    group_id.copy_from_slice(&data[0..32]);
    let iteration = u32::from_le_bytes(data[32..36].try_into().unwrap());
    let content_type = data[36];
    let ciphertext = data[37..].to_vec();
    Ok((group_id, iteration, content_type, ciphertext))
}

/// A member's sender key plus the sender's view of the group roster.
///
/// Carried only as the plaintext of a pairwise `EncryptedMessage` (content
/// type System); a top-level 0x71 envelope is ignored because it would be
/// unauthenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderKeyDistributionPayload {
    pub group_id: [u8; 32],
    pub chain_key: [u8; 32],
    pub iteration: u32,
    /// Group members as known by the sender (may include the recipient).
    /// Rosters only ever add members on the receiving side.
    pub members: Vec<NodeId>,
    /// Members the sender has removed from the group (explicit, because a
    /// stale roster must never be mistaken for a removal).
    pub removed: Vec<NodeId>,
}

/// Maximum members carried in one distribution (spec targets groups < 20).
pub const MAX_DISTRIBUTION_MEMBERS: usize = 255;

/// Serialize a sender key distribution.
/// Layout: type(1=0x71) + group_id(32) + chain_key(32) + iteration(4)
///       + member_count(1) + members(32 each) + removed_count(1) + removed(32 each)
pub fn serialize_sender_key_distribution(payload: &SenderKeyDistributionPayload) -> Vec<u8> {
    let count = payload.members.len().min(MAX_DISTRIBUTION_MEMBERS);
    let removed = payload.removed.len().min(MAX_DISTRIBUTION_MEMBERS);
    let mut buf = Vec::with_capacity(71 + (count + removed) * 32);
    buf.push(WirePayloadType::SenderKeyDistribution as u8);
    buf.extend_from_slice(&payload.group_id);
    buf.extend_from_slice(&payload.chain_key);
    buf.extend_from_slice(&payload.iteration.to_le_bytes());
    buf.push(count as u8);
    for member in payload.members.iter().take(count) {
        buf.extend_from_slice(member.as_bytes());
    }
    buf.push(removed as u8);
    for member in payload.removed.iter().take(removed) {
        buf.extend_from_slice(member.as_bytes());
    }
    buf
}

/// Parse `count(1) + count * NodeId(32)` at `offset`; returns the ids and
/// the offset just past them. Absent section (offset == len) is empty.
fn parse_node_list(data: &[u8], offset: usize) -> Result<(Vec<NodeId>, usize), CodecError> {
    if offset >= data.len() {
        return Ok((Vec::new(), offset));
    }
    let count = data[offset] as usize;
    let start = offset + 1;
    if (data.len() - start) / 32 < count {
        return Err(CodecError::BufferTooShort {
            expected: start + count * 32,
            actual: data.len(),
        });
    }
    let mut ids = Vec::with_capacity(count);
    for i in 0..count {
        let at = start + i * 32;
        let mut id = [0u8; 32];
        id.copy_from_slice(&data[at..at + 32]);
        ids.push(NodeId::from_bytes(id));
    }
    Ok((ids, start + count * 32))
}

/// Deserialize a sender key distribution body (after type byte). A body
/// without the member section (68 bytes) is accepted with an empty roster.
pub fn deserialize_sender_key_distribution(
    data: &[u8],
) -> Result<SenderKeyDistributionPayload, CodecError> {
    if data.len() < 68 {
        return Err(CodecError::BufferTooShort {
            expected: 68,
            actual: data.len(),
        });
    }
    let mut group_id = [0u8; 32];
    group_id.copy_from_slice(&data[0..32]);
    let mut chain_key = [0u8; 32];
    chain_key.copy_from_slice(&data[32..64]);
    let iteration = u32::from_le_bytes(data[64..68].try_into().unwrap());

    let (members, offset) = parse_node_list(data, 68)?;
    let (removed, _) = parse_node_list(data, offset)?;

    Ok(SenderKeyDistributionPayload {
        group_id,
        chain_key,
        iteration,
        members,
        removed,
    })
}

/// Receipt type for delivery/read receipts.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptType {
    Delivered = 0,
    Read = 1,
}

impl ReceiptType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Delivered),
            1 => Some(Self::Read),
            _ => None,
        }
    }
}

/// Serialize a receipt payload.
/// Layout: type(1=0x60) + message_id(16) + receipt_type(1)
pub fn serialize_receipt(message_id: &MessageId, receipt_type: ReceiptType) -> Vec<u8> {
    let mut buf = Vec::with_capacity(18);
    buf.push(WirePayloadType::Receipt as u8);
    buf.extend_from_slice(message_id.as_bytes());
    buf.push(receipt_type as u8);
    buf
}

/// Deserialize receipt body (after type byte).
pub fn deserialize_receipt(data: &[u8]) -> Result<(MessageId, ReceiptType), CodecError> {
    if data.len() < 17 {
        return Err(CodecError::BufferTooShort {
            expected: 17,
            actual: data.len(),
        });
    }
    let mut msg_id = [0u8; 16];
    msg_id.copy_from_slice(&data[0..16]);
    let receipt_type = ReceiptType::from_byte(data[16]).ok_or(CodecError::BufferTooShort {
        expected: 1,
        actual: 0,
    })?;
    Ok((MessageId::from_bytes(msg_id), receipt_type))
}

// --- Channel message serialization ---

/// Serialize a channel message payload.
/// Layout: type(1=0x80) + channel_id(32) + content_type(1) + data
pub fn serialize_channel_message(channel_id: &[u8; 32], content_type: u8, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 32 + 1 + data.len());
    buf.push(WirePayloadType::ChannelMessage as u8);
    buf.extend_from_slice(channel_id);
    buf.push(content_type);
    buf.extend_from_slice(data);
    buf
}

/// Deserialize channel message body (after type byte).
/// Returns: (channel_id, content_type, data)
pub fn deserialize_channel_message(data: &[u8]) -> Result<([u8; 32], u8, Vec<u8>), CodecError> {
    if data.len() < 33 {
        return Err(CodecError::BufferTooShort {
            expected: 33,
            actual: data.len(),
        });
    }
    let mut channel_id = [0u8; 32];
    channel_id.copy_from_slice(&data[0..32]);
    let content_type = data[32];
    let payload = data[33..].to_vec();
    Ok((channel_id, content_type, payload))
}

/// Serialize a channel subscribe payload.
/// Layout: type(1=0x81) + channel_id(32)
pub fn serialize_channel_subscribe(channel_id: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(33);
    buf.push(WirePayloadType::ChannelSubscribe as u8);
    buf.extend_from_slice(channel_id);
    buf
}

/// Deserialize channel subscribe body (after type byte).
/// Returns: channel_id
pub fn deserialize_channel_subscribe(data: &[u8]) -> Result<[u8; 32], CodecError> {
    if data.len() < 32 {
        return Err(CodecError::BufferTooShort {
            expected: 32,
            actual: data.len(),
        });
    }
    let mut channel_id = [0u8; 32];
    channel_id.copy_from_slice(&data[0..32]);
    Ok(channel_id)
}

/// Serialize a channel unsubscribe payload.
/// Layout: type(1=0x82) + channel_id(32)
pub fn serialize_channel_unsubscribe(channel_id: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(33);
    buf.push(WirePayloadType::ChannelUnsubscribe as u8);
    buf.extend_from_slice(channel_id);
    buf
}

/// Deserialize channel unsubscribe body (after type byte).
/// Returns: channel_id
pub fn deserialize_channel_unsubscribe(data: &[u8]) -> Result<[u8; 32], CodecError> {
    deserialize_channel_subscribe(data) // Same format
}

/// Moderation action for channels.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModerationAction {
    RemoveMessage = 0,
    BanUser = 1,
}

impl ModerationAction {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::RemoveMessage),
            1 => Some(Self::BanUser),
            _ => None,
        }
    }
}

/// Serialize a channel moderation payload.
/// Layout: type(1=0x83) + channel_id(32) + action(1) + target_id(32) + signature(64)
pub fn serialize_channel_moderation(
    channel_id: &[u8; 32],
    action: ModerationAction,
    target_id: &[u8; 32],
    signature: &[u8; 64],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(130);
    buf.push(WirePayloadType::ChannelModeration as u8);
    buf.extend_from_slice(channel_id);
    buf.push(action as u8);
    buf.extend_from_slice(target_id);
    buf.extend_from_slice(signature);
    buf
}

/// Deserialize channel moderation body (after type byte).
/// Returns: (channel_id, action, target_id, signature)
#[allow(clippy::type_complexity)]
pub fn deserialize_channel_moderation(
    data: &[u8],
) -> Result<([u8; 32], ModerationAction, [u8; 32], [u8; 64]), CodecError> {
    if data.len() < 129 {
        return Err(CodecError::BufferTooShort {
            expected: 129,
            actual: data.len(),
        });
    }
    let mut channel_id = [0u8; 32];
    channel_id.copy_from_slice(&data[0..32]);
    let action = ModerationAction::from_byte(data[32]).ok_or(CodecError::BufferTooShort {
        expected: 1,
        actual: 0,
    })?;
    let mut target_id = [0u8; 32];
    target_id.copy_from_slice(&data[33..65]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[65..129]);
    Ok((channel_id, action, target_id, signature))
}

// --- Emergency broadcast serialization ---

/// Emergency level for tiered broadcast.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyLevel {
    /// Boosted priority in relay queues. Requires trust > 0.3.
    Priority = 1,
    /// Bypasses per-identity rate limits. Requires trust > 0.6.
    Urgent = 2,
    /// Floods entire mesh. Requires 3+ cosigners with trust > 0.8.
    Critical = 3,
}

impl EmergencyLevel {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Priority),
            2 => Some(Self::Urgent),
            3 => Some(Self::Critical),
            _ => None,
        }
    }
}

/// A level-3 co-signer: who approved, and their signature over the broadcast.
///
/// A bare NodeId proves nothing — anyone can list three trusted ids they do
/// not control. The signature is over
/// `mycelium_crypto::emergency::broadcast_digest` and is
/// verified against the co-signer's stored identity key (ROADMAP T-05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyCosigner {
    pub node_id: NodeId,
    pub signature: [u8; 64],
}

/// A parsed emergency broadcast body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyBroadcastPayload {
    pub level: EmergencyLevel,
    /// Unix seconds at which the originator raised this alert.
    ///
    /// Covered by every co-signature, and bounded on receipt against the
    /// local clock, so a captured alert cannot be replayed indefinitely
    /// (ADR-013). It is the originator's claim, not a relay's: nothing in the
    /// envelope is authenticated.
    pub signed_at: u64,
    pub message: Vec<u8>,
    pub cosigners: Vec<EmergencyCosigner>,
}

/// Smallest valid emergency body (after the type byte):
/// `level(1) + signed_at(8) + msg_len(4) + cosigner_count(1)`.
pub const EMERGENCY_BODY_MIN_LEN: usize = 1 + 8 + 4 + 1;

/// Size of one serialized co-signer entry.
pub const COSIGNER_ENTRY_LEN: usize = 32 + 64;

/// Co-signer entries one broadcast can carry: the count is a single byte.
/// Three are required (ADR-010), so this is a ceiling, not a target.
pub const MAX_EMERGENCY_COSIGNERS: usize = u8::MAX as usize;

/// Domain separator for the digest that identifies an emergency broadcast:
/// what a level-3 co-signer signs, and what a receiver keys flood dedup on
/// (ADR-013). The digest itself is built by
/// `mycelium_crypto::emergency::broadcast_digest`; this crate carries wire
/// bytes and deliberately pulls in no hashing.
///
/// `v2` because the digest gained `signed_at`: a v1 signature must not be
/// readable as a v2 one.
pub const EMERGENCY_BROADCAST_CONTEXT: &[u8] = b"mycelium-emergency-broadcast-v2:";

/// Domain separation for the signature on a `SessionReject` (ROADMAP T-35).
pub const SESSION_REJECT_CONTEXT: &[u8] = b"mycelium-session-reject-v1:";

/// Domain separation for a `SessionInit`'s transcript hash, which is what a
/// `SessionReject` is bound to (ROADMAP T-35).
pub const SESSION_INIT_TRANSCRIPT_CONTEXT: &[u8] = b"mycelium-session-init-transcript-v1:";

/// Serialize an emergency broadcast payload.
/// Layout: type(1=0x90) + level(1) + signed_at(8 LE) + msg_len(4 LE)
///       + message + cosigner_count(1)
///       + cosigners(N * (node_id(32) + signature(64)))
pub fn serialize_emergency_broadcast(
    level: EmergencyLevel,
    signed_at: u64,
    message: &[u8],
    cosigners: &[EmergencyCosigner],
) -> Vec<u8> {
    // Note: the co-signatures cover the envelope's `message_id` as the
    // broadcast id (see `mycelium_crypto::emergency`), which is why the id is
    // not repeated in the body.

    // The count is one byte. Writing more entries than it can express would
    // produce a body this crate's own parser refuses, so the list is cut to
    // what the format holds.
    let cosigners = &cosigners[..cosigners.len().min(MAX_EMERGENCY_COSIGNERS)];

    let mut buf = Vec::with_capacity(
        1 + EMERGENCY_BODY_MIN_LEN + message.len() + cosigners.len() * COSIGNER_ENTRY_LEN,
    );
    buf.push(WirePayloadType::EmergencyBroadcast as u8);
    buf.push(level as u8);
    buf.extend_from_slice(&signed_at.to_le_bytes());
    buf.extend_from_slice(&(message.len() as u32).to_le_bytes());
    buf.extend_from_slice(message);
    buf.push(cosigners.len() as u8);
    for cosigner in cosigners {
        buf.extend_from_slice(cosigner.node_id.as_bytes());
        buf.extend_from_slice(&cosigner.signature);
    }
    buf
}

/// Deserialize an emergency broadcast body (after the type byte).
///
/// The length must match exactly. A body that parses with bytes left over
/// gives one broadcast two encodings, which is the shape of defect the
/// handshake payloads were hardened against in ADR-012; here it would also
/// give it two flood-dedup keys.
pub fn deserialize_emergency_broadcast(
    data: &[u8],
) -> Result<EmergencyBroadcastPayload, CodecError> {
    if data.len() < EMERGENCY_BODY_MIN_LEN {
        return Err(CodecError::BufferTooShort {
            expected: EMERGENCY_BODY_MIN_LEN,
            actual: data.len(),
        });
    }
    let level = EmergencyLevel::from_byte(data[0])
        .ok_or(CodecError::InvalidDiscriminant { value: data[0] })?;
    let signed_at = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let msg_len = u32::from_le_bytes(data[9..13].try_into().unwrap()) as usize;
    // Need msg_len bytes of message plus one cosigner-count byte after offset 13.
    if data.len() - 13 <= msg_len {
        return Err(CodecError::BufferTooShort {
            expected: msg_len.saturating_add(EMERGENCY_BODY_MIN_LEN),
            actual: data.len(),
        });
    }
    let message = data[13..13 + msg_len].to_vec();
    let cosigner_count = data[13 + msg_len] as usize;
    let cosigners_start = 13 + msg_len + 1;
    let expected_len = cosigners_start.saturating_add(cosigner_count * COSIGNER_ENTRY_LEN);
    if data.len() != expected_len {
        return Err(CodecError::BufferTooShort {
            expected: expected_len,
            actual: data.len(),
        });
    }
    let mut cosigners = Vec::with_capacity(cosigner_count);
    for i in 0..cosigner_count {
        let offset = cosigners_start + i * COSIGNER_ENTRY_LEN;
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&data[offset..offset + 32]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[offset + 32..offset + COSIGNER_ENTRY_LEN]);
        cosigners.push(EmergencyCosigner {
            node_id: NodeId::from_bytes(node_id),
            signature,
        });
    }
    Ok(EmergencyBroadcastPayload {
        level,
        signed_at,
        message,
        cosigners,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_header_roundtrip() {
        let header = WireRatchetHeader {
            dh_public: [42u8; 32],
            previous_chain_length: 5,
            message_number: 12,
        };
        let mut buf = Vec::new();
        header.serialize(&mut buf);
        assert_eq!(buf.len(), WireRatchetHeader::SIZE);
        let decoded = WireRatchetHeader::deserialize(&buf).unwrap();
        assert_eq!(decoded.dh_public, header.dh_public);
        assert_eq!(decoded.previous_chain_length, 5);
        assert_eq!(decoded.message_number, 12);
    }

    #[test]
    fn test_encrypted_payload_roundtrip() {
        let payload = EncryptedPayload {
            content_type: 0,
            header: WireRatchetHeader {
                dh_public: [1u8; 32],
                previous_chain_length: 0,
                message_number: 0,
            },
            ciphertext: b"encrypted data here".to_vec(),
        };
        let bytes = payload.serialize();
        assert_eq!(bytes[0], WirePayloadType::EncryptedMessage as u8);
        let decoded = EncryptedPayload::deserialize_body(&bytes[1..]).unwrap();
        assert_eq!(decoded.content_type, 0);
        assert_eq!(decoded.ciphertext, b"encrypted data here");
    }

    #[test]
    fn test_session_init_roundtrip() {
        let init = SessionInitPayload {
            ephemeral_public: [2u8; 32],
            identity_key: [3u8; 32],
            signed_prekey_id: 7,
            one_time_prekey_id: Some(42),
            encrypted_payload: b"first message encrypted".to_vec(),
        };
        let bytes = init.serialize();
        assert_eq!(bytes[0], WirePayloadType::SessionInit as u8);
        let decoded = SessionInitPayload::deserialize_body(&bytes[1..]).unwrap();
        assert_eq!(decoded.ephemeral_public, [2u8; 32]);
        assert_eq!(decoded.identity_key, [3u8; 32]);
        assert_eq!(decoded.signed_prekey_id, 7);
        assert_eq!(decoded.one_time_prekey_id, Some(42));
        assert_eq!(decoded.encrypted_payload, b"first message encrypted");
    }

    #[test]
    fn test_session_init_no_otp_roundtrip() {
        let init = SessionInitPayload {
            ephemeral_public: [2u8; 32],
            identity_key: [3u8; 32],
            signed_prekey_id: 1,
            one_time_prekey_id: None,
            encrypted_payload: b"msg".to_vec(),
        };
        let bytes = init.serialize();
        let decoded = SessionInitPayload::deserialize_body(&bytes[1..]).unwrap();
        assert_eq!(decoded.one_time_prekey_id, None);
        assert_eq!(decoded.encrypted_payload, b"msg");
    }

    #[test]
    fn test_prekey_bundle_roundtrip() {
        let bundle = PrekeyBundlePayload {
            identity_key: [4u8; 32],
            signed_prekey: [5u8; 32],
            signed_prekey_signature: vec![6u8; 64],
            signed_prekey_id: 1,
            one_time_prekey: Some([7u8; 32]),
            one_time_prekey_id: Some(99),
        };
        let bytes = bundle.serialize();
        assert_eq!(bytes[0], WirePayloadType::PrekeyResponse as u8);
        let decoded = PrekeyBundlePayload::deserialize_body(&bytes[1..]).unwrap();
        assert_eq!(decoded.identity_key, [4u8; 32]);
        assert_eq!(decoded.signed_prekey, [5u8; 32]);
        assert_eq!(decoded.signed_prekey_signature.len(), 64);
        assert_eq!(decoded.signed_prekey_id, 1);
        assert_eq!(decoded.one_time_prekey, Some([7u8; 32]));
        assert_eq!(decoded.one_time_prekey_id, Some(99));
    }

    #[test]
    fn test_aodv_rreq_roundtrip() {
        let src = NodeId([10u8; 32]);
        let dst = NodeId([20u8; 32]);
        let bytes = serialize_aodv_rreq(42, &src, 5, &dst, 3, 2, 10);
        assert_eq!(bytes[0], WirePayloadType::AodvRreq as u8);
        let (rid, s, ss, d, ds, hc, ttl) = deserialize_aodv_rreq(&bytes[1..]).unwrap();
        assert_eq!(rid, 42);
        assert_eq!(s, src);
        assert_eq!(ss, 5);
        assert_eq!(d, dst);
        assert_eq!(ds, 3);
        assert_eq!(hc, 2);
        assert_eq!(ttl, 10);
    }

    #[test]
    fn test_aodv_rrep_roundtrip() {
        let src = NodeId([10u8; 32]);
        let dst = NodeId([20u8; 32]);
        let bytes = serialize_aodv_rrep(42, &src, &dst, 3, 2, 30);
        assert_eq!(bytes[0], WirePayloadType::AodvRrep as u8);
        let (rid, s, d, ds, hc, lt) = deserialize_aodv_rrep(&bytes[1..]).unwrap();
        assert_eq!(rid, 42);
        assert_eq!(s, src);
        assert_eq!(d, dst);
        assert_eq!(ds, 3);
        assert_eq!(hc, 2);
        assert_eq!(lt, 30);
    }

    #[test]
    fn test_aodv_rerr_roundtrip() {
        let unr = NodeId([30u8; 32]);
        let src = NodeId([40u8; 32]);
        let bytes = serialize_aodv_rerr(&unr, &src, 7);
        assert_eq!(bytes[0], WirePayloadType::AodvRerr as u8);
        let (u, s, ds) = deserialize_aodv_rerr(&bytes[1..]).unwrap();
        assert_eq!(u, unr);
        assert_eq!(s, src);
        assert_eq!(ds, 7);
    }

    #[test]
    fn test_dtn_relay_roundtrip() {
        let relay = DtnRelayPayload {
            message_id: MessageId::from_bytes([99u8; 16]),
            copies_remaining: 4,
            ttl_secs: 3600,
            payload: b"dtn bundle data".to_vec(),
        };
        let bytes = serialize_dtn_relay(&relay);
        assert_eq!(bytes[0], WirePayloadType::DtnRelay as u8);
        assert_eq!(
            bytes.len(),
            1 + DtnRelayPayload::HEADER_SIZE + relay.payload.len()
        );
        let decoded = deserialize_dtn_relay(&bytes[1..]).unwrap();
        assert_eq!(decoded, relay);

        // Truncated body and inconsistent length prefix are rejected.
        assert!(deserialize_dtn_relay(&bytes[1..DtnRelayPayload::HEADER_SIZE]).is_err());
        let mut bad = bytes[1..].to_vec();
        bad[21..25].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(deserialize_dtn_relay(&bad).is_err());
    }

    #[test]
    fn test_receipt_roundtrip() {
        let msg_id = MessageId::from_bytes([42u8; 16]);
        let bytes = serialize_receipt(&msg_id, ReceiptType::Delivered);
        assert_eq!(bytes[0], WirePayloadType::Receipt as u8);
        let (decoded_id, decoded_type) = deserialize_receipt(&bytes[1..]).unwrap();
        assert_eq!(*decoded_id.as_bytes(), [42u8; 16]);
        assert_eq!(decoded_type, ReceiptType::Delivered);

        let bytes_read = serialize_receipt(&msg_id, ReceiptType::Read);
        let (_, rt) = deserialize_receipt(&bytes_read[1..]).unwrap();
        assert_eq!(rt, ReceiptType::Read);
    }

    #[test]
    fn test_group_message_roundtrip() {
        let group_id = [0xAA; 32];
        let ciphertext = b"encrypted group data";
        let bytes = serialize_group_message(&group_id, 42, 0, ciphertext);
        assert_eq!(bytes[0], WirePayloadType::GroupMessage as u8);
        let (gid, iter, ct, ct_data) = deserialize_group_message(&bytes[1..]).unwrap();
        assert_eq!(gid, group_id);
        assert_eq!(iter, 42);
        assert_eq!(ct, 0);
        assert_eq!(ct_data, ciphertext);
    }

    #[test]
    fn test_sender_key_distribution_roundtrip() {
        let payload = SenderKeyDistributionPayload {
            group_id: [0xBB; 32],
            chain_key: [0xCC; 32],
            iteration: 7,
            members: vec![NodeId([1u8; 32]), NodeId([2u8; 32])],
            removed: vec![NodeId([3u8; 32])],
        };
        let bytes = serialize_sender_key_distribution(&payload);
        assert_eq!(bytes[0], WirePayloadType::SenderKeyDistribution as u8);
        assert_eq!(bytes.len(), 1 + 68 + 1 + 64 + 1 + 32);
        let decoded = deserialize_sender_key_distribution(&bytes[1..]).unwrap();
        assert_eq!(decoded, payload);

        // Members without a removed section → empty removals
        let no_removed = deserialize_sender_key_distribution(&bytes[1..1 + 68 + 1 + 64]).unwrap();
        assert_eq!(no_removed.members, payload.members);
        assert!(no_removed.removed.is_empty());

        // Legacy body without roster is accepted with no members
        let legacy = deserialize_sender_key_distribution(&bytes[1..69]).unwrap();
        assert!(legacy.members.is_empty());
        assert_eq!(legacy.iteration, 7);

        // Roster count larger than the data is rejected
        let mut bad = bytes[1..].to_vec();
        bad[68] = 9;
        assert!(deserialize_sender_key_distribution(&bad).is_err());
    }

    #[test]
    fn test_wire_payload_type_from_byte() {
        assert_eq!(
            WirePayloadType::from_byte(0x10),
            Some(WirePayloadType::EncryptedMessage)
        );
        assert_eq!(
            WirePayloadType::from_byte(0x40),
            Some(WirePayloadType::DtnRelay)
        );
        assert_eq!(
            WirePayloadType::from_byte(0x50),
            Some(WirePayloadType::Beacon)
        );
        assert_eq!(
            WirePayloadType::from_byte(0x60),
            Some(WirePayloadType::Receipt)
        );
        assert_eq!(
            WirePayloadType::from_byte(0x70),
            Some(WirePayloadType::GroupMessage)
        );
        assert_eq!(
            WirePayloadType::from_byte(0x71),
            Some(WirePayloadType::SenderKeyDistribution)
        );
        assert_eq!(
            WirePayloadType::from_byte(0x80),
            Some(WirePayloadType::ChannelMessage)
        );
        assert_eq!(
            WirePayloadType::from_byte(0x81),
            Some(WirePayloadType::ChannelSubscribe)
        );
        assert_eq!(
            WirePayloadType::from_byte(0x82),
            Some(WirePayloadType::ChannelUnsubscribe)
        );
        assert_eq!(
            WirePayloadType::from_byte(0x83),
            Some(WirePayloadType::ChannelModeration)
        );
        assert_eq!(
            WirePayloadType::from_byte(0x90),
            Some(WirePayloadType::EmergencyBroadcast)
        );
        assert_eq!(WirePayloadType::from_byte(0xFF), None);
    }

    #[test]
    fn test_channel_message_roundtrip() {
        let channel_id = [0xDD; 32];
        let data = b"hello channel";
        let bytes = serialize_channel_message(&channel_id, 0, data);
        assert_eq!(bytes[0], WirePayloadType::ChannelMessage as u8);
        let (cid, ct, payload) = deserialize_channel_message(&bytes[1..]).unwrap();
        assert_eq!(cid, channel_id);
        assert_eq!(ct, 0);
        assert_eq!(payload, data);
    }

    #[test]
    fn test_channel_subscribe_roundtrip() {
        let channel_id = [0xEE; 32];
        let bytes = serialize_channel_subscribe(&channel_id);
        assert_eq!(bytes[0], WirePayloadType::ChannelSubscribe as u8);
        let cid = deserialize_channel_subscribe(&bytes[1..]).unwrap();
        assert_eq!(cid, channel_id);
    }

    #[test]
    fn test_channel_unsubscribe_roundtrip() {
        let channel_id = [0xFF; 32];
        let bytes = serialize_channel_unsubscribe(&channel_id);
        assert_eq!(bytes[0], WirePayloadType::ChannelUnsubscribe as u8);
        let cid = deserialize_channel_unsubscribe(&bytes[1..]).unwrap();
        assert_eq!(cid, channel_id);
    }

    #[test]
    fn test_emergency_broadcast_roundtrip() {
        let message = b"Emergency: building collapse at sector 7";
        let cosigners: Vec<EmergencyCosigner> = (1u8..=3)
            .map(|i| EmergencyCosigner {
                node_id: NodeId([i * 0x11; 32]),
                signature: [i; 64],
            })
            .collect();
        let bytes = serialize_emergency_broadcast(
            EmergencyLevel::Critical,
            1_762_000_000,
            message,
            &cosigners,
        );
        assert_eq!(bytes[0], WirePayloadType::EmergencyBroadcast as u8);
        let parsed = deserialize_emergency_broadcast(&bytes[1..]).unwrap();
        assert_eq!(parsed.level, EmergencyLevel::Critical);
        assert_eq!(parsed.signed_at, 1_762_000_000);
        assert_eq!(parsed.message, message);
        assert_eq!(
            parsed.cosigners, cosigners,
            "co-signer ids and signatures must round trip"
        );

        // A truncated signature must be refused, not silently zero-padded.
        let truncated = &bytes[1..bytes.len() - 1];
        assert!(matches!(
            deserialize_emergency_broadcast(truncated),
            Err(CodecError::BufferTooShort { .. })
        ));
    }

    /// A body with bytes left over must be refused: a broadcast that has two
    /// encodings has two flood-dedup keys, and only one of them is the one
    /// the receiver remembered (ADR-013).
    #[test]
    fn test_emergency_broadcast_refuses_trailing_bytes() {
        let bytes =
            serialize_emergency_broadcast(EmergencyLevel::Urgent, 1_762_000_000, b"go", &[]);
        let mut padded = bytes[1..].to_vec();
        padded.push(0);
        assert!(
            matches!(
                deserialize_emergency_broadcast(&padded),
                Err(CodecError::BufferTooShort { .. })
            ),
            "a padded body must not parse"
        );
    }

    /// The count byte cannot express more than 255 entries, and a body whose
    /// count disagrees with its entries is one this parser refuses — so the
    /// serializer must not produce one.
    #[test]
    fn test_emergency_broadcast_caps_the_cosigner_list() {
        let many: Vec<EmergencyCosigner> = (0..300)
            .map(|i| EmergencyCosigner {
                node_id: NodeId([(i % 251) as u8; 32]),
                signature: [1u8; 64],
            })
            .collect();
        let bytes = serialize_emergency_broadcast(EmergencyLevel::Critical, 1, b"x", &many);
        let parsed = deserialize_emergency_broadcast(&bytes[1..])
            .expect("the serializer must not produce a body its own parser refuses");
        assert_eq!(parsed.cosigners.len(), MAX_EMERGENCY_COSIGNERS);
        assert_eq!(parsed.cosigners[..], many[..MAX_EMERGENCY_COSIGNERS]);
    }

    #[test]
    fn test_emergency_broadcast_refuses_an_unknown_level() {
        let mut bytes =
            serialize_emergency_broadcast(EmergencyLevel::Urgent, 1, b"go", &[])[1..].to_vec();
        bytes[0] = 4;
        assert!(matches!(
            deserialize_emergency_broadcast(&bytes),
            Err(CodecError::InvalidDiscriminant { value: 4 })
        ));
    }

    #[test]
    fn test_emergency_broadcast_no_cosigners() {
        let message = b"Priority relay boost";
        let bytes = serialize_emergency_broadcast(EmergencyLevel::Priority, 7, message, &[]);
        let parsed = deserialize_emergency_broadcast(&bytes[1..]).unwrap();
        assert_eq!(parsed.level, EmergencyLevel::Priority);
        assert_eq!(parsed.signed_at, 7);
        assert_eq!(parsed.message, message);
        assert!(parsed.cosigners.is_empty());
    }

    #[test]
    fn test_channel_moderation_roundtrip() {
        let channel_id = [0xAA; 32];
        let target_id = [0xBB; 32];
        let signature = [0xCC; 64];
        let bytes = serialize_channel_moderation(
            &channel_id,
            ModerationAction::BanUser,
            &target_id,
            &signature,
        );
        assert_eq!(bytes[0], WirePayloadType::ChannelModeration as u8);
        let (cid, action, tid, sig) = deserialize_channel_moderation(&bytes[1..]).unwrap();
        assert_eq!(cid, channel_id);
        assert_eq!(action, ModerationAction::BanUser);
        assert_eq!(tid, target_id);
        assert_eq!(sig, signature);
    }
    /// Trailing bytes are refused, because the payload's hash is the identity
    /// a `SessionReject` is bound to (T-35, ADR-012).
    ///
    /// A parse that ignored them let a padded copy of a `SessionInit` be
    /// accepted under a different hash, which left the original free to be
    /// replayed past the receiver's replay check.
    #[test]
    fn test_handshake_payloads_refuse_trailing_bytes() {
        let enc = EncryptedPayload {
            content_type: 0,
            header: WireRatchetHeader {
                dh_public: [1u8; 32],
                previous_chain_length: 0,
                message_number: 0,
            },
            ciphertext: vec![9u8; 24],
        };
        let enc_bytes = enc.serialize();
        assert!(EncryptedPayload::deserialize_body(&enc_bytes[1..]).is_ok());
        let mut padded = enc_bytes[1..].to_vec();
        padded.push(0);
        assert!(matches!(
            EncryptedPayload::deserialize_body(&padded),
            Err(CodecError::PayloadLengthMismatch { .. })
        ));

        let init = SessionInitPayload {
            ephemeral_public: [2u8; 32],
            identity_key: [3u8; 32],
            signed_prekey_id: 7,
            one_time_prekey_id: Some(4),
            encrypted_payload: enc_bytes.clone(),
        };
        let init_bytes = init.serialize();
        assert!(SessionInitPayload::deserialize_body(&init_bytes[1..]).is_ok());
        let mut padded = init_bytes[1..].to_vec();
        padded.push(0);
        assert!(matches!(
            SessionInitPayload::deserialize_body(&padded),
            Err(CodecError::PayloadLengthMismatch { .. })
        ));
    }

    /// Every payload type needs a roundtrip test (CLAUDE.md testing rules).
    #[test]
    fn test_session_reject_roundtrip() {
        let identity_key = [7u8; 32];
        let rejected = [9u8; 32];
        let signature = [3u8; 64];
        for reason in [
            SessionRejectReason::StaleSignedPrekey,
            SessionRejectReason::UnknownOneTimePrekey,
            SessionRejectReason::DecryptFailed,
        ] {
            let bytes = serialize_session_reject(reason, &identity_key, &rejected, &signature);
            assert_eq!(bytes[0], WirePayloadType::SessionReject as u8);
            assert_eq!(bytes.len(), 1 + SESSION_REJECT_BODY_LEN);

            let (got_reason, got_key, got_transcript, got_sig) =
                deserialize_session_reject(&bytes[1..]).unwrap();
            assert_eq!(got_reason, reason);
            assert_eq!(got_key, identity_key);
            assert_eq!(got_transcript, rejected);
            assert_eq!(got_sig, signature);
        }
    }

    #[test]
    fn test_session_reject_rejects_short_and_unknown() {
        assert!(matches!(
            deserialize_session_reject(&[1u8; SESSION_REJECT_BODY_LEN - 1]),
            Err(CodecError::BufferTooShort { .. })
        ));
        let mut body = vec![0u8; SESSION_REJECT_BODY_LEN];
        body[0] = 99; // not a known reason
        assert!(matches!(
            deserialize_session_reject(&body),
            Err(CodecError::InvalidDiscriminant { value: 99 })
        ));
    }
}
