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
    AodvRreq = 0x30,
    AodvRrep = 0x31,
    AodvRerr = 0x32,
    DtnRelay = 0x40,
    Beacon = 0x50,
    Receipt = 0x60,
    GroupMessage = 0x70,
    SenderKeyDistribution = 0x71,
}

impl WirePayloadType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x10 => Some(Self::EncryptedMessage),
            0x11 => Some(Self::SessionInit),
            0x20 => Some(Self::PrekeyRequest),
            0x21 => Some(Self::PrekeyResponse),
            0x30 => Some(Self::AodvRreq),
            0x31 => Some(Self::AodvRrep),
            0x32 => Some(Self::AodvRerr),
            0x40 => Some(Self::DtnRelay),
            0x50 => Some(Self::Beacon),
            0x60 => Some(Self::Receipt),
            0x70 => Some(Self::GroupMessage),
            0x71 => Some(Self::SenderKeyDistribution),
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
        let mut buf = Vec::with_capacity(1 + 1 + WireRatchetHeader::SIZE + 4 + self.ciphertext.len());
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
        if data.len() < 45 + ct_len {
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
        let otp_size = if self.one_time_prekey_id.is_some() { 5 } else { 1 };
        let mut buf = Vec::with_capacity(1 + 32 + 32 + 4 + otp_size + 4 + self.encrypted_payload.len());
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

        if data.len() < offset + payload_len {
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
pub fn serialize_aodv_rerr(
    unreachable: &NodeId,
    source: &NodeId,
    dest_seq: u32,
) -> Vec<u8> {
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

/// Serialize a DTN relay payload.
/// Layout: type(1=0x40) + message_id(16) + payload_len(4) + payload
pub fn serialize_dtn_relay(message_id: &MessageId, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 16 + 4 + payload.len());
    buf.push(WirePayloadType::DtnRelay as u8);
    buf.extend_from_slice(message_id.as_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Deserialize DTN relay body (after type byte).
pub fn deserialize_dtn_relay(data: &[u8]) -> Result<(MessageId, Vec<u8>), CodecError> {
    if data.len() < 20 {
        return Err(CodecError::BufferTooShort {
            expected: 20,
            actual: data.len(),
        });
    }
    let mut msg_id = [0u8; 16];
    msg_id.copy_from_slice(&data[0..16]);
    let payload_len = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    if data.len() < 20 + payload_len {
        return Err(CodecError::PayloadLengthMismatch {
            header: payload_len,
            actual: data.len() - 20,
        });
    }
    let payload = data[20..20 + payload_len].to_vec();
    Ok((MessageId::from_bytes(msg_id), payload))
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

/// Serialize a sender key distribution payload.
/// Layout: type(1=0x71) + group_id(32) + chain_key(32) + iteration(4)
pub fn serialize_sender_key_distribution(
    group_id: &[u8; 32],
    chain_key: &[u8; 32],
    iteration: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(69);
    buf.push(WirePayloadType::SenderKeyDistribution as u8);
    buf.extend_from_slice(group_id);
    buf.extend_from_slice(chain_key);
    buf.extend_from_slice(&iteration.to_le_bytes());
    buf
}

/// Deserialize sender key distribution body (after type byte).
/// Returns: (group_id, chain_key, iteration)
pub fn deserialize_sender_key_distribution(
    data: &[u8],
) -> Result<([u8; 32], [u8; 32], u32), CodecError> {
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
    Ok((group_id, chain_key, iteration))
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
        let msg_id = MessageId::from_bytes([99u8; 16]);
        let payload = b"dtn bundle data";
        let bytes = serialize_dtn_relay(&msg_id, payload);
        assert_eq!(bytes[0], WirePayloadType::DtnRelay as u8);
        let (decoded_id, decoded_payload) = deserialize_dtn_relay(&bytes[1..]).unwrap();
        assert_eq!(*decoded_id.as_bytes(), [99u8; 16]);
        assert_eq!(decoded_payload, payload);
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
        let group_id = [0xBB; 32];
        let chain_key = [0xCC; 32];
        let bytes = serialize_sender_key_distribution(&group_id, &chain_key, 7);
        assert_eq!(bytes[0], WirePayloadType::SenderKeyDistribution as u8);
        let (gid, ck, iter) = deserialize_sender_key_distribution(&bytes[1..]).unwrap();
        assert_eq!(gid, group_id);
        assert_eq!(ck, chain_key);
        assert_eq!(iter, 7);
    }

    #[test]
    fn test_wire_payload_type_from_byte() {
        assert_eq!(WirePayloadType::from_byte(0x10), Some(WirePayloadType::EncryptedMessage));
        assert_eq!(WirePayloadType::from_byte(0x40), Some(WirePayloadType::DtnRelay));
        assert_eq!(WirePayloadType::from_byte(0x50), Some(WirePayloadType::Beacon));
        assert_eq!(WirePayloadType::from_byte(0x60), Some(WirePayloadType::Receipt));
        assert_eq!(WirePayloadType::from_byte(0x70), Some(WirePayloadType::GroupMessage));
        assert_eq!(WirePayloadType::from_byte(0x71), Some(WirePayloadType::SenderKeyDistribution));
        assert_eq!(WirePayloadType::from_byte(0xFF), None);
    }
}
