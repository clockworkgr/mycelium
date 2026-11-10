//! Signed DHT records.
//!
//! A record is a node's claim about its own reachable address. Only the node
//! itself can produce one: the record carries the Ed25519 public key, the
//! signature is checked against it, and the key must hash to the record's
//! NodeId — the same binding rule every other ingress path enforces
//! (spec §14.3). Without this, any peer could publish any address for any
//! NodeId and redirect that node's internet traffic to itself.

use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use mycelium_crypto::identity::{node_id_from_public_key, verify_signature_bytes, Identity};
use mycelium_protocol::types::NodeId;

/// Domain separation tag for the record signature.
pub const DHT_RECORD_CONTEXT: &[u8] = b"mycelium-dht-record-v1:";

/// How long a record stays valid after it was published.
pub const RECORD_TTL_SECS: u64 = 3600;

/// How far into the future a record's timestamp may be before it is refused.
/// Covers ordinary clock skew without letting a peer park a record that
/// outlives every honest one.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// Seconds since the Unix epoch, saturating at 0 for a clock before 1970.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Why a record was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecordRejection {
    /// The public key is not a valid Ed25519 key, or the signature does not
    /// verify over the record's contents.
    #[error("record signature is invalid")]
    BadSignature,
    /// The record's timestamp is further ahead than `MAX_CLOCK_SKEW_SECS`.
    #[error("record is timestamped in the future")]
    FromFuture,
    /// The record is older than `RECORD_TTL_SECS`.
    #[error("record has expired")]
    Expired,
    /// We already hold a record for this node that is at least as new.
    #[error("record is older than the one already stored")]
    Stale,
    /// The store is at capacity and nothing could be evicted for this record.
    #[error("record store is full")]
    StoreFull,
}

/// A signed claim by a node about its own address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtRecord {
    /// The publisher's Ed25519 public key. The record's NodeId is its SHA-256.
    pub public_key: [u8; 32],
    /// The address the publisher says it can be reached on.
    pub addr: SocketAddr,
    /// Seconds since the Unix epoch, as claimed by the publisher.
    pub published_at: u64,
    /// Ed25519 signature over [`DhtRecord::signing_payload`].
    pub signature: [u8; 64],
}

impl DhtRecord {
    /// Build and sign a record for our own address.
    pub fn new_signed(identity: &Identity, addr: SocketAddr, published_at: u64) -> Self {
        let public_key = identity.public_key_bytes();
        let payload = Self::signing_payload(&public_key, &addr, published_at);
        let signature = identity.sign(&payload).to_bytes();
        Self {
            public_key,
            addr,
            published_at,
            signature,
        }
    }

    /// The exact bytes covered by the signature.
    ///
    /// The address and timestamp are both inside it: the address is the claim
    /// itself, and the timestamp is what lets a receiver refuse a replayed
    /// older record in favour of the current one.
    pub fn signing_payload(public_key: &[u8; 32], addr: &SocketAddr, published_at: u64) -> Vec<u8> {
        let addr_bytes = encode_addr(addr);
        let mut payload = Vec::with_capacity(DHT_RECORD_CONTEXT.len() + 32 + addr_bytes.len() + 8);
        payload.extend_from_slice(DHT_RECORD_CONTEXT);
        payload.extend_from_slice(public_key);
        payload.extend_from_slice(&addr_bytes);
        payload.extend_from_slice(&published_at.to_le_bytes());
        payload
    }

    /// The NodeId this record belongs to, derived from its public key.
    ///
    /// Derived rather than carried, so a record can never claim a NodeId its
    /// key does not hash to.
    pub fn node_id(&self) -> NodeId {
        node_id_from_public_key(&self.public_key)
    }

    /// Verify the signature. Returns the NodeId the record binds to.
    pub fn verify(&self) -> Result<NodeId, RecordRejection> {
        let payload = Self::signing_payload(&self.public_key, &self.addr, self.published_at);
        verify_signature_bytes(&self.public_key, &payload, &self.signature)
            .map_err(|_| RecordRejection::BadSignature)?;
        Ok(self.node_id())
    }

    /// Whether the record has outlived `ttl_secs` as of `now`.
    pub fn is_expired(&self, now: u64, ttl_secs: u64) -> bool {
        self.published_at.saturating_add(ttl_secs) <= now
    }
}

/// Encode a socket address: family tag, address bytes, little-endian port.
pub fn encode_addr(addr: &SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(19);
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{}", port).parse().unwrap()
    }

    #[test]
    fn test_signed_record_verifies_and_binds_its_node_id() {
        let identity = Identity::generate();
        let record = DhtRecord::new_signed(&identity, addr(9736), unix_now());
        assert_eq!(record.verify().unwrap(), identity.node_id());
    }

    #[test]
    fn test_tampered_address_fails_verification() {
        let identity = Identity::generate();
        let mut record = DhtRecord::new_signed(&identity, addr(9736), unix_now());
        record.addr = addr(9737);
        assert_eq!(record.verify(), Err(RecordRejection::BadSignature));
    }

    #[test]
    fn test_tampered_timestamp_fails_verification() {
        let identity = Identity::generate();
        let mut record = DhtRecord::new_signed(&identity, addr(9736), unix_now());
        record.published_at += 1;
        assert_eq!(record.verify(), Err(RecordRejection::BadSignature));
    }

    #[test]
    fn test_substituted_public_key_fails_verification() {
        let identity = Identity::generate();
        let other = Identity::generate();
        let mut record = DhtRecord::new_signed(&identity, addr(9736), unix_now());
        // An attacker swapping in its own key also moves the record's NodeId,
        // so it cannot claim someone else's id even if it re-signs.
        record.public_key = other.public_key_bytes();
        assert_eq!(record.verify(), Err(RecordRejection::BadSignature));
    }

    #[test]
    fn test_expiry_uses_the_publish_timestamp() {
        let identity = Identity::generate();
        let record = DhtRecord::new_signed(&identity, addr(9736), 1_000);
        assert!(!record.is_expired(1_000 + RECORD_TTL_SECS - 1, RECORD_TTL_SECS));
        assert!(record.is_expired(1_000 + RECORD_TTL_SECS, RECORD_TTL_SECS));
    }

    #[test]
    fn test_v6_and_v4_addresses_encode_distinctly() {
        let v4: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let v6: SocketAddr = "[::1]:1".parse().unwrap();
        assert_ne!(encode_addr(&v4), encode_addr(&v6));
        assert_eq!(encode_addr(&v4).len(), 7);
        assert_eq!(encode_addr(&v6).len(), 19);
    }
}
