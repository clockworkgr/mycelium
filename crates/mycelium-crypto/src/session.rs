use sha2::{Digest, Sha256};

use mycelium_protocol::types::NodeId;

use crate::double_ratchet::{RatchetError, RatchetHeader, RatchetState};
use crate::identity::Identity;
use crate::x3dh::{self, PrekeyBundle, PrekeyState, X3dhError};

use std::collections::HashMap;

/// A per-peer encrypted session.
pub struct Session {
    pub peer_id: NodeId,
    pub ratchet: RatchetState,
    pub safety_number: String,
    pub is_verified: bool,
}

/// Manages all active crypto sessions.
pub struct SessionManager {
    sessions: HashMap<NodeId, Session>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Initiate a new session with a peer using their prekey bundle.
    pub fn initiate_session(
        &mut self,
        our_identity: &Identity,
        peer_id: NodeId,
        their_bundle: &PrekeyBundle,
    ) -> Result<InitiateResult, SessionError> {
        let x3dh_result = x3dh::x3dh_initiate(our_identity, their_bundle)
            .map_err(SessionError::X3dh)?;

        let ratchet = RatchetState::init_alice(
            x3dh_result.shared_secret,
            their_bundle.signed_prekey,
        );

        let safety_number = compute_safety_number(
            &our_identity.public_key_bytes(),
            &their_bundle.identity_key,
        );

        let session = Session {
            peer_id,
            ratchet,
            safety_number: safety_number.clone(),
            is_verified: false,
        };

        self.sessions.insert(peer_id, session);

        Ok(InitiateResult {
            ephemeral_public: x3dh_result.ephemeral_public,
            ad: x3dh_result.ad,
            safety_number,
            used_signed_prekey_id: their_bundle.signed_prekey_id,
            used_one_time_prekey_id: their_bundle.one_time_prekey_id,
        })
    }

    /// Accept an incoming session from a peer.
    pub fn accept_session(
        &mut self,
        our_state: &mut PrekeyState,
        peer_id: NodeId,
        their_identity_key: &[u8; 32],
        their_ephemeral_key: &[u8; 32],
        used_otp_id: Option<u32>,
    ) -> Result<String, SessionError> {
        let x3dh_result = x3dh::x3dh_respond(
            our_state,
            their_identity_key,
            their_ephemeral_key,
            used_otp_id,
        )
        .map_err(SessionError::X3dh)?;

        // Clone the signed prekey secret for Double Ratchet initialization
        // (Bob uses his signed prekey as initial DH key)
        let bob_spk = x25519_dalek::StaticSecret::from(
            our_state.signed_prekey_secret.to_bytes(),
        );

        let ratchet = RatchetState::init_bob(x3dh_result.shared_secret, bob_spk);

        let safety_number = compute_safety_number(
            &our_state.identity.public_key_bytes(),
            their_identity_key,
        );

        let session = Session {
            peer_id,
            ratchet,
            safety_number: safety_number.clone(),
            is_verified: false,
        };

        self.sessions.insert(peer_id, session);

        Ok(safety_number)
    }

    /// Encrypt a message for a peer.
    pub fn encrypt_for(
        &mut self,
        peer: &NodeId,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(RatchetHeader, Vec<u8>), SessionError> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::NoSession)?;

        session
            .ratchet
            .encrypt(plaintext, ad)
            .map_err(SessionError::Ratchet)
    }

    /// Decrypt a message from a peer.
    pub fn decrypt_from(
        &mut self,
        peer: &NodeId,
        header: &RatchetHeader,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::NoSession)?;

        session
            .ratchet
            .decrypt(header, ciphertext, ad)
            .map_err(SessionError::Ratchet)
    }

    /// Check if a session exists for a peer.
    pub fn has_session(&self, peer: &NodeId) -> bool {
        self.sessions.contains_key(peer)
    }

    /// Get the safety number for a peer's session.
    pub fn safety_number(&self, peer: &NodeId) -> Option<&str> {
        self.sessions.get(peer).map(|s| s.safety_number.as_str())
    }

    /// Mark a session as verified (after in-person safety number confirmation).
    pub fn verify_session(&mut self, peer: &NodeId) -> bool {
        if let Some(session) = self.sessions.get_mut(peer) {
            session.is_verified = true;
            true
        } else {
            false
        }
    }

    /// Remove a session.
    pub fn remove_session(&mut self, peer: &NodeId) {
        self.sessions.remove(peer);
    }

    /// Get an iterator over all sessions for persistence.
    pub fn all_sessions(&self) -> impl Iterator<Item = (&NodeId, &Session)> {
        self.sessions.iter()
    }

    /// Serialize a session to bytes for DB storage.
    pub fn serialize_session(session: &Session) -> Vec<u8> {
        let ratchet_bytes = session.ratchet.to_bytes();
        let safety_bytes = session.safety_number.as_bytes();

        let mut buf = Vec::with_capacity(32 + 4 + ratchet_bytes.len() + 4 + safety_bytes.len() + 1);
        buf.extend_from_slice(session.peer_id.as_bytes());
        buf.extend_from_slice(&(ratchet_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&ratchet_bytes);
        buf.extend_from_slice(&(safety_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(safety_bytes);
        buf.push(session.is_verified as u8);
        buf
    }

    /// Deserialize a session from bytes.
    pub fn deserialize_session(data: &[u8]) -> Result<Session, SessionError> {
        if data.len() < 37 {
            return Err(SessionError::NoSession);
        }
        let mut offset = 0;

        let mut peer_bytes = [0u8; 32];
        peer_bytes.copy_from_slice(&data[offset..offset + 32]);
        let peer_id = NodeId::from_bytes(peer_bytes);
        offset += 32;

        let ratchet_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + ratchet_len > data.len() {
            return Err(SessionError::NoSession);
        }
        let ratchet = RatchetState::from_bytes(&data[offset..offset + ratchet_len])
            .map_err(SessionError::Ratchet)?;
        offset += ratchet_len;

        if offset + 4 > data.len() {
            return Err(SessionError::NoSession);
        }
        let safety_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + safety_len > data.len() {
            return Err(SessionError::NoSession);
        }
        let safety_number = String::from_utf8_lossy(&data[offset..offset + safety_len]).to_string();
        offset += safety_len;

        let is_verified = if offset < data.len() {
            data[offset] != 0
        } else {
            false
        };

        Ok(Session {
            peer_id,
            ratchet,
            safety_number,
            is_verified,
        })
    }

    /// Restore a session from deserialized data.
    pub fn restore_session(&mut self, session: Session) {
        self.sessions.insert(session.peer_id, session);
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of initiating a session.
pub struct InitiateResult {
    pub ephemeral_public: [u8; 32],
    pub ad: Vec<u8>,
    pub safety_number: String,
    pub used_signed_prekey_id: u32,
    pub used_one_time_prekey_id: Option<u32>,
}

/// Compute a human-readable safety number from two identity keys.
/// Format: groups of 5 digits derived from hash of both keys.
fn compute_safety_number(our_key: &[u8; 32], their_key: &[u8; 32]) -> String {
    // Canonical order: smaller key first
    let (first, second) = if our_key < their_key {
        (our_key, their_key)
    } else {
        (their_key, our_key)
    };

    let mut hasher = Sha256::new();
    hasher.update(b"MyceliumSafetyNumber");
    hasher.update(first);
    hasher.update(second);
    let hash = hasher.finalize();

    // Convert to groups of 5 digits (12 groups = 60 digits)
    let mut number = String::with_capacity(71); // 60 digits + 11 spaces
    for (i, chunk) in hash.chunks(2).enumerate() {
        if i > 0 && i % 4 == 0 {
            number.push(' ');
        }
        let val = u16::from_be_bytes([chunk[0], chunk[1]]) % 10000;
        number.push_str(&format!("{:04}", val));
    }

    number
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("no session established with this peer")]
    NoSession,
    #[error("X3DH error: {0}")]
    X3dh(#[from] X3dhError),
    #[error("ratchet error: {0}")]
    Ratchet(#[from] RatchetError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_session_lifecycle() {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();

        let mut bob_prekey_state = PrekeyState::new(bob_id);
        bob_prekey_state.generate_one_time_prekeys(5);
        let bob_bundle = bob_prekey_state.bundle();
        let bob_node_id = bob_prekey_state.identity.node_id();

        let mut alice_sessions = SessionManager::new();
        let mut bob_sessions = SessionManager::new();

        // Alice initiates
        let init_result = alice_sessions
            .initiate_session(&alice_id, bob_node_id, &bob_bundle)
            .unwrap();

        // Bob accepts
        let safety_bob = bob_sessions
            .accept_session(
                &mut bob_prekey_state,
                alice_id.node_id(),
                &alice_id.public_key_bytes(),
                &init_result.ephemeral_public,
                init_result.used_one_time_prekey_id,
            )
            .unwrap();

        // Safety numbers should match
        assert_eq!(init_result.safety_number, safety_bob);

        // Alice sends to Bob
        let ad = b"session-ad";
        let (header, ct) = alice_sessions
            .encrypt_for(&bob_node_id, b"hello bob", ad)
            .unwrap();
        let pt = bob_sessions
            .decrypt_from(&alice_id.node_id(), &header, &ct, ad)
            .unwrap();
        assert_eq!(pt, b"hello bob");

        // Bob sends to Alice
        let (header, ct) = bob_sessions
            .encrypt_for(&alice_id.node_id(), b"hello alice", ad)
            .unwrap();
        let pt = alice_sessions
            .decrypt_from(&bob_node_id, &header, &ct, ad)
            .unwrap();
        assert_eq!(pt, b"hello alice");
    }

    #[test]
    fn test_safety_number_symmetric() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let sn1 = compute_safety_number(&key_a, &key_b);
        let sn2 = compute_safety_number(&key_b, &key_a);
        assert_eq!(sn1, sn2);
    }
}
