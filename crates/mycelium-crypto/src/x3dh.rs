use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::identity::Identity;

/// A prekey bundle published by a node for X3DH.
#[derive(Debug, Clone)]
pub struct PrekeyBundle {
    /// Ed25519 identity public key.
    pub identity_key: [u8; 32],
    /// Signed X25519 prekey (medium-term, rotated weekly).
    pub signed_prekey: [u8; 32],
    /// Ed25519 signature over signed_prekey.
    pub signed_prekey_signature: Vec<u8>,
    pub signed_prekey_id: u32,
    /// Optional one-time X25519 prekey.
    pub one_time_prekey: Option<[u8; 32]>,
    pub one_time_prekey_id: Option<u32>,
}

/// State needed to respond to X3DH initiation (our prekey secrets).
pub struct PrekeyState {
    pub identity: Identity,
    pub signed_prekey_secret: X25519Secret,
    pub signed_prekey_id: u32,
    /// One-time prekeys: (id, secret)
    pub one_time_prekeys: Vec<(u32, X25519Secret)>,
    next_otp_id: u32,
    next_spk_id: u32,
}

impl PrekeyState {
    pub fn new(identity: Identity) -> Self {
        let signed_prekey_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
        Self {
            identity,
            signed_prekey_secret,
            signed_prekey_id: 1,
            one_time_prekeys: Vec::new(),
            next_otp_id: 1,
            next_spk_id: 2,
        }
    }

    /// Generate N one-time prekeys.
    pub fn generate_one_time_prekeys(&mut self, count: u32) {
        for _ in 0..count {
            let secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
            self.one_time_prekeys.push((self.next_otp_id, secret));
            self.next_otp_id += 1;
        }
    }

    /// Rotate the signed prekey.
    pub fn rotate_signed_prekey(&mut self) {
        self.signed_prekey_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
        self.signed_prekey_id = self.next_spk_id;
        self.next_spk_id += 1;
    }

    /// Build a prekey bundle to publish.
    pub fn bundle(&self) -> PrekeyBundle {
        let spk_public = X25519Public::from(&self.signed_prekey_secret);
        let signature = self.identity.sign(spk_public.as_bytes());

        let (otp, otp_id) = if let Some((id, secret)) = self.one_time_prekeys.last() {
            (Some(*X25519Public::from(secret).as_bytes()), Some(*id))
        } else {
            (None, None)
        };

        PrekeyBundle {
            identity_key: self.identity.public_key_bytes(),
            signed_prekey: *spk_public.as_bytes(),
            signed_prekey_signature: signature.to_bytes().to_vec(),
            signed_prekey_id: self.signed_prekey_id,
            one_time_prekey: otp,
            one_time_prekey_id: otp_id,
        }
    }

    /// Consume a one-time prekey by ID (marks it as used).
    pub fn consume_one_time_prekey(&mut self, id: u32) -> Option<X25519Secret> {
        if let Some(pos) = self.one_time_prekeys.iter().position(|(pid, _)| *pid == id) {
            let (_, secret) = self.one_time_prekeys.remove(pos);
            Some(secret)
        } else {
            None
        }
    }

    /// Serialize the prekey state (excluding identity) to bytes for persistence.
    ///
    /// Format: signed_prekey_secret(32) + signed_prekey_id(4) + next_otp_id(4)
    ///       + next_spk_id(4) + num_otps(4) + [otp_id(4) + otp_secret(32)]*
    pub fn to_bytes(&self) -> Vec<u8> {
        let num_otps = self.one_time_prekeys.len();
        let mut buf = Vec::with_capacity(48 + num_otps * 36);

        buf.extend_from_slice(&self.signed_prekey_secret.to_bytes());
        buf.extend_from_slice(&self.signed_prekey_id.to_le_bytes());
        buf.extend_from_slice(&self.next_otp_id.to_le_bytes());
        buf.extend_from_slice(&self.next_spk_id.to_le_bytes());
        buf.extend_from_slice(&(num_otps as u32).to_le_bytes());

        for (id, secret) in &self.one_time_prekeys {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&secret.to_bytes());
        }

        buf
    }

    /// Restore prekey state from bytes (requires identity to be provided separately).
    pub fn from_bytes_with_identity(data: &[u8], identity: Identity) -> Option<Self> {
        if data.len() < 48 {
            return None;
        }

        let mut offset = 0;

        let mut spk_bytes = [0u8; 32];
        spk_bytes.copy_from_slice(&data[offset..offset + 32]);
        let signed_prekey_secret = X25519Secret::from(spk_bytes);
        offset += 32;

        let signed_prekey_id = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let next_otp_id = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let next_spk_id = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let num_otps = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        if data.len() < offset + num_otps * 36 {
            return None;
        }

        let mut one_time_prekeys = Vec::with_capacity(num_otps);
        for _ in 0..num_otps {
            let id = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
            offset += 4;

            let mut secret_bytes = [0u8; 32];
            secret_bytes.copy_from_slice(&data[offset..offset + 32]);
            let secret = X25519Secret::from(secret_bytes);
            offset += 32;

            one_time_prekeys.push((id, secret));
        }

        Some(Self {
            identity,
            signed_prekey_secret,
            signed_prekey_id,
            one_time_prekeys,
            next_otp_id,
            next_spk_id,
        })
    }
}

/// Result of X3DH initiation.
pub struct X3dhInitResult {
    /// Shared secret derived from X3DH (32 bytes).
    pub shared_secret: [u8; 32],
    /// Ephemeral public key to send to recipient.
    pub ephemeral_public: [u8; 32],
    /// Associated data for the first message.
    pub ad: Vec<u8>,
}

/// Result of X3DH response.
pub struct X3dhResponseResult {
    /// Shared secret derived from X3DH (32 bytes).
    pub shared_secret: [u8; 32],
    /// Associated data.
    pub ad: Vec<u8>,
}

/// Initiate X3DH key exchange with a recipient's prekey bundle.
///
/// Performs 3-4 DH operations:
/// 1. DH(our_identity_x25519, their_signed_prekey)
/// 2. DH(ephemeral, their_identity_x25519)
/// 3. DH(ephemeral, their_signed_prekey)
/// 4. DH(ephemeral, their_one_time_prekey) — if available
pub fn x3dh_initiate(
    our_identity: &Identity,
    their_bundle: &PrekeyBundle,
) -> Result<X3dhInitResult, X3dhError> {
    // Verify the signed prekey signature
    let their_identity = VerifyingKey::from_bytes(&their_bundle.identity_key)
        .map_err(|_| X3dhError::InvalidIdentityKey)?;

    let sig_bytes: [u8; 64] = their_bundle
        .signed_prekey_signature
        .as_slice()
        .try_into()
        .map_err(|_| X3dhError::InvalidSignature)?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    their_identity
        .verify(&their_bundle.signed_prekey, &signature)
        .map_err(|_| X3dhError::InvalidSignature)?;

    // Convert our Ed25519 identity key to X25519 for DH
    let our_identity_x25519 = ed25519_to_x25519_secret(our_identity.signing_key());

    // Generate ephemeral X25519 keypair
    let ephemeral_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = X25519Public::from(&ephemeral_secret);

    let their_signed_prekey = X25519Public::from(their_bundle.signed_prekey);
    let their_identity_x25519 = ed25519_public_to_x25519(&their_bundle.identity_key);

    // DH operations
    let dh1 = our_identity_x25519.diffie_hellman(&their_signed_prekey);
    let dh2 = ephemeral_secret.diffie_hellman(&their_identity_x25519);
    let dh3 = ephemeral_secret.diffie_hellman(&their_signed_prekey);

    let mut dh_concat = Vec::with_capacity(128);
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    if let Some(otp) = &their_bundle.one_time_prekey {
        let their_otp = X25519Public::from(*otp);
        let dh4 = ephemeral_secret.diffie_hellman(&their_otp);
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    let shared_secret = kdf_x3dh(&dh_concat);

    // Associated data: both identity keys concatenated
    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(&our_identity.public_key_bytes());
    ad.extend_from_slice(&their_bundle.identity_key);

    Ok(X3dhInitResult {
        shared_secret,
        ephemeral_public: *ephemeral_public.as_bytes(),
        ad,
    })
}

/// Respond to an X3DH initiation.
pub fn x3dh_respond(
    our_state: &mut PrekeyState,
    their_identity_key: &[u8; 32],
    their_ephemeral_key: &[u8; 32],
    used_otp_id: Option<u32>,
) -> Result<X3dhResponseResult, X3dhError> {
    let their_identity_x25519 = ed25519_public_to_x25519(their_identity_key);
    let their_ephemeral = X25519Public::from(*their_ephemeral_key);

    // Convert our Ed25519 identity to X25519
    let our_identity_x25519 = ed25519_to_x25519_secret(our_state.identity.signing_key());

    // DH operations (mirror of initiate)
    let dh1 = our_state
        .signed_prekey_secret
        .diffie_hellman(&their_identity_x25519);
    let dh2 = our_identity_x25519.diffie_hellman(&their_ephemeral);
    let dh3 = our_state
        .signed_prekey_secret
        .diffie_hellman(&their_ephemeral);

    let mut dh_concat = Vec::with_capacity(128);
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    if let Some(otp_id) = used_otp_id {
        let otp_secret = our_state
            .consume_one_time_prekey(otp_id)
            .ok_or(X3dhError::OneTimePrekeyNotFound)?;
        let dh4 = otp_secret.diffie_hellman(&their_ephemeral);
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    let shared_secret = kdf_x3dh(&dh_concat);

    // Associated data
    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(their_identity_key);
    ad.extend_from_slice(&our_state.identity.public_key_bytes());

    Ok(X3dhResponseResult { shared_secret, ad })
}

/// Convert Ed25519 signing key to X25519 static secret.
///
/// Ed25519 keys are derived by hashing the seed with SHA-512 and clamping.
/// The lower 32 bytes of SHA-512(seed), clamped, give the X25519-compatible scalar.
fn ed25519_to_x25519_secret(signing_key: &SigningKey) -> X25519Secret {
    use sha2::{Digest, Sha512};
    let hash = Sha512::digest(signing_key.to_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);
    // Clamp per RFC 7748
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    X25519Secret::from(bytes)
}

/// Convert Ed25519 public key to X25519 public key (Edwards -> Montgomery).
fn ed25519_public_to_x25519(ed25519_pubkey: &[u8; 32]) -> X25519Public {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let compressed = CompressedEdwardsY::from_slice(ed25519_pubkey)
        .expect("invalid Ed25519 public key length");
    let point = compressed.decompress().expect("invalid Ed25519 point");
    let montgomery = point.to_montgomery();
    X25519Public::from(*montgomery.as_bytes())
}

/// KDF for X3DH: HKDF-SHA256 with protocol-specific info.
fn kdf_x3dh(input: &[u8]) -> [u8; 32] {
    let salt = [0u8; 32]; // All zeros per Signal spec
    let hk = Hkdf::<Sha256>::new(Some(&salt), input);
    let mut output = [0u8; 32];
    hk.expand(b"MyceliumX3DH", &mut output)
        .expect("HKDF expansion failed");
    output
}

#[derive(Debug, thiserror::Error)]
pub enum X3dhError {
    #[error("invalid identity key")]
    InvalidIdentityKey,
    #[error("invalid signed prekey signature")]
    InvalidSignature,
    #[error("one-time prekey not found")]
    OneTimePrekeyNotFound,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x3dh_roundtrip_with_otp() {
        let alice = Identity::generate();
        let bob_identity = Identity::generate();

        let mut bob_state = PrekeyState::new(bob_identity);
        bob_state.generate_one_time_prekeys(10);

        let bundle = bob_state.bundle();

        // Alice initiates
        let init_result = x3dh_initiate(&alice, &bundle).unwrap();

        // Bob responds
        let respond_result = x3dh_respond(
            &mut bob_state,
            &alice.public_key_bytes(),
            &init_result.ephemeral_public,
            bundle.one_time_prekey_id,
        )
        .unwrap();

        // Both should derive the same shared secret
        assert_eq!(init_result.shared_secret, respond_result.shared_secret);
    }

    #[test]
    fn test_x3dh_roundtrip_without_otp() {
        let alice = Identity::generate();
        let bob_identity = Identity::generate();

        let mut bob_state = PrekeyState::new(bob_identity);
        // No one-time prekeys

        let bundle = bob_state.bundle();
        assert!(bundle.one_time_prekey.is_none());

        let init_result = x3dh_initiate(&alice, &bundle).unwrap();

        let respond_result = x3dh_respond(
            &mut bob_state,
            &alice.public_key_bytes(),
            &init_result.ephemeral_public,
            None,
        )
        .unwrap();

        assert_eq!(init_result.shared_secret, respond_result.shared_secret);
    }

    #[test]
    fn test_prekey_bundle_signature_verification() {
        let identity = Identity::generate();
        let state = PrekeyState::new(identity);
        let bundle = state.bundle();

        // Verify signature is valid
        let verifying_key = VerifyingKey::from_bytes(&bundle.identity_key).unwrap();
        let sig_bytes: [u8; 64] = bundle.signed_prekey_signature.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(verifying_key.verify(&bundle.signed_prekey, &signature).is_ok());
    }

    #[test]
    fn test_one_time_prekey_consumption() {
        let identity = Identity::generate();
        let mut state = PrekeyState::new(identity);
        state.generate_one_time_prekeys(3);

        assert_eq!(state.one_time_prekeys.len(), 3);

        let id = state.one_time_prekeys[0].0;
        let consumed = state.consume_one_time_prekey(id);
        assert!(consumed.is_some());
        assert_eq!(state.one_time_prekeys.len(), 2);

        // Can't consume same one again
        let again = state.consume_one_time_prekey(id);
        assert!(again.is_none());
    }

    #[test]
    fn test_prekey_state_serialization_roundtrip() {
        let identity = Identity::generate();
        let identity2 = Identity::from_bytes(&identity.to_bytes()).unwrap();

        let mut state = PrekeyState::new(identity);
        state.generate_one_time_prekeys(25);

        let original_spk_id = state.signed_prekey_id;
        let original_otp_count = state.one_time_prekeys.len();
        let original_next_otp_id = state.next_otp_id;
        let original_next_spk_id = state.next_spk_id;

        // Serialize and deserialize
        let bytes = state.to_bytes();
        let restored = PrekeyState::from_bytes_with_identity(&bytes, identity2).unwrap();

        assert_eq!(restored.signed_prekey_id, original_spk_id);
        assert_eq!(restored.one_time_prekeys.len(), original_otp_count);
        assert_eq!(restored.next_otp_id, original_next_otp_id);
        assert_eq!(restored.next_spk_id, original_next_spk_id);

        // Bundles should produce the same public keys
        let bundle_orig = state.bundle();
        let bundle_rest = restored.bundle();
        assert_eq!(bundle_orig.signed_prekey, bundle_rest.signed_prekey);
        assert_eq!(bundle_orig.signed_prekey_id, bundle_rest.signed_prekey_id);
    }

    #[test]
    fn test_prekey_state_serialization_empty_otps() {
        let identity = Identity::generate();
        let identity2 = Identity::from_bytes(&identity.to_bytes()).unwrap();

        let state = PrekeyState::new(identity);
        assert_eq!(state.one_time_prekeys.len(), 0);

        let bytes = state.to_bytes();
        let restored = PrekeyState::from_bytes_with_identity(&bytes, identity2).unwrap();
        assert_eq!(restored.one_time_prekeys.len(), 0);
        assert_eq!(restored.signed_prekey_id, 1);
    }

    #[test]
    fn test_prekey_state_serialization_after_rotation() {
        let identity = Identity::generate();
        let identity2 = Identity::from_bytes(&identity.to_bytes()).unwrap();

        let mut state = PrekeyState::new(identity);
        state.generate_one_time_prekeys(5);
        state.rotate_signed_prekey();
        state.rotate_signed_prekey();

        let bytes = state.to_bytes();
        let restored = PrekeyState::from_bytes_with_identity(&bytes, identity2).unwrap();
        assert_eq!(restored.signed_prekey_id, state.signed_prekey_id);
        assert_eq!(restored.next_spk_id, state.next_spk_id);
    }

    #[test]
    fn test_prekey_state_from_bytes_too_short() {
        let identity = Identity::generate();
        assert!(PrekeyState::from_bytes_with_identity(&[0; 10], identity).is_none());
    }

    #[test]
    fn test_prekey_state_from_bytes_truncated_otps() {
        let identity = Identity::generate();
        let identity2 = Identity::from_bytes(&identity.to_bytes()).unwrap();

        let mut state = PrekeyState::new(identity);
        state.generate_one_time_prekeys(5);
        let mut bytes = state.to_bytes();

        // Truncate: claim 5 OTPs but only provide data for 2
        bytes.truncate(48 + 2 * 36);
        assert!(PrekeyState::from_bytes_with_identity(&bytes, identity2).is_none());
    }
}
