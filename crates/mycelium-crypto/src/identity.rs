use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use mycelium_protocol::types::NodeId;

/// A node's cryptographic identity: Ed25519 signing key + X25519 key exchange key.
///
/// The Ed25519 key is used for signing (identity, vouches, messages).
/// The X25519 key is used for Diffie-Hellman key exchange (X3DH, Double Ratchet).
pub struct Identity {
    signing_key: SigningKey,
    x25519_secret: X25519StaticSecret,
}

impl Identity {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let x25519_secret = X25519StaticSecret::random_from_rng(&mut csprng);
        Self {
            signing_key,
            x25519_secret,
        }
    }

    /// Derive the NodeId from the Ed25519 public key (SHA-256 hash).
    pub fn node_id(&self) -> NodeId {
        let public_key = self.signing_key.verifying_key();
        let hash = Sha256::digest(public_key.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        NodeId(bytes)
    }

    /// Get the Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the Ed25519 public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.signing_key.verifying_key().as_bytes()
    }

    /// Get the X25519 public key for key exchange.
    pub fn x25519_public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.x25519_secret)
    }

    /// Get a reference to the X25519 static secret.
    pub fn x25519_secret(&self) -> &X25519StaticSecret {
        &self.x25519_secret
    }

    /// Get a reference to the Ed25519 signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Sign a message with the Ed25519 key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature against this identity's public key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.signing_key.verifying_key().verify(message, signature).is_ok()
    }

    /// Serialize identity to bytes (64 bytes signing key + 32 bytes x25519 secret).
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut bytes = [0u8; 96];
        bytes[..32].copy_from_slice(&self.signing_key.to_bytes());
        // ed25519-dalek SigningKey is 32 bytes (the seed), we also need the x25519 secret
        bytes[32..64].copy_from_slice(&self.signing_key.to_keypair_bytes()[..32]);
        // Store x25519 secret
        let x25519_bytes = self.x25519_secret.to_bytes();
        bytes[64..96].copy_from_slice(&x25519_bytes);
        bytes
    }

    /// Deserialize identity from bytes.
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, IdentityError> {
        let mut signing_bytes = [0u8; 32];
        signing_bytes.copy_from_slice(&bytes[..32]);
        let signing_key = SigningKey::from_bytes(&signing_bytes);

        let mut x25519_bytes = [0u8; 32];
        x25519_bytes.copy_from_slice(&bytes[64..96]);
        let x25519_secret = X25519StaticSecret::from(x25519_bytes);

        Ok(Self {
            signing_key,
            x25519_secret,
        })
    }
}

/// Verify a signature from a raw public key (used when we don't have an Identity, just a pubkey).
pub fn verify_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &Signature,
) -> Result<(), IdentityError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| IdentityError::InvalidPublicKey)?;
    verifying_key
        .verify(message, signature)
        .map_err(|_| IdentityError::InvalidSignature)
}

/// Compute a NodeId from a raw Ed25519 public key.
pub fn node_id_from_public_key(public_key: &[u8; 32]) -> NodeId {
    let hash = Sha256::digest(public_key);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    NodeId(bytes)
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid key bytes")]
    InvalidKeyBytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let id = Identity::generate();
        let node_id = id.node_id();
        assert_ne!(node_id, NodeId::ZERO);
    }

    #[test]
    fn test_identity_deterministic_node_id() {
        let id = Identity::generate();
        assert_eq!(id.node_id(), id.node_id());
    }

    #[test]
    fn test_sign_verify() {
        let id = Identity::generate();
        let message = b"hello mycelium";
        let sig = id.sign(message);
        assert!(id.verify(message, &sig));

        // Wrong message should fail
        assert!(!id.verify(b"wrong message", &sig));
    }

    #[test]
    fn test_sign_verify_raw() {
        let id = Identity::generate();
        let message = b"test message";
        let sig = id.sign(message);
        let pubkey = id.public_key_bytes();
        assert!(verify_signature(&pubkey, message, &sig).is_ok());
    }

    #[test]
    fn test_node_id_from_public_key() {
        let id = Identity::generate();
        let pubkey = id.public_key_bytes();
        let derived = node_id_from_public_key(&pubkey);
        assert_eq!(id.node_id(), derived);
    }

    #[test]
    fn test_identity_serialization_roundtrip() {
        let id = Identity::generate();
        let bytes = id.to_bytes();
        let restored = Identity::from_bytes(&bytes).unwrap();
        assert_eq!(id.node_id(), restored.node_id());
        assert_eq!(id.public_key_bytes(), restored.public_key_bytes());

        // Verify signing still works after roundtrip
        let msg = b"roundtrip test";
        let sig = restored.sign(msg);
        assert!(id.verify(msg, &sig));
    }

    #[test]
    fn test_different_identities_different_node_ids() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        assert_ne!(id1.node_id(), id2.node_id());
    }

    #[test]
    fn test_x25519_key_exchange() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let alice_shared = alice.x25519_secret().diffie_hellman(&bob.x25519_public_key());
        let bob_shared = bob.x25519_secret().diffie_hellman(&alice.x25519_public_key());
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }
}
