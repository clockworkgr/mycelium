//! Level-3 emergency co-signature construction and verification.
//!
//! A level-3 broadcast floods the entire mesh and bypasses routing rules
//! (MYCELIUM_SPEC.md §9.5), so it requires three co-signers the receiver
//! trusts above 0.8. Carrying bare NodeIds proved nothing: anyone could list
//! three trusted ids they did not control. Co-signers now sign the broadcast
//! and the receiver verifies every signature (ROADMAP T-05, ADR-010).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use mycelium_protocol::types::NodeId;
use mycelium_protocol::wire::{EmergencyCosigner, EmergencyLevel, EMERGENCY_COSIGN_CONTEXT};

use crate::identity::{node_id_from_public_key, Identity};

/// The bytes a co-signer signs.
///
/// Binds the approval to the originator, the level and the exact message, so a
/// signature cannot be lifted onto a different broadcast, replayed at a
/// different level, or reused by a different originator.
pub fn cosign_digest(originator: &NodeId, level: EmergencyLevel, message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EMERGENCY_COSIGN_CONTEXT);
    hasher.update(originator.as_bytes());
    hasher.update([level as u8]);
    hasher.update((message.len() as u32).to_le_bytes());
    hasher.update(message);
    hasher.finalize().into()
}

/// Co-sign a level-3 broadcast.
pub fn cosign(
    signer: &Identity,
    originator: &NodeId,
    level: EmergencyLevel,
    message: &[u8],
) -> EmergencyCosigner {
    let digest = cosign_digest(originator, level, message);
    EmergencyCosigner {
        node_id: signer.node_id(),
        signature: signer.sign(&digest).to_bytes(),
    }
}

/// Why a co-signature was not counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CosignerRejection {
    /// We hold no verified identity key for this co-signer, so the signature
    /// cannot be checked. Not counted — an unverifiable approval is no
    /// approval.
    UnknownIdentityKey,
    /// The stored key is not a valid Ed25519 point.
    MalformedIdentityKey,
    /// The signature does not verify over the broadcast digest.
    BadSignature,
    /// The stored key does not hash to the claimed NodeId.
    IdentityMismatch,
    /// The same co-signer appeared more than once.
    Duplicate,
}

/// Verify one co-signature against a key the caller looked up.
///
/// `identity_key` is `None` when we hold no verified key for that NodeId.
pub fn verify_cosigner(
    cosigner: &EmergencyCosigner,
    identity_key: Option<[u8; 32]>,
    originator: &NodeId,
    level: EmergencyLevel,
    message: &[u8],
) -> Result<(), CosignerRejection> {
    let key = identity_key.ok_or(CosignerRejection::UnknownIdentityKey)?;

    // Same binding rule as every other ingress path: the key must hash to the
    // id it claims (MYCELIUM_SPEC.md §14.3).
    if node_id_from_public_key(&key) != cosigner.node_id {
        return Err(CosignerRejection::IdentityMismatch);
    }

    let verifying =
        VerifyingKey::from_bytes(&key).map_err(|_| CosignerRejection::MalformedIdentityKey)?;
    let signature = Signature::from_bytes(&cosigner.signature);
    let digest = cosign_digest(originator, level, message);

    verifying
        .verify(&digest, &signature)
        .map_err(|_| CosignerRejection::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Identity, NodeId, Vec<u8>) {
        let signer = Identity::generate();
        let originator = Identity::generate().node_id();
        (signer, originator, b"flood warning".to_vec())
    }

    #[test]
    fn test_valid_cosignature_verifies() {
        let (signer, originator, message) = setup();
        let cs = cosign(&signer, &originator, EmergencyLevel::Critical, &message);
        assert_eq!(
            verify_cosigner(
                &cs,
                Some(signer.public_key_bytes()),
                &originator,
                EmergencyLevel::Critical,
                &message
            ),
            Ok(())
        );
    }

    /// A bare NodeId with no signature must not pass. This is the whole point
    /// of the task: the previous format carried only ids.
    #[test]
    fn test_forged_signature_rejected() {
        let (signer, originator, message) = setup();
        let forged = EmergencyCosigner {
            node_id: signer.node_id(),
            signature: [0u8; 64],
        };
        assert_eq!(
            verify_cosigner(
                &forged,
                Some(signer.public_key_bytes()),
                &originator,
                EmergencyLevel::Critical,
                &message
            ),
            Err(CosignerRejection::BadSignature)
        );
    }

    #[test]
    fn test_unknown_identity_key_is_not_an_approval() {
        let (signer, originator, message) = setup();
        let cs = cosign(&signer, &originator, EmergencyLevel::Critical, &message);
        assert_eq!(
            verify_cosigner(&cs, None, &originator, EmergencyLevel::Critical, &message),
            Err(CosignerRejection::UnknownIdentityKey)
        );
    }

    /// A signature cannot be lifted onto a different message, level or
    /// originator.
    #[test]
    fn test_signature_is_bound_to_the_broadcast() {
        let (signer, originator, message) = setup();
        let cs = cosign(&signer, &originator, EmergencyLevel::Critical, &message);
        let key = Some(signer.public_key_bytes());

        assert_eq!(
            verify_cosigner(
                &cs,
                key,
                &originator,
                EmergencyLevel::Critical,
                b"different message"
            ),
            Err(CosignerRejection::BadSignature),
            "must not transfer to another message"
        );
        assert_eq!(
            verify_cosigner(&cs, key, &originator, EmergencyLevel::Urgent, &message),
            Err(CosignerRejection::BadSignature),
            "must not transfer to another level"
        );
        assert_eq!(
            verify_cosigner(
                &cs,
                key,
                &Identity::generate().node_id(),
                EmergencyLevel::Critical,
                &message
            ),
            Err(CosignerRejection::BadSignature),
            "must not transfer to another originator"
        );
    }

    #[test]
    fn test_identity_key_must_hash_to_the_claimed_id() {
        let (signer, originator, message) = setup();
        let mut cs = cosign(&signer, &originator, EmergencyLevel::Critical, &message);
        cs.node_id = NodeId([9u8; 32]);
        assert_eq!(
            verify_cosigner(
                &cs,
                Some(signer.public_key_bytes()),
                &originator,
                EmergencyLevel::Critical,
                &message
            ),
            Err(CosignerRejection::IdentityMismatch)
        );
    }
}
