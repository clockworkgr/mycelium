//! Level-3 emergency co-signature construction and verification.
//!
//! A level-3 broadcast floods the entire mesh and bypasses routing rules
//! (MYCELIUM_SPEC.md §9.5), so it requires three co-signers the receiver
//! trusts above 0.8. Carrying bare NodeIds proved nothing: anyone could list
//! three trusted ids they did not control. Co-signers now sign the broadcast
//! and the receiver verifies every signature (ROADMAP T-05, ADR-010).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use mycelium_protocol::types::{MessageId, NodeId};
use mycelium_protocol::wire::{EmergencyCosigner, EmergencyLevel, EMERGENCY_COSIGN_CONTEXT};

use crate::identity::{node_id_from_public_key, Identity};

/// The bytes a co-signer signs.
///
/// Binds the approval to **this** broadcast: its id, the originator, the level
/// and the exact message. Without the id, an intercepted critical alert could
/// be re-flooded under a fresh envelope id indefinitely — the content-only
/// digest would still verify, and the receiving node's dedup set is keyed on
/// the envelope id it no longer matches.
pub fn cosign_digest(
    broadcast_id: &MessageId,
    originator: &NodeId,
    level: EmergencyLevel,
    message: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EMERGENCY_COSIGN_CONTEXT);
    hasher.update(broadcast_id.as_bytes());
    hasher.update(originator.as_bytes());
    hasher.update([level as u8]);
    hasher.update((message.len() as u32).to_le_bytes());
    hasher.update(message);
    hasher.finalize().into()
}

/// Co-sign a level-3 broadcast.
pub fn cosign(
    signer: &Identity,
    broadcast_id: &MessageId,
    originator: &NodeId,
    level: EmergencyLevel,
    message: &[u8],
) -> EmergencyCosigner {
    let digest = cosign_digest(broadcast_id, originator, level, message);
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
    broadcast_id: &MessageId,
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
    let digest = cosign_digest(broadcast_id, originator, level, message);

    verifying
        .verify(&digest, &signature)
        .map_err(|_| CosignerRejection::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        signer: Identity,
        broadcast_id: MessageId,
        originator: NodeId,
        message: Vec<u8>,
    }

    fn setup() -> Fixture {
        Fixture {
            signer: Identity::generate(),
            broadcast_id: MessageId::random(),
            originator: Identity::generate().node_id(),
            message: b"flood warning".to_vec(),
        }
    }

    fn verify(
        f: &Fixture,
        cs: &EmergencyCosigner,
        key: Option<[u8; 32]>,
    ) -> Result<(), CosignerRejection> {
        verify_cosigner(
            cs,
            key,
            &f.broadcast_id,
            &f.originator,
            EmergencyLevel::Critical,
            &f.message,
        )
    }

    fn sign(f: &Fixture) -> EmergencyCosigner {
        cosign(
            &f.signer,
            &f.broadcast_id,
            &f.originator,
            EmergencyLevel::Critical,
            &f.message,
        )
    }

    #[test]
    fn test_valid_cosignature_verifies() {
        let f = setup();
        let cs = sign(&f);
        assert_eq!(verify(&f, &cs, Some(f.signer.public_key_bytes())), Ok(()));
    }

    /// A bare NodeId with no signature must not pass. This is the whole point
    /// of the task: the previous wire format carried only ids.
    #[test]
    fn test_forged_signature_rejected() {
        let f = setup();
        let forged = EmergencyCosigner {
            node_id: f.signer.node_id(),
            signature: [0u8; 64],
        };
        assert_eq!(
            verify(&f, &forged, Some(f.signer.public_key_bytes())),
            Err(CosignerRejection::BadSignature)
        );
    }

    #[test]
    fn test_unknown_identity_key_is_not_an_approval() {
        let f = setup();
        let cs = sign(&f);
        assert_eq!(
            verify(&f, &cs, None),
            Err(CosignerRejection::UnknownIdentityKey)
        );
    }

    /// A signature must not transfer to another message, level or originator.
    #[test]
    fn test_signature_is_bound_to_the_broadcast() {
        let f = setup();
        let cs = sign(&f);
        let key = Some(f.signer.public_key_bytes());

        assert_eq!(
            verify_cosigner(
                &cs,
                key,
                &f.broadcast_id,
                &f.originator,
                EmergencyLevel::Critical,
                b"different message"
            ),
            Err(CosignerRejection::BadSignature),
            "must not transfer to another message"
        );
        assert_eq!(
            verify_cosigner(
                &cs,
                key,
                &f.broadcast_id,
                &f.originator,
                EmergencyLevel::Urgent,
                &f.message
            ),
            Err(CosignerRejection::BadSignature),
            "must not transfer to another level"
        );
        assert_eq!(
            verify_cosigner(
                &cs,
                key,
                &f.broadcast_id,
                &Identity::generate().node_id(),
                EmergencyLevel::Critical,
                &f.message
            ),
            Err(CosignerRejection::BadSignature),
            "must not transfer to another originator"
        );
    }

    /// An intercepted critical alert must not be re-floodable under a fresh
    /// envelope id: the receiver's dedup set is keyed on that id, so a
    /// content-only digest would let the same approval be replayed forever.
    #[test]
    fn test_signature_cannot_be_replayed_under_a_new_broadcast_id() {
        let f = setup();
        let cs = sign(&f);
        assert_eq!(
            verify_cosigner(
                &cs,
                Some(f.signer.public_key_bytes()),
                &MessageId::random(),
                &f.originator,
                EmergencyLevel::Critical,
                &f.message
            ),
            Err(CosignerRejection::BadSignature),
            "a co-signature must not verify for a different broadcast id"
        );
    }

    #[test]
    fn test_identity_key_must_hash_to_the_claimed_id() {
        let f = setup();
        let mut cs = sign(&f);
        cs.node_id = NodeId([9u8; 32]);
        assert_eq!(
            verify(&f, &cs, Some(f.signer.public_key_bytes())),
            Err(CosignerRejection::IdentityMismatch)
        );
    }
}
