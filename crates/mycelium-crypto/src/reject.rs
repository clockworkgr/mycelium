//! Authenticated session rejection.
//!
//! A `SessionReject` tells an initiator its `SessionInit` cannot be accepted,
//! so it stops retrying against a bundle that can never work. ADR-009 treated
//! it as an unauthenticated hint, on the grounds that no confirmed session
//! exists yet and there is therefore no key to check it with. That reasoning
//! was wrong: the rejecting node has an Ed25519 identity key, the initiator
//! obtained exactly that key in the prekey bundle it ran X3DH against, and the
//! NodeId binding (`SHA-256(identity_key) == source`) ties the key to the
//! sender. The initiator can therefore verify a signature, and a reject that
//! does not verify can be ignored outright instead of bounded (ROADMAP T-35).
//!
//! The signature covers the **transcript** of the `SessionInit` being
//! refused — the payload bytes as they went on the wire — and both NodeIds.
//!
//! Signing the envelope's message id instead is not enough, and the reason is
//! worth recording. An id is cleartext in every envelope, and so is the
//! `source` field, so an observer of Alice's `SessionInit` can send Bob a
//! *malformed* init carrying Alice's id, Alice's source and Alice's public
//! key (which the NodeId binding check requires but which is public). Bob
//! refuses it and signs a rejection naming exactly the id Alice is waiting
//! on — a genuine signature over an attacker's trigger. Alice would accept it
//! and tear down her handshake.
//!
//! The transcript closes that: to make Bob reject, the attacker has to send
//! something Bob refuses, which is by construction *not* the init Alice sent,
//! so the digest Bob signs is not the one Alice recorded. Replaying Alice's
//! init verbatim either succeeds or is refused as a duplicate, and a
//! rejection of the real init is one Alice should act on anyway.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use mycelium_protocol::types::NodeId;
use mycelium_protocol::wire::{
    SessionRejectReason, SESSION_INIT_TRANSCRIPT_CONTEXT, SESSION_REJECT_CONTEXT,
};

use crate::identity::Identity;

/// The transcript of a `SessionInit`: its payload bytes, as sent.
///
/// The initiator hashes what it serialized; the responder hashes the body it
/// received. Nothing else identifies *that* handshake attempt — the envelope's
/// id and source are both forgeable.
pub fn init_transcript(session_init_payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_INIT_TRANSCRIPT_CONTEXT);
    hasher.update((session_init_payload.len() as u32).to_le_bytes());
    hasher.update(session_init_payload);
    hasher.finalize().into()
}

/// The bytes a rejecting node signs.
pub fn reject_digest(
    init_transcript: &[u8; 32],
    initiator: &NodeId,
    rejecter: &NodeId,
    reason: SessionRejectReason,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_REJECT_CONTEXT);
    hasher.update(init_transcript);
    hasher.update(initiator.as_bytes());
    hasher.update(rejecter.as_bytes());
    hasher.update([reason as u8]);
    hasher.finalize().into()
}

/// Sign a rejection of the `SessionInit` with this transcript, addressed to
/// `initiator`.
pub fn sign_reject(
    rejecter: &Identity,
    init_transcript: &[u8; 32],
    initiator: &NodeId,
    reason: SessionRejectReason,
) -> [u8; 64] {
    let digest = reject_digest(init_transcript, initiator, &rejecter.node_id(), reason);
    rejecter.sign(&digest).to_bytes()
}

/// Why a rejection was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectRejection {
    /// The claimed identity key is not a valid Ed25519 point.
    MalformedIdentityKey,
    /// The signature does not verify over the digest.
    BadSignature,
}

/// Verify a rejection against the key it claims to come from.
///
/// The caller must already have checked that `rejecter_key` hashes to the
/// envelope source (spec §14.3) and that `init_transcript` is the transcript
/// of a `SessionInit` it is actually waiting on.
pub fn verify_reject(
    rejecter_key: &[u8; 32],
    init_transcript: &[u8; 32],
    initiator: &NodeId,
    rejecter: &NodeId,
    reason: SessionRejectReason,
    signature: &[u8; 64],
) -> Result<(), RejectRejection> {
    let key = VerifyingKey::from_bytes(rejecter_key)
        .map_err(|_| RejectRejection::MalformedIdentityKey)?;
    let digest = reject_digest(init_transcript, initiator, rejecter, reason);
    key.verify(&digest, &Signature::from_bytes(signature))
        .map_err(|_| RejectRejection::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Identity, NodeId, [u8; 32]) {
        let rejecter = Identity::generate();
        let initiator = Identity::generate().node_id();
        (rejecter, initiator, init_transcript(b"a session init"))
    }

    #[test]
    fn test_the_transcript_changes_with_the_init() {
        assert_ne!(init_transcript(b"init one"), init_transcript(b"init two"));
        // Length-prefixed, so appending cannot be hidden by a split.
        assert_ne!(init_transcript(b"ab"), init_transcript(b"a"));
    }

    #[test]
    fn test_a_signed_rejection_verifies() {
        let (rejecter, initiator, id) = setup();
        let reason = SessionRejectReason::StaleSignedPrekey;
        let signature = sign_reject(&rejecter, &id, &initiator, reason);
        assert_eq!(
            verify_reject(
                &rejecter.public_key_bytes(),
                &id,
                &initiator,
                &rejecter.node_id(),
                reason,
                &signature,
            ),
            Ok(())
        );
    }

    #[test]
    fn test_a_rejection_is_bound_to_its_handshake_and_both_parties() {
        let (rejecter, initiator, id) = setup();
        let reason = SessionRejectReason::DecryptFailed;
        let signature = sign_reject(&rejecter, &id, &initiator, reason);
        let key = rejecter.public_key_bytes();
        let me = rejecter.node_id();

        // A different SessionInit — including the malformed one an attacker
        // would have to send to provoke a rejection at all.
        let other = init_transcript(b"a malformed session init");
        assert_eq!(
            verify_reject(&key, &other, &initiator, &me, reason, &signature),
            Err(RejectRejection::BadSignature)
        );
        // A different initiator: it cannot be relayed to someone else.
        let other_initiator = Identity::generate().node_id();
        assert_eq!(
            verify_reject(&key, &id, &other_initiator, &me, reason, &signature),
            Err(RejectRejection::BadSignature)
        );
        // A different reason: the stated cause is covered too, so it cannot
        // be rewritten to one with a different recovery path.
        assert_eq!(
            verify_reject(
                &key,
                &id,
                &initiator,
                &me,
                SessionRejectReason::UnknownOneTimePrekey,
                &signature,
            ),
            Err(RejectRejection::BadSignature)
        );
        // And a different signer cannot stand in for the rejecter.
        let impostor = Identity::generate();
        assert_eq!(
            verify_reject(
                &impostor.public_key_bytes(),
                &id,
                &initiator,
                &impostor.node_id(),
                reason,
                &signature,
            ),
            Err(RejectRejection::BadSignature)
        );
    }

    #[test]
    fn test_a_key_that_is_not_a_point_is_refused_not_panicked_on() {
        // `[0xFF; 32]` happens to decompress, so the refusal it earns is
        // `BadSignature`; a key that does not decode at all earns
        // `MalformedIdentityKey`. Either way nothing panics and nothing is
        // accepted, which is what an ingress path needs.
        let (rejecter, initiator, id) = setup();
        let reason = SessionRejectReason::DecryptFailed;
        let signature = sign_reject(&rejecter, &id, &initiator, reason);
        for key in [[0xFFu8; 32], [0u8; 32], [1u8; 32]] {
            assert!(
                verify_reject(
                    &key,
                    &id,
                    &initiator,
                    &rejecter.node_id(),
                    reason,
                    &signature,
                )
                .is_err(),
                "a key we did not sign with must never verify"
            );
        }
    }
}
