//! Emergency broadcast identity, co-signatures and freshness.
//!
//! A level-3 broadcast floods the entire mesh and bypasses routing rules
//! (MYCELIUM_SPEC.md §9.5), so it requires three co-signers the receiver
//! trusts above 0.8. Carrying bare NodeIds proved nothing: anyone could list
//! three trusted ids they did not control. Co-signers now sign the broadcast
//! and the receiver verifies every signature (ROADMAP T-05, ADR-010).
//!
//! The digest those signatures cover also *identifies* the broadcast, so the
//! receiver keys flood dedup on it rather than on the envelope's cleartext
//! `message_id` (ADR-013), and it includes `signed_at` so a captured alert
//! stops being acceptable once `EMERGENCY_VALIDITY_SECS` has passed
//! (ROADMAP T-36).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use mycelium_protocol::types::{MessageId, NodeId};
use mycelium_protocol::wire::{
    EmergencyCosigner, EmergencyLevel, EMERGENCY_BROADCAST_CONTEXT, EMERGENCY_ORIGIN_CONTEXT,
};

use crate::identity::{node_id_from_public_key, Identity};

/// How long an emergency broadcast stays acceptable after it was raised.
///
/// It bounds replay: a captured alert is refused once it has passed, which is
/// what lets the flood-dedup set evict entries by age instead of keeping
/// every id it has ever seen. Same value as a DHT record's TTL (ADR-011).
pub const EMERGENCY_VALIDITY_SECS: u64 = 3600;

/// How far ahead of the local clock a broadcast may be dated.
///
/// Covers ordinary clock skew without letting an originator park an alert
/// that outlives every honest one (ADR-011's rule for signed records).
pub const EMERGENCY_MAX_CLOCK_SKEW_SECS: u64 = 300;

/// What identifies one emergency broadcast.
///
/// Every field is covered by the digest, so a copy differing in any of them
/// is a different broadcast — to a co-signature and to flood dedup alike.
#[derive(Debug, Clone, Copy)]
pub struct BroadcastContext<'a> {
    /// The envelope's `message_id`. Not repeated in the body.
    pub broadcast_id: &'a MessageId,
    pub originator: &'a NodeId,
    pub level: EmergencyLevel,
    /// Unix seconds at which the originator raised the alert.
    pub signed_at: u64,
    pub message: &'a [u8],
}

/// The digest that identifies a broadcast: what a co-signer signs, and what a
/// receiver keys flood dedup on.
///
/// Binds the approval to **this** broadcast: its id, the originator, the
/// level, when it was raised and the exact message.
///
/// - **`broadcast_id`** stops an approval being lifted onto another alert.
/// - **`originator`** stops it being reused by a different sender.
/// - **`level`** stops a level-1 approval being promoted to level 3.
/// - **`signed_at`** bounds replay in time. Without it a captured alert
///   verified forever, and the only thing standing between it and a second
///   mesh-wide flood was a dedup set that cleared itself at 10 000 entries.
/// - **`message_len`** before `message` stops a length-extension ambiguity
///   between two broadcasts whose concatenated fields coincide.
pub fn broadcast_digest(ctx: &BroadcastContext<'_>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EMERGENCY_BROADCAST_CONTEXT);
    hasher.update(ctx.broadcast_id.as_bytes());
    hasher.update(ctx.originator.as_bytes());
    hasher.update([ctx.level as u8]);
    hasher.update(ctx.signed_at.to_le_bytes());
    hasher.update((ctx.message.len() as u32).to_le_bytes());
    hasher.update(ctx.message);
    hasher.finalize().into()
}

/// Co-sign a level-3 broadcast.
pub fn cosign(signer: &Identity, ctx: &BroadcastContext<'_>) -> EmergencyCosigner {
    let digest = broadcast_digest(ctx);
    EmergencyCosigner {
        node_id: signer.node_id(),
        signature: signer.sign(&digest).to_bytes(),
    }
}

/// The bytes the **originator** signs: the alert, and the approval list it
/// collected.
///
/// Signing the alert digest alone would leave the approvals unauthenticated,
/// so a relay could forward a copy carrying fewer of them — and if the ones it
/// kept were verifiable here but not downstream, that node would refuse an
/// alert the full set would have satisfied (ADR-013, ADR-014).
///
/// There is no circularity: a co-signer signs `broadcast_digest`, which does
/// not include the list, and the originator signs last, over what it
/// collected. For levels 1 and 2 the list is empty and signing is immediate.
///
/// This digest is deliberately **not** the flood-dedup identity. Holding the
/// signing key, an originator could otherwise pad the list with junk entries
/// and re-sign, minting arbitrarily many identities for one alert — each
/// accepted, each flooded — with no new co-signatures. One alert is one entry,
/// keyed on `broadcast_digest`, however its approvals are presented.
pub fn origin_digest(alert: &[u8; 32], cosigners: &[EmergencyCosigner]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EMERGENCY_ORIGIN_CONTEXT);
    hasher.update(alert);
    hasher.update([cosigners.len() as u8]);
    for cosigner in cosigners {
        hasher.update(cosigner.node_id.as_bytes());
        hasher.update(cosigner.signature);
    }
    hasher.finalize().into()
}

/// Sign a broadcast as its originator.
pub fn sign_broadcast(
    signer: &Identity,
    ctx: &BroadcastContext<'_>,
    cosigners: &[EmergencyCosigner],
) -> [u8; 64] {
    let digest = origin_digest(&broadcast_digest(ctx), cosigners);
    signer.sign(&digest).to_bytes()
}

/// Why a broadcast's origin was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginRejection {
    /// The carried key is not a valid Ed25519 point.
    MalformedIdentityKey,
    /// The carried key does not hash to the claimed source NodeId.
    IdentityMismatch,
    /// The signature does not verify over the origin digest.
    BadSignature,
}

/// Verify that `source` really raised this alert, with these approvals.
///
/// The key is carried in the broadcast rather than looked up, so a receiver
/// with no prior contact can still check it; what makes that safe is the
/// binding `SHA-256(identity_key) == source`, the rule every other ingress
/// path enforces (MYCELIUM_SPEC.md §14.3).
pub fn verify_origin(
    identity_key: &[u8; 32],
    source: &NodeId,
    ctx: &BroadcastContext<'_>,
    cosigners: &[EmergencyCosigner],
    signature: &[u8; 64],
) -> Result<(), OriginRejection> {
    if node_id_from_public_key(identity_key) != *source {
        return Err(OriginRejection::IdentityMismatch);
    }
    let verifying = VerifyingKey::from_bytes(identity_key)
        .map_err(|_| OriginRejection::MalformedIdentityKey)?;
    let digest = origin_digest(&broadcast_digest(ctx), cosigners);
    verifying
        .verify(&digest, &Signature::from_bytes(signature))
        .map_err(|_| OriginRejection::BadSignature)
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
    ctx: &BroadcastContext<'_>,
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
    let digest = broadcast_digest(ctx);

    verifying
        .verify(&digest, &signature)
        .map_err(|_| CosignerRejection::BadSignature)
}

/// Why a broadcast was refused on its date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessRejection {
    /// Dated further ahead than `EMERGENCY_MAX_CLOCK_SKEW_SECS`.
    FromFuture,
    /// Raised more than `EMERGENCY_VALIDITY_SECS` ago.
    Expired,
}

/// Bound a broadcast's `signed_at` against the local clock.
///
/// Both ends matter. Without the upper bound an attacker could post-date a
/// captured alert and have it outlive every honest one; without the lower
/// bound a year-old alert, co-signatures and all, would still verify.
pub fn check_freshness(signed_at: u64, now: u64) -> Result<(), FreshnessRejection> {
    if signed_at > now.saturating_add(EMERGENCY_MAX_CLOCK_SKEW_SECS) {
        return Err(FreshnessRejection::FromFuture);
    }
    if now > signed_at.saturating_add(EMERGENCY_VALIDITY_SECS) {
        return Err(FreshnessRejection::Expired);
    }
    Ok(())
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
        let signer = Identity::generate();
        Fixture {
            // The same identity stands in for the originator and the
            // co-signer here; the origin tests need a key that hashes to the
            // source, and the co-signature tests do not care.
            originator: signer.node_id(),
            signer,
            broadcast_id: MessageId::random(),
            message: b"flood warning".to_vec(),
        }
    }

    impl Fixture {
        fn ctx(&self) -> BroadcastContext<'_> {
            BroadcastContext {
                broadcast_id: &self.broadcast_id,
                originator: &self.originator,
                level: EmergencyLevel::Critical,
                signed_at: 1_762_000_000,
                message: &self.message,
            }
        }
    }

    fn verify(
        f: &Fixture,
        cs: &EmergencyCosigner,
        key: Option<[u8; 32]>,
    ) -> Result<(), CosignerRejection> {
        verify_cosigner(cs, key, &f.ctx())
    }

    fn sign(f: &Fixture) -> EmergencyCosigner {
        cosign(&f.signer, &f.ctx())
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

    /// A signature must not transfer to another message, level, originator or
    /// time.
    #[test]
    fn test_signature_is_bound_to_the_broadcast() {
        let f = setup();
        let cs = sign(&f);
        let key = Some(f.signer.public_key_bytes());
        let other = Identity::generate().node_id();

        let cases: [(&str, BroadcastContext<'_>); 4] = [
            (
                "must not transfer to another message",
                BroadcastContext {
                    message: b"different message",
                    ..f.ctx()
                },
            ),
            (
                "must not transfer to another level",
                BroadcastContext {
                    level: EmergencyLevel::Urgent,
                    ..f.ctx()
                },
            ),
            (
                "must not transfer to another originator",
                BroadcastContext {
                    originator: &other,
                    ..f.ctx()
                },
            ),
            (
                "must not transfer to another signing time",
                BroadcastContext {
                    signed_at: f.ctx().signed_at + 1,
                    ..f.ctx()
                },
            ),
        ];

        for (why, ctx) in cases {
            assert_eq!(
                verify_cosigner(&cs, key, &ctx),
                Err(CosignerRejection::BadSignature),
                "{why}"
            );
        }
    }

    /// An intercepted critical alert must not be re-floodable under a fresh
    /// envelope id: the receiver's dedup set is keyed on the digest, so a
    /// content-only digest would let the same approval be replayed forever.
    #[test]
    fn test_signature_cannot_be_replayed_under_a_new_broadcast_id() {
        let f = setup();
        let cs = sign(&f);
        let other_id = MessageId::random();
        assert_eq!(
            verify_cosigner(
                &cs,
                Some(f.signer.public_key_bytes()),
                &BroadcastContext {
                    broadcast_id: &other_id,
                    ..f.ctx()
                }
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

    /// A relay must not be able to edit the approval list: the originator's
    /// signature covers it, so stripping or padding breaks the alert.
    #[test]
    fn test_the_origin_signature_covers_the_approval_list() {
        let f = setup();
        let approvals = vec![sign(&f), sign(&f)];
        let signature = sign_broadcast(&f.signer, &f.ctx(), &approvals);
        let key = f.signer.public_key_bytes();
        let source = f.signer.node_id();

        assert_eq!(
            verify_origin(&key, &source, &f.ctx(), &approvals, &signature),
            Ok(())
        );
        assert_eq!(
            verify_origin(&key, &source, &f.ctx(), &approvals[..1], &signature),
            Err(OriginRejection::BadSignature),
            "a stripped approval list must break the origin signature"
        );
        let mut padded = approvals.clone();
        padded.push(EmergencyCosigner {
            node_id: NodeId([4u8; 32]),
            signature: [5u8; 64],
        });
        assert_eq!(
            verify_origin(&key, &source, &f.ctx(), &padded, &signature),
            Err(OriginRejection::BadSignature),
            "a padded approval list must break it too"
        );
    }

    /// The carried key is only worth anything because it is bound to the id it
    /// claims. Without that check an attacker signs with a key of its own.
    #[test]
    fn test_the_origin_key_must_hash_to_the_claimed_source() {
        let f = setup();
        let signature = sign_broadcast(&f.signer, &f.ctx(), &[]);
        assert_eq!(
            verify_origin(
                &f.signer.public_key_bytes(),
                &NodeId([9u8; 32]),
                &f.ctx(),
                &[],
                &signature
            ),
            Err(OriginRejection::IdentityMismatch)
        );

        // An attacker's own key, over an alert claiming someone else.
        let attacker = Identity::generate();
        let forged = sign_broadcast(&attacker, &f.ctx(), &[]);
        assert_eq!(
            verify_origin(
                &attacker.public_key_bytes(),
                &f.signer.node_id(),
                &f.ctx(),
                &[],
                &forged
            ),
            Err(OriginRejection::IdentityMismatch),
            "a signature by the wrong key must not pass as the claimed source"
        );
    }

    /// An origin signature must not transfer to another alert.
    #[test]
    fn test_the_origin_signature_is_bound_to_the_alert() {
        let f = setup();
        let signature = sign_broadcast(&f.signer, &f.ctx(), &[]);
        let key = f.signer.public_key_bytes();
        let source = f.signer.node_id();
        let other_id = MessageId::random();

        for (why, ctx) in [
            (
                "another message",
                BroadcastContext {
                    message: b"different",
                    ..f.ctx()
                },
            ),
            (
                "another level",
                BroadcastContext {
                    level: EmergencyLevel::Priority,
                    ..f.ctx()
                },
            ),
            (
                "another id",
                BroadcastContext {
                    broadcast_id: &other_id,
                    ..f.ctx()
                },
            ),
            (
                "another date",
                BroadcastContext {
                    signed_at: f.ctx().signed_at + 1,
                    ..f.ctx()
                },
            ),
        ] {
            assert_eq!(
                verify_origin(&key, &source, &ctx, &[], &signature),
                Err(OriginRejection::BadSignature),
                "must not transfer to {why}"
            );
        }
    }

    /// The origin digest and the alert digest are different things, and the
    /// alert digest is what dedup keys on — see `origin_digest`.
    #[test]
    fn test_padding_approvals_does_not_change_the_alert_digest() {
        let f = setup();
        let alert = broadcast_digest(&f.ctx());
        let padded = vec![sign(&f)];
        assert_eq!(
            alert,
            broadcast_digest(&f.ctx()),
            "the alert digest does not depend on approvals"
        );
        assert_ne!(
            origin_digest(&alert, &[]),
            origin_digest(&alert, &padded),
            "the origin digest does"
        );
    }

    /// The freshness window is what makes age-based dedup eviction safe: once
    /// a broadcast is outside it, forgetting its digest costs nothing.
    #[test]
    fn test_freshness_bounds_both_ends() {
        let now = 1_762_000_000;
        assert_eq!(check_freshness(now, now), Ok(()));
        assert_eq!(
            check_freshness(now + EMERGENCY_MAX_CLOCK_SKEW_SECS, now),
            Ok(()),
            "skew up to the tolerance is accepted"
        );
        assert_eq!(
            check_freshness(now + EMERGENCY_MAX_CLOCK_SKEW_SECS + 1, now),
            Err(FreshnessRejection::FromFuture)
        );
        assert_eq!(
            check_freshness(now - EMERGENCY_VALIDITY_SECS, now),
            Ok(()),
            "exactly at the validity edge is still acceptable"
        );
        assert_eq!(
            check_freshness(now - EMERGENCY_VALIDITY_SECS - 1, now),
            Err(FreshnessRejection::Expired)
        );
    }

    /// A clock before 1970, or a `signed_at` near `u64::MAX`, must not panic
    /// or wrap into acceptance.
    #[test]
    fn test_freshness_saturates_at_the_extremes() {
        assert_eq!(check_freshness(0, 0), Ok(()));
        assert_eq!(
            check_freshness(u64::MAX, 0),
            Err(FreshnessRejection::FromFuture)
        );
        assert_eq!(
            check_freshness(0, u64::MAX),
            Err(FreshnessRejection::Expired)
        );
        assert_eq!(check_freshness(u64::MAX, u64::MAX), Ok(()));
    }
}
