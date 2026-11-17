//! Group discovery: the key behind a shared passphrase, the hint a beacon
//! carries, and the proof of possession that hint cannot give (ADR-019).

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use mycelium_protocol::types::NodeId;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Bytes of the discovery hint a beacon advertises.
pub const GROUP_HINT_LEN: usize = 8;

/// Bytes of a challenge nonce.
pub const GROUP_NONCE_LEN: usize = 32;

/// Derive a 32-byte group discovery key from a passphrase using HKDF.
///
/// Same passphrase always produces the same key, which is what lets two nodes
/// that were never introduced recognise each other.
///
/// This is *not* a password hash: one HKDF extract-and-expand, no salt and no
/// iterations. Every beacon publishes [`group_discovery_hint`] of the result,
/// so a guessable passphrase can be recovered offline from eight bytes
/// overheard once, and a recovered key answers [`group_proof_mac`] correctly.
/// The passphrase has to carry real entropy; see ROADMAP T-52.
pub fn derive_group_discovery_key(passphrase: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, passphrase.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"MyceliumGroupDiscovery", &mut key)
        .expect("HKDF expansion failed");
    key
}

/// The hint a beacon carries for a group key (§10.1): the first eight bytes of
/// `SHA-256(key)`.
///
/// One-way and static, and it grants nothing on its own — anyone in radio
/// range can copy it, which is why a match is only a hint and the vouch waits
/// for [`group_proof_mac`] (ADR-019).
pub fn group_discovery_hint(group_key: &[u8; 32]) -> [u8; GROUP_HINT_LEN] {
    let digest = Sha256::digest(group_key);
    let mut hint = [0u8; GROUP_HINT_LEN];
    hint.copy_from_slice(&digest[..GROUP_HINT_LEN]);
    hint
}

/// The MAC key behind a group key.
///
/// Separated from the hint by its own info string: the hint is a public
/// SHA-256 of the key, this is an HKDF output under `MyceliumGroupProof`, and
/// neither reveals the other. Without the separation the one value a group
/// broadcasts in the clear and the key it authenticates challenges with would
/// be two uses of the same secret in two constructions, which is the shape
/// that eventually collides (ADR-019).
pub fn derive_group_proof_key(group_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, group_key);
    let mut key = [0u8; 32];
    hk.expand(b"MyceliumGroupProof", &mut key)
        .expect("HKDF expansion failed");
    key
}

/// The answer a challenge requires: `HMAC(proof_key, nonce ‖ verifier ‖
/// responder)`.
///
/// Both ends of the pairing are in the MAC, and each side supplies them from
/// its own view rather than from the wire: the responder always MACs the peer
/// that asked and *itself*, the verifier always checks itself and the peer it
/// asked. An answer therefore belongs to exactly one pairing in one direction,
/// so a response collected by asking a real member cannot be handed on as
/// one's own — the two ids would have to swap places (ADR-019).
pub fn group_proof_mac(
    proof_key: &[u8; 32],
    nonce: &[u8; GROUP_NONCE_LEN],
    verifier: &NodeId,
    responder: &NodeId,
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(proof_key).expect("HMAC takes a key of any length");
    mac.update(nonce);
    mac.update(verifier.as_bytes());
    mac.update(responder.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Whether `answer` is the response this pairing's challenge requires.
///
/// Constant-time, and false for an answer of the wrong length rather than a
/// panic: the caller is an ingress path and the answer came off a radio.
pub fn verify_group_proof(
    proof_key: &[u8; 32],
    nonce: &[u8; GROUP_NONCE_LEN],
    verifier: &NodeId,
    responder: &NodeId,
    answer: &[u8],
) -> bool {
    let mut mac = HmacSha256::new_from_slice(proof_key).expect("HMAC takes a key of any length");
    mac.update(nonce);
    mac.update(verifier.as_bytes());
    mac.update(responder.as_bytes());
    mac.verify_slice(answer).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (NodeId, NodeId) {
        (NodeId::from_bytes([1u8; 32]), NodeId::from_bytes([2u8; 32]))
    }

    #[test]
    fn test_same_passphrase_same_key() {
        let k1 = derive_group_discovery_key("secret community");
        let k2 = derive_group_discovery_key("secret community");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_different_passphrase_different_key() {
        let k1 = derive_group_discovery_key("secret community");
        let k2 = derive_group_discovery_key("other community");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_key_is_nonzero() {
        let k = derive_group_discovery_key("test");
        assert_ne!(k, [0u8; 32]);
    }

    #[test]
    fn test_the_hint_is_not_the_key() {
        let key = derive_group_discovery_key("secret community");
        let hint = group_discovery_hint(&key);
        assert_ne!(hint, key[..GROUP_HINT_LEN]);
    }

    /// The one value a group broadcasts must not be the key it authenticates
    /// challenges with, nor anything derivable from it in that direction.
    #[test]
    fn test_the_proof_key_is_separated_from_the_hint() {
        let key = derive_group_discovery_key("secret community");
        let proof_key = derive_group_proof_key(&key);
        assert_ne!(proof_key, key);
        assert_ne!(proof_key[..GROUP_HINT_LEN], group_discovery_hint(&key));
        // Not the same derivation as the discovery key itself, either: the
        // group key is the IKM here, the passphrase is there.
        assert_ne!(proof_key, derive_group_discovery_key("secret community"));
    }

    #[test]
    fn test_the_right_answer_verifies() {
        let proof_key = derive_group_proof_key(&derive_group_discovery_key("phrase"));
        let (verifier, responder) = ids();
        let nonce = [7u8; GROUP_NONCE_LEN];
        let mac = group_proof_mac(&proof_key, &nonce, &verifier, &responder);
        assert!(verify_group_proof(
            &proof_key, &nonce, &verifier, &responder, &mac
        ));
    }

    #[test]
    fn test_every_input_changes_the_answer() {
        let proof_key = derive_group_proof_key(&derive_group_discovery_key("phrase"));
        let (verifier, responder) = ids();
        let nonce = [7u8; GROUP_NONCE_LEN];
        let mac = group_proof_mac(&proof_key, &nonce, &verifier, &responder);

        let other_key = derive_group_proof_key(&derive_group_discovery_key("other"));
        assert_ne!(
            mac,
            group_proof_mac(&other_key, &nonce, &verifier, &responder)
        );
        assert_ne!(
            mac,
            group_proof_mac(&proof_key, &[8u8; GROUP_NONCE_LEN], &verifier, &responder)
        );
        assert_ne!(
            mac,
            group_proof_mac(
                &proof_key,
                &nonce,
                &NodeId::from_bytes([9u8; 32]),
                &responder
            )
        );
        assert_ne!(
            mac,
            group_proof_mac(
                &proof_key,
                &nonce,
                &verifier,
                &NodeId::from_bytes([9u8; 32])
            )
        );
    }

    /// The reason a node can answer a stranger's challenge at all: what it
    /// hands back has its own id in the responder's place, and nothing can
    /// move it to the verifier's.
    #[test]
    fn test_an_answer_cannot_be_lifted_into_the_other_direction() {
        let proof_key = derive_group_proof_key(&derive_group_discovery_key("phrase"));
        let (attacker, member) = ids();
        let nonce = [7u8; GROUP_NONCE_LEN];

        // What a member hands an attacker that challenged it.
        let collected = group_proof_mac(&proof_key, &nonce, &attacker, &member);

        // What the attacker would have to produce to be vouched by that same
        // member, for the very same nonce.
        assert!(!verify_group_proof(
            &proof_key, &nonce, &member, &attacker, &collected
        ));
    }

    #[test]
    fn test_a_wrong_or_misshapen_answer_is_refused() {
        let proof_key = derive_group_proof_key(&derive_group_discovery_key("phrase"));
        let (verifier, responder) = ids();
        let nonce = [7u8; GROUP_NONCE_LEN];
        let mac = group_proof_mac(&proof_key, &nonce, &verifier, &responder);

        let mut flipped = mac;
        flipped[31] ^= 1;
        assert!(!verify_group_proof(
            &proof_key, &nonce, &verifier, &responder, &flipped
        ));
        // A prefix of the right answer is not the right answer, and does not
        // panic its way out of the ingress path either.
        assert!(!verify_group_proof(
            &proof_key,
            &nonce,
            &verifier,
            &responder,
            &mac[..16]
        ));
        assert!(!verify_group_proof(
            &proof_key,
            &nonce,
            &verifier,
            &responder,
            &[]
        ));
    }
}
