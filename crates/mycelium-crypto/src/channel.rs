//! Keyed, authenticated transport channels.
//!
//! Used by the internet transport (spec §8.4, ADR-011). Two problems make a
//! signature-only handshake insufficient there:
//!
//! 1. **A signature over exchanged nonces can be relayed.** An attacker that
//!    sits between two honest nodes chooses *its* nonce last on each
//!    connection, so it can arrange for both nonce pairs to coincide and
//!    present a victim's signed hello as its own. Ordering the nonces in the
//!    signed payload does not help: the attacker simply waits.
//! 2. **TCP gives no integrity.** Even a perfect handshake only authenticates
//!    the first frame; anything on the path can inject or alter later ones.
//!
//! Both are closed the same way: each side signs a fresh X25519 **ephemeral
//! public key**, and every frame after the handshake is AEAD-protected under a
//! key derived from the resulting shared secret. A relay can forward a
//! victim's signed hello, but it cannot derive the key without the victim's
//! ephemeral secret, so it cannot send or read a single frame. Authentication
//! is bound to the channel rather than to a replayable transcript.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::{Zeroize, Zeroizing};

/// Domain separation for the signature over an ephemeral key.
pub const CHANNEL_HELLO_CONTEXT: &[u8] = b"mycelium-internet-hello-v2:";

/// Domain separation for the channel transcript.
pub const CHANNEL_TRANSCRIPT_CONTEXT: &[u8] = b"mycelium-internet-channel-v1:";

/// Bytes an AES-256-GCM tag adds to every sealed frame.
pub const AEAD_TAG_LEN: usize = 16;

/// Something went wrong establishing or using a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    /// The peer's ephemeral key produced an all-zero shared secret. Only a
    /// low-order or zero point does that, and no honest peer sends one.
    #[error("peer offered a degenerate ephemeral key")]
    DegenerateKey,
    /// The peer reused our own ephemeral key, which would make both
    /// directions share one key stream.
    #[error("peer echoed our ephemeral key")]
    EchoedKey,
    /// AEAD open failed: a forged, altered, reordered or replayed frame.
    #[error("frame failed authentication")]
    FrameAuthFailed,
    /// The frame counter is exhausted. Unreachable in practice (2^64 frames).
    #[error("frame counter exhausted")]
    CounterExhausted,
    /// The peer's key-confirmation frame did not match our transcript.
    #[error("channel confirmation did not match")]
    ConfirmationMismatch,
}

/// The exact bytes a channel hello signature covers.
///
/// The ephemeral key is the only freshness the handshake needs: it is new per
/// connection, and it is what the frame keys come from, so a replayed hello
/// buys an attacker a channel it cannot speak on.
pub fn channel_hello_payload(
    ephemeral_public: &[u8; 32],
    identity_key: &[u8; 32],
    listen_port: u16,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(CHANNEL_HELLO_CONTEXT.len() + 32 + 32 + 2);
    payload.extend_from_slice(CHANNEL_HELLO_CONTEXT);
    payload.extend_from_slice(ephemeral_public);
    payload.extend_from_slice(identity_key);
    payload.extend_from_slice(&listen_port.to_le_bytes());
    payload
}

/// Our half of a channel handshake: an ephemeral keypair awaiting the peer's.
pub struct ChannelHandshake {
    secret: EphemeralSecret,
    public: [u8; 32],
}

impl ChannelHandshake {
    /// Generate a fresh ephemeral keypair for one connection.
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = *X25519PublicKey::from(&secret).as_bytes();
        Self { secret, public }
    }

    /// The ephemeral public key to put in our hello.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Complete the handshake against the peer's hello.
    ///
    /// `identity_key` pairs are folded into the transcript in sorted order, so
    /// both ends derive the same keys without needing to agree on who dialled.
    pub fn complete(
        self,
        peer_ephemeral: &[u8; 32],
        my_identity_key: &[u8; 32],
        peer_identity_key: &[u8; 32],
    ) -> Result<ChannelKeys, ChannelError> {
        if *peer_ephemeral == self.public {
            return Err(ChannelError::EchoedKey);
        }
        let shared = Zeroizing::new(
            *self
                .secret
                .diffie_hellman(&X25519PublicKey::from(*peer_ephemeral))
                .as_bytes(),
        );
        if shared.iter().all(|b| *b == 0) {
            return Err(ChannelError::DegenerateKey);
        }

        let transcript = channel_transcript(
            &self.public,
            peer_ephemeral,
            my_identity_key,
            peer_identity_key,
        );
        let hk = Hkdf::<Sha256>::new(Some(&transcript), shared.as_ref());

        // Each side's send key is labelled with its own ephemeral key, so the
        // peer's receive key matches it without either side knowing its role.
        let mut send = Zeroizing::new([0u8; 32]);
        let mut recv = Zeroizing::new([0u8; 32]);
        hk.expand(&frame_info(&self.public), send.as_mut())
            .expect("32 bytes is a valid HKDF length");
        hk.expand(&frame_info(peer_ephemeral), recv.as_mut())
            .expect("32 bytes is a valid HKDF length");

        Ok(ChannelKeys {
            transcript,
            send: FrameCipher::new(*send),
            recv: FrameCipher::new(*recv),
        })
    }
}

impl Default for ChannelHandshake {
    fn default() -> Self {
        Self::new()
    }
}

fn frame_info(ephemeral_public: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::with_capacity(6 + 32);
    info.extend_from_slice(b"frame:");
    info.extend_from_slice(ephemeral_public);
    info
}

/// The order-independent hash of what both sides exchanged.
fn channel_transcript(
    my_ephemeral: &[u8; 32],
    peer_ephemeral: &[u8; 32],
    my_identity_key: &[u8; 32],
    peer_identity_key: &[u8; 32],
) -> [u8; 32] {
    let (eph_lo, eph_hi) = sorted(my_ephemeral, peer_ephemeral);
    let (id_lo, id_hi) = sorted(my_identity_key, peer_identity_key);
    let mut hasher = Sha256::new();
    hasher.update(CHANNEL_TRANSCRIPT_CONTEXT);
    hasher.update(eph_lo);
    hasher.update(eph_hi);
    hasher.update(id_lo);
    hasher.update(id_hi);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn sorted<'a>(a: &'a [u8; 32], b: &'a [u8; 32]) -> (&'a [u8; 32], &'a [u8; 32]) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// The two directional ciphers for an established channel.
pub struct ChannelKeys {
    /// What both ends must agree on, sent once as key confirmation.
    pub transcript: [u8; 32],
    pub send: FrameCipher,
    pub recv: FrameCipher,
}

/// One direction of a channel: AES-256-GCM with a strictly increasing counter.
///
/// The counter is the nonce, so it is never reused under one key, and the
/// receiver tracks its own counter independently. TCP already guarantees
/// ordering, so a frame that arrives out of order, twice, or forged simply
/// fails to open — replay and reordering need no separate detection.
pub struct FrameCipher {
    key: [u8; 32],
    counter: u64,
}

impl FrameCipher {
    fn new(key: [u8; 32]) -> Self {
        Self { key, counter: 0 }
    }

    /// The number of frames sealed or opened so far.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    fn nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// Seal the next frame.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ChannelError> {
        let cipher =
            Aes256Gcm::new_from_slice(&self.key).map_err(|_| ChannelError::FrameAuthFailed)?;
        let nonce = Self::nonce(self.counter);
        let sealed = cipher
            .encrypt(
                aes_gcm::Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|_| ChannelError::FrameAuthFailed)?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(ChannelError::CounterExhausted)?;
        Ok(sealed)
    }

    /// Open the next frame. The counter advances only on success, so a forged
    /// frame cannot desynchronise the channel.
    pub fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, ChannelError> {
        let cipher =
            Aes256Gcm::new_from_slice(&self.key).map_err(|_| ChannelError::FrameAuthFailed)?;
        let nonce = Self::nonce(self.counter);
        let plaintext = cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(&nonce),
                Payload {
                    msg: sealed,
                    aad: &[],
                },
            )
            .map_err(|_| ChannelError::FrameAuthFailed)?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(ChannelError::CounterExhausted)?;
        Ok(plaintext)
    }
}

impl Drop for FrameCipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    /// Run a handshake between two parties and return both key sets.
    fn pair() -> (ChannelKeys, ChannelKeys) {
        let a_identity = Identity::generate();
        let b_identity = Identity::generate();
        let a = ChannelHandshake::new();
        let b = ChannelHandshake::new();
        let (a_pub, b_pub) = (a.public_key(), b.public_key());
        let a_keys = a
            .complete(
                &b_pub,
                &a_identity.public_key_bytes(),
                &b_identity.public_key_bytes(),
            )
            .unwrap();
        let b_keys = b
            .complete(
                &a_pub,
                &b_identity.public_key_bytes(),
                &a_identity.public_key_bytes(),
            )
            .unwrap();
        (a_keys, b_keys)
    }

    #[test]
    fn test_both_sides_derive_the_same_transcript() {
        let (a, b) = pair();
        assert_eq!(a.transcript, b.transcript);
    }

    #[test]
    fn test_frames_round_trip_in_both_directions() {
        let (mut a, mut b) = pair();
        let sealed = a.send.seal(b"hello").unwrap();
        assert_eq!(b.recv.open(&sealed).unwrap(), b"hello");
        let back = b.send.seal(b"and back").unwrap();
        assert_eq!(a.recv.open(&back).unwrap(), b"and back");
    }

    #[test]
    fn test_the_two_directions_use_different_keys() {
        let (mut a, mut b) = pair();
        let sealed = a.send.seal(b"one way").unwrap();
        // Opening with the wrong direction's cipher must fail, or the two
        // directions would share a key stream.
        assert_eq!(
            a.recv.open(&sealed),
            Err(ChannelError::FrameAuthFailed),
            "a frame we sealed must not open with our own receive key"
        );
        assert!(b.recv.open(&sealed).is_ok());
    }

    #[test]
    fn test_an_altered_frame_does_not_open() {
        let (mut a, mut b) = pair();
        let mut sealed = a.send.seal(b"important").unwrap();
        sealed[0] ^= 0x01;
        assert_eq!(b.recv.open(&sealed), Err(ChannelError::FrameAuthFailed));
    }

    #[test]
    fn test_a_replayed_frame_does_not_open() {
        let (mut a, mut b) = pair();
        let first = a.send.seal(b"one").unwrap();
        let _second = a.send.seal(b"two").unwrap();
        assert!(b.recv.open(&first).is_ok());
        assert_eq!(
            b.recv.open(&first),
            Err(ChannelError::FrameAuthFailed),
            "the counter is the nonce, so a repeat cannot open"
        );
    }

    #[test]
    fn test_a_reordered_frame_does_not_open() {
        let (mut a, mut b) = pair();
        let first = a.send.seal(b"one").unwrap();
        let second = a.send.seal(b"two").unwrap();
        assert_eq!(
            b.recv.open(&second),
            Err(ChannelError::FrameAuthFailed),
            "frames must open in order"
        );
        // A failed open must not have advanced the counter.
        assert!(b.recv.open(&first).is_ok());
        assert!(b.recv.open(&second).is_ok());
    }

    #[test]
    fn test_a_relayed_hello_yields_no_usable_channel() {
        // The attack a nonce-signature handshake cannot stop: the attacker
        // forwards the victim's signed hello as its own. It completes the
        // handshake and then cannot speak, because the key comes from an
        // ephemeral secret it does not hold.
        let victim_identity = Identity::generate();
        let server_identity = Identity::generate();

        let victim = ChannelHandshake::new();
        let victim_public = victim.public_key();

        let server = ChannelHandshake::new();
        let server_public = server.public_key();

        // The server believes it is talking to the victim, and derives keys
        // from the victim's relayed ephemeral key.
        let mut server_keys = server
            .complete(
                &victim_public,
                &server_identity.public_key_bytes(),
                &victim_identity.public_key_bytes(),
            )
            .unwrap();

        // The attacker holds its own ephemeral secret, not the victim's.
        let attacker = ChannelHandshake::new();
        let mut attacker_keys = attacker
            .complete(
                &server_public,
                &victim_identity.public_key_bytes(),
                &server_identity.public_key_bytes(),
            )
            .unwrap();

        assert_ne!(
            attacker_keys.transcript, server_keys.transcript,
            "the attacker cannot reproduce the transcript it claimed"
        );
        let forged = attacker_keys.send.seal(b"as the victim").unwrap();
        assert_eq!(
            server_keys.recv.open(&forged),
            Err(ChannelError::FrameAuthFailed),
            "a relayed hello must buy no ability to send"
        );
    }

    #[test]
    fn test_an_echoed_ephemeral_key_is_refused() {
        let identity = Identity::generate();
        let peer = Identity::generate();
        let handshake = ChannelHandshake::new();
        let own = handshake.public_key();
        assert_eq!(
            handshake
                .complete(&own, &identity.public_key_bytes(), &peer.public_key_bytes())
                .err(),
            Some(ChannelError::EchoedKey)
        );
    }

    #[test]
    fn test_a_zero_ephemeral_key_is_refused() {
        let identity = Identity::generate();
        let peer = Identity::generate();
        let handshake = ChannelHandshake::new();
        assert_eq!(
            handshake
                .complete(
                    &[0u8; 32],
                    &identity.public_key_bytes(),
                    &peer.public_key_bytes()
                )
                .err(),
            Some(ChannelError::DegenerateKey),
            "a low-order point would make the shared secret all zeros"
        );
    }

    #[test]
    fn test_the_transcript_binds_both_identities() {
        let a_identity = Identity::generate();
        let b_identity = Identity::generate();
        let impostor = Identity::generate();

        let a = ChannelHandshake::new();
        let b = ChannelHandshake::new();
        let (a_pub, b_pub) = (a.public_key(), b.public_key());

        let honest = a
            .complete(
                &b_pub,
                &a_identity.public_key_bytes(),
                &b_identity.public_key_bytes(),
            )
            .unwrap();
        // Same ephemeral exchange, but B's identity swapped for an impostor's.
        let mismatched = b
            .complete(
                &a_pub,
                &impostor.public_key_bytes(),
                &a_identity.public_key_bytes(),
            )
            .unwrap();
        assert_ne!(honest.transcript, mismatched.transcript);
    }

    #[test]
    fn test_the_signed_payload_covers_the_ephemeral_key_and_port() {
        let base = channel_hello_payload(&[1u8; 32], &[2u8; 32], 9736);
        assert_ne!(base, channel_hello_payload(&[9u8; 32], &[2u8; 32], 9736));
        assert_ne!(base, channel_hello_payload(&[1u8; 32], &[9u8; 32], 9736));
        assert_ne!(base, channel_hello_payload(&[1u8; 32], &[2u8; 32], 9737));
        assert!(base.starts_with(CHANNEL_HELLO_CONTEXT));
    }
}
