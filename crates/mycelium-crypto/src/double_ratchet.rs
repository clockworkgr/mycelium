use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroize;

use std::collections::HashMap;

/// Header sent with each ratchet message.
#[derive(Debug, Clone)]
pub struct RatchetHeader {
    /// Current ratchet DH public key.
    pub dh_public: [u8; 32],
    /// Number of messages in previous sending chain.
    pub previous_chain_length: u32,
    /// Message number in current sending chain.
    pub message_number: u32,
}

/// Upper bound on skipped message keys retained across all chains. Bounds
/// memory even if a peer legitimately drops many messages.
const MAX_SKIPPED_KEYS_TOTAL: usize = 2000;

/// The Double Ratchet state machine.
///
/// The raw key fields (`root_key`, both chain keys and every retained skipped
/// message key) are wiped on drop. They are plain `[u8; 32]` rather than
/// `Zeroizing` wrappers because the struct is serialized to a fixed byte
/// layout for storage; `Drop` keeps the layout while still clearing the
/// freed memory. `dh_secret` is an `x25519_dalek::StaticSecret`, which
/// zeroizes itself.
#[derive(Clone)]
pub struct RatchetState {
    /// Our current DH ratchet key pair.
    dh_secret: X25519Secret,
    dh_public: X25519Public,

    /// The remote party's current DH public key.
    remote_dh_public: Option<X25519Public>,

    /// Root key (32 bytes).
    root_key: [u8; 32],

    /// Sending chain key.
    chain_key_send: Option<[u8; 32]>,
    /// Receiving chain key.
    chain_key_recv: Option<[u8; 32]>,

    /// Number of messages sent in current sending chain.
    send_count: u32,
    /// Number of messages received in current receiving chain.
    recv_count: u32,
    /// Number of messages in previous sending chain.
    previous_send_count: u32,

    /// Skipped message keys for out-of-order decryption.
    /// Key: (dh_public_bytes, message_number) -> message_key
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,

    /// Maximum number of skipped message keys to store.
    max_skip: u32,
}

impl RatchetState {
    /// Initialize as the initiator (Alice) after X3DH.
    /// `shared_secret` is the X3DH output, `their_dh_public` is from the prekey bundle.
    pub fn init_alice(shared_secret: [u8; 32], their_signed_prekey: [u8; 32]) -> Self {
        let dh_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let dh_public = X25519Public::from(&dh_secret);
        let remote_dh_public = X25519Public::from(their_signed_prekey);

        // Perform DH and derive first root key + sending chain key
        let dh_output = dh_secret.diffie_hellman(&remote_dh_public);
        let (root_key, chain_key_send) = kdf_rk(&shared_secret, dh_output.as_bytes());

        Self {
            dh_secret,
            dh_public,
            remote_dh_public: Some(remote_dh_public),
            root_key,
            chain_key_send: Some(chain_key_send),
            chain_key_recv: None,
            send_count: 0,
            recv_count: 0,
            previous_send_count: 0,
            skipped_keys: HashMap::new(),
            max_skip: 1000,
        }
    }

    /// Initialize as the responder (Bob) after X3DH.
    pub fn init_bob(shared_secret: [u8; 32], our_signed_prekey_secret: X25519Secret) -> Self {
        let dh_public = X25519Public::from(&our_signed_prekey_secret);

        Self {
            dh_secret: our_signed_prekey_secret,
            dh_public,
            remote_dh_public: None,
            root_key: shared_secret,
            chain_key_send: None,
            chain_key_recv: None,
            send_count: 0,
            recv_count: 0,
            previous_send_count: 0,
            skipped_keys: HashMap::new(),
            max_skip: 1000,
        }
    }

    /// Encrypt a plaintext message.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(RatchetHeader, Vec<u8>), RatchetError> {
        let chain_key = self.chain_key_send.ok_or(RatchetError::NoSendingChain)?;

        let (new_chain_key, message_key) = kdf_ck(&chain_key);
        let message_key = zeroize::Zeroizing::new(message_key);
        self.chain_key_send = Some(new_chain_key);

        let header = RatchetHeader {
            dh_public: *self.dh_public.as_bytes(),
            previous_chain_length: self.previous_send_count,
            message_number: self.send_count,
        };

        self.send_count += 1;

        let ciphertext = encrypt_aead(&message_key, plaintext, ad, &header)?;

        Ok((header, ciphertext))
    }

    /// Decrypt a received message.
    ///
    /// State changes (DH ratchet step, chain advance, skipped-key bookkeeping)
    /// are committed only if the ciphertext authenticates. The header travels
    /// in cleartext, so a relay could otherwise desynchronize the session by
    /// flipping a bit in it.
    pub fn decrypt(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        let mut candidate = self.clone();
        let plaintext = candidate.decrypt_in_place(header, ciphertext, ad)?;
        *self = candidate;
        Ok(plaintext)
    }

    fn decrypt_in_place(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        // Check if we have a skipped message key for this
        let key = (header.dh_public, header.message_number);
        if let Some(message_key) = self.skipped_keys.remove(&key) {
            // `remove` moves the key out of the map, past the struct's `Drop`.
            let message_key = zeroize::Zeroizing::new(message_key);
            return decrypt_aead(&message_key, ciphertext, ad, header);
        }

        let their_dh = X25519Public::from(header.dh_public);

        // Do we need a DH ratchet step?
        let need_ratchet = match &self.remote_dh_public {
            Some(current) => current.as_bytes() != &header.dh_public,
            None => true,
        };

        if need_ratchet {
            // Skip any remaining messages in the current receiving chain
            if self.chain_key_recv.is_some() {
                self.skip_message_keys(header.previous_chain_length)?;
            }

            // DH ratchet step
            self.dh_ratchet(their_dh)?;
        }

        // Skip ahead in the receiving chain if needed
        self.skip_message_keys(header.message_number)?;

        // Derive the message key
        let chain_key = self.chain_key_recv.ok_or(RatchetError::NoReceivingChain)?;
        let (new_chain_key, message_key) = kdf_ck(&chain_key);
        let message_key = zeroize::Zeroizing::new(message_key);
        self.chain_key_recv = Some(new_chain_key);
        self.recv_count = header.message_number + 1;

        decrypt_aead(&message_key, ciphertext, ad, header)
    }

    /// Perform a DH ratchet step.
    fn dh_ratchet(&mut self, their_dh: X25519Public) -> Result<(), RatchetError> {
        self.previous_send_count = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;
        self.remote_dh_public = Some(their_dh);

        // Derive new receiving chain key
        let dh_recv = self.dh_secret.diffie_hellman(&their_dh);
        let (root_key, chain_key_recv) = kdf_rk(&self.root_key, dh_recv.as_bytes());
        self.root_key = root_key;
        self.chain_key_recv = Some(chain_key_recv);

        // Generate new DH key pair
        self.dh_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
        self.dh_public = X25519Public::from(&self.dh_secret);

        // Derive new sending chain key
        let dh_send = self.dh_secret.diffie_hellman(&their_dh);
        let (root_key, chain_key_send) = kdf_rk(&self.root_key, dh_send.as_bytes());
        self.root_key = root_key;
        self.chain_key_send = Some(chain_key_send);

        Ok(())
    }

    /// Skip message keys for out-of-order decryption.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        if let Some(chain_key) = &self.chain_key_recv {
            if until > self.recv_count.saturating_add(self.max_skip) {
                return Err(RatchetError::TooManySkippedKeys);
            }
            let to_skip = until.saturating_sub(self.recv_count) as usize;
            if self.skipped_keys.len().saturating_add(to_skip) > MAX_SKIPPED_KEYS_TOTAL {
                return Err(RatchetError::TooManySkippedKeys);
            }

            let remote_dh = self
                .remote_dh_public
                .as_ref()
                .ok_or(RatchetError::NoRemoteKey)?;
            let remote_dh_bytes = *remote_dh.as_bytes();

            let mut ck = zeroize::Zeroizing::new(*chain_key);
            while self.recv_count < until {
                let (new_ck, mk) = kdf_ck(&ck);
                self.skipped_keys
                    .insert((remote_dh_bytes, self.recv_count), mk);
                *ck = new_ck;
                self.recv_count += 1;
            }
            self.chain_key_recv = Some(*ck);
        }
        Ok(())
    }

    /// Get our current DH public key.
    pub fn our_public_key(&self) -> [u8; 32] {
        *self.dh_public.as_bytes()
    }

    /// Serialize ratchet state to bytes for persistent storage.
    /// Serialize for storage.
    ///
    /// The returned buffer contains the root key and both chain keys in the
    /// clear. Callers must wipe it once it has been written (see
    /// `Node::persist_session`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // dh_secret (32)
        buf.extend_from_slice(&self.dh_secret.to_bytes());
        // dh_public (32)
        buf.extend_from_slice(self.dh_public.as_bytes());

        // remote_dh_public (1 + 32 optional)
        match &self.remote_dh_public {
            Some(pk) => {
                buf.push(1);
                buf.extend_from_slice(pk.as_bytes());
            }
            None => buf.push(0),
        }

        // root_key (32)
        buf.extend_from_slice(&self.root_key);

        // chain_key_send (1 + 32 optional)
        match &self.chain_key_send {
            Some(ck) => {
                buf.push(1);
                buf.extend_from_slice(ck);
            }
            None => buf.push(0),
        }

        // chain_key_recv (1 + 32 optional)
        match &self.chain_key_recv {
            Some(ck) => {
                buf.push(1);
                buf.extend_from_slice(ck);
            }
            None => buf.push(0),
        }

        // Counters (4 each)
        buf.extend_from_slice(&self.send_count.to_le_bytes());
        buf.extend_from_slice(&self.recv_count.to_le_bytes());
        buf.extend_from_slice(&self.previous_send_count.to_le_bytes());
        buf.extend_from_slice(&self.max_skip.to_le_bytes());

        // Skipped keys
        let count = self.skipped_keys.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());
        for ((dh_pub, msg_num), msg_key) in &self.skipped_keys {
            buf.extend_from_slice(dh_pub);
            buf.extend_from_slice(&msg_num.to_le_bytes());
            buf.extend_from_slice(msg_key);
        }

        buf
    }

    /// Deserialize ratchet state from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, RatchetError> {
        if data.len() < 115 {
            return Err(RatchetError::CryptoError);
        }
        let mut offset = 0;

        // dh_secret (32)
        let mut dh_secret_bytes = [0u8; 32];
        dh_secret_bytes.copy_from_slice(&data[offset..offset + 32]);
        let dh_secret = X25519Secret::from(dh_secret_bytes);
        offset += 32;

        // dh_public (32)
        let mut dh_pub_bytes = [0u8; 32];
        dh_pub_bytes.copy_from_slice(&data[offset..offset + 32]);
        let dh_public = X25519Public::from(dh_pub_bytes);
        offset += 32;

        // remote_dh_public
        let has_remote = data[offset];
        offset += 1;
        let remote_dh_public = if has_remote == 1 {
            if offset + 32 > data.len() {
                return Err(RatchetError::CryptoError);
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            Some(X25519Public::from(bytes))
        } else {
            None
        };

        // root_key (32)
        if offset + 32 > data.len() {
            return Err(RatchetError::CryptoError);
        }
        let mut root_key = [0u8; 32];
        root_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // chain_key_send
        if offset >= data.len() {
            return Err(RatchetError::CryptoError);
        }
        let has_send = data[offset];
        offset += 1;
        let chain_key_send = if has_send == 1 {
            if offset + 32 > data.len() {
                return Err(RatchetError::CryptoError);
            }
            let mut ck = [0u8; 32];
            ck.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            Some(ck)
        } else {
            None
        };

        // chain_key_recv
        if offset >= data.len() {
            return Err(RatchetError::CryptoError);
        }
        let has_recv = data[offset];
        offset += 1;
        let chain_key_recv = if has_recv == 1 {
            if offset + 32 > data.len() {
                return Err(RatchetError::CryptoError);
            }
            let mut ck = [0u8; 32];
            ck.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            Some(ck)
        } else {
            None
        };

        // Counters
        if offset + 16 > data.len() {
            return Err(RatchetError::CryptoError);
        }
        let send_count = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let recv_count = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let previous_send_count = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let max_skip = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // Skipped keys
        if offset + 4 > data.len() {
            return Err(RatchetError::CryptoError);
        }
        let skip_count = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        let mut skipped_keys = HashMap::new();
        for _ in 0..skip_count {
            if offset + 68 > data.len() {
                return Err(RatchetError::CryptoError);
            }
            let mut dh_pub = [0u8; 32];
            dh_pub.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            let msg_num = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let mut msg_key = [0u8; 32];
            msg_key.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            skipped_keys.insert((dh_pub, msg_num), msg_key);
        }

        Ok(Self {
            dh_secret,
            dh_public,
            remote_dh_public,
            root_key,
            chain_key_send,
            chain_key_recv,
            send_count,
            recv_count,
            previous_send_count,
            skipped_keys,
            max_skip,
        })
    }
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(ck) = self.chain_key_send.as_mut() {
            ck.zeroize();
        }
        if let Some(ck) = self.chain_key_recv.as_mut() {
            ck.zeroize();
        }
        for key in self.skipped_keys.values_mut() {
            key.zeroize();
        }
        self.skipped_keys.clear();
    }
}

/// KDF for root key chain: (root_key, dh_output) -> (new_root_key, chain_key).
fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut output = [0u8; 64];
    hk.expand(b"MyceliumRatchet", &mut output)
        .expect("HKDF expansion failed");

    let mut new_root = [0u8; 32];
    let mut chain_key = [0u8; 32];
    new_root.copy_from_slice(&output[..32]);
    chain_key.copy_from_slice(&output[32..]);
    (new_root, chain_key)
}

/// KDF for chain key: chain_key -> (new_chain_key, message_key).
fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    use sha2::Digest;
    // Signal protocol uses HMAC-SHA256 with different constants
    let mut hasher = Sha256::new();
    hasher.update(chain_key);
    hasher.update([0x01]); // message key constant
    let message_key_hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(chain_key);
    hasher.update([0x02]); // chain key constant
    let chain_key_hash = hasher.finalize();

    let mut new_chain = [0u8; 32];
    let mut msg_key = [0u8; 32];
    new_chain.copy_from_slice(&chain_key_hash);
    msg_key.copy_from_slice(&message_key_hash);
    (new_chain, msg_key)
}

/// AEAD encrypt using AES-256-GCM.
fn encrypt_aead(
    message_key: &[u8; 32],
    plaintext: &[u8],
    ad: &[u8],
    header: &RatchetHeader,
) -> Result<Vec<u8>, RatchetError> {
    // Derive AES key and nonce from message key via HKDF
    let hk = Hkdf::<Sha256>::new(None, message_key);
    let mut key_and_nonce = zeroize::Zeroizing::new([0u8; 44]); // 32 key + 12 nonce
    hk.expand(b"MyceliumAEAD", key_and_nonce.as_mut_slice())
        .expect("HKDF expansion failed");

    let aes_key = &key_and_nonce[..32];
    let nonce = &key_and_nonce[32..44];

    // Build AAD: ad || header
    let mut aad = ad.to_vec();
    aad.extend_from_slice(&header.dh_public);
    aad.extend_from_slice(&header.previous_chain_length.to_le_bytes());
    aad.extend_from_slice(&header.message_number.to_le_bytes());

    let cipher = Aes256Gcm::new_from_slice(aes_key).map_err(|_| RatchetError::CryptoError)?;
    let nonce = aes_gcm::Nonce::from_slice(nonce);

    cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| RatchetError::EncryptionFailed)
}

/// AEAD decrypt using AES-256-GCM.
fn decrypt_aead(
    message_key: &[u8; 32],
    ciphertext: &[u8],
    ad: &[u8],
    header: &RatchetHeader,
) -> Result<Vec<u8>, RatchetError> {
    let hk = Hkdf::<Sha256>::new(None, message_key);
    let mut key_and_nonce = zeroize::Zeroizing::new([0u8; 44]);
    hk.expand(b"MyceliumAEAD", key_and_nonce.as_mut_slice())
        .expect("HKDF expansion failed");

    let aes_key = &key_and_nonce[..32];
    let nonce = &key_and_nonce[32..44];

    let mut aad = ad.to_vec();
    aad.extend_from_slice(&header.dh_public);
    aad.extend_from_slice(&header.previous_chain_length.to_le_bytes());
    aad.extend_from_slice(&header.message_number.to_le_bytes());

    let cipher = Aes256Gcm::new_from_slice(aes_key).map_err(|_| RatchetError::CryptoError)?;
    let nonce = aes_gcm::Nonce::from_slice(nonce);

    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| RatchetError::DecryptionFailed)
}

#[derive(Debug, thiserror::Error)]
pub enum RatchetError {
    #[error("no sending chain established")]
    NoSendingChain,
    #[error("no receiving chain established")]
    NoReceivingChain,
    #[error("no remote DH key")]
    NoRemoteKey,
    #[error("too many skipped message keys")]
    TooManySkippedKeys,
    #[error("crypto error")]
    CryptoError,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_basic_roundtrip() {
        // Simulate X3DH shared secret
        let shared_secret = [42u8; 32];

        // Bob's signed prekey
        let bob_spk_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let bob_spk_public = X25519Public::from(&bob_spk_secret);

        let mut alice = RatchetState::init_alice(shared_secret, *bob_spk_public.as_bytes());
        let mut bob = RatchetState::init_bob(shared_secret, bob_spk_secret);

        let ad = b"test-ad";

        // Alice sends to Bob
        let (header, ciphertext) = alice.encrypt(b"hello bob!", ad).unwrap();
        let plaintext = bob.decrypt(&header, &ciphertext, ad).unwrap();
        assert_eq!(plaintext, b"hello bob!");

        // Bob sends to Alice
        let (header, ciphertext) = bob.encrypt(b"hello alice!", ad).unwrap();
        let plaintext = alice.decrypt(&header, &ciphertext, ad).unwrap();
        assert_eq!(plaintext, b"hello alice!");
    }

    #[test]
    fn test_ratchet_multiple_messages() {
        let shared_secret = [42u8; 32];
        let bob_spk_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let bob_spk_public = X25519Public::from(&bob_spk_secret);

        let mut alice = RatchetState::init_alice(shared_secret, *bob_spk_public.as_bytes());
        let mut bob = RatchetState::init_bob(shared_secret, bob_spk_secret);

        let ad = b"test";

        // Alice sends 3 messages
        for i in 0..3 {
            let msg = format!("message {}", i);
            let (header, ct) = alice.encrypt(msg.as_bytes(), ad).unwrap();
            let pt = bob.decrypt(&header, &ct, ad).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }

        // Bob replies
        let (header, ct) = bob.encrypt(b"reply!", ad).unwrap();
        let pt = alice.decrypt(&header, &ct, ad).unwrap();
        assert_eq!(pt, b"reply!");

        // Alice sends again (after DH ratchet)
        let (header, ct) = alice.encrypt(b"after ratchet", ad).unwrap();
        let pt = bob.decrypt(&header, &ct, ad).unwrap();
        assert_eq!(pt, b"after ratchet");
    }

    #[test]
    fn test_ratchet_out_of_order() {
        let shared_secret = [42u8; 32];
        let bob_spk_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let bob_spk_public = X25519Public::from(&bob_spk_secret);

        let mut alice = RatchetState::init_alice(shared_secret, *bob_spk_public.as_bytes());
        let mut bob = RatchetState::init_bob(shared_secret, bob_spk_secret);

        let ad = b"test";

        // Alice sends 3 messages
        let (h1, c1) = alice.encrypt(b"msg1", ad).unwrap();
        let (h2, c2) = alice.encrypt(b"msg2", ad).unwrap();
        let (h3, c3) = alice.encrypt(b"msg3", ad).unwrap();

        // Bob receives out of order: msg3, msg1, msg2
        let pt3 = bob.decrypt(&h3, &c3, ad).unwrap();
        assert_eq!(pt3, b"msg3");

        let pt1 = bob.decrypt(&h1, &c1, ad).unwrap();
        assert_eq!(pt1, b"msg1");

        let pt2 = bob.decrypt(&h2, &c2, ad).unwrap();
        assert_eq!(pt2, b"msg2");
    }

    /// A message whose cleartext header was tampered with in transit must
    /// fail without corrupting the session: the untampered copy and all
    /// later traffic in both directions must still decrypt.
    #[test]
    fn test_ratchet_tampered_header_does_not_corrupt_state() {
        let shared_secret = [42u8; 32];
        let bob_spk_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let bob_spk_public = X25519Public::from(&bob_spk_secret);
        let mut alice = RatchetState::init_alice(shared_secret, *bob_spk_public.as_bytes());
        let mut bob = RatchetState::init_bob(shared_secret, bob_spk_secret);
        let ad = b"ad";

        let (h1, c1) = alice.encrypt(b"one", ad).unwrap();
        assert_eq!(bob.decrypt(&h1, &c1, ad).unwrap(), b"one");

        let (h2, c2) = alice.encrypt(b"two", ad).unwrap();
        let mut forged = h2.clone();
        forged.dh_public[0] ^= 0x01; // looks like a new DH ratchet key
        assert!(bob.decrypt(&forged, &c2, ad).is_err());

        // Forged message_number far ahead with garbage ciphertext: no keys retained.
        let mut jump = h2.clone();
        jump.message_number += 500;
        assert!(bob.decrypt(&jump, b"garbage", ad).is_err());
        assert!(bob.skipped_keys.is_empty());

        assert_eq!(bob.decrypt(&h2, &c2, ad).unwrap(), b"two");
        let (h3, c3) = bob.encrypt(b"three", ad).unwrap();
        assert_eq!(alice.decrypt(&h3, &c3, ad).unwrap(), b"three");
    }

    #[test]
    fn test_ratchet_wrong_ad_fails() {
        let shared_secret = [42u8; 32];
        let bob_spk_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let bob_spk_public = X25519Public::from(&bob_spk_secret);

        let mut alice = RatchetState::init_alice(shared_secret, *bob_spk_public.as_bytes());
        let mut bob = RatchetState::init_bob(shared_secret, bob_spk_secret);

        let (header, ct) = alice.encrypt(b"secret", b"correct-ad").unwrap();
        let result = bob.decrypt(&header, &ct, b"wrong-ad");
        assert!(result.is_err());
    }

    #[test]
    fn test_kdf_ck_deterministic() {
        let ck = [1u8; 32];
        let (new_ck1, mk1) = kdf_ck(&ck);
        let (new_ck2, mk2) = kdf_ck(&ck);
        assert_eq!(new_ck1, new_ck2);
        assert_eq!(mk1, mk2);
        assert_ne!(new_ck1, mk1); // Chain and message keys are different
    }
}
