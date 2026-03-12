use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::Sha256;

use std::collections::HashMap;

use mycelium_protocol::types::NodeId;

/// A sender key for group messaging.
/// Each group member generates their own sender key and distributes it
/// to all other members via pairwise Double Ratchet sessions.
#[derive(Debug, Clone)]
pub struct SenderKey {
    /// Initial chain key (32 bytes).
    pub chain_key: [u8; 32],
    /// Current iteration in the chain.
    pub iteration: u32,
}

impl SenderKey {
    /// Generate a new random sender key.
    pub fn generate() -> Self {
        let mut chain_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut chain_key);
        Self {
            chain_key,
            iteration: 0,
        }
    }

    /// Derive the message key for the current iteration and advance the chain.
    pub fn next_message_key(&mut self) -> (u32, [u8; 32]) {
        let iteration = self.iteration;
        let message_key = derive_message_key(&self.chain_key, iteration);
        self.chain_key = derive_next_chain_key(&self.chain_key);
        self.iteration += 1;
        (iteration, message_key)
    }

    /// Derive the message key for a specific iteration (for decryption).
    /// Advances the chain if needed.
    pub fn message_key_for_iteration(&mut self, target: u32) -> Result<[u8; 32], GroupError> {
        if target < self.iteration {
            return Err(GroupError::IterationAlreadyUsed);
        }

        // Advance chain to target iteration
        while self.iteration < target {
            self.chain_key = derive_next_chain_key(&self.chain_key);
            self.iteration += 1;
        }

        let message_key = derive_message_key(&self.chain_key, self.iteration);
        self.chain_key = derive_next_chain_key(&self.chain_key);
        self.iteration += 1;

        Ok(message_key)
    }
}

/// A sender key group (simplified MLS for v0.1, max ~20 members).
pub struct SenderKeyGroup {
    /// Group identifier.
    pub group_id: [u8; 32],
    /// Our sender key (for encrypting our messages to the group).
    pub our_sender_key: SenderKey,
    /// Other members' sender keys (for decrypting their messages).
    pub member_keys: HashMap<NodeId, SenderKey>,
    /// Group member list.
    pub members: Vec<NodeId>,
}

impl SenderKeyGroup {
    /// Create a new group.
    pub fn new(group_id: [u8; 32]) -> Self {
        Self {
            group_id,
            our_sender_key: SenderKey::generate(),
            member_keys: HashMap::new(),
            members: Vec::new(),
        }
    }

    /// Add a member with their sender key.
    pub fn add_member(&mut self, member: NodeId, sender_key: SenderKey) {
        self.member_keys.insert(member, sender_key);
        if !self.members.contains(&member) {
            self.members.push(member);
        }
    }

    /// Remove a member and rotate our sender key.
    pub fn remove_member(&mut self, member: &NodeId) {
        self.member_keys.remove(member);
        self.members.retain(|m| m != member);
        // Rotate our sender key — must be redistributed to remaining members
        self.our_sender_key = SenderKey::generate();
    }

    /// Encrypt a message for the group using our sender key.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<GroupMessage, GroupError> {
        let (iteration, message_key) = self.our_sender_key.next_message_key();

        let ciphertext = encrypt_group_aead(&message_key, plaintext, &self.group_id)?;

        Ok(GroupMessage {
            group_id: self.group_id,
            iteration,
            ciphertext,
        })
    }

    /// Decrypt a group message from a specific sender.
    pub fn decrypt(
        &mut self,
        sender: &NodeId,
        message: &GroupMessage,
    ) -> Result<Vec<u8>, GroupError> {
        let sender_key = self
            .member_keys
            .get_mut(sender)
            .ok_or(GroupError::UnknownSender)?;

        let message_key = sender_key.message_key_for_iteration(message.iteration)?;

        decrypt_group_aead(&message_key, &message.ciphertext, &self.group_id)
    }

    /// Get our sender key for distribution to other members.
    pub fn our_sender_key_for_distribution(&self) -> SenderKey {
        SenderKey {
            chain_key: self.our_sender_key.chain_key,
            iteration: self.our_sender_key.iteration,
        }
    }

    /// Number of members.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Serialize group state for persistence.
    ///
    /// Format: group_id(32) + our_chain_key(32) + our_iteration(4) + num_members(4)
    ///       + [node_id(32) + chain_key(32) + iteration(4)] * num_members
    pub fn to_bytes(&self) -> Vec<u8> {
        let num = self.members.len();
        let mut buf = Vec::with_capacity(72 + num * 68);
        buf.extend_from_slice(&self.group_id);
        buf.extend_from_slice(&self.our_sender_key.chain_key);
        buf.extend_from_slice(&self.our_sender_key.iteration.to_le_bytes());
        buf.extend_from_slice(&(num as u32).to_le_bytes());
        for member in &self.members {
            buf.extend_from_slice(member.as_bytes());
            if let Some(sk) = self.member_keys.get(member) {
                buf.extend_from_slice(&sk.chain_key);
                buf.extend_from_slice(&sk.iteration.to_le_bytes());
            } else {
                // Placeholder for member without a sender key yet
                buf.extend_from_slice(&[0u8; 32]);
                buf.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        buf
    }

    /// Deserialize group state from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 72 {
            return None;
        }
        let mut offset = 0;

        let mut group_id = [0u8; 32];
        group_id.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut our_chain_key = [0u8; 32];
        our_chain_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let our_iteration = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let num_members = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        if data.len() < offset + num_members * 68 {
            return None;
        }

        let mut members = Vec::with_capacity(num_members);
        let mut member_keys = HashMap::new();

        for _ in 0..num_members {
            let mut node_id_bytes = [0u8; 32];
            node_id_bytes.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;

            let mut chain_key = [0u8; 32];
            chain_key.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;

            let iteration = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
            offset += 4;

            let node_id = NodeId(node_id_bytes);
            members.push(node_id);
            member_keys.insert(
                node_id,
                SenderKey {
                    chain_key,
                    iteration,
                },
            );
        }

        Some(Self {
            group_id,
            our_sender_key: SenderKey {
                chain_key: our_chain_key,
                iteration: our_iteration,
            },
            member_keys,
            members,
        })
    }
}

/// An encrypted group message.
#[derive(Debug, Clone)]
pub struct GroupMessage {
    pub group_id: [u8; 32],
    pub iteration: u32,
    pub ciphertext: Vec<u8>,
}

fn derive_message_key(chain_key: &[u8; 32], iteration: u32) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(chain_key), &iteration.to_le_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"MyceliumGroupMK", &mut key)
        .expect("HKDF failed");
    key
}

fn derive_next_chain_key(chain_key: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(chain_key);
    hasher.update(b"MyceliumGroupCK");
    let result = hasher.finalize();
    let mut new_key = [0u8; 32];
    new_key.copy_from_slice(&result);
    new_key
}

fn encrypt_group_aead(
    message_key: &[u8; 32],
    plaintext: &[u8],
    group_id: &[u8; 32],
) -> Result<Vec<u8>, GroupError> {
    let hk = Hkdf::<Sha256>::new(None, message_key);
    let mut key_and_nonce = [0u8; 44];
    hk.expand(b"MyceliumGroupAEAD", &mut key_and_nonce)
        .expect("HKDF failed");

    let cipher =
        Aes256Gcm::new_from_slice(&key_and_nonce[..32]).map_err(|_| GroupError::CryptoError)?;
    let nonce = aes_gcm::Nonce::from_slice(&key_and_nonce[32..44]);

    cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: group_id,
            },
        )
        .map_err(|_| GroupError::EncryptionFailed)
}

fn decrypt_group_aead(
    message_key: &[u8; 32],
    ciphertext: &[u8],
    group_id: &[u8; 32],
) -> Result<Vec<u8>, GroupError> {
    let hk = Hkdf::<Sha256>::new(None, message_key);
    let mut key_and_nonce = [0u8; 44];
    hk.expand(b"MyceliumGroupAEAD", &mut key_and_nonce)
        .expect("HKDF failed");

    let cipher =
        Aes256Gcm::new_from_slice(&key_and_nonce[..32]).map_err(|_| GroupError::CryptoError)?;
    let nonce = aes_gcm::Nonce::from_slice(&key_and_nonce[32..44]);

    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: group_id,
            },
        )
        .map_err(|_| GroupError::DecryptionFailed)
}

#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("unknown sender")]
    UnknownSender,
    #[error("message iteration already used")]
    IterationAlreadyUsed,
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

    fn make_group_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
        id
    }

    #[test]
    fn test_sender_key_chain() {
        let mut sk = SenderKey::generate();
        let (iter0, key0) = sk.next_message_key();
        let (iter1, key1) = sk.next_message_key();
        assert_eq!(iter0, 0);
        assert_eq!(iter1, 1);
        assert_ne!(key0, key1); // Different message keys
    }

    #[test]
    fn test_group_encrypt_decrypt() {
        let group_id = make_group_id();
        let alice_id = NodeId([1u8; 32]);
        let bob_id = NodeId([2u8; 32]);

        let mut alice_group = SenderKeyGroup::new(group_id);
        let mut bob_group = SenderKeyGroup::new(group_id);

        // Exchange sender keys
        let alice_sk = alice_group.our_sender_key_for_distribution();
        let bob_sk = bob_group.our_sender_key_for_distribution();

        alice_group.add_member(bob_id, bob_sk);
        bob_group.add_member(alice_id, alice_sk);

        // Alice sends
        let msg = alice_group.encrypt(b"hello group!").unwrap();
        let pt = bob_group.decrypt(&alice_id, &msg).unwrap();
        assert_eq!(pt, b"hello group!");

        // Bob sends
        let msg = bob_group.encrypt(b"hey everyone!").unwrap();
        let pt = alice_group.decrypt(&bob_id, &msg).unwrap();
        assert_eq!(pt, b"hey everyone!");
    }

    #[test]
    fn test_group_multiple_messages() {
        let group_id = make_group_id();
        let alice_id = NodeId([1u8; 32]);
        let bob_id = NodeId([2u8; 32]);

        let mut alice_group = SenderKeyGroup::new(group_id);
        let mut bob_group = SenderKeyGroup::new(group_id);

        let alice_sk = alice_group.our_sender_key_for_distribution();
        bob_group.add_member(alice_id, alice_sk);

        for i in 0..5 {
            let text = format!("message {}", i);
            let msg = alice_group.encrypt(text.as_bytes()).unwrap();
            let pt = bob_group.decrypt(&alice_id, &msg).unwrap();
            assert_eq!(pt, text.as_bytes());
        }
    }

    #[test]
    fn test_group_member_removal_rotates_key() {
        let group_id = make_group_id();
        let bob_id = NodeId([2u8; 32]);

        let mut group = SenderKeyGroup::new(group_id);
        let initial_key = group.our_sender_key.chain_key;

        group.add_member(bob_id, SenderKey::generate());
        group.remove_member(&bob_id);

        assert_ne!(group.our_sender_key.chain_key, initial_key);
        assert_eq!(group.member_count(), 0);
    }
}
