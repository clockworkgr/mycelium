use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::Sha256;

use std::collections::HashMap;

use mycelium_protocol::types::NodeId;

/// Maximum number of chain iterations a single incoming group message may
/// skip ahead. Bounds CPU spent on a forged `iteration` (each step is a hash).
pub const MAX_GROUP_SKIP: u32 = 1000;

/// Maximum skipped message keys retained per sender for out-of-order delivery.
const MAX_GROUP_SKIPPED_KEYS: usize = 2000;

/// A sender key for group messaging.
/// Each group member generates their own sender key and distributes it
/// to all other members via pairwise Double Ratchet sessions.
#[derive(Debug, Clone)]
pub struct SenderKey {
    /// Initial chain key (32 bytes).
    pub chain_key: [u8; 32],
    /// Current iteration in the chain.
    pub iteration: u32,
    /// Message keys for iterations that were skipped (message arrived out of
    /// order or was lost). Not persisted: lost on restart.
    skipped_keys: HashMap<u32, [u8; 32]>,
}

impl SenderKey {
    /// Generate a new random sender key.
    pub fn generate() -> Self {
        let mut chain_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut chain_key);
        Self::from_parts(chain_key, 0)
    }

    /// Build a sender key from a distributed chain key and iteration.
    pub fn from_parts(chain_key: [u8; 32], iteration: u32) -> Self {
        Self {
            chain_key,
            iteration,
            skipped_keys: HashMap::new(),
        }
    }

    /// Derive the message key for the current iteration and advance the chain.
    ///
    /// Fails once the 32-bit chain is exhausted rather than wrapping, since a
    /// repeated iteration would reuse an AEAD nonce.
    pub fn next_message_key(&mut self) -> Result<(u32, [u8; 32]), GroupError> {
        let iteration = self.iteration;
        let next = iteration.checked_add(1).ok_or(GroupError::ChainExhausted)?;
        let message_key = derive_message_key(&self.chain_key, iteration);
        self.chain_key = derive_next_chain_key(&self.chain_key);
        self.iteration = next;
        Ok((iteration, message_key))
    }

    /// Derive the message key for a specific iteration (for decryption).
    ///
    /// Advances the chain if needed, retaining the keys of skipped iterations
    /// so messages that arrive later (out of order) can still be decrypted.
    pub fn message_key_for_iteration(&mut self, target: u32) -> Result<[u8; 32], GroupError> {
        if target < self.iteration {
            return self
                .skipped_keys
                .remove(&target)
                .ok_or(GroupError::IterationAlreadyUsed);
        }

        let gap = target - self.iteration;
        if gap > MAX_GROUP_SKIP {
            return Err(GroupError::TooManySkippedKeys);
        }
        if self.skipped_keys.len().saturating_add(gap as usize) > MAX_GROUP_SKIPPED_KEYS {
            return Err(GroupError::TooManySkippedKeys);
        }
        let next = target.checked_add(1).ok_or(GroupError::ChainExhausted)?;

        // Advance chain to target iteration, keeping skipped keys
        while self.iteration < target {
            let skipped = derive_message_key(&self.chain_key, self.iteration);
            self.skipped_keys.insert(self.iteration, skipped);
            self.chain_key = derive_next_chain_key(&self.chain_key);
            self.iteration += 1;
        }

        let message_key = derive_message_key(&self.chain_key, self.iteration);
        self.chain_key = derive_next_chain_key(&self.chain_key);
        self.iteration = next;

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

    /// Add a member whose sender key has not arrived yet. Their messages
    /// fail with `UnknownSender` until `add_member` installs the real key.
    pub fn add_pending_member(&mut self, member: NodeId) {
        if !self.members.contains(&member) {
            self.members.push(member);
        }
    }

    /// Whether `node` is on the member list (with or without a key).
    pub fn is_member(&self, node: &NodeId) -> bool {
        self.members.contains(node)
    }

    /// Drop a member without rotating our key (used when another member's
    /// roster tells us someone left).
    pub fn forget_member(&mut self, member: &NodeId) {
        self.member_keys.remove(member);
        self.members.retain(|m| m != member);
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
        let (iteration, message_key) = self.our_sender_key.next_message_key()?;

        let ciphertext = encrypt_group_aead(&message_key, plaintext, &self.group_id)?;

        Ok(GroupMessage {
            group_id: self.group_id,
            iteration,
            ciphertext,
        })
    }

    /// Decrypt a group message from a specific sender.
    ///
    /// The sender's chain state is committed only if the ciphertext
    /// authenticates, so a forged message cannot advance or corrupt it.
    pub fn decrypt(
        &mut self,
        sender: &NodeId,
        message: &GroupMessage,
    ) -> Result<Vec<u8>, GroupError> {
        let sender_key = self
            .member_keys
            .get_mut(sender)
            .ok_or(GroupError::UnknownSender)?;

        let mut candidate = sender_key.clone();
        let message_key = candidate.message_key_for_iteration(message.iteration)?;
        let plaintext = decrypt_group_aead(&message_key, &message.ciphertext, &self.group_id)?;
        *sender_key = candidate;
        Ok(plaintext)
    }

    /// Get our sender key for distribution to other members.
    pub fn our_sender_key_for_distribution(&self) -> SenderKey {
        SenderKey::from_parts(self.our_sender_key.chain_key, self.our_sender_key.iteration)
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

        // Overflow-safe on 32-bit targets: compare against the remaining length.
        if (data.len() - offset) / 68 < num_members {
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
            // An all-zero chain key at iteration 0 is the placeholder written
            // for members whose sender key has not been received yet; restore
            // them as key-less so decryption reports UnknownSender, not a
            // spurious AEAD failure.
            if chain_key != [0u8; 32] || iteration != 0 {
                member_keys.insert(node_id, SenderKey::from_parts(chain_key, iteration));
            }
        }

        Some(Self {
            group_id,
            our_sender_key: SenderKey::from_parts(our_chain_key, our_iteration),
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
    #[error("message skips too many chain iterations")]
    TooManySkippedKeys,
    #[error("sender key chain exhausted")]
    ChainExhausted,
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
        let (iter0, key0) = sk.next_message_key().unwrap();
        let (iter1, key1) = sk.next_message_key().unwrap();
        assert_eq!(iter0, 0);
        assert_eq!(iter1, 1);
        assert_ne!(key0, key1); // Different message keys
    }

    /// Messages from one sender may arrive in any order over a DTN mesh.
    #[test]
    fn test_group_out_of_order_decrypt() {
        let group_id = make_group_id();
        let alice_id = NodeId([1u8; 32]);
        let mut alice_group = SenderKeyGroup::new(group_id);
        let mut bob_group = SenderKeyGroup::new(group_id);
        bob_group.add_member(alice_id, alice_group.our_sender_key_for_distribution());

        let m0 = alice_group.encrypt(b"zero").unwrap();
        let m1 = alice_group.encrypt(b"one").unwrap();
        let m2 = alice_group.encrypt(b"two").unwrap();

        assert_eq!(bob_group.decrypt(&alice_id, &m2).unwrap(), b"two");
        assert_eq!(bob_group.decrypt(&alice_id, &m0).unwrap(), b"zero");
        assert_eq!(bob_group.decrypt(&alice_id, &m1).unwrap(), b"one");
        // Replay of an already-used iteration is rejected.
        assert!(matches!(
            bob_group.decrypt(&alice_id, &m1),
            Err(GroupError::IterationAlreadyUsed)
        ));
    }

    /// A forged message must neither hang the CPU (huge iteration) nor
    /// advance the sender's chain past the real messages.
    #[test]
    fn test_group_forged_iteration_does_not_corrupt_chain() {
        let group_id = make_group_id();
        let alice_id = NodeId([1u8; 32]);
        let mut alice_group = SenderKeyGroup::new(group_id);
        let mut bob_group = SenderKeyGroup::new(group_id);
        bob_group.add_member(alice_id, alice_group.our_sender_key_for_distribution());

        let forged_far = GroupMessage {
            group_id,
            iteration: u32::MAX,
            ciphertext: vec![0u8; 32],
        };
        assert!(matches!(
            bob_group.decrypt(&alice_id, &forged_far),
            Err(GroupError::TooManySkippedKeys)
        ));

        let forged_near = GroupMessage {
            group_id,
            iteration: 5,
            ciphertext: vec![0u8; 32],
        };
        assert!(matches!(
            bob_group.decrypt(&alice_id, &forged_near),
            Err(GroupError::DecryptionFailed)
        ));

        // Real traffic still decrypts from iteration 0.
        let m0 = alice_group.encrypt(b"zero").unwrap();
        assert_eq!(bob_group.decrypt(&alice_id, &m0).unwrap(), b"zero");
    }

    /// Persisted groups restore key-less members as key-less.
    #[test]
    fn test_group_serialization_preserves_missing_keys() {
        let group_id = make_group_id();
        let mut group = SenderKeyGroup::new(group_id);
        let keyed = NodeId([1u8; 32]);
        let placeholder = NodeId([2u8; 32]);
        group.add_member(keyed, SenderKey::generate());
        group.members.push(placeholder);

        let restored = SenderKeyGroup::from_bytes(&group.to_bytes()).unwrap();
        assert_eq!(restored.member_count(), 2);
        assert!(restored.member_keys.contains_key(&keyed));
        assert!(!restored.member_keys.contains_key(&placeholder));
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
