use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::identity::Identity;

/// A prekey bundle published by a node for X3DH.
#[derive(Debug, Clone)]
pub struct PrekeyBundle {
    /// Ed25519 identity public key.
    pub identity_key: [u8; 32],
    /// Signed X25519 prekey (medium-term, rotated weekly).
    pub signed_prekey: [u8; 32],
    /// Ed25519 signature over signed_prekey.
    pub signed_prekey_signature: Vec<u8>,
    pub signed_prekey_id: u32,
    /// Optional one-time X25519 prekey.
    pub one_time_prekey: Option<[u8; 32]>,
    pub one_time_prekey_id: Option<u32>,
}

/// The key an answered handshake is remembered by.
///
/// A hash of the binding rather than the binding itself: 32 bytes a record
/// can hold a thousand of, and the binding is public anyway, so there is
/// nothing here to protect — only to compare.
pub(crate) fn handshake_binding_hash(binding: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"mycelium-answered-handshake-v1:");
    hasher.update(binding);
    hasher.finalize().into()
}

/// State needed to respond to X3DH initiation (our prekey secrets).
pub struct PrekeyState {
    pub identity: Identity,
    pub signed_prekey_secret: X25519Secret,
    pub signed_prekey_id: u32,
    /// One-time prekeys not yet handed out in any bundle: (id, secret)
    pub one_time_prekeys: Vec<(u32, X25519Secret)>,
    /// One-time prekeys already included in an issued bundle but not yet
    /// consumed by an incoming `SessionInit`. Kept so the responder can still
    /// complete X3DH, but never re-issued to another initiator.
    issued_one_time_prekeys: Vec<(u32, X25519Secret)>,
    /// Signed prekeys this node has rotated away from, newest first.
    ///
    /// A bundle other nodes cached before a rotation still names the old
    /// `signed_prekey_id`. Without the matching secret the responder derives a
    /// different shared secret, the AEAD tag fails, and the conversation is
    /// permanently stuck (ROADMAP T-06). Retained for at least the
    /// bundle-cache lifetime.
    previous_signed_prekeys: Vec<(u32, X25519Secret)>,
    next_otp_id: u32,
    next_spk_id: u32,
    /// Handshakes already answered, as `(signed_prekey_id, binding hash)`,
    /// oldest first.
    ///
    /// A `SessionInit` stays derivable for as long as the signed prekey it
    /// names is retained, so an init we have already answered can be replayed
    /// until then — and accepted again, replacing a working session with one
    /// that was abandoned. Nothing else stops it: a one-time prekey is only
    /// retired if the init named one, and a session's own record of the init
    /// it was built from dies with that session, while the prekey lives on.
    ///
    /// Keyed on the **binding** — the header the derivation covers — not on
    /// the payload: the nested message is free to vary, and a captured
    /// follow-up from the same chain decrypts on a fresh ratchet, so a
    /// payload-keyed record is bypassed by substituting it.
    ///
    /// Entries are written only where the AEAD has verified, which is what
    /// keeps the bound out of an attacker's reach, and are dropped when their
    /// signed prekey retires, because the replay dies with it (ADR-015).
    answered_handshakes: Vec<(u32, [u8; 32])>,
    /// Whether `answered_handshakes` has gained an entry since the blob was
    /// last written.
    ///
    /// The record is only as good as its persistence: an entry promoted on a
    /// decrypt and never written is gone on the next start, and the handshake
    /// it covers is answerable again. The flag lets the caller write the blob
    /// on the decrypt that promoted something and not on every message —
    /// it holds the one-time prekeys too, so it is not a cheap write.
    needs_persist: bool,
}

/// How many rotated signed prekeys to keep.
///
/// Rotation is roughly weekly and cached bundles expire after 7 days, so two
/// covers the window with a margin.
pub const MAX_RETAINED_SIGNED_PREKEYS: usize = 2;

/// How many answered handshakes to remember, across all retained prekeys.
///
/// One entry per handshake that authenticated — a peer that cannot complete
/// X3DH cannot add one — so this bounds a real conversation count, not an
/// attacker's. Three weeks of handshakes at weekly rotation would have to
/// exceed it before the oldest entry is evicted, and an evicted entry's init
/// becomes replayable again until its prekey retires.
pub const MAX_ANSWERED_HANDSHAKES: usize = 1024;

impl PrekeyState {
    pub fn new(identity: Identity) -> Self {
        let signed_prekey_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
        Self {
            identity,
            signed_prekey_secret,
            signed_prekey_id: 1,
            one_time_prekeys: Vec::new(),
            issued_one_time_prekeys: Vec::new(),
            previous_signed_prekeys: Vec::new(),
            next_otp_id: 1,
            next_spk_id: 2,
            answered_handshakes: Vec::new(),
            needs_persist: false,
        }
    }

    /// Generate N one-time prekeys.
    pub fn generate_one_time_prekeys(&mut self, count: u32) {
        for _ in 0..count {
            let secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
            self.one_time_prekeys.push((self.next_otp_id, secret));
            self.next_otp_id += 1;
        }
    }

    /// Rotate the signed prekey, retaining the outgoing one.
    ///
    /// The previous secret is kept so a peer initiating from a bundle it
    /// cached before the rotation can still complete X3DH.
    pub fn rotate_signed_prekey(&mut self) {
        let retiring = std::mem::replace(
            &mut self.signed_prekey_secret,
            X25519Secret::random_from_rng(rand::rngs::OsRng),
        );
        self.previous_signed_prekeys
            .insert(0, (self.signed_prekey_id, retiring));
        self.previous_signed_prekeys
            .truncate(MAX_RETAINED_SIGNED_PREKEYS);

        self.signed_prekey_id = self.next_spk_id;
        self.next_spk_id += 1;

        // An answered handshake whose signed prekey has retired cannot be
        // derived again, so its record has no more work to do.
        let live: Vec<u32> = std::iter::once(self.signed_prekey_id)
            .chain(self.previous_signed_prekeys.iter().map(|(id, _)| *id))
            .collect();
        self.answered_handshakes
            .retain(|(spk_id, _)| live.contains(spk_id));
    }

    /// Whether a signed-prekey id still resolves to a secret we hold, and so
    /// whether an init naming it can still be derived.
    fn signed_prekey_is_live(&self, id: u32) -> bool {
        id == self.signed_prekey_id
            || self
                .previous_signed_prekeys
                .iter()
                .any(|(spk_id, _)| *spk_id == id)
    }

    /// Record a handshake as answered, so the init that produced it cannot be
    /// answered a second time. See `answered_handshakes`.
    ///
    /// Call it only once the init has authenticated — where the one-time
    /// prekey is retired — never on an unauthenticated path, or a forgery
    /// could fill the bound with bindings of its own choosing.
    pub fn mark_handshake_answered(&mut self, signed_prekey_id: u32, binding: &[u8]) {
        self.mark_handshake_answered_hash(signed_prekey_id, handshake_binding_hash(binding));
    }

    /// As `mark_handshake_answered`, for a caller that already holds the hash
    /// — the promotion in `SessionManager::decrypt_from`, which has the
    /// session's record and not the init's bytes.
    pub fn mark_handshake_answered_hash(&mut self, signed_prekey_id: u32, hash: [u8; 32]) {
        // An entry whose signed prekey has retired protects nothing: the init
        // it remembers can no longer be derived. Recording one would be worse
        // than useless — a long-lived session re-offers its marker on every
        // decrypt, so obsolete entries would accumulate and, at capacity,
        // evict the ones still doing work.
        if !self.signed_prekey_is_live(signed_prekey_id) {
            return;
        }
        if self
            .answered_handshakes
            .iter()
            .any(|(_, known)| *known == hash)
        {
            return;
        }
        if self.answered_handshakes.len() >= MAX_ANSWERED_HANDSHAKES {
            self.answered_handshakes.remove(0);
        }
        self.answered_handshakes.push((signed_prekey_id, hash));
        self.needs_persist = true;
    }

    /// Whether the record has changed since the blob was last written. See
    /// `needs_persist`.
    pub fn needs_persist(&self) -> bool {
        self.needs_persist
    }

    /// Clear the flag, once the blob really is written.
    ///
    /// Separate from reading it because the write can fail: clearing first and
    /// ignoring the error left the promotion unpersisted for good, since the
    /// record deduplicates and a later decrypt would never ask again.
    pub fn mark_persisted(&mut self) {
        self.needs_persist = false;
    }

    /// How many answered handshakes are on record. For tests and diagnostics.
    pub fn answered_handshake_count(&self) -> usize {
        self.answered_handshakes.len()
    }

    /// Whether this exact handshake has already been answered.
    pub fn has_answered_handshake(&self, binding: &[u8]) -> bool {
        let hash = handshake_binding_hash(binding);
        self.answered_handshakes
            .iter()
            .any(|(_, known)| *known == hash)
    }

    /// The secret for a given signed-prekey id: the current one, or a retained
    /// one if the initiator used a bundle from before a rotation.
    pub fn signed_prekey_secret_for(&self, id: u32) -> Option<&X25519Secret> {
        if id == self.signed_prekey_id {
            return Some(&self.signed_prekey_secret);
        }
        self.previous_signed_prekeys
            .iter()
            .find(|(pid, _)| *pid == id)
            .map(|(_, secret)| secret)
    }

    /// Build a prekey bundle without reserving the one-time prekey.
    ///
    /// Peeks at the most recent unissued OTP. Use [`issue_bundle`](Self::issue_bundle)
    /// when actually answering a prekey request so that no two initiators are
    /// handed the same one-time prekey.
    pub fn bundle(&self) -> PrekeyBundle {
        let otp = self.one_time_prekeys.last();
        self.build_bundle(otp)
    }

    /// Build a prekey bundle and reserve its one-time prekey.
    ///
    /// The OTP is moved out of the unissued pool so a subsequent call hands out
    /// a different key; it stays available for [`consume_one_time_prekey`]
    /// until an initiator uses it. Returns a bundle without an OTP when the
    /// pool is empty.
    pub fn issue_bundle(&mut self) -> PrekeyBundle {
        match self.one_time_prekeys.pop() {
            Some(entry) => {
                let bundle = self.build_bundle(Some(&entry));
                self.issued_one_time_prekeys.push(entry);
                bundle
            }
            None => self.build_bundle(None),
        }
    }

    fn build_bundle(&self, otp: Option<&(u32, X25519Secret)>) -> PrekeyBundle {
        let spk_public = X25519Public::from(&self.signed_prekey_secret);
        let signature = self.identity.sign(spk_public.as_bytes());

        let (otp, otp_id) = match otp {
            Some((id, secret)) => (Some(*X25519Public::from(secret).as_bytes()), Some(*id)),
            None => (None, None),
        };

        PrekeyBundle {
            identity_key: self.identity.public_key_bytes(),
            signed_prekey: *spk_public.as_bytes(),
            signed_prekey_signature: signature.to_bytes().to_vec(),
            signed_prekey_id: self.signed_prekey_id,
            one_time_prekey: otp,
            one_time_prekey_id: otp_id,
        }
    }

    /// Number of one-time prekeys that can still be issued in new bundles.
    pub fn available_one_time_prekeys(&self) -> usize {
        self.one_time_prekeys.len()
    }

    /// Consume a one-time prekey by ID (marks it as used).
    /// The secret for `id` without spending it.
    ///
    /// X3DH derives with this; `consume_one_time_prekey` is called only once
    /// the first message has authenticated, so a corrupted copy of an init
    /// cannot burn a prekey and make the genuine init fail (ADR-015).
    pub fn one_time_prekey_secret(&self, id: u32) -> Option<&X25519Secret> {
        self.issued_one_time_prekeys
            .iter()
            .chain(self.one_time_prekeys.iter())
            .find(|(pid, _)| *pid == id)
            .map(|(_, secret)| secret)
    }

    pub fn consume_one_time_prekey(&mut self, id: u32) -> Option<X25519Secret> {
        if let Some(pos) = self
            .issued_one_time_prekeys
            .iter()
            .position(|(pid, _)| *pid == id)
        {
            return Some(self.issued_one_time_prekeys.remove(pos).1);
        }
        if let Some(pos) = self.one_time_prekeys.iter().position(|(pid, _)| *pid == id) {
            let (_, secret) = self.one_time_prekeys.remove(pos);
            Some(secret)
        } else {
            None
        }
    }

    /// Serialize the prekey state (excluding identity) to bytes for persistence.
    ///
    /// The buffer contains the signed prekey secret, every one-time prekey and
    /// every retained rotated secret in the clear. Callers must wipe it once
    /// written; `Node` does so via `Zeroizing`.
    ///
    /// Format: signed_prekey_secret(32) + signed_prekey_id(4) + next_otp_id(4)
    ///       + next_spk_id(4) + num_otps(4) + [otp_id(4) + otp_secret(32)]*
    pub fn to_bytes(&self) -> Vec<u8> {
        // Issued-but-unconsumed OTPs are persisted alongside the unissued pool;
        // after a restart they become issuable again, which is harmless.
        let num_otps = self.one_time_prekeys.len() + self.issued_one_time_prekeys.len();
        // Capacity must cover every appended field — the retained signed
        // prekeys and the answered-handshake record. A realloc here would copy
        // the secrets already written and free the old allocation without
        // wiping it, which the caller's `Zeroizing` wrapper cannot undo.
        let mut buf = Vec::with_capacity(
            48 + num_otps * 36
                + 4
                + self.previous_signed_prekeys.len() * 36
                + 4
                + self.answered_handshakes.len() * 36,
        );

        buf.extend_from_slice(&self.signed_prekey_secret.to_bytes());
        buf.extend_from_slice(&self.signed_prekey_id.to_le_bytes());
        buf.extend_from_slice(&self.next_otp_id.to_le_bytes());
        buf.extend_from_slice(&self.next_spk_id.to_le_bytes());
        buf.extend_from_slice(&(num_otps as u32).to_le_bytes());

        for (id, secret) in self
            .issued_one_time_prekeys
            .iter()
            .chain(self.one_time_prekeys.iter())
        {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&secret.to_bytes());
        }

        // Retained signed prekeys, appended after the one-time pool. A blob
        // written before this field existed simply ends here, and `from_bytes`
        // reads that as "none retained" — so no version byte is needed.
        buf.extend_from_slice(&(self.previous_signed_prekeys.len() as u32).to_le_bytes());
        for (id, secret) in &self.previous_signed_prekeys {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&secret.to_bytes());
        }

        // Answered handshakes, appended after those, and optional on the way
        // back in for the same reason. They have to be durable: a restart that
        // lost them would let every init still inside the retention window be
        // answered a second time.
        buf.extend_from_slice(&(self.answered_handshakes.len() as u32).to_le_bytes());
        for (id, hash) in &self.answered_handshakes {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(hash);
        }

        buf
    }

    /// Restore prekey state from bytes (requires identity to be provided separately).
    pub fn from_bytes_with_identity(data: &[u8], identity: Identity) -> Option<Self> {
        if data.len() < 48 {
            return None;
        }

        let mut offset = 0;

        let mut spk_bytes = [0u8; 32];
        spk_bytes.copy_from_slice(&data[offset..offset + 32]);
        let signed_prekey_secret = X25519Secret::from(spk_bytes);
        offset += 32;

        let signed_prekey_id = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let next_otp_id = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let next_spk_id = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let num_otps = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        // Overflow-safe on 32-bit targets: compare against the remaining length.
        if (data.len() - offset) / 36 < num_otps {
            return None;
        }

        let mut one_time_prekeys = Vec::with_capacity(num_otps);
        for _ in 0..num_otps {
            let id = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
            offset += 4;

            let mut secret_bytes = [0u8; 32];
            secret_bytes.copy_from_slice(&data[offset..offset + 32]);
            let secret = X25519Secret::from(secret_bytes);
            offset += 32;

            one_time_prekeys.push((id, secret));
        }

        // Retained signed prekeys are optional: a blob written before the
        // field existed ends after the one-time pool.
        let mut previous_signed_prekeys = Vec::new();
        if data.len() - offset >= 4 {
            let num_retained =
                u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
            offset += 4;
            // Overflow-safe on 32-bit targets.
            if (data.len() - offset) / 36 < num_retained {
                return None;
            }
            for _ in 0..num_retained {
                let id = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
                offset += 4;
                let mut secret_bytes = [0u8; 32];
                secret_bytes.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;
                previous_signed_prekeys.push((id, X25519Secret::from(secret_bytes)));
            }
        }

        // Answered handshakes: also optional, for blobs written before the
        // field existed.
        let mut answered_handshakes = Vec::new();
        if data.len() - offset >= 4 {
            let num_answered =
                u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
            offset += 4;
            // Overflow-safe on 32-bit targets.
            if (data.len() - offset) / 36 < num_answered {
                return None;
            }
            for _ in 0..num_answered {
                let id = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
                offset += 4;
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;
                answered_handshakes.push((id, hash));
            }
        }

        Some(Self {
            identity,
            signed_prekey_secret,
            signed_prekey_id,
            one_time_prekeys,
            issued_one_time_prekeys: Vec::new(),
            previous_signed_prekeys,
            next_otp_id,
            next_spk_id,
            answered_handshakes,
            // Just loaded, so it matches the blob on disk.
            needs_persist: false,
        })
    }
}

/// Result of X3DH initiation.
pub struct X3dhInitResult {
    /// Shared secret derived from X3DH (32 bytes).
    pub shared_secret: [u8; 32],
    /// Ephemeral public key to send to recipient.
    pub ephemeral_public: [u8; 32],
    /// Associated data for the first message.
    pub ad: Vec<u8>,
    /// The one-time prekey this derivation actually used, which is *not*
    /// simply the one the bundle offered: a message-less init takes the
    /// signed-prekey-only variant and uses none (ADR-015). The `SessionInit`
    /// must name this, or the responder derives something else.
    pub one_time_prekey_id: Option<u32>,
}

/// Result of X3DH response.
pub struct X3dhResponseResult {
    /// Shared secret derived from X3DH (32 bytes).
    pub shared_secret: [u8; 32],
    /// Associated data.
    pub ad: Vec<u8>,
}

/// Initiate X3DH key exchange with a recipient's prekey bundle.
///
/// Performs 3-4 DH operations:
/// 1. DH(our_identity_x25519, their_signed_prekey)
/// 2. DH(ephemeral, their_identity_x25519)
/// 3. DH(ephemeral, their_signed_prekey)
/// 4. DH(ephemeral, their_one_time_prekey) — if available
pub fn x3dh_initiate(
    our_identity: &Identity,
    their_bundle: &PrekeyBundle,
    carries_message: bool,
) -> Result<X3dhInitResult, X3dhError> {
    // Verify the signed prekey signature
    let their_identity = VerifyingKey::from_bytes(&their_bundle.identity_key)
        .map_err(|_| X3dhError::InvalidIdentityKey)?;

    let sig_bytes: [u8; 64] = their_bundle
        .signed_prekey_signature
        .as_slice()
        .try_into()
        .map_err(|_| X3dhError::InvalidSignature)?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    their_identity
        .verify(&their_bundle.signed_prekey, &signature)
        .map_err(|_| X3dhError::InvalidSignature)?;

    // Convert our Ed25519 identity key to X25519 for DH
    let our_identity_x25519 = ed25519_to_x25519_secret(our_identity.signing_key());

    // Generate ephemeral X25519 keypair
    let ephemeral_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = X25519Public::from(&ephemeral_secret);

    let their_signed_prekey = X25519Public::from(their_bundle.signed_prekey);
    let their_identity_x25519 = ed25519_public_to_x25519(&their_bundle.identity_key)?;

    // DH operations
    let dh1 = our_identity_x25519.diffie_hellman(&their_signed_prekey);
    let dh2 = ephemeral_secret.diffie_hellman(&their_identity_x25519);
    let dh3 = ephemeral_secret.diffie_hellman(&their_signed_prekey);

    // Zeroizing at the allocation, not a wipe before the happy-path
    // return: `?` on a missing one-time prekey would otherwise leave raw
    // DH output in freed heap memory.
    let mut dh_concat = zeroize::Zeroizing::new(Vec::with_capacity(128));
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    // A message-less init takes the signed-prekey-only variant, whatever the
    // bundle offers: with nothing in the init to authenticate the initiator
    // there is no event on which a one-time prekey could be spent, so naming
    // one is refused outright (ADR-015). Using it here produced an init the
    // responder could only reject.
    let one_time_prekey_id = if carries_message {
        their_bundle.one_time_prekey_id
    } else {
        None
    };

    if let (true, Some(otp)) = (carries_message, &their_bundle.one_time_prekey) {
        let their_otp = X25519Public::from(*otp);
        let dh4 = ephemeral_secret.diffie_hellman(&their_otp);
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    // Exactly the header bytes this init will carry, so the responder derives
    // the same value from what it parsed (ADR-015).
    let binding = mycelium_protocol::wire::session_init_binding(
        ephemeral_public.as_bytes(),
        &our_identity.public_key_bytes(),
        their_bundle.signed_prekey_id,
        one_time_prekey_id,
        carries_message,
    );
    let shared_secret = kdf_x3dh(&dh_concat, &binding);

    // Associated data: both identity keys concatenated
    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(&our_identity.public_key_bytes());
    ad.extend_from_slice(&their_bundle.identity_key);

    Ok(X3dhInitResult {
        shared_secret,
        ephemeral_public: *ephemeral_public.as_bytes(),
        ad,
        one_time_prekey_id,
    })
}

/// Respond to an X3DH initiation.
pub fn x3dh_respond(
    our_state: &mut PrekeyState,
    their_identity_key: &[u8; 32],
    their_ephemeral_key: &[u8; 32],
    used_signed_prekey_id: u32,
    used_otp_id: Option<u32>,
    carries_message: bool,
) -> Result<X3dhResponseResult, X3dhError> {
    let their_identity_x25519 = ed25519_public_to_x25519(their_identity_key)?;
    let their_ephemeral = X25519Public::from(*their_ephemeral_key);

    // The initiator built its half of the exchange against a specific signed
    // prekey. Use that one — current or retained — rather than whichever is
    // current now, or a rotation since the bundle was cached silently derives
    // a different secret and only shows up as an AEAD failure (ROADMAP T-06).
    let signed_prekey_secret = our_state
        .signed_prekey_secret_for(used_signed_prekey_id)
        .ok_or(X3dhError::SignedPrekeyNotFound)?
        .clone();

    // Convert our Ed25519 identity to X25519
    let our_identity_x25519 = ed25519_to_x25519_secret(our_state.identity.signing_key());

    // DH operations (mirror of initiate)
    let dh1 = signed_prekey_secret.diffie_hellman(&their_identity_x25519);
    let dh2 = our_identity_x25519.diffie_hellman(&their_ephemeral);
    let dh3 = signed_prekey_secret.diffie_hellman(&their_ephemeral);

    // Zeroizing at the allocation, not a wipe before the happy-path
    // return: `?` on a missing one-time prekey would otherwise leave raw
    // DH output in freed heap memory.
    let mut dh_concat = zeroize::Zeroizing::new(Vec::with_capacity(128));
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    if let Some(otp_id) = used_otp_id {
        // Peeked, not spent. The prekey is retired by the caller once the
        // enclosed first message authenticates: spending it here let a
        // corrupted copy of an init burn it, after which the genuine init
        // failed and drew a rejection the initiator acted on (ADR-015).
        let otp_secret = our_state
            .one_time_prekey_secret(otp_id)
            .ok_or(X3dhError::OneTimePrekeyNotFound)?;
        let dh4 = otp_secret.diffie_hellman(&their_ephemeral);
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    let binding = mycelium_protocol::wire::session_init_binding(
        their_ephemeral_key,
        their_identity_key,
        used_signed_prekey_id,
        used_otp_id,
        carries_message,
    );
    let shared_secret = kdf_x3dh(&dh_concat, &binding);

    // Associated data
    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(their_identity_key);
    ad.extend_from_slice(&our_state.identity.public_key_bytes());

    Ok(X3dhResponseResult { shared_secret, ad })
}

/// Convert Ed25519 signing key to X25519 static secret.
///
/// Ed25519 keys are derived by hashing the seed with SHA-512 and clamping.
/// The lower 32 bytes of SHA-512(seed), clamped, give the X25519-compatible scalar.
fn ed25519_to_x25519_secret(signing_key: &SigningKey) -> X25519Secret {
    use sha2::{Digest, Sha512};
    let hash = Sha512::digest(signing_key.to_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);
    // Clamp per RFC 7748
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    X25519Secret::from(bytes)
}

/// Convert Ed25519 public key to X25519 public key (Edwards -> Montgomery).
///
/// Returns `InvalidIdentityKey` for byte strings that are not a valid
/// Ed25519 point (roughly half of all random 32-byte values). This must never
/// panic: `x3dh_respond` receives the key straight from a network peer.
fn ed25519_public_to_x25519(ed25519_pubkey: &[u8; 32]) -> Result<X25519Public, X3dhError> {
    // VerifyingKey::from_bytes rejects non-canonical / non-decompressible points.
    let verifying =
        VerifyingKey::from_bytes(ed25519_pubkey).map_err(|_| X3dhError::InvalidIdentityKey)?;
    let montgomery = verifying.to_montgomery();
    Ok(X25519Public::from(montgomery.to_bytes()))
}

/// KDF for X3DH: HKDF-SHA256 over the DH outputs, with the init's binding in
/// the info string.
///
/// The binding is what makes an equivalent ephemeral useless. RFC 7748 §7:
/// for any X25519 public key there are other, publicly computable keys that
/// produce the same shared secret, so two inits can be equivalent to the
/// responder while differing on the wire — which is a second identity for one
/// handshake, and ADR-012 showed what that buys an attacker. With the wire
/// bytes in the derivation, the altered copy derives a different secret and
/// its first message simply does not decrypt (ADR-015).
///
/// `v2` because the derivation changed: a session from the old one cannot be
/// continued, and the protocol is `0.1-draft` with no deployed nodes.
fn kdf_x3dh(input: &[u8], binding: &[u8]) -> [u8; 32] {
    let salt = [0u8; 32]; // All zeros per Signal spec
    let hk = Hkdf::<Sha256>::new(Some(&salt), input);
    let mut info = Vec::with_capacity(X3DH_INFO.len() + binding.len());
    info.extend_from_slice(X3DH_INFO);
    info.extend_from_slice(binding);
    let mut output = [0u8; 32];
    hk.expand(&info, &mut output)
        .expect("HKDF expansion failed");
    output
}

/// Domain separation for the X3DH derivation, followed by the init binding.
const X3DH_INFO: &[u8] = b"MyceliumX3DH-v2:";

#[derive(Debug, thiserror::Error)]
pub enum X3dhError {
    #[error("invalid identity key")]
    InvalidIdentityKey,
    #[error("invalid signed prekey signature")]
    InvalidSignature,
    #[error("one-time prekey not found")]
    OneTimePrekeyNotFound,
    /// The initiator used a signed prekey we no longer hold: its bundle is
    /// older than `MAX_RETAINED_SIGNED_PREKEYS` rotations.
    #[error("signed prekey not found (stale bundle)")]
    SignedPrekeyNotFound,
}

#[cfg(test)]
mod tests {

    /// RFC 7748 §7: for any X25519 public key `u` there are other, publicly
    /// computable keys that produce the same shared secret. `u⁻¹ mod p` is
    /// one, and the dangerous one: unlike a flipped high bit or a value at or
    /// above p, it is a **canonical** encoding, so `is_canonical_x25519`
    /// cannot tell it from the original. An attacker could take an init, swap
    /// its ephemeral for the inverse, and have the responder derive the same
    /// X3DH secret from different wire bytes — a second identity for one
    /// handshake, which ADR-012 showed is what makes a replay of the original
    /// collectable as an actionable rejection.
    ///
    /// The init's own bytes are in the derivation now, so the equivalent key
    /// derives a different secret and its first message cannot decrypt
    /// (ADR-015). This runs the real responder derivation on both encodings.
    #[test]
    fn test_an_equivalent_ephemeral_derives_a_different_secret() {
        // An X25519 public key and its inverse mod 2^255-19, which is the
        // same point to X25519 and a different 32 bytes on the wire. The
        // equality assertion below re-derives the equivalence from these
        // constants, so a wrong constant fails the test rather than making it
        // pass vacuously.
        const EPHEMERAL: [u8; 32] = [
            0x2e, 0x8b, 0x28, 0x83, 0xc2, 0x7b, 0x39, 0x13, 0x59, 0xd7, 0xd0, 0xc1, 0x5d, 0x00,
            0x81, 0x5a, 0x66, 0x93, 0x29, 0x0a, 0x38, 0xdd, 0x8e, 0xba, 0x34, 0x1c, 0xc0, 0x7d,
            0xda, 0xa8, 0xed, 0x4d,
        ];
        const EQUIVALENT: [u8; 32] = [
            0xa3, 0xf9, 0xf6, 0x95, 0x9c, 0x87, 0xd5, 0x1c, 0x16, 0xdb, 0x0d, 0xc3, 0x6a, 0xe0,
            0x20, 0x1f, 0x6e, 0x23, 0x42, 0x31, 0x56, 0x00, 0xa6, 0xfd, 0xe4, 0x74, 0xeb, 0xb3,
            0xb9, 0xa5, 0xa9, 0x38,
        ];
        assert_ne!(EPHEMERAL, EQUIVALENT);

        // Both pass ingress: the canonical-encoding check is no defence here.
        assert!(crate::identity::is_canonical_x25519(&EPHEMERAL));
        assert!(crate::identity::is_canonical_x25519(&EQUIVALENT));

        let initiator = Identity::generate();
        let mut state = PrekeyState::new(Identity::generate());
        state.generate_one_time_prekeys(1);
        let bundle = state.issue_bundle();
        let spk_id = bundle.signed_prekey_id;
        let otp_id = bundle.one_time_prekey_id;

        // The pair really is equivalent: the responder's own prekeys derive
        // one shared secret from both encodings, which is why the DH outputs
        // alone cannot distinguish the two inits.
        for secret in [
            state.signed_prekey_secret_for(spk_id).unwrap().to_bytes(),
            state
                .one_time_prekey_secret(otp_id.unwrap())
                .unwrap()
                .to_bytes(),
        ] {
            let secret = X25519Secret::from(secret);
            assert_eq!(
                secret
                    .diffie_hellman(&X25519Public::from(EPHEMERAL))
                    .to_bytes(),
                secret
                    .diffie_hellman(&X25519Public::from(EQUIVALENT))
                    .to_bytes(),
                "the constants are not an equivalent pair"
            );
        }

        // Same DH material, different init bytes: the binding separates them.
        let honest = x3dh_respond(
            &mut state,
            &initiator.public_key_bytes(),
            &EPHEMERAL,
            spk_id,
            otp_id,
            true,
        )
        .unwrap();
        let altered = x3dh_respond(
            &mut state,
            &initiator.public_key_bytes(),
            &EQUIVALENT,
            spk_id,
            otp_id,
            true,
        )
        .unwrap();
        assert_ne!(
            honest.shared_secret, altered.shared_secret,
            "an equivalent ephemeral must not derive the handshake's secret"
        );

        // And the prekey selection is bound too: the same ephemeral against a
        // different prekey id is a different handshake.
        let other_prekey = kdf_x3dh(
            &[7u8; 96],
            &mycelium_protocol::wire::session_init_binding(
                &EPHEMERAL,
                &[3u8; 32],
                1,
                Some(3),
                true,
            ),
        );
        let same_prekey = kdf_x3dh(
            &[7u8; 96],
            &mycelium_protocol::wire::session_init_binding(
                &EPHEMERAL,
                &[3u8; 32],
                1,
                Some(2),
                true,
            ),
        );
        assert_ne!(other_prekey, same_prekey);
    }

    /// A one-time prekey is spent by the caller once a message authenticates,
    /// not by the derivation: peeking must leave it available, or a corrupted
    /// copy of an init burns it and the genuine init fails (ADR-015).
    #[test]
    fn test_deriving_does_not_spend_the_one_time_prekey() {
        let identity = Identity::generate();
        let mut state = PrekeyState::new(identity);
        state.generate_one_time_prekeys(1);
        let bundle = state.issue_bundle();
        let otp_id = bundle
            .one_time_prekey_id
            .expect("the bundle offers the prekey just generated");

        let initiator = Identity::generate();
        let init = x3dh_initiate(&initiator, &bundle, true).expect("initiate");

        let first = x3dh_respond(
            &mut state,
            &initiator.public_key_bytes(),
            &init.ephemeral_public,
            bundle.signed_prekey_id,
            Some(otp_id),
            true,
        )
        .expect("respond");
        assert!(
            state.one_time_prekey_secret(otp_id).is_some(),
            "the prekey is still there for the genuine init"
        );

        // So the same init derives the same secret again, which is what lets
        // the real one succeed after a corrupted copy failed.
        let second = x3dh_respond(
            &mut state,
            &initiator.public_key_bytes(),
            &init.ephemeral_public,
            bundle.signed_prekey_id,
            Some(otp_id),
            true,
        )
        .expect("respond again");
        assert_eq!(first.shared_secret, second.shared_secret);

        state.consume_one_time_prekey(otp_id);
        assert!(
            state.one_time_prekey_secret(otp_id).is_none(),
            "and it is gone once the caller spends it"
        );
    }
    use super::*;

    /// A non-decompressible Ed25519 encoding (y = 2 has no valid x) must be
    /// rejected, not panic, on the responder side.
    /// A bundle cached before a signed-prekey rotation must still work.
    ///
    /// The responder used to run X3DH with whatever signed prekey was current,
    /// ignoring the `signed_prekey_id` the initiator told it on the wire. After
    /// a rotation that silently derived a different shared secret, so the AEAD
    /// tag failed and the conversation was stuck forever (ROADMAP T-06).
    #[test]
    fn test_respond_with_retained_signed_prekey_after_rotation() {
        let mut bob_state = PrekeyState::new(Identity::generate());
        bob_state.generate_one_time_prekeys(2);

        // Alice caches a bundle, then Bob rotates.
        let cached = bob_state.issue_bundle();
        let cached_spk_id = cached.signed_prekey_id;
        bob_state.rotate_signed_prekey();
        assert_ne!(
            bob_state.signed_prekey_id, cached_spk_id,
            "precondition: the rotation must change the id"
        );

        let alice = Identity::generate();
        let init = x3dh_initiate(&alice, &cached, true).unwrap();
        let respond = x3dh_respond(
            &mut bob_state,
            &alice.public_key_bytes(),
            &init.ephemeral_public,
            cached.signed_prekey_id,
            cached.one_time_prekey_id,
            true,
        )
        .expect("a bundle from before the rotation must still complete X3DH");

        assert_eq!(
            init.shared_secret, respond.shared_secret,
            "both sides must derive the same secret across a rotation"
        );
    }

    /// A bundle older than the retention window fails loudly, rather than
    /// deriving a secret that silently disagrees.
    #[test]
    fn test_respond_rejects_signed_prekey_beyond_retention() {
        let mut bob_state = PrekeyState::new(Identity::generate());
        let cached = bob_state.bundle();

        for _ in 0..=MAX_RETAINED_SIGNED_PREKEYS {
            bob_state.rotate_signed_prekey();
        }

        let alice = Identity::generate();
        let init = x3dh_initiate(&alice, &cached, true).unwrap();
        let result = x3dh_respond(
            &mut bob_state,
            &alice.public_key_bytes(),
            &init.ephemeral_public,
            cached.signed_prekey_id,
            cached.one_time_prekey_id,
            true,
        );

        assert!(
            matches!(result, Err(X3dhError::SignedPrekeyNotFound)),
            "a bundle older than the retention window must fail loudly"
        );
    }

    /// Retained signed prekeys must survive a persistence round trip, or a
    /// restart re-opens the window this task closed.
    #[test]
    fn test_retained_signed_prekeys_survive_roundtrip() {
        let identity = Identity::generate();
        let identity_bytes = identity.to_bytes();
        let mut state = PrekeyState::new(identity);
        let cached = state.bundle();
        state.rotate_signed_prekey();

        let restored = PrekeyState::from_bytes_with_identity(
            &state.to_bytes(),
            Identity::from_bytes(&identity_bytes).unwrap(),
        )
        .unwrap();
        assert!(
            restored
                .signed_prekey_secret_for(cached.signed_prekey_id)
                .is_some(),
            "the retained signed prekey must be restored"
        );

        // And it still completes X3DH after the round trip.
        let mut restored = restored;
        let alice = Identity::generate();
        let init = x3dh_initiate(&alice, &cached, true).unwrap();
        let respond = x3dh_respond(
            &mut restored,
            &alice.public_key_bytes(),
            &init.ephemeral_public,
            cached.signed_prekey_id,
            cached.one_time_prekey_id,
            true,
        )
        .unwrap();
        assert_eq!(init.shared_secret, respond.shared_secret);
    }

    #[test]
    fn test_x3dh_respond_rejects_invalid_identity_key() {
        let mut bob_state = PrekeyState::new(Identity::generate());
        let mut bad_key = [0u8; 32];
        bad_key[0] = 0x02;
        let spk_id = bob_state.signed_prekey_id;
        let result = x3dh_respond(&mut bob_state, &bad_key, &[7u8; 32], spk_id, None, true);
        assert!(matches!(result, Err(X3dhError::InvalidIdentityKey)));
    }

    /// Two initiators must never be handed the same one-time prekey.
    #[test]
    fn test_issue_bundle_reserves_one_time_prekey() {
        let mut bob_state = PrekeyState::new(Identity::generate());
        bob_state.generate_one_time_prekeys(3);

        let b1 = bob_state.issue_bundle();
        let b2 = bob_state.issue_bundle();
        assert_ne!(b1.one_time_prekey_id, b2.one_time_prekey_id);
        assert_eq!(bob_state.available_one_time_prekeys(), 1);

        // Both initiators can still complete X3DH with their issued OTP.
        let alice = Identity::generate();
        let carol = Identity::generate();
        let a = x3dh_initiate(&alice, &b1, true).unwrap();
        let c = x3dh_initiate(&carol, &b2, true).unwrap();
        let ra = x3dh_respond(
            &mut bob_state,
            &alice.public_key_bytes(),
            &a.ephemeral_public,
            b1.signed_prekey_id,
            b1.one_time_prekey_id,
            true,
        )
        .unwrap();
        let rc = x3dh_respond(
            &mut bob_state,
            &carol.public_key_bytes(),
            &c.ephemeral_public,
            b2.signed_prekey_id,
            b2.one_time_prekey_id,
            true,
        )
        .unwrap();
        assert_eq!(a.shared_secret, ra.shared_secret);
        assert_eq!(c.shared_secret, rc.shared_secret);

        // Issued OTPs survive a persistence round-trip.
        let mut state2 = PrekeyState::new(Identity::generate());
        state2.generate_one_time_prekeys(2);
        let issued = state2.issue_bundle();
        let restored =
            PrekeyState::from_bytes_with_identity(&state2.to_bytes(), Identity::generate())
                .unwrap();
        assert!(restored
            .one_time_prekeys
            .iter()
            .any(|(id, _)| Some(*id) == issued.one_time_prekey_id));
    }

    #[test]
    fn test_x3dh_roundtrip_with_otp() {
        let alice = Identity::generate();
        let bob_identity = Identity::generate();

        let mut bob_state = PrekeyState::new(bob_identity);
        bob_state.generate_one_time_prekeys(10);

        let bundle = bob_state.bundle();

        // Alice initiates
        let init_result = x3dh_initiate(&alice, &bundle, true).unwrap();

        // Bob responds
        let respond_result = x3dh_respond(
            &mut bob_state,
            &alice.public_key_bytes(),
            &init_result.ephemeral_public,
            bundle.signed_prekey_id,
            bundle.one_time_prekey_id,
            true,
        )
        .unwrap();

        // Both should derive the same shared secret
        assert_eq!(init_result.shared_secret, respond_result.shared_secret);
    }

    #[test]
    fn test_x3dh_roundtrip_without_otp() {
        let alice = Identity::generate();
        let bob_identity = Identity::generate();

        let mut bob_state = PrekeyState::new(bob_identity);
        // No one-time prekeys

        let bundle = bob_state.bundle();
        assert!(bundle.one_time_prekey.is_none());

        let init_result = x3dh_initiate(&alice, &bundle, true).unwrap();

        let respond_result = x3dh_respond(
            &mut bob_state,
            &alice.public_key_bytes(),
            &init_result.ephemeral_public,
            bundle.signed_prekey_id,
            None,
            true,
        )
        .unwrap();

        assert_eq!(init_result.shared_secret, respond_result.shared_secret);
    }

    #[test]
    fn test_prekey_bundle_signature_verification() {
        let identity = Identity::generate();
        let state = PrekeyState::new(identity);
        let bundle = state.bundle();

        // Verify signature is valid
        let verifying_key = VerifyingKey::from_bytes(&bundle.identity_key).unwrap();
        let sig_bytes: [u8; 64] = bundle
            .signed_prekey_signature
            .as_slice()
            .try_into()
            .unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(verifying_key
            .verify(&bundle.signed_prekey, &signature)
            .is_ok());
    }

    #[test]
    fn test_one_time_prekey_consumption() {
        let identity = Identity::generate();
        let mut state = PrekeyState::new(identity);
        state.generate_one_time_prekeys(3);

        assert_eq!(state.one_time_prekeys.len(), 3);

        let id = state.one_time_prekeys[0].0;
        let consumed = state.consume_one_time_prekey(id);
        assert!(consumed.is_some());
        assert_eq!(state.one_time_prekeys.len(), 2);

        // Can't consume same one again
        let again = state.consume_one_time_prekey(id);
        assert!(again.is_none());
    }

    #[test]
    fn test_prekey_state_serialization_roundtrip() {
        let identity = Identity::generate();
        let identity2 = Identity::from_bytes(&identity.to_bytes()).unwrap();

        let mut state = PrekeyState::new(identity);
        state.generate_one_time_prekeys(25);

        let original_spk_id = state.signed_prekey_id;
        let original_otp_count = state.one_time_prekeys.len();
        let original_next_otp_id = state.next_otp_id;
        let original_next_spk_id = state.next_spk_id;

        // Serialize and deserialize
        let bytes = state.to_bytes();
        let restored = PrekeyState::from_bytes_with_identity(&bytes, identity2).unwrap();

        assert_eq!(restored.signed_prekey_id, original_spk_id);
        assert_eq!(restored.one_time_prekeys.len(), original_otp_count);
        assert_eq!(restored.next_otp_id, original_next_otp_id);
        assert_eq!(restored.next_spk_id, original_next_spk_id);

        // Bundles should produce the same public keys
        let bundle_orig = state.bundle();
        let bundle_rest = restored.bundle();
        assert_eq!(bundle_orig.signed_prekey, bundle_rest.signed_prekey);
        assert_eq!(bundle_orig.signed_prekey_id, bundle_rest.signed_prekey_id);
    }

    #[test]
    fn test_prekey_state_serialization_empty_otps() {
        let identity = Identity::generate();
        let identity2 = Identity::from_bytes(&identity.to_bytes()).unwrap();

        let state = PrekeyState::new(identity);
        assert_eq!(state.one_time_prekeys.len(), 0);

        let bytes = state.to_bytes();
        let restored = PrekeyState::from_bytes_with_identity(&bytes, identity2).unwrap();
        assert_eq!(restored.one_time_prekeys.len(), 0);
        assert_eq!(restored.signed_prekey_id, 1);
    }

    #[test]
    fn test_prekey_state_serialization_after_rotation() {
        let identity = Identity::generate();
        let identity2 = Identity::from_bytes(&identity.to_bytes()).unwrap();

        let mut state = PrekeyState::new(identity);
        state.generate_one_time_prekeys(5);
        state.rotate_signed_prekey();
        state.rotate_signed_prekey();

        let bytes = state.to_bytes();
        let restored = PrekeyState::from_bytes_with_identity(&bytes, identity2).unwrap();
        assert_eq!(restored.signed_prekey_id, state.signed_prekey_id);
        assert_eq!(restored.next_spk_id, state.next_spk_id);
    }

    #[test]
    fn test_prekey_state_from_bytes_too_short() {
        let identity = Identity::generate();
        assert!(PrekeyState::from_bytes_with_identity(&[0; 10], identity).is_none());
    }

    #[test]
    fn test_prekey_state_from_bytes_truncated_otps() {
        let identity = Identity::generate();
        let identity2 = Identity::from_bytes(&identity.to_bytes()).unwrap();

        let mut state = PrekeyState::new(identity);
        state.generate_one_time_prekeys(5);
        let mut bytes = state.to_bytes();

        // Truncate: claim 5 OTPs but only provide data for 2
        bytes.truncate(48 + 2 * 36);
        assert!(PrekeyState::from_bytes_with_identity(&bytes, identity2).is_none());
    }

    /// The answered-handshake record is bounded, does not grow on a repeat,
    /// and retires with the signed prekey it belongs to.
    ///
    /// Retiring with the prekey is the point: that is when the init it
    /// remembers stops being derivable, so keeping the entry any longer would
    /// be bookkeeping for an attack that can no longer happen (ADR-015).
    #[test]
    fn test_answered_handshakes_are_bounded_and_retire_with_their_prekey() {
        let mut state = PrekeyState::new(Identity::generate());
        let first_spk = state.signed_prekey_id;

        let binding = |n: u8| vec![n; 69];
        state.mark_handshake_answered(first_spk, &binding(1));
        state.mark_handshake_answered(first_spk, &binding(1));
        assert!(state.has_answered_handshake(&binding(1)));
        assert!(!state.has_answered_handshake(&binding(2)));
        assert_eq!(
            state.answered_handshake_count(),
            1,
            "a repeat must not take a second slot"
        );

        // One rotation: the prekey is retained, so the record stays.
        state.rotate_signed_prekey();
        let second_spk = state.signed_prekey_id;
        state.mark_handshake_answered(second_spk, &binding(2));
        assert!(state.has_answered_handshake(&binding(1)));

        // Enough rotations to push the first prekey out of retention, and the
        // record goes with it.
        for _ in 0..MAX_RETAINED_SIGNED_PREKEYS {
            state.rotate_signed_prekey();
        }
        assert!(state.signed_prekey_secret_for(first_spk).is_none());
        assert!(
            !state.has_answered_handshake(&binding(1)),
            "an init whose signed prekey has retired cannot be derived again"
        );
        assert!(
            state.has_answered_handshake(&binding(2)),
            "and one whose prekey is still retained is still remembered"
        );

        // Nor can a retired one come back. A long-lived session re-offers its
        // marker on every decrypt, so without this the obsolete entries would
        // accumulate and, at capacity, evict the ones still doing work.
        state.mark_persisted(); // the inserts above set it
        state.mark_handshake_answered(first_spk, &binding(1));
        assert!(!state.has_answered_handshake(&binding(1)));
        assert!(
            !state.needs_persist(),
            "and a refused entry must not ask for a blob write either"
        );
    }

    /// The bound holds, oldest first.
    #[test]
    fn test_the_answered_handshake_record_evicts_its_oldest() {
        let mut state = PrekeyState::new(Identity::generate());
        let spk = state.signed_prekey_id;
        let binding = |n: u32| n.to_le_bytes().to_vec();

        for n in 0..(MAX_ANSWERED_HANDSHAKES as u32 + 2) {
            state.mark_handshake_answered(spk, &binding(n));
        }
        assert_eq!(state.answered_handshake_count(), MAX_ANSWERED_HANDSHAKES);
        assert!(!state.has_answered_handshake(&binding(0)));
        assert!(!state.has_answered_handshake(&binding(1)));
        assert!(state.has_answered_handshake(&binding(MAX_ANSWERED_HANDSHAKES as u32 + 1)));
    }

    /// The record survives the prekey blob, and a blob written before it
    /// existed still loads.
    #[test]
    fn test_answered_handshakes_round_trip_through_the_blob() {
        let identity = Identity::generate();
        let identity_bytes = identity.to_bytes();
        let mut state = PrekeyState::new(identity);
        state.generate_one_time_prekeys(3);
        state.rotate_signed_prekey();
        let spk = state.signed_prekey_id;
        state.mark_handshake_answered(spk, b"a binding");

        let blob = state.to_bytes();
        let restored = PrekeyState::from_bytes_with_identity(
            &blob,
            Identity::from_bytes(&identity_bytes).unwrap(),
        )
        .expect("round-trips");
        assert!(restored.has_answered_handshake(b"a binding"));
        assert_eq!(restored.signed_prekey_id, spk);

        let older = &blob[..blob.len() - (4 + 36)];
        let legacy = PrekeyState::from_bytes_with_identity(
            older,
            Identity::from_bytes(&identity_bytes).unwrap(),
        )
        .expect("an older blob still loads");
        assert_eq!(legacy.answered_handshake_count(), 0);
        assert_eq!(legacy.signed_prekey_id, spk);
        assert_eq!(legacy.one_time_prekeys.len(), 3);
    }
}
