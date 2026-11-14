use sha2::{Digest, Sha256};

use mycelium_protocol::types::{MessageId, NodeId};

use crate::double_ratchet::{RatchetError, RatchetHeader, RatchetState};
use crate::identity::{node_id_from_public_key, Identity};
use crate::x3dh::{self, PrekeyBundle, PrekeyState, X3dhError};

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A `SessionInit` we have sent and the peer has not confirmed.
///
/// The transcript is what a `SessionReject` has to name: the envelope's id and
/// source are cleartext and forgeable, so an attacker could otherwise provoke
/// a genuine rejection of a `SessionInit` it fabricated under our name and
/// have us act on it.
struct UnconfirmedHandshake {
    transcript: [u8; 32],
    /// The message carried inside the `SessionInit`.
    init_message: MessageId,
    /// Messages sent after it, before the peer confirmed anything.
    follow_ups: Vec<MessageId>,
    /// When the `SessionInit` went out, so a handshake that is never
    /// answered can be given up on — see `stale_handshakes`.
    started: Instant,
    /// Whether the peer has acknowledged a message sent under this handshake.
    ///
    /// Evidence that it holds the session, for a conversation that will never
    /// confirm one: confirmation needs something of the peer's to decrypt, and
    /// a peer that reads and acknowledges without ever replying produces
    /// nothing. Kept here rather than read back from the message rows, which
    /// the user can delete — deleting a conversation then abandoned a healthy
    /// session at the next sweep (ADR-015).
    ///
    /// Not confirmation: a receipt is unauthenticated, so a forged one must
    /// not keep a dead session alive or strip a live handshake of its
    /// rejection protection. It only suppresses the sweep, which is what the
    /// pairing had before the sweep existed (T-42).
    acknowledged: bool,
}

/// The fields of a `SessionInit` that identify its handshake.
///
/// Carried as one value because they are always wanted together — by the
/// derivation, by the binding and by both replay records — and because
/// threading them separately is how a caller comes to pass one that disagrees
/// with the others. `first_message_number` answers both questions the binding
/// asks about the payload: whether there is one, and, if there is, that it is
/// the first of its chain.
#[derive(Clone, Copy)]
struct InitFields<'a> {
    identity_key: &'a [u8; 32],
    ephemeral_key: &'a [u8; 32],
    signed_prekey_id: u32,
    one_time_prekey_id: Option<u32>,
    first_message_number: Option<u32>,
}

impl InitFields<'_> {
    /// Whether the init encloses a message — which is part of its identity, so
    /// that stripping or adding a payload is a different handshake rather than
    /// the same one wearing a different coat.
    fn carries_message(&self) -> bool {
        self.first_message_number.is_some()
    }

    fn binding(&self) -> Vec<u8> {
        mycelium_protocol::wire::session_init_binding(
            self.ephemeral_key,
            self.identity_key,
            self.signed_prekey_id,
            self.one_time_prekey_id,
            self.carries_message(),
        )
    }

    fn binding_hash(&self) -> [u8; 32] {
        crate::x3dh::handshake_binding_hash(&self.binding())
    }
}

/// A per-peer encrypted session.
#[derive(Clone)]
pub struct Session {
    pub peer_id: NodeId,
    pub ratchet: RatchetState,
    pub safety_number: String,
    pub is_verified: bool,
    /// The **binding** of the `SessionInit` this session was accepted from,
    /// hashed, when we were the responder.
    ///
    /// Kept so a replay of that init can be recognised. An envelope's
    /// `message_id` is not covered by it and duplicate detection keys on that,
    /// so a relay can re-deliver an init we accepted under a fresh id; the
    /// rejection we would send is then a *valid* rejection of an init the
    /// initiator really sent, which it would act on (ADR-012).
    ///
    /// The binding rather than a hash of the whole payload, because the
    /// payload's nested message is free to vary: a captured later ciphertext
    /// from the same chain decrypts on a fresh ratchet, so an init with this
    /// header and that message inside would derive this very session again and
    /// install it over one that has moved on — rewinding a ratchet, which
    /// reuses message keys. The binding is what the derivation covers, so it
    /// identifies the handshake (ADR-015).
    ///
    /// `PrekeyState::answered_handshakes` is the other half, and the two have
    /// different lifetimes on purpose: this one is per session, holds one
    /// entry, and so cannot be grown by a forged message-less init; that one
    /// outlives the session and covers the handshakes we answered without
    /// building a session from them.
    pub accepted_binding: Option<AnsweredInit>,
}

/// The init a session was accepted from: what identifies it, and which signed
/// prekey it used.
///
/// The prekey id travels with the hash because the durable record is scoped to
/// the prekey's retention — see `PrekeyState::answered_handshakes` — and the
/// promotion in `decrypt_from` has only the session to hand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnsweredInit {
    pub binding_hash: [u8; 32],
    pub signed_prekey_id: u32,
}

/// Manages all active crypto sessions.
pub struct SessionManager {
    sessions: HashMap<NodeId, Session>,
    /// When we last initiated a session with each peer. Used to detect the
    /// race where both peers initiate at the same time (not persisted).
    recent_initiations: HashMap<NodeId, Instant>,
    /// Handshakes we initiated that the peer has not confirmed, with the
    /// messages we sent under them.
    ///
    /// The initiator installs its session optimistically, so `has_session` is
    /// not evidence the peer agrees. A peer is confirmed the moment we
    /// successfully decrypt anything from it: only its own ratchet could have
    /// produced that. Until then a `SessionReject` may legitimately tear the
    /// session down; afterwards it may not, which is what stops a forged
    /// reject from killing working traffic (ADR-009, ROADMAP T-06).
    ///
    /// In memory only. After a restart an unconfirmed handshake is treated as
    /// confirmed, so a reject arriving across a restart is ignored and
    /// recovery waits for the next send to fail.
    unconfirmed_handshakes: HashMap<NodeId, UnconfirmedHandshake>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            recent_initiations: HashMap::new(),
            unconfirmed_handshakes: HashMap::new(),
        }
    }

    /// Whether we initiated a session with `peer` within `window`.
    pub fn initiated_recently(&self, peer: &NodeId, window: Duration) -> bool {
        self.recent_initiations
            .get(peer)
            .map(|t| t.elapsed() < window)
            .unwrap_or(false)
    }

    /// Decrypt the first message of an incoming `SessionInit` with the
    /// session it would create, without installing that session. Used when
    /// both peers initiated at once and our session is the one that survives:
    /// the peer's first message is still delivered, and the peer switches to
    /// our session when our `SessionInit` reaches it.
    #[allow(clippy::too_many_arguments)]
    pub fn decrypt_first_message_only(
        our_state: &mut PrekeyState,
        peer_id: NodeId,
        their_identity_key: &[u8; 32],
        their_ephemeral_key: &[u8; 32],
        used_signed_prekey_id: u32,
        used_otp_id: Option<u32>,
        header: &RatchetHeader,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let init = InitFields {
            identity_key: their_identity_key,
            ephemeral_key: their_ephemeral_key,
            signed_prekey_id: used_signed_prekey_id,
            one_time_prekey_id: used_otp_id,
            first_message_number: Some(header.message_number),
        };
        let mut session = Self::build_accepted_session(our_state, peer_id, init)?;
        let plaintext = session
            .ratchet
            .decrypt(header, ciphertext, ad)
            .map_err(SessionError::Ratchet)?;

        // The message was genuine, so this handshake is answered: record it,
        // and retire the prekey if it named one. Both commit on the same
        // event, and for the same reason — a replay of this init, under a
        // fresh envelope id or after a restart, must not be able to derive it
        // again and install the session we deliberately discarded. The prekey
        // alone was not enough: an init that named none retired nothing
        // (ADR-015).
        Self::mark_answered(our_state, init);
        if let Some(otp_id) = used_otp_id {
            our_state.consume_one_time_prekey(otp_id);
        }

        Ok(plaintext)
    }

    /// Initiate a new session with a peer using their prekey bundle.
    ///
    /// `carries_message` says whether the `SessionInit` this derives will
    /// enclose a first message. It is part of the handshake's identity, so the
    /// two forms derive different secrets and an init cannot be turned into
    /// the other by stripping or adding a payload (ADR-015). A message-less
    /// initiator must pass `false`, and takes the signed-prekey-only variant.
    pub fn initiate_session(
        &mut self,
        our_identity: &Identity,
        peer_id: NodeId,
        their_bundle: &PrekeyBundle,
        carries_message: bool,
    ) -> Result<InitiateResult, SessionError> {
        // The NodeId is SHA-256 of the identity key: a bundle whose key does
        // not hash to `peer_id` was not published by that peer.
        if node_id_from_public_key(&their_bundle.identity_key) != peer_id {
            return Err(SessionError::IdentityMismatch);
        }

        let x3dh_result = x3dh::x3dh_initiate(our_identity, their_bundle, carries_message)
            .map_err(SessionError::X3dh)?;

        let ratchet =
            RatchetState::init_alice(x3dh_result.shared_secret, their_bundle.signed_prekey);

        let safety_number =
            compute_safety_number(&our_identity.public_key_bytes(), &their_bundle.identity_key);

        let session = Session {
            peer_id,
            ratchet,
            safety_number: safety_number.clone(),
            is_verified: false,
            // We initiated this one; there is no init of theirs behind it.
            accepted_binding: None,
        };

        self.sessions.insert(peer_id, session);
        self.recent_initiations.insert(peer_id, Instant::now());

        Ok(InitiateResult {
            ephemeral_public: x3dh_result.ephemeral_public,
            ad: x3dh_result.ad,
            safety_number,
            used_signed_prekey_id: their_bundle.signed_prekey_id,
            // What the derivation used, not what the bundle offered: a
            // message-less init takes the signed-prekey-only variant, and an
            // init naming a prekey it did not use is one the responder can
            // only reject (ADR-015).
            used_one_time_prekey_id: x3dh_result.one_time_prekey_id,
        })
    }

    /// Accept an incoming session from a peer.
    ///
    /// Returns the safety number and the ids of any messages we had sent
    /// under the session this one replaces — see `install_accepted`.
    #[allow(clippy::too_many_arguments)]
    /// Accept a `SessionInit` that carries no message.
    ///
    /// Nothing here authenticates the initiator, so a one-time prekey must not
    /// be spent: there is no message to decide that the init was genuine. An
    /// init that names one is refused, and a sender that wants this form uses
    /// the signed-prekey-only X3DH variant — which costs that handshake its
    /// one-time-prekey forward secrecy, the honest price for an init with
    /// nothing to authenticate (ADR-015).
    pub fn accept_session(
        &mut self,
        our_state: &mut PrekeyState,
        peer_id: NodeId,
        their_identity_key: &[u8; 32],
        their_ephemeral_key: &[u8; 32],
        used_signed_prekey_id: u32,
        used_otp_id: Option<u32>,
    ) -> Result<(String, Vec<MessageId>), SessionError> {
        // Refused before deriving anything: there is no message to show the
        // init was genuine, so spending the prekey here would let a forgery
        // burn it, and leaving it unspent while installing a session would
        // hand the next forgery the same prekey again.
        if used_otp_id.is_some() {
            return Err(SessionError::PrekeyWithoutMessage);
        }

        let init = InitFields {
            identity_key: their_identity_key,
            ephemeral_key: their_ephemeral_key,
            signed_prekey_id: used_signed_prekey_id,
            one_time_prekey_id: used_otp_id,
            first_message_number: None,
        };
        self.refuse_if_answered(&peer_id, init)?;

        let mut session = Self::build_accepted_session(our_state, peer_id, init)?;
        // Recorded even though nothing here authenticates the initiator: it is
        // one slot on this session, replaced by the next init we accept from
        // the peer, so a forgery cannot grow it. That is why this record can
        // cover the message-less path and the prekey-scoped one cannot.
        session.accepted_binding = Some(AnsweredInit {
            binding_hash: init.binding_hash(),
            signed_prekey_id: used_signed_prekey_id,
        });
        let safety_number = session.safety_number.clone();
        let superseded = self.install_accepted(peer_id, session);
        Ok((safety_number, superseded))
    }

    /// Remember a handshake we have answered, keyed on its bound header.
    ///
    /// Only ever called where the AEAD has verified: an unauthenticated path
    /// would let a forgery choose the bindings that fill the record's bound.
    fn mark_answered(our_state: &mut PrekeyState, init: InitFields<'_>) {
        our_state.mark_handshake_answered(init.signed_prekey_id, &init.binding());
    }

    /// Install an accepted session, clearing any handshake of our own it
    /// supersedes and returning the messages that died with it.
    ///
    /// Only the **follow-ups** die. Under ADR-007's tie-break the peer that
    /// keeps its own session still decrypts the first message out of ours, so
    /// the message carried inside our `SessionInit` was delivered; reporting
    /// it failed would overwrite a status that may already be "delivered" or
    /// "read". Messages sent after it went out under the session the peer
    /// discarded, so those cannot arrive.
    ///
    /// Clearing the entry is the point: `handshake_unconfirmed` stayed true
    /// for a peer whose session we had just authenticated, so a
    /// `SessionReject` passed that gate and deleted a working session along
    /// with its stored row and cached bundle.
    fn install_accepted(&mut self, peer_id: NodeId, session: Session) -> Vec<MessageId> {
        self.sessions.insert(peer_id, session);
        self.unconfirmed_handshakes
            .remove(&peer_id)
            .map(|handshake| handshake.follow_ups)
            .unwrap_or_default()
    }

    /// Accept an incoming session and decrypt the first message it carries.
    ///
    /// The new session only replaces any existing session for `peer_id` if the
    /// enclosed message authenticates under it. A forged or replayed
    /// `SessionInit` therefore cannot clobber a working session.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_session_with_first_message(
        &mut self,
        our_state: &mut PrekeyState,
        peer_id: NodeId,
        their_identity_key: &[u8; 32],
        their_ephemeral_key: &[u8; 32],
        used_signed_prekey_id: u32,
        used_otp_id: Option<u32>,
        header: &RatchetHeader,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<(String, Vec<u8>, Vec<MessageId>), SessionError> {
        let init = InitFields {
            identity_key: their_identity_key,
            ephemeral_key: their_ephemeral_key,
            signed_prekey_id: used_signed_prekey_id,
            one_time_prekey_id: used_otp_id,
            first_message_number: Some(header.message_number),
        };
        self.refuse_if_answered(&peer_id, init)?;

        let mut session = Self::build_accepted_session(our_state, peer_id, init)?;
        session.accepted_binding = Some(AnsweredInit {
            binding_hash: init.binding_hash(),
            signed_prekey_id: used_signed_prekey_id,
        });
        let plaintext = session
            .ratchet
            .decrypt(header, ciphertext, ad)
            .map_err(SessionError::Ratchet)?;

        // The message authenticated, so the handshake is answered and the
        // one-time prekey is spent now and not before: derivation only peeks
        // at it. A corrupted copy of an init used to burn the prekey, after
        // which the genuine init failed and drew a rejection the initiator
        // acted on (ADR-015).
        Self::mark_answered(our_state, init);
        if let Some(otp_id) = used_otp_id {
            our_state.consume_one_time_prekey(otp_id);
        }

        let safety_number = session.safety_number.clone();
        let superseded = self.install_accepted(peer_id, session);
        Ok((safety_number, plaintext, superseded))
    }

    fn build_accepted_session(
        our_state: &mut PrekeyState,
        peer_id: NodeId,
        init: InitFields<'_>,
    ) -> Result<Session, SessionError> {
        let InitFields {
            identity_key: their_identity_key,
            ephemeral_key: their_ephemeral_key,
            signed_prekey_id: used_signed_prekey_id,
            one_time_prekey_id: used_otp_id,
            first_message_number,
        } = init;

        if node_id_from_public_key(their_identity_key) != peer_id {
            return Err(SessionError::IdentityMismatch);
        }

        // One encoding per key, so the init's bytes identify the handshake.
        // X25519 masks the high bit and reduces modulo p, so without this an
        // altered copy of an init derives the same secrets and decrypts the
        // same message while hashing differently — which is a second identity
        // for one handshake, and that is what lets a replay of the original
        // collect an actionable rejection (T-35, ADR-012).
        if !crate::identity::is_canonical_x25519(their_ephemeral_key) {
            return Err(SessionError::NonCanonicalEphemeralKey);
        }

        // The enclosed message must be the first of its chain.
        //
        // The initiator encrypts it on a ratchet it has just built, so message
        // 0 is the only thing a genuine init can carry. A relay that captured
        // a later message from that chain could otherwise wrap it into a copy
        // of the init and get that answered first: the handshake is then spent
        // on the wrong message, and the genuine init — now a handshake we have
        // already answered — arrives to find the key for message 0 gone with
        // whichever session that copy was derived into. One message of the
        // conversation, lost silently (ADR-007, ADR-015).
        if matches!(first_message_number, Some(n) if n != 0) {
            return Err(SessionError::NotTheFirstMessage);
        }

        // An init stays derivable while its signed prekey is retained, so the
        // only thing stopping a second answer to the same handshake is the
        // record of the first. Checked on the binding, which is what the
        // derivation covers, so substituting the nested message changes
        // nothing here (ADR-015).
        let binding = init.binding();
        if our_state.has_answered_handshake(&binding) {
            return Err(SessionError::HandshakeAlreadyAnswered);
        }

        // Resolve the signed prekey the initiator actually used before any DH,
        // so a stale bundle fails loudly here instead of producing a session
        // whose keys silently disagree.
        let used_spk = x25519_dalek::StaticSecret::from(
            our_state
                .signed_prekey_secret_for(used_signed_prekey_id)
                .ok_or(SessionError::X3dh(x3dh::X3dhError::SignedPrekeyNotFound))?
                .to_bytes(),
        );

        let x3dh_result = x3dh::x3dh_respond(
            our_state,
            their_identity_key,
            their_ephemeral_key,
            used_signed_prekey_id,
            used_otp_id,
            init.carries_message(),
        )
        .map_err(SessionError::X3dh)?;

        // Bob's initial Double Ratchet DH key is the same signed prekey the
        // initiator used, not whichever is current now.
        let bob_spk = used_spk;

        let ratchet = RatchetState::init_bob(x3dh_result.shared_secret, bob_spk);

        let safety_number =
            compute_safety_number(&our_state.identity.public_key_bytes(), their_identity_key);

        Ok(Session {
            peer_id,
            ratchet,
            safety_number,
            is_verified: false,
            // Set by the caller, which knows the init it accepted.
            accepted_binding: None,
        })
    }

    /// Encrypt a message for a peer.
    pub fn encrypt_for(
        &mut self,
        peer: &NodeId,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(RatchetHeader, Vec<u8>), SessionError> {
        let session = self.sessions.get_mut(peer).ok_or(SessionError::NoSession)?;

        session
            .ratchet
            .encrypt(plaintext, ad)
            .map_err(SessionError::Ratchet)
    }

    /// Decrypt a message from a peer.
    pub fn decrypt_from(
        &mut self,
        our_state: &mut PrekeyState,
        peer: &NodeId,
        header: &RatchetHeader,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let session = self.sessions.get_mut(peer).ok_or(SessionError::NoSession)?;

        let plaintext = session
            .ratchet
            .decrypt(header, ciphertext, ad)
            .map_err(SessionError::Ratchet)?;

        // The init this session was accepted from is now durably answered.
        //
        // Until this point its only record was the session's own slot, which
        // dies with the session — so replacing the session dropped the marker
        // while the signed prekey was still retained, and the old init's
        // header plus a captured first-chain ciphertext could reinstall the
        // obsolete session over the working one. Promoting it here moves it to
        // the record that retires with the prekey instead.
        //
        // This is the right moment for two reasons: the decrypt just
        // authenticated the peer, so a forgery cannot drive the promotion; and
        // it is the *earliest* moment that matters, because a responder has no
        // sending chain until something of the initiator's arrives. Before
        // this, the session has carried no traffic in either direction and
        // reinstalling an identical one costs nothing (ADR-015).
        //
        // The session's own entry stays where it is. Clearing it would make the
        // two records a handover, and a handover across two stores has an
        // order to get wrong: the prekey blob is written by the caller, so a
        // promotion followed by a lost write would leave neither marker. Kept,
        // they are independent, and losing either leaves the other. Promoting
        // again on a later decrypt is a no-op the record deduplicates.
        if let Some(answered) = session.accepted_binding {
            our_state
                .mark_handshake_answered_hash(answered.signed_prekey_id, answered.binding_hash);
        }

        // Only the peer's own ratchet could have produced something we can
        // decrypt, so the handshake is confirmed.
        self.unconfirmed_handshakes.remove(peer);
        Ok(plaintext)
    }

    /// Record a `SessionInit` the peer has not confirmed.
    ///
    /// `transcript` is the hash of the init's payload as sent, which is what a
    /// `SessionReject` must name to be acted on, and `init_message` is the
    /// message carried inside it — tracked apart from later sends because the
    /// two die differently (see `install_accepted`).
    pub fn mark_handshake_pending(
        &mut self,
        peer: NodeId,
        transcript: [u8; 32],
        init_message: MessageId,
    ) {
        self.unconfirmed_handshakes.insert(
            peer,
            UnconfirmedHandshake {
                transcript,
                init_message,
                follow_ups: Vec::new(),
                started: Instant::now(),
                acknowledged: false,
            },
        );
    }

    /// Record a message sent after the init, while the handshake is still
    /// unconfirmed. Ignored if there is no such handshake.
    pub fn record_unconfirmed_message(&mut self, peer: NodeId, message_id: MessageId) {
        if let Some(handshake) = self.unconfirmed_handshakes.get_mut(&peer) {
            if handshake.init_message != message_id {
                handshake.follow_ups.push(message_id);
            }
        }
    }

    /// The transcript of the `SessionInit` we are waiting on, if any.
    pub fn handshake_transcript(&self, peer: &NodeId) -> Option<[u8; 32]> {
        self.unconfirmed_handshakes.get(peer).map(|h| h.transcript)
    }

    /// Whether this is the very `SessionInit` our session with the peer was
    /// accepted from — that is, a replay of it.
    ///
    /// Answering it again means refusing it, because its one-time prekey is
    /// spent and the ratchet has moved past its message, and that refusal
    /// would be a valid rejection of an init the peer really sent.
    pub fn is_answered_init(&self, peer: &NodeId, binding: &[u8]) -> bool {
        let hash = crate::x3dh::handshake_binding_hash(binding);
        self.sessions
            .get(peer)
            .and_then(|s| s.accepted_binding)
            .is_some_and(|accepted| accepted.binding_hash == hash)
    }

    /// Refuse an init this session was already accepted from.
    ///
    /// `PrekeyState`'s record cannot cover this case: a message-less init is
    /// unauthenticated, so recording it there would let forged inits — one per
    /// identity an attacker generates — fill a bound shared with every real
    /// handshake. The session's own single slot has no such problem, and it is
    /// what stops an init being re-accepted with a different message inside
    /// (ADR-015).
    fn refuse_if_answered(
        &self,
        peer_id: &NodeId,
        init: InitFields<'_>,
    ) -> Result<(), SessionError> {
        let hash = init.binding_hash();
        let answered = self
            .sessions
            .get(peer_id)
            .and_then(|s| s.accepted_binding)
            .is_some_and(|accepted| accepted.binding_hash == hash);
        if answered {
            return Err(SessionError::HandshakeAlreadyAnswered);
        }
        Ok(())
    }
    /// Whether we are waiting for this peer to confirm a handshake.
    pub fn handshake_unconfirmed(&self, peer: &NodeId) -> bool {
        self.unconfirmed_handshakes.contains_key(peer)
    }

    /// Take every message sent under an unconfirmed handshake, clearing it.
    ///
    /// For a rejection: the peer refused the `SessionInit` itself, so the
    /// message inside it died with the follow-ups.
    pub fn take_unconfirmed_messages(&mut self, peer: &NodeId) -> Vec<MessageId> {
        match self.unconfirmed_handshakes.remove(peer) {
            Some(handshake) => {
                let mut ids = vec![handshake.init_message];
                ids.extend(handshake.follow_ups);
                ids
            }
            None => Vec::new(),
        }
    }

    /// Remove the session this handshake installed, if it is still the
    /// outstanding one, returning the messages that died with it.
    ///
    /// The comparison and the removal are one operation on purpose: done as a
    /// read then a write, an authenticated `SessionInit` accepted in between
    /// was deleted anyway (T-35). `None` means the handshake is no longer
    /// ours and nothing was touched.
    pub fn remove_if_handshake(
        &mut self,
        peer: &NodeId,
        transcript: &[u8; 32],
    ) -> Option<Vec<MessageId>> {
        if self.handshake_transcript(peer) != Some(*transcript) {
            return None;
        }
        let dead = self.take_unconfirmed_messages(peer);
        self.remove_session(peer);
        Some(dead)
    }

    /// Note that the peer has acknowledged a message sent under its current
    /// handshake. See `UnconfirmedHandshake::acknowledged`.
    ///
    /// `message_id` must be one this handshake sent **after** the init. A
    /// receipt for some older message of that peer's would otherwise vouch for
    /// a handshake it knows nothing about — receipts arrive late, so one from a
    /// session long gone could permanently suppress the recovery of a newer
    /// dead handshake.
    ///
    /// The init's own message does not count, and that is the subtle half.
    /// Under ADR-007's tie-break the winner decrypts it with a session it then
    /// *discards*, and sends a perfectly genuine receipt for it — so a receipt
    /// for the init message proves the peer read it, not that the peer holds
    /// the session it arrived under. If the winner's own init were then lost,
    /// that receipt would pin an unusable handshake for ever. A follow-up
    /// travels as a bare `EncryptedMessage` under the installed session, so
    /// decrypting one is possible only for a peer that kept it.
    pub fn note_handshake_acknowledged(&mut self, peer: &NodeId, message_id: &MessageId) {
        if let Some(handshake) = self.unconfirmed_handshakes.get_mut(peer) {
            if handshake.follow_ups.contains(message_id) {
                handshake.acknowledged = true;
            }
        }
    }

    /// Handshakes the peer has neither confirmed nor acknowledged within
    /// `timeout`, with the messages sent under each. Nothing is removed.
    ///
    /// This is the only way out of a handshake that is never answered. The
    /// initiator installs its session optimistically, so after a
    /// `SessionInit` that cannot be accepted — a bundle whose signed prekey
    /// we no longer hold, a one-time prekey already spent — every later send
    /// is a bare `EncryptedMessage` the peer cannot read. A rejection used to
    /// be the way back, but a rejection is only sent when the responder holds
    /// no session with us (ADR-015 rule 3): a responder that kept a stale
    /// session of its own stays silent, and without this sweep that pairing
    /// never recovers.
    ///
    /// Dropping the session is what makes the next send re-handshake; the
    /// caller drops the cached bundle with it, or the retry derives from the
    /// same dead bundle. Confirmation is anything we decrypt from the peer,
    /// so an entry here means nothing of theirs has ever arrived — which is
    /// not the same as the peer not having it. A peer that reads and
    /// acknowledges without ever replying leaves a healthy session looking
    /// exactly like a dead one, which is why an acknowledged handshake is
    /// excluded here rather than left to the caller.
    ///
    /// The entry is in memory only, so a restart loses it and the sweep
    /// cannot fire. That gap predates this sweep — a late rejection is
    /// likewise ignored once the handshake record is gone — and is ROADMAP
    /// T-41.
    pub fn stale_handshakes(&self, timeout: Duration) -> Vec<(NodeId, Vec<MessageId>)> {
        self.unconfirmed_handshakes
            .iter()
            .filter(|(_, handshake)| {
                handshake.started.elapsed() >= timeout && !handshake.acknowledged
            })
            .map(|(peer, handshake)| {
                let mut ids = vec![handshake.init_message];
                ids.extend(handshake.follow_ups.iter().copied());
                (*peer, ids)
            })
            .collect()
    }

    /// Give up on one handshake, returning the messages that died with it.
    ///
    /// Separate from `stale_handshakes` so the caller can decide, with what
    /// it knows and this crate does not — whether any of those messages has
    /// been acknowledged — which of the stale handshakes to abandon.
    pub fn give_up_on_handshake(&mut self, peer: &NodeId) -> Vec<MessageId> {
        // Ids first: `remove_session` clears the handshake entry, and taking
        // them afterwards always yielded an empty list.
        let dead = self.take_unconfirmed_messages(peer);
        self.remove_session(peer);
        dead
    }

    /// Mark a handshake confirmed without decrypting (e.g. a verified receipt
    /// for a message we sent under it).
    pub fn confirm_handshake(&mut self, peer: &NodeId) {
        self.unconfirmed_handshakes.remove(peer);
    }

    /// Check if a session exists for a peer.
    pub fn has_session(&self, peer: &NodeId) -> bool {
        self.sessions.contains_key(peer)
    }

    /// Get the safety number for a peer's session.
    pub fn safety_number(&self, peer: &NodeId) -> Option<&str> {
        self.sessions.get(peer).map(|s| s.safety_number.as_str())
    }

    /// Mark a session as verified (after in-person safety number confirmation).
    pub fn verify_session(&mut self, peer: &NodeId) -> bool {
        if let Some(session) = self.sessions.get_mut(peer) {
            session.is_verified = true;
            true
        } else {
            false
        }
    }

    /// Remove a session.
    /// Forget a session.
    ///
    /// Also clears the recent-initiation marker: ADR-007's simultaneous-
    /// initiation tie-break asks whether we initiated with this peer in the
    /// last 60 s, and a node that keeps the marker after dropping the session
    /// would refuse the peer's valid `SessionInit` while holding nothing of
    /// its own — a deadlock until the window expires.
    pub fn remove_session(&mut self, peer: &NodeId) {
        self.sessions.remove(peer);
        self.recent_initiations.remove(peer);
        self.unconfirmed_handshakes.remove(peer);
    }

    /// Get an iterator over all sessions for persistence.
    pub fn all_sessions(&self) -> impl Iterator<Item = (&NodeId, &Session)> {
        self.sessions.iter()
    }

    /// Serialize a session to bytes for DB storage.
    pub fn serialize_session(session: &Session) -> Vec<u8> {
        // `to_bytes` returns the root key and both chain keys in the clear;
        // wipe this copy once it has been folded into `buf`.
        let ratchet_bytes = zeroize::Zeroizing::new(session.ratchet.to_bytes());
        let safety_bytes = session.safety_number.as_bytes();

        let mut buf = Vec::with_capacity(32 + 4 + ratchet_bytes.len() + 4 + safety_bytes.len() + 1);
        buf.extend_from_slice(session.peer_id.as_bytes());
        buf.extend_from_slice(&(ratchet_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&ratchet_bytes);
        buf.extend_from_slice(&(safety_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(safety_bytes);
        buf.push(session.is_verified as u8);
        // Appended, and optional on the way back in, so a row written before
        // this field existed still loads.
        match session.accepted_binding {
            Some(answered) => {
                buf.push(1);
                buf.extend_from_slice(&answered.binding_hash);
                buf.extend_from_slice(&answered.signed_prekey_id.to_le_bytes());
            }
            None => buf.push(0),
        }
        buf
    }

    /// Deserialize a session from bytes.
    pub fn deserialize_session(data: &[u8]) -> Result<Session, SessionError> {
        if data.len() < 37 {
            return Err(SessionError::NoSession);
        }
        let mut offset = 0;

        let mut peer_bytes = [0u8; 32];
        peer_bytes.copy_from_slice(&data[offset..offset + 32]);
        let peer_id = NodeId::from_bytes(peer_bytes);
        offset += 32;

        let ratchet_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if data.len() - offset < ratchet_len {
            return Err(SessionError::NoSession);
        }
        let ratchet = RatchetState::from_bytes(&data[offset..offset + ratchet_len])
            .map_err(SessionError::Ratchet)?;
        offset += ratchet_len;

        if offset + 4 > data.len() {
            return Err(SessionError::NoSession);
        }
        let safety_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if data.len() - offset < safety_len {
            return Err(SessionError::NoSession);
        }
        let safety_number = String::from_utf8_lossy(&data[offset..offset + safety_len]).to_string();
        offset += safety_len;

        let is_verified = if offset < data.len() {
            data[offset] != 0
        } else {
            false
        };
        offset += 1;

        // Same slot as before, holding a binding hash rather than a payload
        // transcript. A row written before the change holds a transcript,
        // which simply never matches a binding — the handshake it names is no
        // longer recognised, which costs that one session its replay marker
        // and nothing else (pre-release, no deployed nodes).
        let accepted_binding = match data.get(offset) {
            Some(1) if data.len() >= offset + 37 => {
                let mut binding_hash = [0u8; 32];
                binding_hash.copy_from_slice(&data[offset + 1..offset + 33]);
                let mut id_bytes = [0u8; 4];
                id_bytes.copy_from_slice(&data[offset + 33..offset + 37]);
                let signed_prekey_id = u32::from_le_bytes(id_bytes);
                Some(AnsweredInit {
                    binding_hash,
                    signed_prekey_id,
                })
            }
            // Absent, truncated, or a row from before this field held a
            // binding and a prekey id. Such a row loses its replay marker and
            // nothing else; the durable record covers any handshake the peer
            // has since spoken on (pre-release, no deployed nodes).
            _ => None,
        };

        Ok(Session {
            peer_id,
            ratchet,
            safety_number,
            is_verified,
            accepted_binding,
        })
    }

    /// Restore a session from deserialized data.
    pub fn restore_session(&mut self, session: Session) {
        self.sessions.insert(session.peer_id, session);
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of initiating a session.
#[derive(Debug)]
pub struct InitiateResult {
    pub ephemeral_public: [u8; 32],
    pub ad: Vec<u8>,
    pub safety_number: String,
    pub used_signed_prekey_id: u32,
    pub used_one_time_prekey_id: Option<u32>,
}

/// Compute a human-readable safety number from two identity keys.
/// Format: 16 groups of 4 digits (in 4 space-separated blocks) derived from
/// a hash of both keys in canonical order, so both peers see the same value.
fn compute_safety_number(our_key: &[u8; 32], their_key: &[u8; 32]) -> String {
    // Canonical order: smaller key first
    let (first, second) = if our_key < their_key {
        (our_key, their_key)
    } else {
        (their_key, our_key)
    };

    let mut hasher = Sha256::new();
    hasher.update(b"MyceliumSafetyNumber");
    hasher.update(first);
    hasher.update(second);
    let hash = hasher.finalize();

    // 16 groups of 4 digits = 64 digits, a space after every 4 groups
    let mut number = String::with_capacity(67); // 64 digits + 3 spaces
    for (i, chunk) in hash.chunks(2).enumerate() {
        if i > 0 && i % 4 == 0 {
            number.push(' ');
        }
        let val = u16::from_be_bytes([chunk[0], chunk[1]]) % 10000;
        number.push_str(&format!("{:04}", val));
    }

    number
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("no session established with this peer")]
    NoSession,
    #[error("identity key does not match the claimed node id")]
    IdentityMismatch,
    #[error("the peer's ephemeral key is not in its canonical encoding")]
    NonCanonicalEphemeralKey,
    #[error("a SessionInit with no message may not spend a one-time prekey")]
    PrekeyWithoutMessage,
    /// The message enclosed in a `SessionInit` is not the first on its chain.
    ///
    /// It is by construction: the initiator encrypts it on a ratchet it has
    /// just built. A copy carrying a later message of the same chain is a
    /// relay's work, and answering it would spend the handshake on the wrong
    /// message — see the guard in `build_accepted_session`.
    #[error("the message in this SessionInit is not the first of its chain")]
    NotTheFirstMessage,
    /// This exact handshake — the bound init header — has already been
    /// answered. Answering it again would install a session that was
    /// abandoned, over one that works. See
    /// `PrekeyState::answered_handshakes`.
    #[error("this handshake has already been answered")]
    HandshakeAlreadyAnswered,
    #[error("X3DH error: {0}")]
    X3dh(#[from] X3dhError),
    #[error("ratchet error: {0}")]
    Ratchet(#[from] RatchetError),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A prekey state for a side of a test that has none of its own.
    ///
    /// `decrypt_from` promotes the decrypting session's accepted init into its
    /// prekey state; where a test is not about that promotion, the initiator's
    /// side has no prekeys to speak of and this stands in for them.
    fn no_prekeys_of_its_own() -> PrekeyState {
        PrekeyState::new(Identity::generate())
    }

    #[test]
    fn test_full_session_lifecycle() {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();

        // No one-time prekeys on purpose: this exercises `accept_session`,
        // the form with no message to authenticate the initiator, and such an
        // init may not name a one-time prekey (ADR-015). The one-time-prekey
        // path is covered by the `accept_session_with_first_message` tests.
        let mut bob_prekey_state = PrekeyState::new(bob_id);
        let bob_bundle = bob_prekey_state.bundle();
        let bob_node_id = bob_prekey_state.identity.node_id();
        assert!(bob_bundle.one_time_prekey_id.is_none());

        let mut alice_sessions = SessionManager::new();
        let mut bob_sessions = SessionManager::new();

        // Alice initiates
        let init_result = alice_sessions
            .initiate_session(&alice_id, bob_node_id, &bob_bundle, false)
            .unwrap();

        // Bob accepts
        let safety_bob = bob_sessions
            .accept_session(
                &mut bob_prekey_state,
                alice_id.node_id(),
                &alice_id.public_key_bytes(),
                &init_result.ephemeral_public,
                init_result.used_signed_prekey_id,
                init_result.used_one_time_prekey_id,
            )
            .unwrap();

        // Safety numbers should match
        assert_eq!(init_result.safety_number, safety_bob.0);

        // Alice sends to Bob
        let ad = b"session-ad";
        let (header, ct) = alice_sessions
            .encrypt_for(&bob_node_id, b"hello bob", ad)
            .unwrap();
        let pt = bob_sessions
            .decrypt_from(&mut bob_prekey_state, &alice_id.node_id(), &header, &ct, ad)
            .unwrap();
        assert_eq!(pt, b"hello bob");

        // Bob sends to Alice
        let (header, ct) = bob_sessions
            .encrypt_for(&alice_id.node_id(), b"hello alice", ad)
            .unwrap();
        let pt = alice_sessions
            .decrypt_from(&mut no_prekeys_of_its_own(), &bob_node_id, &header, &ct, ad)
            .unwrap();
        assert_eq!(pt, b"hello alice");
    }

    /// A bundle/SessionInit whose identity key does not hash to the claimed
    /// NodeId must be rejected on both sides (prevents impersonation).
    #[test]
    fn test_identity_mismatch_rejected() {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();
        let mallory = Identity::generate();

        let mut bob_prekey_state = PrekeyState::new(bob_id);
        let mallory_state = PrekeyState::new(mallory);
        let mallory_bundle = mallory_state.bundle();
        let bob_node_id = bob_prekey_state.identity.node_id();

        let mut alice_sessions = SessionManager::new();
        let err = alice_sessions
            .initiate_session(&alice_id, bob_node_id, &mallory_bundle, true)
            .unwrap_err();
        assert!(matches!(err, SessionError::IdentityMismatch));
        assert!(!alice_sessions.has_session(&bob_node_id));

        let mut bob_sessions = SessionManager::new();
        let bob_spk_id = bob_prekey_state.signed_prekey_id;
        let err = bob_sessions
            .accept_session(
                &mut bob_prekey_state,
                alice_id.node_id(),
                &mallory_state.identity.public_key_bytes(),
                &[9u8; 32],
                bob_spk_id,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, SessionError::IdentityMismatch));
    }

    /// A SessionInit whose first message fails to authenticate must not
    /// replace an existing working session.
    #[test]
    fn test_accept_with_first_message_keeps_existing_session_on_failure() {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();
        let bob_node_id = bob_id.node_id();
        let alice_node_id = alice_id.node_id();

        let mut bob_prekey_state = PrekeyState::new(bob_id);
        let bob_bundle = bob_prekey_state.bundle();

        let mut alice_sessions = SessionManager::new();
        let mut bob_sessions = SessionManager::new();
        let init = alice_sessions
            .initiate_session(&alice_id, bob_node_id, &bob_bundle, true)
            .unwrap();
        let ad = b"ad";
        let (header, ct) = alice_sessions.encrypt_for(&bob_node_id, b"m1", ad).unwrap();
        let (_, pt, _) = bob_sessions
            .accept_session_with_first_message(
                &mut bob_prekey_state,
                alice_node_id,
                &alice_id.public_key_bytes(),
                &init.ephemeral_public,
                init.used_signed_prekey_id,
                init.used_one_time_prekey_id,
                &header,
                &ct,
                ad,
            )
            .unwrap();
        assert_eq!(pt, b"m1");

        // Forged SessionInit with a random ephemeral: first message cannot
        // decrypt. It re-uses the *first* message's header and ciphertext,
        // because an init may only enclose message 0 of its chain — a copy
        // carrying a later one is refused before the derivation, which would
        // make this test prove something else.
        let bob_spk_id_2 = bob_prekey_state.signed_prekey_id;
        let (header2, ct2) = alice_sessions.encrypt_for(&bob_node_id, b"m2", ad).unwrap();
        let err = bob_sessions
            .accept_session_with_first_message(
                &mut bob_prekey_state,
                alice_node_id,
                &alice_id.public_key_bytes(),
                &[5u8; 32],
                bob_spk_id_2,
                None,
                &header,
                &ct,
                ad,
            )
            .unwrap_err();
        assert!(matches!(err, SessionError::Ratchet(_)));

        // The original session still works.
        let pt2 = bob_sessions
            .decrypt_from(&mut bob_prekey_state, &alice_node_id, &header2, &ct2, ad)
            .unwrap();
        assert_eq!(pt2, b"m2");
    }

    /// The binding a session was accepted from survives persistence, and is
    /// what identifies a replay of that init (T-35, ADR-012, ADR-015).
    #[test]
    fn test_the_accepted_binding_round_trips_and_marks_replays() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_node = alice.node_id();
        let mut bob_state = PrekeyState::new(Identity::from_bytes(&bob.to_bytes()).unwrap());
        bob_state.generate_one_time_prekeys(1);
        let bob_bundle = bob_state.bundle();

        let mut alice_sm = SessionManager::new();
        let init = alice_sm
            .initiate_session(&alice, bob.node_id(), &bob_bundle, true)
            .unwrap();
        let ad = b"ad";
        let (header, ct) = alice_sm.encrypt_for(&bob.node_id(), b"m", ad).unwrap();

        let mut bob_sm = SessionManager::new();
        bob_sm
            .accept_session_with_first_message(
                &mut bob_state,
                alice_node,
                &alice.public_key_bytes(),
                &init.ephemeral_public,
                init.used_signed_prekey_id,
                init.used_one_time_prekey_id,
                &header,
                &ct,
                ad,
            )
            .unwrap();

        let binding = mycelium_protocol::wire::session_init_binding(
            &init.ephemeral_public,
            &alice.public_key_bytes(),
            init.used_signed_prekey_id,
            init.used_one_time_prekey_id,
            true,
        );
        assert!(
            bob_sm.is_answered_init(&alice_node, &binding),
            "the init this session came from is a replay if it arrives again"
        );

        // The payload is not part of the key, which is the point: a replay
        // carrying a different nested message has the same binding.
        let other_prekey = mycelium_protocol::wire::session_init_binding(
            &init.ephemeral_public,
            &alice.public_key_bytes(),
            init.used_signed_prekey_id,
            Some(init.used_one_time_prekey_id.unwrap_or(0) + 1),
            true,
        );
        assert!(
            !bob_sm.is_answered_init(&alice_node, &other_prekey),
            "a different handshake is a new attempt, not a replay"
        );

        // And the same holds after a restart, which is when the in-memory
        // alternative would have let the replay through.
        let session = bob_sm.all_sessions().next().unwrap().1.clone();
        let blob = SessionManager::serialize_session(&session);
        let restored = SessionManager::deserialize_session(&blob).unwrap();
        let mut restored_sm = SessionManager::new();
        restored_sm.restore_session(restored);
        assert!(restored_sm.is_answered_init(&alice_node, &binding));

        // A session we initiated has no accepted binding, and round-trips as
        // such — the field is optional on the way back in, so rows written
        // before it existed still load.
        let ours = alice_sm.all_sessions().next().unwrap().1.clone();
        assert_eq!(ours.accepted_binding, None);
        let blob = SessionManager::serialize_session(&ours);
        assert_eq!(
            SessionManager::deserialize_session(&blob)
                .unwrap()
                .accepted_binding,
            None
        );
    }

    /// Accepting a peer's session must clear the handshake of our own that it
    /// supersedes, and hand back what that handshake recorded.
    ///
    /// A `SessionReject` is unauthenticated and its only gate is "do we have
    /// an unconfirmed handshake with this peer". Leaving ours in place after
    /// accepting an authenticated session let a forged reject delete a
    /// working session (T-35).
    #[test]
    fn test_accepting_a_session_clears_the_handshake_it_supersedes() {
        let a_id = Identity::generate();
        let b_id = Identity::generate();
        let (a_node, b_node) = (a_id.node_id(), b_id.node_id());
        let mut a_state = PrekeyState::new(Identity::from_bytes(&a_id.to_bytes()).unwrap());
        let mut b_state = PrekeyState::new(Identity::from_bytes(&b_id.to_bytes()).unwrap());
        a_state.generate_one_time_prekeys(2);
        b_state.generate_one_time_prekeys(2);
        let a_bundle = a_state.issue_bundle();
        let b_bundle = b_state.issue_bundle();

        let mut a_sm = SessionManager::new();
        let mut b_sm = SessionManager::new();

        // B initiates and sends two messages under its optimistic session.
        let b_init = b_sm
            .initiate_session(&b_id, a_node, &a_bundle, true)
            .unwrap();
        let ad = b"ad";
        let (b_h, b_c) = b_sm.encrypt_for(&a_node, b"from b", ad).unwrap();
        let init_message = MessageId::random();
        let follow_up = MessageId::random();
        b_sm.mark_handshake_pending(a_node, [7u8; 32], init_message);
        b_sm.record_unconfirmed_message(a_node, follow_up);
        assert!(b_sm.handshake_unconfirmed(&a_node));
        assert_eq!(b_sm.handshake_transcript(&a_node), Some([7u8; 32]));
        let _ = b_init;

        // A initiated too, and B accepts A's session: B's own handshake is
        // superseded, so it is reported rather than left behind.
        let a_init = a_sm
            .initiate_session(&a_id, b_node, &b_bundle, true)
            .unwrap();
        let (a_h, a_c) = a_sm.encrypt_for(&b_node, b"from a", ad).unwrap();
        let (_, plaintext, superseded) = b_sm
            .accept_session_with_first_message(
                &mut b_state,
                a_node,
                &a_id.public_key_bytes(),
                &a_init.ephemeral_public,
                a_init.used_signed_prekey_id,
                a_init.used_one_time_prekey_id,
                &a_h,
                &a_c,
                ad,
            )
            .unwrap();
        assert_eq!(plaintext, b"from a");
        assert_eq!(
            superseded,
            vec![follow_up],
            "only the follow-ups die: ADR-007 has the winner decrypt the first \
             message out of the session it discards, so reporting that one failed \
             would overwrite a delivery that happened"
        );
        assert!(
            !b_sm.handshake_unconfirmed(&a_node),
            "a reject must no longer find an unconfirmed handshake to act on"
        );
        // The accepted session is the one that works.
        let (h, c) = a_sm.encrypt_for(&b_node, b"a2", ad).unwrap();
        assert_eq!(
            b_sm.decrypt_from(&mut b_state, &a_node, &h, &c, ad)
                .unwrap(),
            b"a2"
        );
        let _ = (b_h, b_c);
    }

    /// Both peers initiate at once. The lower NodeId keeps its own session and
    /// only decrypts the other side's first message; the higher NodeId
    /// replaces its session with the peer's. Afterwards both directions work.
    #[test]
    fn test_simultaneous_initiation_tie_break() {
        // A is the winner by construction (lower node id).
        let (a_id, b_id) = loop {
            let a = Identity::generate();
            let b = Identity::generate();
            if a.node_id().as_bytes() < b.node_id().as_bytes() {
                break (a, b);
            }
        };
        let (a_node, b_node) = (a_id.node_id(), b_id.node_id());
        let mut a_state = PrekeyState::new(Identity::from_bytes(&a_id.to_bytes()).unwrap());
        let mut b_state = PrekeyState::new(Identity::from_bytes(&b_id.to_bytes()).unwrap());
        a_state.generate_one_time_prekeys(2);
        b_state.generate_one_time_prekeys(2);
        let a_bundle = a_state.issue_bundle();
        let b_bundle = b_state.issue_bundle();

        let mut a_sm = SessionManager::new();
        let mut b_sm = SessionManager::new();
        let a_init = a_sm
            .initiate_session(&a_id, b_node, &b_bundle, true)
            .unwrap();
        let b_init = b_sm
            .initiate_session(&b_id, a_node, &a_bundle, true)
            .unwrap();
        assert!(a_sm.initiated_recently(&b_node, Duration::from_secs(60)));
        assert!(!a_sm.initiated_recently(&a_node, Duration::from_secs(60)));
        let ad = b"ad";
        let (a_h, a_c) = a_sm.encrypt_for(&b_node, b"from a", ad).unwrap();
        let (b_h, b_c) = b_sm.encrypt_for(&a_node, b"from b", ad).unwrap();

        // A (winner) receives B's SessionInit: decrypt only, keep own session.
        let pt = SessionManager::decrypt_first_message_only(
            &mut a_state,
            b_node,
            &b_id.public_key_bytes(),
            &b_init.ephemeral_public,
            b_init.used_signed_prekey_id,
            b_init.used_one_time_prekey_id,
            &b_h,
            &b_c,
            ad,
        )
        .unwrap();
        assert_eq!(pt, b"from b");

        // B (loser) receives A's SessionInit: replaces its own session.
        let (_, pt, _) = b_sm
            .accept_session_with_first_message(
                &mut b_state,
                a_node,
                &a_id.public_key_bytes(),
                &a_init.ephemeral_public,
                a_init.used_signed_prekey_id,
                a_init.used_one_time_prekey_id,
                &a_h,
                &a_c,
                ad,
            )
            .unwrap();
        assert_eq!(pt, b"from a");

        // Both directions now work on A's surviving session.
        let (h, c) = a_sm.encrypt_for(&b_node, b"a2", ad).unwrap();
        assert_eq!(
            b_sm.decrypt_from(&mut b_state, &a_node, &h, &c, ad)
                .unwrap(),
            b"a2"
        );
        let (h, c) = b_sm.encrypt_for(&a_node, b"b2", ad).unwrap();
        assert_eq!(
            a_sm.decrypt_from(&mut a_state, &b_node, &h, &c, ad)
                .unwrap(),
            b"b2"
        );
    }

    #[test]
    fn test_safety_number_symmetric() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let sn1 = compute_safety_number(&key_a, &key_b);
        let sn2 = compute_safety_number(&key_b, &key_a);
        assert_eq!(sn1, sn2);
    }

    /// A message-less `SessionInit` may not name a one-time prekey.
    ///
    /// There is nothing in such an init to show the initiator sent it, so
    /// spending the prekey would let a forgery burn it while installing the
    /// session without it would hand the next forgery the same prekey. The
    /// form exists — it just has to use the signed-prekey-only variant, and
    /// pay for it with that handshake's one-time-prekey forward secrecy
    /// (ADR-015).
    #[test]
    fn test_a_message_less_init_may_not_name_a_one_time_prekey() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_node = bob.node_id();
        let mut bob_state = PrekeyState::new(bob);
        bob_state.generate_one_time_prekeys(1);
        let bundle = bob_state.issue_bundle();
        let otp_id = bundle.one_time_prekey_id.expect("a prekey was generated");

        let mut alice_sm = SessionManager::new();
        let init = alice_sm
            .initiate_session(&alice, bob_node, &bundle, true)
            .unwrap();
        assert_eq!(init.used_one_time_prekey_id, Some(otp_id));

        let mut bob_sm = SessionManager::new();
        let err = bob_sm
            .accept_session(
                &mut bob_state,
                alice.node_id(),
                &alice.public_key_bytes(),
                &init.ephemeral_public,
                init.used_signed_prekey_id,
                init.used_one_time_prekey_id,
            )
            .unwrap_err();
        assert!(matches!(err, SessionError::PrekeyWithoutMessage));
        assert!(
            !bob_sm.has_session(&alice.node_id()),
            "nothing may be installed for an init with nothing to authenticate it"
        );
        assert!(
            bob_state.one_time_prekey_secret(otp_id).is_some(),
            "and the prekey must still be there for the genuine init"
        );
    }

    /// Keeping our own session under ADR-007's tie-break still spends the
    /// peer's one-time prekey, because its message authenticated.
    ///
    /// Left unspent, a replay of that same init — a fresh envelope id, hours
    /// later or after a restart, past the duplicate check — derives the
    /// handshake again and installs the session we deliberately discarded,
    /// breaking traffic that works (ADR-015).
    #[test]
    fn test_decrypting_the_losing_first_message_still_spends_the_prekey() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_node = bob.node_id();
        let alice_node = alice.node_id();
        let bob_bytes = bob.to_bytes();
        let mut bob_state = PrekeyState::new(bob);
        bob_state.generate_one_time_prekeys(1);
        let bundle = bob_state.issue_bundle();
        let otp_id = bundle.one_time_prekey_id.expect("a prekey was generated");

        let mut alice_sm = SessionManager::new();
        let init = alice_sm
            .initiate_session(&alice, bob_node, &bundle, true)
            .unwrap();
        let ad = b"ad";
        let (header, ct) = alice_sm.encrypt_for(&bob_node, b"first", ad).unwrap();

        let plaintext = SessionManager::decrypt_first_message_only(
            &mut bob_state,
            alice_node,
            &alice.public_key_bytes(),
            &init.ephemeral_public,
            init.used_signed_prekey_id,
            init.used_one_time_prekey_id,
            &header,
            &ct,
            ad,
        )
        .unwrap();
        assert_eq!(plaintext, b"first");
        assert!(
            bob_state.one_time_prekey_secret(otp_id).is_none(),
            "the message authenticated, so the prekey is spent"
        );

        // The replay therefore cannot derive the handshake a second time. It
        // is refused on the answered-handshake record, which is checked before
        // the prekey is even looked up — and has to be, because an init that
        // named no prekey retires nothing and would otherwise still derive.
        // The spent prekey asserted above is the second line, not the first.
        let err = SessionManager::decrypt_first_message_only(
            &mut bob_state,
            alice_node,
            &alice.public_key_bytes(),
            &init.ephemeral_public,
            init.used_signed_prekey_id,
            init.used_one_time_prekey_id,
            &header,
            &ct,
            ad,
        )
        .unwrap_err();
        assert!(matches!(err, SessionError::HandshakeAlreadyAnswered));

        // And with the record cleared — an older prekey blob, written before
        // it existed — the spent prekey still refuses it on its own.
        let blob = bob_state.to_bytes();
        let older = &blob[..blob.len() - (4 + 36)];
        let mut legacy =
            PrekeyState::from_bytes_with_identity(older, Identity::from_bytes(&bob_bytes).unwrap())
                .expect("an older blob still loads");
        let err = SessionManager::decrypt_first_message_only(
            &mut legacy,
            alice_node,
            &alice.public_key_bytes(),
            &init.ephemeral_public,
            init.used_signed_prekey_id,
            init.used_one_time_prekey_id,
            &header,
            &ct,
            ad,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SessionError::X3dh(X3dhError::OneTimePrekeyNotFound)
        ));
    }

    /// A handshake the peer never answers is torn down, and the messages sent
    /// under it are reported.
    ///
    /// Rule 3 of ADR-015 stops a responder rejecting while it holds a session,
    /// so a responder sitting on a stale session of ours says nothing at all.
    /// Without this sweep the initiator keeps an optimistic session for ever
    /// and every later message is undecryptable.
    #[test]
    fn test_an_unanswered_handshake_is_given_up_on() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_node = bob.node_id();
        let mut bob_state = PrekeyState::new(bob);
        let bundle = bob_state.issue_bundle();

        let mut alice_sm = SessionManager::new();
        alice_sm
            .initiate_session(&alice, bob_node, &bundle, true)
            .unwrap();
        let init_message = MessageId::random();
        let follow_up = MessageId::random();
        alice_sm.mark_handshake_pending(bob_node, [8u8; 32], init_message);
        alice_sm.record_unconfirmed_message(bob_node, follow_up);

        // Still inside the timeout: nothing is even a candidate. A handshake
        // in flight over DTN can take days to confirm, and tearing it down
        // early costs a real session and reports delivered messages as failed.
        assert!(alice_sm
            .stale_handshakes(Duration::from_secs(3600))
            .is_empty());
        assert!(alice_sm.has_session(&bob_node));

        let stale = alice_sm.stale_handshakes(Duration::ZERO);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].0, bob_node);
        assert_eq!(stale[0].1, vec![init_message, follow_up]);
        assert!(
            alice_sm.has_session(&bob_node),
            "listing candidates must not touch anything: the caller decides, \
             because only it can see whether these messages were acknowledged"
        );

        let dead = alice_sm.give_up_on_handshake(&bob_node);
        assert_eq!(dead, vec![init_message, follow_up]);
        assert!(
            !alice_sm.has_session(&bob_node),
            "dropping the session is what makes the next send re-handshake"
        );
        assert!(!alice_sm.handshake_unconfirmed(&bob_node));
        assert!(
            !alice_sm.initiated_recently(&bob_node, Duration::from_secs(60)),
            "the tie-break marker goes too, or we refuse the peer's valid \
             SessionInit while holding nothing of our own"
        );
    }

    /// A confirmed handshake is never swept, however old it is: confirmation
    /// is anything we decrypt from the peer, which only their ratchet could
    /// have produced.
    #[test]
    fn test_a_confirmed_handshake_outlives_the_sweep() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_node = bob.node_id();
        let alice_node = alice.node_id();
        let mut bob_state = PrekeyState::new(bob);
        bob_state.generate_one_time_prekeys(1);
        let bundle = bob_state.issue_bundle();

        let mut alice_sm = SessionManager::new();
        let mut bob_sm = SessionManager::new();
        let init = alice_sm
            .initiate_session(&alice, bob_node, &bundle, true)
            .unwrap();
        alice_sm.mark_handshake_pending(bob_node, [8u8; 32], MessageId::random());

        let ad = b"ad";
        let (header, ct) = alice_sm.encrypt_for(&bob_node, b"first", ad).unwrap();
        bob_sm
            .accept_session_with_first_message(
                &mut bob_state,
                alice_node,
                &alice.public_key_bytes(),
                &init.ephemeral_public,
                init.used_signed_prekey_id,
                init.used_one_time_prekey_id,
                &header,
                &ct,
                ad,
            )
            .unwrap();

        // Bob answers, and that answer is the confirmation.
        let (b_header, b_ct) = bob_sm.encrypt_for(&alice_node, b"reply", ad).unwrap();
        alice_sm
            .decrypt_from(
                &mut no_prekeys_of_its_own(),
                &bob_node,
                &b_header,
                &b_ct,
                ad,
            )
            .unwrap();

        assert!(alice_sm.stale_handshakes(Duration::ZERO).is_empty());
        assert!(alice_sm.has_session(&bob_node));
    }

    /// The record of an answered handshake must survive a restart, because the
    /// restart is when it matters: the simultaneous-initiation window goes with
    /// it, and the signed prekey the init names does not.
    ///
    /// The last step is the counterfactual — the init is still perfectly live,
    /// deriving and decrypting against a prekey state holding the same secrets
    /// and no record — so this test is about the record and not about the init
    /// having expired some other way (ADR-015).
    #[test]
    fn test_an_answered_handshake_survives_a_restart() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_node = alice.node_id();
        let bob_node = bob.node_id();

        // Signed-prekey-only, so authentication retires nothing and only the
        // record stands between a replay and a session.
        let mut alice_state = PrekeyState::new(Identity::from_bytes(&alice.to_bytes()).unwrap());
        let alice_bundle = alice_state.bundle();
        assert!(alice_bundle.one_time_prekey_id.is_none());
        let bob_state = PrekeyState::new(Identity::from_bytes(&bob.to_bytes()).unwrap());

        let mut alice_sm = SessionManager::new();
        alice_sm
            .initiate_session(&alice, bob_node, &bob_state.bundle(), true)
            .unwrap();
        let mut bob_sm = SessionManager::new();
        let bob_init = bob_sm
            .initiate_session(&bob, alice_node, &alice_bundle, true)
            .unwrap();
        let ad = b"ad";
        let (header, ct) = bob_sm.encrypt_for(&alice_node, b"theirs", ad).unwrap();

        // Alice wins the tie-break: she decrypts Bob's first message and keeps
        // her own session, which answers Bob's handshake.
        let plaintext = SessionManager::decrypt_first_message_only(
            &mut alice_state,
            bob_node,
            &bob.public_key_bytes(),
            &bob_init.ephemeral_public,
            bob_init.used_signed_prekey_id,
            None,
            &header,
            &ct,
            ad,
        )
        .unwrap();
        assert_eq!(plaintext, b"theirs");

        let binding = mycelium_protocol::wire::session_init_binding(
            &bob_init.ephemeral_public,
            &bob.public_key_bytes(),
            bob_init.used_signed_prekey_id,
            None,
            true,
        );
        assert!(alice_state.has_answered_handshake(&binding));

        // The restart. Note there is no session here at all — expired, or
        // replaced by a later handshake — which is the case a session-scoped
        // record could not cover, because it died with the session while the
        // signed prekey lived on.
        let blob = alice_state.to_bytes();
        let mut restored = PrekeyState::from_bytes_with_identity(
            &blob,
            Identity::from_bytes(&alice.to_bytes()).unwrap(),
        )
        .expect("the prekey blob round-trips");
        assert!(
            restored.has_answered_handshake(&binding),
            "the replay this stops is one a restart would otherwise forget"
        );

        let err = SessionManager::new()
            .accept_session_with_first_message(
                &mut restored,
                bob_node,
                &bob.public_key_bytes(),
                &bob_init.ephemeral_public,
                bob_init.used_signed_prekey_id,
                None,
                &header,
                &ct,
                ad,
            )
            .expect_err("an answered handshake must not be answered again");
        assert!(matches!(err, SessionError::HandshakeAlreadyAnswered));

        // The counterfactual, and the compatibility check in one: a blob
        // written before this field existed ends after the retained signed
        // prekeys, which is this blob without its trailing count and entry.
        let older = &blob[..blob.len() - (4 + 36)];
        let mut forgetful = PrekeyState::from_bytes_with_identity(
            older,
            Identity::from_bytes(&alice.to_bytes()).unwrap(),
        )
        .expect("an older blob still loads");
        assert!(!forgetful.has_answered_handshake(&binding));
        let (_, replayed, _) = SessionManager::new()
            .accept_session_with_first_message(
                &mut forgetful,
                bob_node,
                &bob.public_key_bytes(),
                &bob_init.ephemeral_public,
                bob_init.used_signed_prekey_id,
                None,
                &header,
                &ct,
                ad,
            )
            .expect("the init is still live: only the record stops it");
        assert_eq!(replayed, b"theirs");
    }

    /// Swapping the message inside a discarded init must not get the init
    /// accepted.
    ///
    /// Remembering an init by its *transcript* — a hash of the whole payload —
    /// leaves the nested message free to vary. The loser of ADR-007's
    /// tie-break sent follow-ups under the session it was about to discard; a
    /// relay that captured one can build an init with the loser's header and
    /// that follow-up inside. The header is what the derivation binds, so it
    /// derives the same session, and the ratchet retains skipped keys, so a
    /// later message in the same chain decrypts on a fresh one. The transcript
    /// differs, so a transcript-keyed record misses it, and the session both
    /// sides abandoned is installed over a working one.
    ///
    /// A handshake is identified by what the derivation covers — the bound
    /// header — so that is what the record keys on (ADR-015).
    #[test]
    fn test_a_substituted_message_cannot_revive_a_discarded_init() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_node = alice.node_id();
        let bob_node = bob.node_id();

        // Signed-prekey-only: authentication retires nothing, so only the
        // record stands between the replay and a session.
        let mut alice_state = PrekeyState::new(Identity::from_bytes(&alice.to_bytes()).unwrap());
        let alice_bundle = alice_state.bundle();
        assert!(alice_bundle.one_time_prekey_id.is_none());
        let bob_state = PrekeyState::new(Identity::from_bytes(&bob.to_bytes()).unwrap());

        let mut alice_sm = SessionManager::new();
        alice_sm
            .initiate_session(&alice, bob_node, &bob_state.bundle(), true)
            .unwrap();
        let mut bob_sm = SessionManager::new();
        let bob_init = bob_sm
            .initiate_session(&bob, alice_node, &alice_bundle, true)
            .unwrap();

        // Bob's init carries the first message; the second goes out after it,
        // on the same chain, and a relay keeps a copy.
        let ad = b"ad";
        let (h0, c0) = bob_sm.encrypt_for(&alice_node, b"first", ad).unwrap();
        let (h1, c1) = bob_sm.encrypt_for(&alice_node, b"second", ad).unwrap();

        // Alice wins the tie-break: she decrypts the first message and keeps
        // her own session.
        SessionManager::decrypt_first_message_only(
            &mut alice_state,
            bob_node,
            &bob.public_key_bytes(),
            &bob_init.ephemeral_public,
            bob_init.used_signed_prekey_id,
            None,
            &h0,
            &c0,
            ad,
        )
        .unwrap();

        // The substitution: the loser's header, the captured follow-up inside.
        // Keyed on the payload this would be a handshake nothing had seen; it
        // is now refused for a simpler reason, before any record is consulted,
        // because an init encloses message 0 of its chain or it is not that
        // init. The record is the second line, and
        // `test_an_answered_handshake_survives_a_restart` is what exercises it:
        // that replay carries the genuine first message.
        let err = alice_sm
            .accept_session_with_first_message(
                &mut alice_state,
                bob_node,
                &bob.public_key_bytes(),
                &bob_init.ephemeral_public,
                bob_init.used_signed_prekey_id,
                None,
                &h1,
                &c1,
                ad,
            )
            .expect_err("a substituted message must not be answered as the init");
        assert!(
            matches!(err, SessionError::NotTheFirstMessage),
            "refused on the message number, before the record: {err:?}"
        );
    }

    /// A message-less init cannot be re-accepted with a message wrapped into
    /// it.
    ///
    /// The message-less path is the one that installs a session with nothing
    /// authenticating the initiator, so it deliberately records nothing in the
    /// prekey state — a forged init would otherwise fill a bound shared with
    /// every real handshake, one entry per identity an attacker generates. The
    /// session's own single slot is what covers it: an attacker who captured
    /// the init header and any later ciphertext from that peer's chain would
    /// otherwise have the session re-derived from scratch and installed over
    /// one that has moved on — a ratchet rewind, which reuses message keys
    /// (ADR-015).
    #[test]
    fn test_a_message_less_init_cannot_be_re_accepted_with_a_message() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_node = alice.node_id();
        let bob_node = bob.node_id();

        // Message-less inits are signed-prekey-only, so nothing is retired and
        // the handshake stays derivable.
        let bob_bytes = bob.to_bytes();
        let mut bob_state = PrekeyState::new(Identity::from_bytes(&bob_bytes).unwrap());
        let bob_bundle = bob_state.bundle();
        assert!(bob_bundle.one_time_prekey_id.is_none());

        let mut alice_sm = SessionManager::new();
        let init = alice_sm
            .initiate_session(&alice, bob_node, &bob_bundle, false)
            .unwrap();

        // Bob accepts it with no message, and talks under the session.
        let mut bob_sm = SessionManager::new();
        bob_sm
            .accept_session(
                &mut bob_state,
                alice_node,
                &alice.public_key_bytes(),
                &init.ephemeral_public,
                init.used_signed_prekey_id,
                None,
            )
            .unwrap();
        //
        // Alice speaks first, necessarily: a responder has no sending chain
        // until something of the initiator's arrives, which is a plain
        // consequence of the ratchet rather than of this path.
        let ad = b"ad";
        let (first_header, first_ct) = alice_sm.encrypt_for(&bob_node, b"from alice", ad).unwrap();
        assert_eq!(
            bob_sm
                .decrypt_from(&mut bob_state, &alice_node, &first_header, &first_ct, ad)
                .unwrap(),
            b"from alice"
        );
        let (bob_header, bob_ct) = bob_sm.encrypt_for(&alice_node, b"from bob", ad).unwrap();
        assert_eq!(
            alice_sm
                .decrypt_from(
                    &mut no_prekeys_of_its_own(),
                    &bob_node,
                    &bob_header,
                    &bob_ct,
                    ad
                )
                .unwrap(),
            b"from bob"
        );

        // The accept wrote nothing to the prekey record — that path
        // authenticates nothing — but Alice's message did: decrypting it
        // promoted the session's own marker into the durable record, which is
        // what makes the refusal below survive losing the session.
        let binding = mycelium_protocol::wire::session_init_binding(
            &init.ephemeral_public,
            &alice.public_key_bytes(),
            init.used_signed_prekey_id,
            None,
            false,
        );
        assert!(
            bob_state.has_answered_handshake(&binding),
            "the first decrypt promotes the accepted init into the record that \
             retires with the signed prekey"
        );
        assert!(
            bob_state.needs_persist(),
            "and says so, because a promotion never written is gone on the next \
             start and the init it covers is answerable again"
        );
        assert!(
            PrekeyState::from_bytes_with_identity(
                &bob_state.to_bytes(),
                Identity::from_bytes(&bob_bytes).unwrap(),
            )
            .expect("the blob round-trips")
            .has_answered_handshake(&binding),
            "the promoted entry has to survive the blob, which is the only \
             place it is kept"
        );

        // Alice's traffic, captured by a relay, wrapped into the very init Bob
        // accepted. Carrying a message is part of the binding, so this is not
        // the handshake Bob answered: it derives a different secret, and the
        // captured ciphertext cannot authenticate under it. The derivation
        // refuses it before any record has to.
        let (header, ct) = alice_sm.encrypt_for(&bob_node, b"later", ad).unwrap();
        let err = bob_sm
            .accept_session_with_first_message(
                &mut bob_state,
                alice_node,
                &alice.public_key_bytes(),
                &init.ephemeral_public,
                init.used_signed_prekey_id,
                None,
                &header,
                &ct,
                ad,
            )
            .expect_err("a message wrapped into a message-less init is not that handshake");
        assert!(
            matches!(err, SessionError::Ratchet(_)),
            "the binding separates the two forms, so this fails to decrypt \
             rather than being recognised: {err:?}"
        );

        // And the session that was there still works, both ways.
        assert_eq!(
            bob_sm
                .decrypt_from(&mut bob_state, &alice_node, &header, &ct, ad)
                .unwrap(),
            b"later"
        );
        let (h, c) = bob_sm.encrypt_for(&alice_node, b"still here", ad).unwrap();
        assert_eq!(
            alice_sm
                .decrypt_from(&mut no_prekeys_of_its_own(), &bob_node, &h, &c, ad)
                .unwrap(),
            b"still here"
        );

        // A replay of the init itself — the same message-less form, so the same
        // handshake — is refused, and goes on being refused once the session is
        // gone. That is what the promotion bought: the session's own slot died
        // with the session, so an expiry or a later handshake used to make this
        // init answerable again while its signed prekey was still retained.
        bob_sm.remove_session(&alice_node);
        let err = bob_sm
            .accept_session(
                &mut bob_state,
                alice_node,
                &alice.public_key_bytes(),
                &init.ephemeral_public,
                init.used_signed_prekey_id,
                None,
            )
            .expect_err("the init Bob answered must not be answered again");
        assert!(matches!(err, SessionError::HandshakeAlreadyAnswered));
    }

    /// An acknowledged handshake is never a candidate for the sweep.
    ///
    /// A conversation where the peer reads and acknowledges but never replies
    /// produces no confirmation ever — confirmation needs something of the
    /// peer's to decrypt — so without this the sweep abandoned working
    /// sessions, and everything the peer then sent was dropped until our own
    /// next send re-handshaked.
    ///
    /// The flag lives on the handshake, not in the message rows: deriving it
    /// from the rows meant deleting a conversation took the evidence with it
    /// (ADR-015, T-42).
    #[test]
    fn test_an_acknowledged_handshake_is_never_swept() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_node = bob.node_id();
        let bob_state = PrekeyState::new(bob);

        let mut sm = SessionManager::new();
        sm.initiate_session(&alice, bob_node, &bob_state.bundle(), true)
            .unwrap();
        let init_message = MessageId::random();
        let follow_up = MessageId::random();
        sm.mark_handshake_pending(bob_node, [8u8; 32], init_message);
        sm.record_unconfirmed_message(bob_node, follow_up);

        assert_eq!(
            sm.stale_handshakes(Duration::ZERO).len(),
            1,
            "unacknowledged and past the timeout: a candidate"
        );

        // A receipt for some older message of that peer's vouches for nothing:
        // receipts arrive late, and one from a session that is long gone must
        // not suppress the recovery of this handshake.
        sm.note_handshake_acknowledged(&bob_node, &MessageId::random());
        assert_eq!(
            sm.stale_handshakes(Duration::ZERO).len(),
            1,
            "a receipt for a message this handshake never sent is not evidence"
        );

        sm.note_handshake_acknowledged(&bob_node, &follow_up);
        assert!(
            sm.stale_handshakes(Duration::ZERO).is_empty(),
            "the peer has decrypted something of ours, so it holds the session"
        );
        assert!(
            sm.has_session(&bob_node),
            "and the session it holds is still here"
        );

        // Still unconfirmed, though: an acknowledgement is not something only
        // the peer's ratchet could have produced, so it must not pass for
        // confirmation — a forged receipt would otherwise strip a live
        // handshake of its rejection protection.
        assert!(sm.handshake_unconfirmed(&bob_node));

        // And a peer we have no handshake with is a no-op, not a panic.
        sm.note_handshake_acknowledged(&Identity::generate().node_id(), &init_message);
    }

    /// A message-less initiation ignores the one-time prekey the bundle
    /// offers, and both sides still agree.
    ///
    /// The variant is not optional: an init with nothing to authenticate the
    /// initiator may not name a prekey, so an initiator that used the offered
    /// one produced an init the responder could only reject
    /// (`PrekeyWithoutMessage`) — a handshake that could never complete
    /// against any bundle with prekeys left in it, which is all of them
    /// (ADR-015).
    #[test]
    fn test_a_message_less_initiation_uses_no_one_time_prekey() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_node = alice.node_id();
        let bob_node = bob.node_id();

        // A bundle with a prekey on offer, which is the case that was broken.
        let mut bob_state = PrekeyState::new(Identity::from_bytes(&bob.to_bytes()).unwrap());
        bob_state.generate_one_time_prekeys(5);
        let bundle = bob_state.issue_bundle();
        assert!(bundle.one_time_prekey_id.is_some());

        let mut alice_sm = SessionManager::new();
        let init = alice_sm
            .initiate_session(&alice, bob_node, &bundle, false)
            .unwrap();
        assert!(
            init.used_one_time_prekey_id.is_none(),
            "a message-less init takes the signed-prekey-only variant whatever \
             the bundle offers"
        );

        // The responder accepts it, which it could not do for an init naming a
        // prekey, and the two derive the same secret: Alice's first message
        // decrypts.
        let mut bob_sm = SessionManager::new();
        bob_sm
            .accept_session(
                &mut bob_state,
                alice_node,
                &alice.public_key_bytes(),
                &init.ephemeral_public,
                init.used_signed_prekey_id,
                init.used_one_time_prekey_id,
            )
            .expect("the signed-prekey-only variant is acceptable");

        let ad = b"ad";
        let (header, ct) = alice_sm.encrypt_for(&bob_node, b"after", ad).unwrap();
        assert_eq!(
            bob_sm
                .decrypt_from(&mut bob_state, &alice_node, &header, &ct, ad)
                .unwrap(),
            b"after",
            "both sides derived the same secret from the same variant"
        );

        // And the prekey the bundle offered is still there for an init that
        // can actually authenticate its use of it.
        assert!(bob_state
            .one_time_prekey_secret(bundle.one_time_prekey_id.unwrap())
            .is_some());
    }
}
