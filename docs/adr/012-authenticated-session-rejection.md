# ADR-012: Authenticated Session Rejection

## Status

**Partially implemented (2026-11-11).** The signature, the bookkeeping and the
status rules below are built and tested. The claim this ADR was written to
make — that a forged `SessionReject` achieves nothing — is **not yet true**:
binding the rejection to a hash of the init's wire bytes turned out not to
identify a handshake, and the remaining work is ROADMAP T-35. Recorded as it
stands, with the gap named, rather than as an accepted design.

Supersedes the rejection rationale in ADR-009, which remains the record of the
signed-prekey retention and session-acceptance rules.

## Context

A `SessionReject` tells an initiator that its `SessionInit` cannot be accepted
— a signed prekey rotated out of retention, a one-time prekey already
consumed, a ciphertext that does not decrypt — so that it stops retrying
against a bundle that can never work (ROADMAP T-06, ADR-009).

ADR-009 made it unauthenticated on this reasoning: *"A reject cannot be
authenticated: by definition no confirmed session exists yet."* It then bounded
the damage instead — act only on an unconfirmed handshake, do nothing when
nothing was initiated, and accept that "the worst a forgery achieves is one
discarded unconfirmed handshake and one extra prekey request".

**The premise was wrong.** The rejecting node has an Ed25519 identity key; the
initiator obtained exactly that key in the prekey bundle it ran X3DH against;
and the NodeId binding every handshake ingress path enforces
(`SHA-256(identity_key) == envelope.source`, spec §14.3) ties the key to the
sender. Nothing was missing but a signature.

The bound was also weaker than it claimed, because the bookkeeping it rested on
was not maintained (ROADMAP T-35): accepting an authenticated session left the
peer's unconfirmed-handshake entry in place, so a forged reject could delete a
session the peer had already proved it held, along with its stored row and its
cached bundle.

## Decision

### The reject is signed

```
SessionReject = reason(1) ‖ identity_key(32) ‖ init_transcript(32) ‖ signature(64)

init_transcript = SHA-256( b"mycelium-session-init-transcript-v1:"
                         ‖ len(payload)(4 LE) ‖ session_init_payload )
signature       = Ed25519( SHA-256( b"mycelium-session-reject-v1:"
                         ‖ init_transcript(32) ‖ initiator(32)
                         ‖ rejecter(32) ‖ reason(1) ) )
```

The initiator acts on a reject only when all three hold: the identity key
hashes to the envelope source; the signature verifies under that key; and the
transcript is the one it recorded for the `SessionInit` it is waiting on.

### Why the transcript, and not the message id

Binding the signature to the rejected envelope's `message_id` — the first
design — is **not** enough, and the reason generalises.

An envelope's `message_id` and `source` are cleartext, and a `SessionInit`
carries the initiator's public key, which is public by construction. An
attacker who observes Alice's `SessionInit` to Bob can therefore send Bob a
*malformed* init that claims Alice's source, Alice's id and Alice's key. Bob
refuses it — the ciphertext does not decrypt — and signs a rejection naming
exactly the id Alice is waiting on. The signature is genuine; only the trigger
was forged. Alice would verify it and tear down her handshake, which is the
attack the signature was supposed to prevent.

The transcript closes this. To make Bob reject anything, the attacker has to
send something Bob refuses, which is by construction not the init Alice sent,
so the digest Bob signs is not the digest Alice recorded.

The initiator hashes the payload it serialized; the responder hashes the body
it received. The type byte is the dispatcher's and is excluded from both.

### Replaying the init verbatim, which the transcript alone does not stop

One case survives the transcript: replaying Alice's init **unchanged**. The
transcript does not cover the envelope, and duplicate detection keys on the
envelope's `message_id`, so a relay can re-deliver an init Bob already
accepted under a fresh id. Its one-time prekey is spent and the ratchet has
moved past its message, so accepting fails — and the rejection Bob would send
is a *valid* rejection of an init Alice really sent, which she would act on.
The attacker gets the teardown the signature was supposed to prevent, with
Bob's own key.

Two rules close it:

- A session records the transcript of the init it was **accepted from**
  (`Session::accepted_init`, persisted with the session, so a restart does not
  reopen the window). An init whose transcript matches it is a replay of the
  one we already answered, and is answered with silence.
- A node keeping its own session under **ADR-007's tie-break never rejects**.
  It only decrypts the first message out of the init it discards, and a
  decrypt failure there is what a replay looks like; the initiator is the
  loser of the tie-break and will accept *our* init, so it needs no rejection
  at all.

A genuine re-handshake is unaffected: it carries a fresh ephemeral, so its
transcript differs and it is answered normally.

For the transcript to identify a handshake at all, the bytes it hashes have to
be **canonical**: two inits the responder would treat identically must hash
identically, or an attacker can mint a second identity for the same handshake.
Accept the altered copy first and the original is free to be replayed past the
replay check, with the rejection it provokes naming the transcript the
initiator recorded. Three kinds of slack had to go:

- **Trailing bytes.** `SessionInitPayload` and `EncryptedPayload` took "at
  least" their declared lengths and ignored the rest. Both now require an
  exact match.
- **A non-canonical flag.** The one-time-prekey presence byte was read as
  `!= 0`, so `2` parsed like `1` and hashed differently. Only `0` and `1` are
  accepted.
- **An unauthenticated field.** `content_type` travels in the clear beside the
  ciphertext and was not in the AEAD's associated data, so retyping a message
  left it decryptable. The associated data is now
  `source ‖ destination ‖ content_type`, which also closes a gap worth closing
  on its own: a relay could previously turn a text message into a GPS pin.
- **A malleable key encoding.** X25519 masks the high bit of the u-coordinate
  and reduces modulo `p = 2^255 - 19` (RFC 7748 §5), so several byte strings
  denote one key and derive one shared secret. An init with the high bit of
  its ephemeral key flipped therefore decrypts exactly like the original and
  hashes differently. Only canonical encodings are accepted — high bit clear,
  value below `p`.

Each of these was found one round after the last, and the fifth is where the
approach runs out: **canonical encodings are not enough, because the curve
itself has equivalent public keys.** RFC 7748 §7 says it plainly — for any
X25519 public key there are other, publicly computable keys that produce the
same shared secret, so "using a public key as an identifier and knowledge of a
shared secret as proof of ownership (without including the public keys in the
key derivation) might lead to subtle vulnerabilities". Replacing the ephemeral
`u` with its reciprocal passes every canonicality check, derives the same
secrets, decrypts the same first message, and hashes differently. One more
identity for the same handshake.

A hash over a wire encoding is therefore the wrong identity. What identifies a
handshake is what the AEAD authenticates, so the remaining work is to bind the
raw ephemeral — the whole init header — into the key derivation or the first
message's associated data, which is exactly the mitigation RFC 7748 names. The
canonical-encoding rules above are worth keeping as hygiene; they are not the
guarantee.

### The bookkeeping the rejection acts on

An unconfirmed handshake is now a record, not a list:

```rust
struct UnconfirmedHandshake {
    transcript: [u8; 32],
    init_message: MessageId,
    follow_ups: Vec<MessageId>,
}
```

- It is written **before** the `SessionInit` is handed to routing, under the
  same lock that initiates the session and encrypts the first message. Written
  afterwards, a reject that came back faster was dropped for want of an
  unconfirmed handshake; worse, a reply that arrived first and *confirmed* the
  handshake had its confirmation undone by the later write, leaving a
  confirmed session exposed. Splitting it across locks left the same gap for a
  concurrent send or accept to land in.
- Messages sent while the handshake is still unconfirmed are recorded against
  it, under the lock that advances the ratchet for them. Only the first used
  to be, so a reject reported one failure and left every follow-up claiming
  "sent" though the peer had discarded the session they were encrypted under.
- Accepting an authenticated session **clears** the entry, and reports its
  **follow-ups** as failed. The init message is deliberately not reported:
  under ADR-007's simultaneous-initiation tie-break the peer that keeps its
  own session still decrypts the first message out of the one it discards, so
  that message was delivered, and failing it would overwrite a status that may
  already be "delivered" or "read".
- A *rejection* fails the init message as well, because the peer refused the
  `SessionInit` itself.

### A send only tears down the session it created

A failed send discards the session it installed, or the peer would never
receive the handshake those later `EncryptedMessage`s assume. It must not
discard a *different* session: an authenticated `SessionInit` accepted while
the transport write was in flight replaces ours and clears our handshake
record, so a late failure would delete the peer's live replacement. The
outstanding transcript is the evidence — if it is no longer ours, the session
is not ours to remove.

### Status writes do not undo a settled outcome

`mark_message_sent` applies only to a message still in flight
(`pending`/`dtn_pending`), `mark_message_failed` only to one that has not been
acknowledged (`pending`/`sent`/`dtn_pending`), and `mark_message_dtn_pending`
only to one whose send has not been settled (`pending`/`sent`). A send and a
rejection overlap in practice: the transport write completes while a reject
for the same handshake is being processed, and the unconditional writes turned
an undeliverable message back into "sent" in one direction and a delivered
message into "failed" in the other. The DTN transition was a third route to
the same place — discovery expiry hands a message to DTN after the fact, and
writing `dtn_pending` over a rejection's "failed" let it be retried and
reported sent, though its ciphertext belongs to a ratchet that no longer
exists.

## Consequences

**Easier:**

- A forged `SessionReject` is much more expensive: it has to be signed by the
  peer it claims to come from, which means provoking that peer into rejecting
  an init it can be made to treat as the victim's. ADR-009's bound — "the
  worst a forgery achieves is one discarded unconfirmed handshake" — still
  holds, and is no longer the only thing holding: the bookkeeping fixes below
  mean a rejection can no longer reach an authenticated session, a cached
  bundle it did not invalidate, or a message that was delivered.
- It is **not** yet true that a forgery achieves nothing. Three ways to mint a
  second identity for one handshake remain open, all recorded in ROADMAP T-35:
  equivalent ephemeral keys (above); a corrupted copy that burns the one-time
  prekey before authentication, so the untouched original then fails; and the
  simultaneous-initiation suppression, which expires with the 60-second
  initiation timer and is not persisted.
- A reject is now self-contained evidence, so it can be relayed over multiple
  hops or arrive late through DTN without being any more dangerous.
- What a reject reports is accurate: every message that died with the
  handshake, and nothing that did not.

**Harder:**

- **Breaking wire change.** The body grows from 33 to 129 bytes and its
  meaning changes. The protocol is `0.1-draft` with no deployed nodes;
  precedent is ADR-005, ADR-009, ADR-010, ADR-011.
- The initiator must retain the transcript of each outstanding `SessionInit`,
  which is 32 bytes per peer with a handshake in flight, and a responder
  retains the transcript of the init each session was accepted from — another
  32 bytes per session, in the session's stored blob (appended, and optional
  on the way back in, so earlier rows still load).
- A reject whose key the initiator cannot verify is ignored, where before it
  was a hint. The failure mode is a handshake that times out instead of being
  retried sooner — the same outcome as the reject being lost, which the
  protocol already tolerates.
- A rejecting node signs a statement about a handshake it refused. That is a
  deliberate, narrow attestation: it names a transcript, both parties and a
  reason, and proves only "I will not accept this".

## Alternatives Considered

1. **Leave the reject unauthenticated and keep ADR-009's bound.** The bound
   was never as tight as it read — it depended on bookkeeping that was wrong —
   and a forgery still cost the victim its cached bundle and a round trip.
   Signing costs 64 bytes and one verification.
2. **Bind the signature to the envelope's `message_id`.** Implemented first and
   discarded: see "Why the transcript". Recorded because the flaw is invisible
   from the signed payload alone — every field in it looks peer-specific.
3. **Require a confirmed session before acting on a reject.** Circular: the
   reject exists precisely because the session was never established.
4. **Encrypt the reject under the initiating X3DH secret.** The responder can
   derive it, so this authenticates too — but it conflates "I refuse this
   handshake" with "I completed this handshake", and the rejections that
   matter most are the ones where the derivation itself failed.
5. **Dedup inits by envelope `message_id` alone.** What the code already did,
   and what the verbatim replay walks straight through: the id is not covered
   by anything the initiator signed, so the attacker simply changes it.
6. **Have the initiator re-request a bundle on a timeout and ignore rejects
   entirely.** Simpler, and strictly worse for the user: a retry against a
   stale bundle fails exactly as the first attempt did, and the timeout has to
   be long enough for DTN.
