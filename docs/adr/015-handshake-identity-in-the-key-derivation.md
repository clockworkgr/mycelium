# ADR-015: Handshake Identity in the Key Derivation

## Status

Accepted (2026-11-12). **Implementation pending — ROADMAP T-35.**

## Context

ADR-012 signed the `SessionReject` and bound it to the refused `SessionInit`,
identifying that init by `SHA-256(context ‖ len ‖ payload)` — a hash of its
wire bytes. Six review rounds then found a new way round that hash each time,
and the last one is not a bug but a property of the curve: RFC 7748 §7 says
that for any X25519 public key there are other, publicly computable keys that
produce the same shared secret, `u⁻¹ mod p` among them. Canonical encoding does
not help, because the alternatives are canonical.

So a hash of the wire bytes is the wrong identity. Several inits can be
equivalent to the responder while hashing differently, and each is a way to
have the responder sign a rejection the initiator will act on: get the altered
copy accepted, then replay the original and collect a valid rejection of it.

Two smaller holes have the same shape. X3DH retires the one-time prekey before
the init authenticates, so a corrupted copy can spend it and leave the genuine
init to fail and draw a rejection. And the rule that a tie-break winner never
rejects keys off a 60-second timer that a restart forgets.

## Decision

### The raw init header goes into the key derivation

The exact bytes of the init header — the ephemeral key as it appeared on the
wire, with the identity key and the prekey selection — are fed into the X3DH
key derivation. This is the mitigation RFC 7748 §7 names, and it changes what
an equivalent key is worth: a copy carrying `u⁻¹` derives a *different* key, so
its enclosed first message does not decrypt, so it is not accepted and cannot
mint a second identity for one handshake. A handshake is then identified by
what the AEAD authenticates rather than by a hash of bytes that are not.

Binding into the first message's associated data instead was rejected because
an init may carry no message, and that path would keep the hole with no AEAD
to bind to.

### A one-time prekey is retired only after authentication

Consumption commits when the enclosed first message decrypts, mirroring
ADR-009's rule that a session installs only after the AEAD verifies. An init
that carries no message is refused when it would spend a prekey, and an unknown
nested payload type is refused rather than ignored. Reserving the prekey and
releasing it on failure was rejected: reservation state has to survive a crash,
and a stuck reservation is a denial of the bundle it was meant to protect.

### A rejection is sent only when no session exists

The 60-second initiation timer goes. If we hold any session with that peer, a
failing init draws silence; we reject only when we hold none, which is exactly
the case where a rejection tells the initiator something it does not already
know. Because sessions are persisted, this survives a restart by construction,
with no new table and no transcript list to retain.

The cost is real and accepted: a stale session plus a genuinely dead bundle now
recovers by handshake timeout rather than by a rejection. Persisting the
discarded tie-break transcripts would keep that case fast, at the price of more
durable state in the mechanism whose bookkeeping was wrong to begin with.

## Consequences

**Easier:**

- A signed rejection becomes useless to an attacker: to have one signed, the
  attacker must send something the responder refuses, which — once equivalent
  ephemerals derive different keys — is not the init the initiator sent.
- The prekey, the session and the rejection all commit on the same event: the
  first message authenticating. One rule instead of three.
- Replay suppression stops depending on a timer, and on remembering anything.

**Harder:**

- Breaking crypto change. Every session derived by the old derivation is
  incompatible, so there is no interoperability with the current code; the
  protocol is `0.1-draft` with no deployed nodes, and the version field stays 1
  (precedent ADR-005, ADR-009, ADR-010, ADR-011, ADR-013).
- The derivation gains an input that must be captured at exactly the right
  point on both sides — the initiator hashes what it serialized, the responder
  what it received — which is the class of mistake that took six rounds to find
  the first time. It needs a reciprocal-key regression test (`u` and
  `u⁻¹ mod p` must not both work) rather than only a round-trip test.
- A message-less init to a peer we have no session with can no longer consume a
  prekey, so that path needs its own answer for how a session is established —
  either it carries a message or it is refused.

## Alternatives Considered

1. **Bind the raw init into the first message's associated data.** Smaller, and
   silent on inits that carry no message.
2. **Reserve the prekey and free it on failure.** Keeps message-less inits
   working; adds crash-durable reservation state and a stuck-reservation
   failure mode.
3. **Never sign a prekey-exhausted failure.** Removes the lever without
   touching the cause, and a genuinely dead bundle then recovers only by
   timeout — which was the reason to sign rejections at all.
4. **Persist the discarded tie-break transcripts.** Keeps rejections working
   for a stale session with a dead bundle; more durable state, and a migration,
   for a case a timeout already covers.
5. **Abandon signed rejections entirely** and return to ADR-009's bound. Still
   the fallback if the derivation change proves too invasive: it deletes the
   attack class rather than defending against it, at the cost of recovery
   speed.

## Note (2026-11-12)

This record left open how a message-less `SessionInit` establishes a session,
now that it cannot consume a one-time prekey.

**It uses the signed-prekey-only X3DH variant.** A message-less init derives
from the identity and signed prekeys alone — a documented X3DH variant — so
there is no consumable resource for a corrupted copy to burn, and nothing has
to be reserved or refused. The alternatives were to refuse message-less inits
outright (one code path, but it makes "establish a session with nothing to
say" require a padded `SYSTEM` message, a convention this protocol does not
have) and to hold the prekey in limbo until a later authenticated message
(provisional state that must survive a crash, and a prekey nobody may claim).

The consequence is that such a handshake gets no one-time-prekey forward
secrecy. That is the honest trade for a form of init that has nothing to
authenticate, and the spec must say which variant each init form uses rather
than describing one X3DH.
