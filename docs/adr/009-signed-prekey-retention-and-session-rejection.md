# ADR-009: Signed-Prekey Retention and Session Rejection

## Status

Accepted (2026-11-10)

## Context

X3DH lets a node start a conversation with a peer that is offline, by using a
prekey bundle the peer published earlier (spec §5.2). Bundles are cached: a
supernode serves them from `prekey_cache`, and a phone keeps one for up to
7 days.

Signed prekeys rotate roughly weekly. `rotate_signed_prekey` replaced
`signed_prekey_secret` outright, keeping nothing. Two consequences, both found
while working through ROADMAP T-06:

1. **A rotation silently invalidated every cached bundle.** `SessionInitPayload`
   carries the `signed_prekey_id` the initiator used, and the initiator has
   always filled it in — but the responder never read it. `x3dh_respond` used
   whatever secret was current, so after a rotation it derived a *different*
   shared secret from the one the initiator derived. There is no integrity check
   on the shared secret itself, so the failure only surfaced as an AEAD tag
   mismatch on the enclosed first message.

   `build_accepted_session` had the same bug for a second reason: it seeded the
   Double Ratchet's `init_bob` DH key from the current signed prekey as well, so
   even a correct X3DH would have produced a ratchet the initiator could not
   follow.

2. **Nothing told the initiator.** The responder's failure path was
   `debug!(..); return;`. The initiator kept its cached bundle, retried against
   it, and failed identically every time. From the user's point of view the
   conversation was permanently stuck with no error.

## Decision

### Retention

`PrekeyState` keeps the secrets it rotates away from, newest first, bounded by
`MAX_RETAINED_SIGNED_PREKEYS = 2`. Rotation is weekly and a cached bundle
expires after 7 days, so two covers the window with a margin.

`signed_prekey_secret_for(id)` resolves an id to the current or a retained
secret. `x3dh_respond` takes `used_signed_prekey_id` and uses that secret;
`build_accepted_session` resolves it once and uses the same secret for both
X3DH and `init_bob`. An id we no longer hold is
`X3dhError::SignedPrekeyNotFound` — a loud failure, never a silently
mismatched derivation.

The id is threaded from `init.signed_prekey_id` through `accept_session`,
`accept_session_with_first_message` and `decrypt_first_message_only`. It was
already on the wire; only the plumbing was missing.

Retained secrets are persisted. The serialized `PrekeyState` appends the
retained list after the one-time pool, so a blob written before this field
simply ends earlier and loads as "none retained" — no version byte, and no
migration.

### Rejection

New payload type `0x22 SessionReject`:

```
type(1 = 0x22) + reason(1) + identity_key(32)
```

`reason` is one of `StaleSignedPrekey = 1`, `UnknownOneTimePrekey = 2`,
`DecryptFailed = 3`. The breakdown is deliberately coarse: the initiator only
needs to know its bundle is dead, and a finer answer would tell a prober which
prekeys we still hold.

Both failure branches of `handle_session_init` emit one, after releasing their
locks. On receipt, `handle_session_reject` discards the cached bundle for that
peer so the next send re-requests a fresh one.

**A reject cannot be authenticated.** By definition no confirmed session exists
when it is sent, so there is no key to sign it with that the receiver can
check. It is therefore treated as a hint and bounded three ways:

- the NodeId ↔ identity-key binding check applies, as on every other ingress
  path (spec §14.3);
- it only acts on an *unconfirmed* handshake. The initiator installs its
  session optimistically, before the peer has accepted anything, so holding a
  session does not mean the peer agrees. A handshake is **confirmed** the
  moment we successfully decrypt anything from that peer: only their ratchet
  could have produced it. `SessionManager` tracks unconfirmed handshakes and
  the message ids sent under them; a reject tears down the session, discards
  the cached bundle from memory and storage, and marks exactly those messages
  failed. A confirmed session is never touched, which is what stops a forged
  reject from killing working traffic.

  An earlier draft of this ADR used a 60-second window instead, on the theory
  that a reject arriving soon after an initiation must be answering it. That
  was wrong in both directions: it let a forgery tear down a session that had
  been established and used seconds earlier, and it ignored a legitimate
  reject that arrived later, which DTN handshakes routinely do. Confirmation
  is a state, not a deadline;
- it does nothing at all when no bundle is cached and nothing was just
  initiated, so it is not an amplification vector.

The worst a forgery achieves is one discarded unconfirmed handshake and one
extra prekey request. That is strictly better than the alternative it replaces,
which was being permanently stuck.

## Consequences

**Easier:**

- A conversation started from a cached bundle survives the peer rotating its
  signed prekey, which is the common case for a bundle served by a supernode.
- A genuinely dead bundle now produces a recovery round instead of silence.

**Harder:**

- Two extra X25519 secrets are held in memory and on disk per node. They are
  covered by the same zeroization as the current secret.
- A bundle older than two rotations still fails — now loudly. The initiator
  recovers by re-requesting, so this is a latency cost, not a dead end.
- `SessionReject` is a new unauthenticated control message. Its blast radius is
  argued above, but it is a new ingress path and should be re-examined if the
  handshake ever gains a confirmation step that would let it be signed.
- **The unconfirmed-handshake map is in memory only.** A reject that arrives
  after the initiator restarts is therefore ignored, and recovery waits for the
  next send to fail and re-handshake. Persisting it needs a table and a
  decision about how long an unconfirmed handshake stays revocable — a window
  during which a forged reject would be actionable again. Left as follow-up
  work rather than guessed at.
- The signed-prekey rotation interval moved from 24 hours to the weekly value
  the spec always documented, because two retained keys cannot span a 7-day
  bundle cache at daily rotation. `SPK_ROTATION_TICKS` and
  `MAX_RETAINED_SIGNED_PREKEYS` are now coupled in a comment so the next change
  to either has to consider the other.
- Breaking wire change: a node built before `0x22` existed ignores the type
  (unknown payload types are dropped) and simply keeps retrying, i.e. the old
  behaviour. The protocol is `0.1-draft` with no deployed nodes, so no
  compatibility shim is provided; the version field stays `1`. Precedent:
  ADR-005.

## Alternatives Considered

1. **Keep no retained secrets and rely on the reject alone.** The initiator
   would recover, but every rotation would cost every peer with a cached bundle
   a failed handshake plus a round trip. Retention makes the common case work
   outright and leaves rejection for the genuinely stale case.
2. **Sign the reject with the responder's identity key.** The receiver would
   have to fetch and trust that key before it has a session, which is the
   problem the handshake exists to solve, and it would make the reject a
   signing oracle. Rejected in favour of bounding what a reject can do.
3. **Retain secrets indefinitely.** Unbounded key material on disk, directly
   against the forward-secrecy goal. The bound is the point.
4. **Have the responder re-derive against every retained secret and pick the
   one that authenticates.** Works without the wire field, but costs N X3DH
   derivations per handshake and hides which prekey was used. The id is already
   on the wire; using it is both cheaper and clearer.

## Note (2026-11-11)

"the same binding rule as every other ingress path (spec §14.3)" above means
the handlers that §14.3's identity-binding rule actually names: `SessionInit`
and `PrekeyResponse`, which are dropped unless
`NodeId = SHA-256(identity key)`. It is not a property of every handler in
that table — `PrekeyRequest`, for instance, has an empty body and carries no
key to bind — and it is not a claim about transport peer identity. BLE and Wi-Fi Direct exchange a bare NodeId with no key and no proof
of possession (ROADMAP T-34), and the internet transport only began proving it
in ADR-011. Appended rather than edited in place, because these records are
append-only.
