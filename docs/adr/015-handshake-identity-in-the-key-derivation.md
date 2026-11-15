# ADR-015: Handshake Identity in the Key Derivation

## Status

Accepted (2026-11-12). **Implemented (2026-11-14) — ROADMAP T-35.** See the
note at the end: one mechanism this record relied on did not exist when it was
written.

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

## Note (2026-11-14): implemented, and the timeout this record assumed

All three decisions are built. The binding is
`mycelium_protocol::wire::session_init_binding` — the `SessionInit` header as
it travels — fed to HKDF as `b"MyceliumX3DH-v2:" ‖ binding`, so the initiator
binds what it serialized and the responder what it received.

**"The 60-second initiation timer goes" is too broad.** What stopped depending
on it is *rejection suppression*: a rejection is now sent on the state question
"do we hold a session with this peer". ADR-007's tie-break still asks whether we
initiated within `SIMULTANEOUS_INIT_WINDOW`, because that is a genuinely
time-bounded question — did these two inits cross? — and it is still 60 seconds.
What the tie-break no longer carries is the *replay* protection it used to imply:
that comes from the records below and from requiring an init to enclose message
0 of its chain, neither of which expires.

**The handshake timeout did not exist.** Twice above — the accepted cost of
rule 3, and alternative 4's "a case a timeout already covers" — this record
leaned on a recovery mechanism that was nowhere in the code. Nothing had ever
given up on an unconfirmed handshake. That made rule 3 a straight loss for the
legitimate case: an initiator holding an optimistic session against a dead
bundle, whose responder keeps a stale session and therefore stays silent, had
no way back at all. The code review found it.

It exists now, and the shape it settled into after review is not quite the one
this paragraph first described. `SessionManager::stale_handshakes` *lists* the
handshakes past the deadline without touching anything, and the 30-second
maintenance tick decides: for each one it abandons it does what a rejection does
— drop the session row, drop the cached bundle from memory and from storage,
report the messages sent under it — and only then calls
`give_up_on_handshake`. The split is there so the caller can skip a handshake
the peer has acknowledged, and so that every durable write commits *before*
anything is forgotten: while the handshake is still in place a failed write is
retried on the next tick, and once it is gone a failure would strand durable
state with nothing left to clean it up.

The deadline is two DTN delivery windows — the init's and the reply's, together
the slowest a legitimate handshake can confirm — as
`handshake_confirmation_timeout(dtn.ttl_hours)`: `2 × max(dtn.ttl_hours, 72)`.
Derived rather than fixed because `dtn.ttl_hours` is configurable and bounds how
long our own init can still be in flight, and floored at the documented default
because the *reply's* window is the peer's choice and nothing on the wire says
what it is. A shorter bound would tear down handshakes still in flight and
report messages the peer had read as failed; the shape is fixed here, the
multiplier is a knob to measure (T-15).

**A limitation this leaves, stated rather than hidden.** The floor assumes the
peer keeps bundles for no longer than the 72-hour default. A peer configured
above that can have a legitimate reply still queued when we give up at 144
hours, and that reply then arrives for a session we have dropped. Closing it
needs the peer's window on the wire, which is capability negotiation (T-20);
until then §5.2 states the assumption and a node that raises its own
`dtn.ttl_hours` should expect peers to expire its handshakes on the default.

One gap stays, recorded rather than papered over: `unconfirmed_handshakes` is
in memory, so a restart loses the record and the sweep cannot fire. It predates
the sweep — a late rejection is ignored after a restart for the same reason —
so it is not a regression from rule 3. **ROADMAP T-41.**

**Two things the implementation found.** Deferring the prekey spend to "the
caller" has *two* callers, and the second was missed: the tie-break path that
keeps our own session and decrypts only the loser's first message left the
prekey unspent, so a replay of that init under a fresh envelope id could derive
the handshake again and reinstall the session we had deliberately discarded.
Both paths now spend it on the same event — the AEAD verifying. And the
message-less path needed the refusal stated here to be a refusal *before* any
derivation, not after: accepting such an init and merely not spending the
prekey leaves it for the next forgery.

**The reciprocal-key claim was checked, not assumed.** `u⁻¹ mod p` is canonical
— under `p`, so `is_canonical_x25519` admits it — and it does produce the
identical shared secret; verified against an independent implementation of RFC
7748 before the test was written. With the binding removed from the KDF, the
honest init and the swapped one derive the same secret byte for byte, which is
what the regression test now demonstrates through the real responder
derivation.

**Five more replays, found in review, and each fix found the next.** Retiring
the one-time prekey on authentication stops the replay of a discarded tie-break
loser only when that init *named* a prekey. A signed-prekey-only loser retires
nothing and stayed replayable for as long as its signed prekey was retained — a
fortnight, not the sixty seconds of the initiation window.

The first attempt was a per-session list of discarded init **transcripts**, and
each round took the next layer off it:

1. A transcript covers the whole payload, so **substituting the nested message**
   walks past it. The loser had sent follow-ups on the same chain, the ratchet
   retains skipped keys so a later message decrypts on a fresh one, and the
   derivation binds only the header.
2. A per-session record **dies with the session** while the prekey it depends on
   lives on, so an expiry or a re-handshake made the old init replayable again.
3. A prekey-scoped record cannot cover the **message-less** init: that path
   authenticates nothing, so recording there would let an attacker generating
   identities fill a bound shared with every real handshake. Left uncovered, an
   attacker holding the init header and any later ciphertext from the peer's
   chain could have the session derived from scratch over one that had moved on
   — rewinding a ratchet and reusing message keys.
4. **Stripping** a payload left the binding untouched, so a stripped copy was
   answered on the unauthenticated path and the genuine init was then met with
   silence, losing its message.
5. And a marker promoted but **never written** was gone on the next start, which
   is the only place that record is kept.

So: two records, keyed on a binding that now says whether the init carries a
message. `Session::accepted_binding` is one slot — ungrowable by a forgery,
which is what lets it cover the message-less form — and the first successful
decrypt copies it into `PrekeyState::answered_handshakes`, which retires with the
signed prekey, writing the blob on that decrypt. The session's entry is kept
rather than moved: a handover across two stores has an order to get wrong, and a
promotion followed by a lost write would leave neither marker, while two
independent records mean losing either leaves the other. Promotion is driven by
an authenticated event, is refused once the prekey has retired — a long-lived
session re-offers its entry on every decrypt, and obsolete entries would evict
live ones at capacity — and is the earliest moment that matters, because a
responder has no sending chain until the initiator speaks.

Both are enforced in the derivation layer, not only at the node's gate, because
a refusal there maps to a `SessionReject` and signing anything about an init the
peer really sent is the lever ADR-012 is about. Alternative 4's "persist the
discarded transcripts" was the right instinct with the wrong key and lifetime.

Changing what `accepted_binding` holds let the `init_transcript` parameter go
from both accept methods: they derive the binding from fields they already have,
so a caller cannot pass the wrong thing. The prekey-scoped record is capped at
1024, oldest evicted: a peer able to complete 1024 handshakes could evict an
entry and replay that init, where an uncapped record would let any peer grow a
blob rewritten on every init. A table deleted on rotation is the alternative if
it ever outgrows the blob.

**And an init encloses message 0 of its chain.** A relay could otherwise
reorder: wrap a captured later message from the chain into a copy of the init,
have *that* answered first, and leave the genuine init — a handshake already
answered — to be met with silence, losing the conversation's first message
silently, because the session works and nothing retries. Delivering the enclosed
message from the already-answered path was the first answer to this, and it was
the wrong one: on the tie-break path the surviving session is not the one that
payload was encrypted under, so the delivery could not succeed there anyway.
Requiring message 0 stops the reorder at the source, and the captured message
then arrives as what it always was — an ordinary message. The nested-type check
moved ahead of the record lookup in the same change, so an unknown type is
refused before anything consults any state.

**And the message-less variant is chosen by the form.** `x3dh_initiate` used the
bundle's one-time prekey whatever the form, so a message-less init named a prekey
it was not allowed to name: an init the responder could only reject, against any
bundle with prekeys left in it. The variant now decides the derivation, the
binding and the id named, and `InitiateResult` reports what was used rather than
what was offered.

**The sweep keeps an acknowledged handshake.** A conversation where the peer
reads and acknowledges but never replies never confirms — confirmation needs
something of the peer's to decrypt — so the sweep abandoned working sessions
every 144 h, and everything the peer then sent was dropped until our own next
send. The acknowledgement lives on the handshake, which knows the messages it sent,
and it is noted without consulting the message rows at all, because those can be
deleted. A receipt counts only if it names a message sent **after** the init:
receipts arrive late, so one from a session long gone must not vouch for a newer
handshake, and — the subtle half — the init's own message is decrypted by an
ADR-007 tie-break winner with a session it then *discards*, and receipted
honestly. Such a receipt proves the peer read the message, not that it holds the
session the message arrived under; if the winner's own init were then lost, it
would pin an unusable handshake for ever.

Two kinds of conversation therefore cannot be acknowledged at all: one of
exactly a single message, and one carrying only sender-key distribution, since
`ContentType::System` draws no receipt. Both are swept at the deadline and
re-handshaked on the next send, which costs a handshake and loses nothing. T-42
is the acknowledgement that would settle all of it.
Receipts are *not* treated as confirmation: they are unauthenticated, and a
forged one would then pin a dead session for ever and strip a live handshake of
its rejection protection. As a gate on keeping something, a forgery costs that
pairing its recovery, which is the behaviour from before the sweep. The
unforgeable version — an acknowledgement encrypted under the new session — is
ROADMAP T-42.

**And the sweep is one critical section.** Dropping a session and then deleting
its row left a gap in which another task could accept and persist a new session
for that peer, whose row the delete would then remove — a session that works
until the next restart and is gone after it. The sweep holds the session write
lock across the row delete, the bundle eviction and the status writes; nothing
takes the bundle cache and then that lock, so the order is safe. What remains is
in the send path, not here: a send that has already copied a cached bundle can
still initiate from it after the invalidation, costing one handshake that the
next sweep retires. The rejection path has always had that same window.

**One stale comment mattered.** `PrekeyState::to_bytes` reserves its capacity up
front *because* a realloc would free an allocation holding prekey secrets
without wiping it, which the caller's `Zeroizing` wrapper cannot undo. Two
fields had been appended since without being added to the reservation.

**What the rejection guarantee still does not cover.** Retiring the one-time
prekey on authentication stops a *corrupted copy* of an init from burning it.
It does not bind the prekey to the initiator it was issued to, and a bundle is
public: any node holding Bob's bundle can initiate with it, under its own
identity and its own valid first message, and consume the prekey Alice's init
names. Alice's untouched init then fails with `UnknownOneTimePrekey` and draws a
rejection that is entirely *honest* — Bob really cannot complete it — but a
third party has forced that pairing to re-handshake at the cost of one prekey.
Bundles served from a supernode cache make the collision ordinary rather than
adversarial, since the same cached bundle goes to many initiators. So the claim
"a forged or provoked `SessionReject` changes nothing" holds for a forged one
and for a replay, and not for this: it provokes a true refusal. **ROADMAP
T-43.**

## Note (2026-11-15)

A review of the landed change against this record found two ways the two
answered-handshake stores could disagree. Both are durability, not derivation,
and both are fixed; the record is appended rather than rewritten.

**The teardown is one transaction, because the retry is not guaranteed.** The
note above has the sweep committing every durable write before anything is
forgotten in memory, so that a failure leaves the handshake stale and the next
tick retries. Ordering was necessary and not sufficient. As three independent
writes, a failure part-way through had already deleted the session row while the
live session stayed in memory — and the retry it was counting on could be
cancelled outright by a single follow-up receipt, because acknowledging a
handshake removes it from `stale_handshakes` for good. The result was a working
session with no row to reload. `abandon_unconfirmed_handshake` now does the
session delete, the bundle eviction and the status writes in one SQLCipher
transaction, so "the next tick retries" is true rather than merely intended.

**The two answered-handshake stores can still diverge across a restart, and
reconciling them from the session rows would be worse.** Keeping both markers —
rather than clearing one on promotion — was chosen to avoid an ordering hazard
across two stores. It leaves a different one: they are separate rows, written
separately, so a failed prekey-blob write leaves the marker on the session
alone, and a session holds exactly one slot, so the next handshake with that
peer overwrites it. The ADR-007 tie-break winner is worse off still: it records
the loser's init in the durable record *only*, because the session it keeps has
no marker of its own, so a lost write there loses the marker with nothing to
repair it from. In memory both survive — `needs_persist` stays set and any later
successful write commits them — so a restart is required for either to bite.

Re-asserting every loaded session's `accepted_binding` at startup was
implemented and then **withdrawn**, because it trades a narrow durability hole
for a cheaper attack on the same guarantee. The two records have deliberately
different shapes: the session's single slot can cover the message-less init
precisely because a forgery cannot grow it, while `answered_handshakes` is
bounded and shared and is therefore written only where the AEAD has verified.
A session built from a message-less init authenticates nothing, so promoting
every loaded session's marker would let an attacker — identities are free, and
the message-less form needs no key of ours — stand up more sessions than the
bound and evict the authenticated markers out of it on the next restart. That
is a worse failure than the one it repairs, and it would have been introduced by
the fix rather than found in the design.

What a sound version needs is authentication evidence stored *with* the marker,
so only markers whose peer has authenticated are reconciled. The session's
ratchet does not supply it: `recv_count` resets on every DH step, so "has ever
decrypted" is not recoverable from it. That means a trailing field on the
serialized session, or the session row and the prekey blob written in one
transaction — which the in-memory records of **T-41** have to settle anyway.
Folded into that task rather than guessed at here.
