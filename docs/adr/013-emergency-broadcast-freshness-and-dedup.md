# ADR-013: Emergency Broadcast Freshness and Flood Dedup

## Status

Accepted (2026-11-12)

## Context

ADR-010 made a level-3 emergency broadcast's co-signatures real: three
co-signers the receiver trusts above 0.8, each signature verified against a
stored identity key. Reviewing that record against the code during T-09 turned
up two defects in the mechanism *around* the signatures — the flood-dedup set
— either of which undoes the work ADR-010 did.

### A copy that verifies against nothing could suppress one that verifies

`handle_emergency_broadcast` inserted the envelope's `message_id` into the
dedup set **before** the trust threshold and the co-signature checks. A
`message_id` is cleartext in every envelope and nothing authenticates it, so
any node that relays a legitimate critical alert could read the id off it and
immediately send a bogus copy carrying the same id. The receiver remembered
the id, refused the copy, and then dropped the real alert as a duplicate.

One unverifiable packet suppressed a verified mesh-wide alert — on the single
message type whose whole purpose is to arrive.

### The set cleared itself, and nothing bounded a broadcast in time

At 10 000 entries the set was cleared wholesale. ADR-010's digest covered
`broadcast_id ‖ originator ‖ level ‖ message` and nothing else, so a captured,
correctly co-signed critical alert verified forever; the only thing keeping it
from a second mesh-wide flood was the dedup entry for its id. An attacker
could force the clear by flooding distinct ids first, and then replay the
original.

ADR-010 named `broadcast_id` as what "stops replay". It bounds *transfer* of
an approval to another alert, which is a different property: the id is part of
the alert being replayed, so a verbatim replay satisfies it. The replay bound
was the dedup set alone, and the dedup set erased itself.

## Decision

### Verify, then remember

The order becomes: parse → freshness → trust and co-signature checks →
remember → raise and flood. Nothing is remembered until it has been accepted,
so a copy the receiver refused can never stand in for one it would have taken.

The cost is that unaccepted copies are re-checked rather than short-circuited
by the dedup set, which makes that work an attacker's lever. It is budgeted:
at most `MAX_COSIGNER_CANDIDATES` (16) co-signer entries per broadcast reach
the expensive checks — a trust-graph traversal and an Ed25519 verification.

The budget is charged only once an entry gets that far. A duplicate id, or an
id the receiver holds no identity key for, is dismissed by one indexed lookup
and costs nothing, so the cheap filters run over the whole list. That ordering
matters: with a positional cap, padding a broadcast with 16 unknown ids would
have hidden three genuine approvals sitting behind them, which is a way to
suppress an alert by appending to it. Three valid co-signatures are required,
so a legitimate alert has no reason to carry sixteen candidates whose keys the
receiver holds; and to pad the list with entries that do reach the budget an
attacker would have to know which contacts that receiver has.

### A known digest short-circuits before the checks, not before acceptance

Remembering a digest before checking it was the defect; *reading* one before
checking is not. An entry exists only because this node already accepted that
exact broadcast, so a hit is proof the work has been done, and a replay costs
a hash and a map lookup instead of sixteen signature verifications. That
matters because the cheapest way to make a node work is to replay one captured
alert, and a 1-hop neighbour is not rate-limited at all. A stranger can do it
too, five times an hour; being vouched — by hand, or automatically because its
beacon carried a group-discovery hash matching ours, which anyone in range can
copy (ROADMAP T-04) — is what removes the bound.

What the lookup does not decide is whether to **forward**: see below.

### A copy that cannot travel is no substitute for one that can

The envelope's TTL is cleartext and cannot be part of the digest, because
every hop decrements it. So a relay could deliver a captured alert with
`ttl = 0` ahead of the genuine copy: the receiver accepted it, raised it
locally, had nothing to forward, and then dismissed the real copy as a
duplicate. The alert stopped there and everything downstream never heard it —
the suppression attack again, one hop further out.

A dedup entry therefore records the furthest **reach** (remaining TTL) seen for
its key. A copy that reaches further is checked and forwarded, and its reach
recorded; it does not raise a second local alert. Three details make that
safe:

- The *probe* before the checks never records a reach, so a bogus copy cannot
  pin a figure the genuine one then fails to beat.
- A further-reaching copy is **verified before it is forwarded**. The digest
  covers the alert, not the approvals attached to it — co-signatures are not
  part of what the alert *is* — so a relay could otherwise have a node pass on
  a stripped copy in place of the one it checked.
- Reach is clamped to `MAX_FLOOD_TTL` (20) on the way in and on the way out.
  That bounds re-*forwarding* to at most 21 sends of one broadcast per node
  however many copies arrive, because only an accepted copy records a reach
  and reach only increases. It also stops a forged `ttl = 255` flooding far
  past what the originator intended.

  It does **not** bound the checking. A copy that claims more reach and then
  fails verification records nothing, so it can be sent again — each time
  costing up to sixteen signature verifications. That work is bounded only by
  the per-neighbour rate limiter, which does not bound a 1-hop neighbour at
  all, and the clean answer is T-37's originator signature: one verification
  would then reject a forged copy before any co-signature is looked at. Until
  then it is a cost, not a correctness problem, and it is cheaper than the
  alternative — remembering copies that failed would mean a bogus copy
  suppressing the genuine one, which is the defect this record exists to
  close.

### A flood is addressed to everyone, and only to everyone

The destination is not part of the digest either — a flood carries none — so a
copy addressed to one node in particular still verifies. It also behaves
differently: it is not routed away, so it reaches the flood handler, and
forwarding preserves that destination, which means every downstream node
unicasts it back towards the addressee instead of flooding it. Accepting one
therefore remembered the alert, raised it locally, and left the genuine
broadcast behind it looking like a duplicate — the alert stopped at that node.

Both flood handlers now refuse anything whose destination is not
`NodeId::ZERO`, before it is remembered.

### Dedup is keyed on the broadcast digest, not the envelope id

Remembering a `message_id` means remembering an attacker-chosen value. The key
becomes the digest that identifies the broadcast — the same digest the
co-signatures cover — so a copy that differs in anything the receiver acts on
is a different entry, and a copy that differs in nothing *is* the alert.

This also covers levels 1 and 2, which carry no signatures at all and where
"verify, then remember" has nothing to verify beyond a trust score computed
over a forgeable `envelope.source`. A forged copy of a level-1 alert can no
longer suppress the real one, because it cannot produce the real one's key
without reproducing the alert.

The channel-message flood gets the same treatment with its own
domain-separated key (`mycelium-channel-flood-v1:` over id, source, channel,
content type and body), closing the same suppression hole there.

### `signed_at` joins the body and the digest

```
type(1 = 0x90) ‖ level(1) ‖ signed_at(8 LE) ‖ msg_len(4 LE) ‖ message
               ‖ cosigner_count(1) ‖ cosigners(N × 96)
```

```
SHA-256( b"mycelium-emergency-broadcast-v2:"
       ‖ broadcast_id (16)      // the envelope's message_id
       ‖ originator  (32)
       ‖ level        (1)
       ‖ signed_at    (8 LE)
       ‖ message_len  (4 LE)
       ‖ message )
```

A receiver refuses a broadcast dated more than
`EMERGENCY_MAX_CLOCK_SKEW_SECS` (300) ahead of its clock, or raised more than
`EMERGENCY_VALIDITY_SECS` (3600) ago — the rule ADR-011 settled on for signed
DHT records, for the same reasons: without the upper bound a post-dated alert
outlives every honest one, and without the lower bound a year-old alert still
verifies.

The context string moves to `v2`, because a v1 signature must not be readable
as a v2 one. The digest's name moves with its second job: it is
`broadcast_digest`, not `cosign_digest`.

The body is also parsed strictly — exact length, known level — like the
handshake payloads in ADR-012. A body that parses with bytes left over is a
broadcast with two encodings, and only one of them is the one the receiver
remembered. The serializer is capped at 255 co-signers to match, since the
count is one byte and a body whose count disagrees with its entries is one
this parser refuses.

### Dedup expires by age, and evicts the oldest

`FloodDedup` replaces the `HashSet<MessageId>`: a map from key to the instant
it was seen, swept on a timer, and at capacity it drops the **oldest eighth**
rather than everything.

Retention is `EMERGENCY_VALIDITY_SECS + EMERGENCY_MAX_CLOCK_SKEW_SECS`, plus
one second. The relationship is the point, not the number: an entry is
forgotten only once no broadcast it could be about would pass the freshness
check, so eviction by age cannot reopen the replay the entry was holding shut.
The extra second covers the two clocks disagreeing at the edge — freshness is
compared in whole wall-clock seconds, retention in monotonic time — so a
broadcast dated exactly `+300` is not acceptable for a fraction of a second
after its entry has aged out. A unit test asserts the inequality, because
clearing the set broke it unconditionally and nothing in the code said so.

That is enough while the two clocks agree, and they do not always. Retention
*must* be monotonic — a flood's age is measured from when it arrived — while
freshness *must* be wall-clock, because it is measured against a time the
originator wrote, and a backward clock correction of a few seconds would
otherwise retire an entry while the alert it covers is still acceptable. So an
entry also carries a `keep_until`: the wall-clock second its broadcast stops
being acceptable. It is spent only when **both** clocks say so — the TTL has
elapsed *and* the wall clock is past `keep_until` — which makes each clock's
failure mode covered by the other. A copy cannot shorten the window it finds,
only lengthen it. The capacity cap is what keeps the map bounded if a device's
clock sits far in the past.

One case no live entry can cover: a step backwards *after* the entry was
swept. Sweeping is irreversible, so an entry dropped the instant its window
closed is gone if the clock then reopens that window. Hence the grace —
`keep_until` plus `CLOCK_REGRESSION_GRACE_SECS` (300, the same figure the
freshness check already tolerates as skew) — which costs one map entry for a
message that is refused on freshness anyway. A correction larger than the
grace, landing in the moments after a sweep, can still reopen one replay of
one alert.

The alternative was a non-regressing clock of our own: remember the highest
wall-clock second ever seen and compare freshness against that, so a
rollback cannot make a stale alert fresh again. Rejected because its failure
mode is worse than the one it fixes. A clock briefly set far in the future —
a bad NTP reply, a user setting the date — would stick at that value and make
the node refuse *every* emergency alert until it restarted. For an alerting
system, refusing everything silently is a worse outcome than one replay of a
genuine alert inside its validity window.

### The sets are kept apart: per flood type, and per emergency level

Channel floods and emergency floods get separate sets, so channel traffic —
ordinary, and far higher volume — cannot evict an emergency entry.

Emergency floods are then split again, one set per level. A shared set is
flushed by whichever level is cheapest to get accepted, and the entry pushed
out need not be of that level. Level 1 needs only a trust score over
`envelope.source`, which nothing authenticates (ROADMAP T-37) and which a
peer 1 hop away clears outright — vouched by hand, or auto-vouched because
its beacon carried a matching group-discovery hash — and that tier is not
rate-limited at all. Ten thousand junk level-1
alerts would evict the entry holding a captured level-3 alert shut.

(The rate limiter charges the transport peer for every message before any
payload is parsed, so no emergency level escapes that gate. What emergency
broadcasts skip — at every level, not just level 2 — is the *per-originator*
gate, which only `EncryptedMessage`, `GroupMessage` and `ChannelMessage` pass
through. The per-level privileges spec §9.5 describes are not implemented per
level; ROADMAP T-37 carries that.)

Per level, evicting a level-3 entry costs ten thousand *accepted* level-3
broadcasts: three verifying co-signatures each, over a digest that covers the
id, originator, level, date and message — so one capture yields exactly one of
them. An attacker who can pay that can already flood the mesh without a
replay.

## Consequences

**Easier:**

- A node cannot be talked out of an alert it can verify. The suppression
  attack needs the real alert's bytes, at which point it *is* the alert.
- A captured alert stops working after an hour, whatever the dedup set does.
  Replay is bounded by the signature, not by a cache.
- The channel-flood dedup set no longer grows without bound, which was
  ROADMAP T-14's second bullet.

**Harder:**

- Breaking wire change: the emergency body grows by 8 bytes and the digest is
  incompatible with ADR-010's. Protocol `0.1-draft`, no deployed nodes, no
  shim, version field stays 1. Precedent: ADR-005, ADR-009, ADR-010, ADR-011.
- Unaccepted copies are re-checked. Bounded as above, but a node in radio
  range of an attacker does more work per packet than before.
- Emergency broadcasts now depend on a roughly correct clock. A node whose
  clock is off by more than the skew tolerance will refuse alerts it should
  take, or accept ones it should not — the same exposure signed DHT records
  already have, and the reason a skew tolerance exists at all.
- Three valid co-signatures must appear among the first sixteen candidates the
  receiver holds keys for. A refinement of ADR-010's "three distinct valid
  co-signers", and the price of checking before remembering.
- The set is in memory, so a restart empties it. Inside the validity window a
  captured alert can therefore be accepted, reported and flooded once more per
  restart, with no capacity pressure needed. What that buys is one extra flood
  of a *genuine* alert less than an hour old — the same nuisance as the
  eviction case, not a forgery — and the fix if it ever matters is to persist
  the marks, at the price of a write per accepted alert and a sweep.
- Capacity pressure within a level still evicts, so a replay inside the
  validity window remains possible for whoever can fill that level's set. For
  level 3 that costs more than the replay buys; for levels 1 and 2 it is moot
  while they are unauthenticated, since forging a fresh alert is cheaper than
  replaying an old one (ROADMAP T-37).
- A copy claiming more reach is verified before it is forwarded, and a copy
  that fails verification records nothing, so an attacker can ask for that
  checking repeatedly. The clamp bounds the *forwarding*, not the checking;
  the latter is bounded only by the per-neighbour rate limiter, and the answer
  is an originator signature (T-37) rather than a memory of failed copies,
  which would be the suppression defect over again.

## What this does not fix

**A relay can weaken the approval set it passes on.** The digest identifies
the alert, not the approvals attached to it: a co-signature is evidence
*about* an alert rather than part of what it says, and a receiver that holds
no key for a co-signer could not reproduce the identity anyway. So a relay can
forward a copy carrying fewer approvals than the one it received. If the three
it keeps are ones this node can verify but a downstream node cannot, that node
refuses an alert the full set would have satisfied.

Dedup cannot tell the difference, and no bookkeeping here can: a receiver
cannot distinguish an approval it cannot verify from one invented on the spot,
so "forward again when a copy brings more approvals" is a lever an attacker
pulls with junk entries. Counting them loses — pad the first copy to twenty —
and tracking the union of entry ids loses as soon as the cap on remembered
entries is full. The fix is to authenticate the set: the originator signature
ROADMAP T-37 calls for should cover the co-signer list, after which a relay
can neither strip nor pad it, the dedup identity can include the approvals,
and "more approvals" becomes a claim a receiver can check. Recorded in T-05,
which builds collection, and T-37.

Its weight today: a relay that is a receiver's only path can simply drop the
alert, so stripping buys something only where the receiver has another path
and the stripped copy wins the race. And nothing collects co-signatures yet
(T-05), so there is no multi-approval alert to strip.

**A channel message becomes floodable again after 900 seconds.** Emergency
retention is tied to a signed validity window; a channel message has no such
window, because nothing in it is signed — `device_timestamp` is a relay's to
edit. Its dedup entry is therefore a plain 900-second bound on how long a loop
or a re-delivery can take, and once it expires the same message is accepted,
reported to API clients and flooded again. A captured channel message is
replayable indefinitely at that interval.

Nothing in this layer fixes it: a freshness bound a relay can rewrite is not a
bound, so the answer is the same originator signature ADR-017 defers and
ROADMAP T-14 carries. Keeping the entry longer only widens the interval, and
keeping it forever is the unbounded set this record replaced.

**A forged channel message still takes the genuine one's place in storage.**
`store_channel_message` is an `INSERT OR IGNORE` keyed on the envelope's
`message_id`, so a copy stored first keeps the row. The flood no longer stops
— the genuine message is now forwarded onward, where before it was dropped as
a duplicate — but this node's own history keeps the forgery. The row's
identity should be the digest the flood is keyed on, or channel messages
should be authenticated; both are channel work, recorded in ROADMAP T-14.

**Emergency broadcasts are not origin-authenticated.** Levels 1 and 2 carry no
signature of their own, and `envelope.source` is cleartext and unverified, so
any neighbour can emit a level-2 "Urgent" claiming a trusted id: it passes the
trust gate, skips the per-originator rate limit that ordinary user data is
charged for, and is flooded. This work
stops a forgery *suppressing* a real alert; it does not stop one being
injected. Separately, the handler floods every accepted level, while spec §9.5
reserves mesh-wide flooding for level 3 — code and spec disagree, and the fix
(an originator signature at every level, and a flood scope per level) is a
design decision rather than a dedup fix. Recorded as ROADMAP T-37.

## Alternatives Considered

1. **Keep the id as the dedup key and just move the insert after
   verification.** Fixes level 3, where there is something to verify, and
   leaves levels 1 and 2 suppressible by any neighbour. Rejected once it was
   clear the digest was already available and strictly more precise.
2. **Derive freshness from the envelope's `device_timestamp`.** No wire growth,
   but the envelope is unauthenticated: a relay could re-date a captured alert
   and the co-signatures would not notice. A freshness bound an attacker can
   edit is not a bound.
3. **Keep the wholesale clear but make the set bigger.** Postpones the replay
   window rather than closing it, and the attacker chooses when it opens by
   flooding distinct ids.
4. **Remember refused copies too, to avoid re-verification.** This is the
   defect, stated as an optimisation: it is exactly how one unverifiable
   packet suppresses an alert.
5. **Refuse new entries when the set is full instead of evicting.** Trades a
   replay window for a suppression window — whoever fills the set first
   decides which alerts are remembered at all — and failing open instead would
   re-flood every copy of a looping alert. Separating the sets attacks the
   pressure rather than the response to it.
6. **Per-originator sequence numbers instead of a timestamp.** Stronger replay
   protection, but it needs per-originator state that survives restarts on
   every node in the mesh, for a message type that arrives from nodes a
   receiver has never heard from. A validity window needs no state at all.

## Note (2026-11-13)

**ADR-014 supersedes parts of this record.** Following it as written now
produces packets every receiver refuses.

- **The body has two more fields.** It is `level(1) ‖ signed_at(8 LE) ‖
  identity_key(32) ‖ signature(64) ‖ msg_len(4 LE) ‖ message ‖
  cosigner_count(1) ‖ cosigners(N × 96)`, and the minimum body is 110 bytes,
  not 14. The originator's signature over the alert *and* its approval list is
  mandatory at every level, and is checked before the trust gate.
- **"Emergency broadcasts are not origin-authenticated" no longer holds.** That
  paragraph described the state this record left behind; ADR-014 closes it. A
  stranger can no longer name a source its neighbours trust, and a relay can
  no longer strip or pad the approvals.
- **"A relay can weaken the approval set it passes on" is closed too**, by the
  same signature — along with the reasoning here about why no bookkeeping in
  this layer could close it. That reasoning was right: the answer was
  authentication, not bookkeeping.
- **The dedup identity stays `broadcast_digest`.** This record's "what this
  does not fix" suggested the origin signature would let the dedup identity
  cover the approvals. It must not: the originator holds the signing key, so
  it could pad the list and re-sign into arbitrarily many accepted entries,
  which is this record's own capacity argument broken. One alert is one entry.
- **Reach is tracked per approval list, not per entry.** The reach rule above
  describes one figure per entry. An entry now keeps up to three
  `(approval-list digest, reach forwarded)` pairs, and a copy is worth
  forwarding only if it reaches further than *its own* list already did, or
  brings a list with a free slot. A single pair could not express "this list
  travelled 20 hops, that one travelled none", which let a spent-TTL copy of a
  new list block the copy that could carry it, and let a higher TTL buy a slot
  past the ceiling.
- **The "21 sends per node" bound above is withdrawn.** It was already
  corrected here for *rejected* copies; with per-list reach the forwarding
  bound is `MAX_APPROVAL_LISTS` (3) distinct lists, each advancing only while
  its own reach increases, so the figure is bounded but no longer 21.

What this record still governs unchanged: verify-before-remember, the digest
as the dedup key, `signed_at` and the freshness window, dual-clock retention
with its grace, per-level and per-flood-type sets, the destination rule, and
the strict body parsing.
