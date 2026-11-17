# ADR-019: Group Discovery Proof of Possession

## Status

Implemented (2026-11-17, ROADMAP T-04). Accepted 2026-11-12.

## Context

A seed-phrase group derives a discovery key by HKDF over the passphrase
(`MyceliumGroupDiscovery`), and a beacon advertises membership as a truncated
8-byte hash of it. `handle_beacon` auto-vouches a peer whose beacon hash
matches the local one, which puts that peer 1 hop away at trust 1.0 — above
every trust threshold in the protocol, including the ones that gate emergency
broadcasts.

The hash is a static value broadcast in the clear. Anyone in radio range can
copy it from a beacon and replay it in their own, and be auto-vouched into a
group they have no key for. Matching a broadcast value is not evidence of
holding the secret behind it.

## Decision

### A vouch requires answering a challenge

A beacon match becomes a *hint*, not a credential. On a match the verifier
sends a fresh random nonce, and the peer must return

```
HMAC(group_discovery_key, nonce ‖ verifier_node_id ‖ responder_node_id)
```

The auto-vouch happens only on a correct response. Two new payload types carry
the challenge and the response.

Both node ids are in the MAC so a response cannot be lifted out of one pairing
and replayed into another, and the nonce is fresh per attempt so a captured
response is worth nothing. The key itself never travels, and a wrong answer
gets nothing: the verifier simply does not vouch.

### The beacon hash stays as it is

Rotating it — `HMAC(group_key, time bucket)` — would limit replay to a bucket
and was considered as an addition. It is not part of this decision: it does not
prove possession, so the challenge is needed anyway, and a rotating hint means
a second constant (the bucket) and two mechanisms that must agree about time.
A static hint that grants nothing by itself is acceptable; it leaks only that
*some* node in range claims this group, which it already does today.

## Consequences

**Easier:**

- Group membership becomes something a peer demonstrates rather than asserts,
  so the 1-hop trust it grants is earned. Every threshold built on trust —
  including emergency levels — inherits that.
- The failure is silent and local: an unanswered or wrong challenge means no
  vouch, with nothing sent on the wire to tell a prober whether it was close.

**Harder:**

- Discovery gains a round trip before any trust is granted, so a peer that
  appears and disappears inside one beacon interval may never be vouched. That
  is the correct direction, and it makes group formation slower on a flaky
  radio link.
- Two new payload types and their handlers, each needing the rate-limit and
  dedup treatment every ingress path needs — a challenge is a cheap thing to
  ask a node to compute, so answering must be bounded per peer.
- The group key is now used for a MAC as well as for the discovery hash. The
  domain separation has to be explicit, or the two uses can be made to collide.

## Alternatives Considered

1. **Time-bucketed beacon hash alone.** No round trip and no new payload types;
   still replayable inside the bucket by anyone in range, so it limits the
   window rather than closing it.
2. **Both the rotating hash and the challenge.** Strongest, and the rotating
   half adds a constant to choose and a clock to agree on for a hint that
   grants nothing on its own.
3. **Sign the beacon with the node's identity key.** Proves who sent the
   beacon, not that they hold the group key — the wrong property for this gate.

## Implementation note (2026-11-17, T-04)

What the decision above left open, and one thing it got wrong about the code it
was describing.

**The hint was never the key's first eight bytes.** This ADR and spec §10.2
both said a beacon carries the first 8 bytes of the group key. It carries
`SHA-256(key)[..8]`, and has since the feature was written. The distinction
matters for the paragraph below: the published value was already a one-way
function of the key, not the key itself.

**Domain separation is one-sided, on purpose.** The hint stays exactly as it
was, as decided — so the MAC key is the new value: `HKDF-SHA256(key, info =
"MyceliumGroupProof")`. The two uses are then a public SHA-256 of the key and
an HKDF output under its own info string, and neither reveals the other.
Deriving the hint through HKDF too would have been tidier and would have
changed a value on the wire for no security gain.

**The decoded group key is wiped, the configured one is not.** `Node::new`
derives the hint and the MAC key and zeroizes the decoded bytes — but
`config.group_seed` keeps the hex string for the life of the node, and on the
daemon path it is sitting in a TOML file besides, so this is tidiness rather
than a protection. Key material at rest is T-08's subject (ADR-020).

**The hint and the MAC key are taken as a pair.** `GroupProofCtx::group`
hands out both or neither, so a node can never hold a hint it cannot answer
for, or answer for a group it does not advertise. A `group_seed` that is not
32 bytes of hex is logged and ignored rather than half-applied.

**Both messages are link-local.** `ttl = 1`, `SYSTEM`, sent straight to the
transport peer, and refused unless the envelope's source is that peer and the
destination is this node. The hint they answer is link-local — a beacon is
never forwarded — so the exchange is too, and the two ids in the MAC are then
the ones the link itself proved (ADR-021). On BT Classic and LoRa, which still
assert peer identity rather than proving it, this inherits exactly the weakness
those transports already have (T-47).

A challenge addressed to the broadcast id is refused. Without that check one
packet would make every member in earshot answer — the amplifier this ADR's
rate limit exists to prevent, arriving by a different door.

Both checks sit *before* the generic forwarder, not only in the handlers. The
forwarder runs between ingress and dispatch, so a challenge addressed past us
was relayed one hop — and relayed on the protocol-message exemption these
types need, which skips both the per-peer limiter and the blacklist. Routing
work for free, for a peer that may be over its budget or blacklisted
outright.

The same guard covers the **beacon**, which spec §10.1 has always said is
never forwarded and which was being forwarded for exactly the same reason: a
unicast beacon addressed past this node reached the forwarder on the same
exemption. Broadcast is left to the handlers, because broadcast is how a
beacon normally arrives — so a challenge addressed to the broadcast id is
refused one step later, by the handler's own destination check, rather than
here where it would take beacons with it.

**Neither side ever takes an id from the payload.** The response carries only
the MAC. The responder MACs the peer that asked and itself; the verifier checks
itself and the peer it asked. This is what makes answering a stranger safe,
and it is worth spelling out because the ADR asserted the property without
saying what enforces it: a MAC obtained by challenging a real member is
`HMAC(k, nonce ‖ collector ‖ member)`, and being vouched requires
`HMAC(k, nonce' ‖ verifier ‖ self)`. The collector's id is in the verifier's
place and cannot be moved to the responder's without holding the key, so the
oracle this opens hands out nothing usable. Relaying a verifier's challenge
onward does not help either: the responder's slot is always filled with the
responder's own id.

**One guess per nonce.** The first response spends the attempt, right or wrong.
A nonce is good for 30 s.

**One attempt per peer per 120 s.** The ADR did not say how often to challenge,
and "on a match" is the wrong answer: beacons arrive every 10–30 s, so an
unvouched peer in range would be challenged twice a minute, for each identity
it cares to beacon under. The cooldown runs from the attempt rather than from
its outcome, so answering wrongly does not buy the next nonce sooner. It costs
a real member one further wait when a challenge is lost on a flaky link, which
is the "slower group formation" this ADR already accepted.

All four numbers here — 30 s, 120 s, 256 pending, 30 an hour — are reasoned
from the beacon interval and from what one HMAC costs, and measured against
neither a testbed nor a radio. They are shapes with placeholder numbers, on
the list ROADMAP keeps for exactly that, and the first two are what a lossy
link will argue with first: a nonce that expires before a fragmented reply
lands, or a cooldown that makes a lost challenge cost two minutes.

**At capacity the table refuses, it does not evict.** 256 outstanding
challenges. Evicting the oldest would be the wrong way round: a node beaconing
under many identities would displace the nonce a genuine member still owes an
answer to. Refusing costs that member a later attempt; evicting costs it the
vouch it had already earned. Nothing is persisted — the answer to a nonce
nobody is waiting on is worthless, so a restart forgetting them all is correct.

**The rate limit is a fourth book, not a tier.** 30 messages an hour per peer,
flat. The trust-tiered books cannot price this path, because it is the one
ingress path whose purpose is to run *before* any trust exists: the
unknown-peer tier is five an hour, and a real member would spend that on
beacons and routing before it could prove anything. Charged to the transport
peer rather than to `envelope.source`, so nobody can spend another node's
allowance and keep it from ever being vouched; charged on the work a stranger
asks for (answering a challenge, checking a response), while our own sending is
bounded by the cooldown instead. A blacklisted peer gets nothing: no challenge,
no answer.

That exemption from the generic limiter is also why the blacklist is checked
inside the handlers — the protocol-message exemption skips it.

**The proof book does not auto-blacklist**, unlike the two user-data books and
like the alert book, for the same shape of reason: the peer it would blacklist
is the one that may be trying to join, the blacklist is read by the other
books as well, and refusing the message already bounds the work. An hour of
silence for exceeding a 30-an-hour onboarding budget would cost a real member
far more than it costs an attacker.

**The "dedup treatment" is the budget and the nonce.** A replayed challenge is
answered again and costs the replayer a message from its budget; a replayed
response is refused by the spent nonce. No set of seen ids is kept, because
neither message carries anything worth remembering past the attempt.

**The vouch is stored before it is granted.** The database owns a vouch — the
trust graph is rebuilt from it at construction — so the write comes first and
the in-memory edge second. The other order, which is what the code it replaces
did and what every other vouch path still does, grants trust that a failed
write makes invisible: `has_vouched` then stops this node ever challenging that
peer again, and a restart drops the trust the graph claimed to hold. Failing
closed costs a legitimate member one more exchange when the cooldown is up,
which the protocol retries by itself. This is ADR-018's rule about one commit
point per piece of state, arrived at from the other end.

**No new event type.** The failure is silent and local, as decided, and the
auto-vouch it replaces emitted nothing either.

**A node that does not implement these payload types never gets vouched.** It
drops the challenge as an unknown type and answers nothing. That is the correct
outcome — it cannot prove possession — and it is a behaviour change for any
older node in a group.

### What this does not fix

- **No node is ever in a group through the app** (T-51). The onboarding screen
  writes the phrase to `SharedPreferences`; `mycelium_node_new` has no
  parameter for it, so `group_seed` is `None` and the exchange above never
  runs outside a hand-configured daemon. `derive_group_discovery_key` has no
  caller in the tree at all. This was found while implementing T-04, and it
  means the vulnerability this ADR closes was reachable only on the daemon
  path.
- **The passphrase is not stretched** (T-52). One HKDF pass, no salt, no
  iterations, with eight bytes of the key's hash in every beacon: a guessable
  phrase can be recovered offline, and the recovered key answers the challenge
  correctly. A challenge proves possession of the key; it cannot make a weak
  key strong. This is the residual risk in "a static hint that grants nothing
  by itself is acceptable" — it grants nothing, but it does verify a guess.
- **The vouch is stored unsigned** (T-53), as every local vouch is.
- **A vouch the old path granted survives the upgrade** (T-54). Vouches are
  persisted and reloaded into the trust graph at construction, so a peer
  auto-vouched on a hash match before this change stays vouched — and is not
  challenged, since `has_vouched` is what stops us challenging a peer we
  already vouch for. The stored rows cannot be told apart: a hash-match vouch
  and one the user made by hand are both unsigned and both name this node as
  voucher, which is why a safe migration needs the provenance that T-53's
  signing would give it, and why dropping all unsigned local vouches is not an
  option — that is all of them, including the in-person attestations the whole
  trust model rests on. Automatic revocation is worse: a member whose
  challenge is lost on a flaky radio would lose a vouch it had earned. Nothing
  in the tree ever sets `group_seed` (T-51), so the only database that can
  carry such a row is a hand-configured daemon's; the operator's remedy is to
  delete the vouch row.
