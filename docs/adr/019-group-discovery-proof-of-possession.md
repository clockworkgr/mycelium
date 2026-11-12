# ADR-019: Group Discovery Proof of Possession

## Status

Accepted (2026-11-12). **Implementation pending — ROADMAP T-04.**

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
