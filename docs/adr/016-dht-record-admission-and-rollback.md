# ADR-016: DHT Record Admission and Rollback Protection

## Status

Accepted (2026-11-12). **Implementation pending — ROADMAP T-38.**

## Context

ADR-011 states that a replayed older record cannot roll an address back,
because `store_record` refuses a record no newer than the one it holds. That
rule depends on *holding* the newer record, and capacity eviction throws it
away: at `max_records` (4096) the store drops whatever is closest to expiring
and admits the newcomer.

Both halves of the attack are free. A record is self-signed, and identities
cost a keypair, so a peer can fill the store with records for identities it
generates, evict a victim's current record, and then replay that victim's
older, still-fresh record. Nothing is left to compare against, so it is
accepted and lookups answer with the stale address — exactly what ADR-011
exists to prevent.

## Decision

### A mark is never evicted inside the replay window

The store keeps a `NodeId → newest published_at` table, consulted on admission
and surviving the record's eviction, so a record older than one ever held for
that id is refused whether or not that record is still present.

The table is bounded, and the rule that makes the bound safe is **what happens
when it is full**: a mark inside the replay window is never evicted. Admission
of a publisher the table has never seen is refused instead, until retention
drains it.

That ordering is the whole decision, because an identity is free. A quota per
publisher does not survive identity rotation: one attacker mints ten thousand
keypairs, publishes one record each — every one inside its own quota — and
churns both the store and any table that evicts. Protecting what is known and
refusing what is new inverts that: rotation buys the attacker nothing it could
not get by publishing honestly, and the worst it achieves is that *new*
publishers are refused while the table is full, for at most one retention
period. A denial of new entries is a far better failure than a silent rollback
of an existing one.

Marks are persisted (see the note below) and retained for the replay window, so
the table drains by itself and its size is "how many distinct publishers can be
fresh at once" rather than "how many ids exist".

### Admission is still bounded per publisher

A single publisher may occupy only a bounded share of the *record* store. This
no longer carries the rollback argument — identity rotation defeats it, as
above — but it keeps one identity from crowding out the records of peers a node
actually talks to, which is worth having on its own.

### A wildcard address is refused on admission

A record for `0.0.0.0` or `::` is refused in `store_record`, not only in the
publish path. The internet transport already declines to sign one, but a
peer's correctly signed wildcard record is admitted and served to `FindValue`,
where nothing can dial it: it occupies a slot and answers a lookup with an
address that cannot work (ADR-011's appended note). Both families need the
check, and both need a test.

## Consequences

**Easier:**

- ADR-011's rollback claim becomes true unconditionally, instead of true only
  while the current record happens to be resident — and stays true against an
  attacker who rotates identities, which no quota achieves.
- A full store is a capacity condition, not a lever: one publisher cannot
  deny the rest of the mesh its records.
- A lookup can no longer be answered with an address nothing can dial.

**Harder:**

- Two new pieces of state in the admission path, and admission ordering
  becomes: signature and binding, freshness, high-water mark, publisher quota,
  capacity. Every refusal needs its own reason and its own test.
- The quota needs a figure. Too low and a legitimate supernode publishing for
  many peers is throttled; too high and the bound is decorative. It belongs in
  the ADR that implements it, with the reasoning rather than just the number.
- A peer whose records were evicted before the mark table existed keeps no
  protection for ids it has forgotten. The marks are a high-water record, not
  history, so the protection is only as old as the table's retention.
- When the table is full, a publisher the node has never seen cannot be
  admitted at all until retention drains it. That is the chosen failure
  direction, and it is a real denial: a legitimate new peer joining a mesh
  under attack waits.

## Alternatives Considered

1. **Per-publisher quota as the rollback defence.** This was the first version
   of this decision and it is wrong: a publisher is an identity, identities are
   free, so an attacker rotates keypairs and stays inside every quota while
   churning the store and any evictable table. The quota survives here only as
   a fairness measure.
2. **High-water marks that evict like any cache.** Directly enforces "no older
   record ever wins" until the table is full, at which point it inherits the
   attack it was meant to stop. Refusing new entries instead is what makes the
   bound mean something.
3. **Admit only addresses we have dialled successfully.** The strongest rule,
   and it changes what the DHT is for: a node behind NAT could no longer
   publish, which is most of the point of T-31 and T-33.
4. **Raise the capacity.** Postpones the attack by a constant and keeps the
   defect.

## Note (2026-11-12)

This record left open how long a high-water mark survives, and said the quota
figure belonged to the implementing commit.

**The marks are persisted in SQLCipher**, with a retention sweep, so rollback
protection survives a restart for as long as retention keeps it. The
alternatives were in-memory marks — which reset on every restart, and on a
phone the daemon stops whenever the OS decides, so the protection would rarely
be older than a few hours — and marks kept only while a record, route or
contact for that id exists, which drops protection silently for an id that
falls out of all three.

**The marks are persisted, and the admission order is fixed:** signature and
NodeId binding, freshness, wildcard address, high-water mark, publisher quota,
capacity. Each refusal gets its own reason and its own test.

**Three questions this record does not settle, found by reviewing it against
the code and against ADR-013.** They belong to the implementing task, and are
written here so they are not discovered again as surprises.

1. **Saturation can deny new publishers indefinitely.** Marks are retained for
   the replay window and refreshed by each new record, so an attacker holding
   admitted identities can keep refreshing them and the table never drains —
   first-seen publishers are refused for as long as that continues. The
   "refuse the unseen" rule bounds rollback at the price of an unbounded
   denial, and that trade needs an answer: a share of the table reserved for
   first-seen publishers, eviction of the least recently refreshed mark whose
   record is not resident (reopening rollback for a publisher nobody has heard
   from in a retention period), or something else. Tests must cover sustained
   renewals past one retention period, not just a single burst.

2. **The quota has no defined principal.** The store already holds at most one
   record per signing NodeId, so a quota per *signer* is vacuous, and
   `store_record` receives no authenticated identity for whoever *delivered*
   the record. An uploader quota therefore needs attribution the function does
   not have today — the authenticated peer is known one layer out, at the
   channel ADR-011 proves, so it would have to be passed in, and records
   learned from a lookup answer attributed to the peer that answered.
   Replacements and evictions need the same treatment or the accounting
   drifts. Until that is specified the quota is not implementable as written.

3. **Retention is measured from the wrong clock.** "Outlives the record" is not
   enough: after a mark is swept, a backward wall-clock correction can make an
   older signed record fresh again, and a restart does the same if marks are
   not loaded. ADR-013 hit exactly this and its answer applies — measure
   retention against the record's *signed* expiry
   (`published_at + record_ttl`), keep it past that by a clock-regression
   grace, and state the residual. Sweep, rollback and restart each need a
   test.

**The quota and the retention period are shapes, not numbers, in this record.**
They are to be set against the testbed (ROADMAP T-19) or hardware (T-15): too
low a quota throttles a supernode publishing for many peers, too high and the
bound is decorative, and both depend on how many peers a real deployment
carries. What must hold whatever the figures are: no single publisher can
occupy enough of the store to force eviction, and a mark outlives the record it
guards.
