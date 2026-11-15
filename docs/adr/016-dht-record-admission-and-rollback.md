# ADR-016: DHT Record Admission and Rollback Protection

## Status

Accepted (2026-11-12). **Implemented 2026-11-15 — ROADMAP T-38.**

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

## Note (2026-11-15) — implemented, with three decisions this record left open

Implemented as ROADMAP T-38. The three questions the 2026-11-12 note handed to
the implementing task are answered below, and two claims in the Decision
section above are now narrower than they read. Appended rather than edited,
because these records are append-only; the Status line is the one exception,
and it is flipped by the commit that implements the record.

### 1. Saturation: a share of the table is reserved, so the unseen are never refused

The Decision above says "admission of a publisher the table has never seen is
refused instead, until retention drains it". **That is no longer what the code
does, and the note's own first open question is why.** An attacker holding
admitted identities can refresh them forever, so the table never drains and a
legitimate new publisher is refused for as long as that continues — an
unbounded denial traded for a bounded rollback.

The table now has two regions:

- **Established** — publishers seen continuously for at least `graduation_age`.
  Never evicted inside the replay window; dropped only by the retention sweep,
  once the record they guard can no longer be fresh.
- **Probationary** — everything newer, evicted least-recently-refreshed first.
  `mark_first_seen_reserve` is a **floor** on how many of these a full table
  holds, not a ceiling: establishment is capped at
  `mark_capacity - mark_first_seen_reserve`, so a full table always contains at
  least that many probationary marks for a newcomer to evict. Nothing bounds
  them from above, and before anything has graduated the whole table is
  probationary.

A first-seen publisher is therefore **always admitted**: the probationary region
makes room from its own entries and never touches an established mark. An
attacker minting identities churns only that slice.

**The price, stated plainly, because the sentence above is what a reader would
otherwise rely on: a probationary mark *is* evicted inside the replay window.**
A publisher that has not yet graduated can have its mark evicted by enough
first-seen publishers, and with its record already gone the replay then lands
and the stale address is served — the exact outcome this record exists to
prevent, for publishers seen recently and briefly. It is pinned by
`test_a_probationary_mark_evicted_in_its_window_loses_its_protection`, which
asserts the gap rather than the guarantee, so a later change claiming to close
it has something to flip.

**A third exception, from configuration rather than from attack.** Restoration
chooses which marks the table takes, so lowering `mark_capacity` or raising
`mark_first_seen_reserve` between runs demotes established marks beyond the new
`protected_capacity`, and marks beyond the new capacity are reconciled away as
orphans — both inside the replay window. "Never evicted" is a statement about
steady-state operation under a fixed configuration, not about a restart that
shrinks the table. Changing these figures downward forfeits protection for
whatever no longer fits, which is worth knowing before tuning them on a
constrained device.

The second residual is the mirror image: an attacker that *maintains* identities
across a full `graduation_age` graduates them and can fill the established
region. New publishers are still admitted — they are never refused — but they
can no longer graduate, so their protection lasts only as long as they hold a
probationary slot. A far higher bar than churning a cache, bounded, and not
closed.

### 2. The quota's principal: the authenticated delivering peer

The note said the quota "is not implementable as written" because
`store_record` receives no authenticated identity. That is true of the function
and false of the system: the authenticated peer exists one layer out and was
simply not passed in. `store_record` now takes a `RecordSource`:

- `Local` — our own record, exempt. Refusing to publish ourselves because peers
  filled the store would be self-defeating.
- `Peer(NodeId)` from a `Store` request — the peer the transport authenticated,
  captured before `add_peer` consumes it.
- `Peer(NodeId)` from a lookup answer — the peer that answered. The spawned
  task used to return only the reply and drop the peer; it now carries both.

**Counted by scanning, deliberately.** Each held record keeps the peer that
delivered it, and the bound is checked by counting matching entries rather than
by maintaining a counter map. This record warned that "replacements and
evictions need the same treatment or the accounting drifts"; a scan over at most
`max_records` entries cannot drift. A replacement from the *same* peer is exempt
because it does not grow that peer's share; one from a different peer is not,
because it moves a slot between peers. Without that exemption the bound would
stop peers republishing and the records would simply expire.

### 3. Retention is measured from the signed expiry

As the note required, and as ADR-013 answered the same question: a mark is kept
while `now <= published_at + record_ttl_secs + mark_retention_grace_secs`, in
one predicate (`MarkTable::retains`) used by both the sweep and restoration, so
the two cannot drift apart on it. `graduation_age` is that whole window —
`record_ttl_secs + mark_retention_grace_secs` — derived rather than configured,
so there is no second figure to get wrong.

The residual this record already names stands: once a mark is swept there is
nothing left to compare against, so protection is only as old as retention.

### The figures, and what they are measured against

| Constant | Default | Basis |
|---|---|---|
| `mark_capacity` | 8192 | Twice `max_records` (4096), so the table can remember every publisher whose record could be resident and the same number again that have been evicted. |
| `mark_first_seen_reserve` | 512 | 1/16 of the table. Large enough that first-seen admission is never the bottleneck; small enough that an identity-churning attacker cannot reach the established region. |
| `mark_retention_grace_secs` | 86 400 | One day past the signed expiry, so a backward wall-clock correction smaller than a day cannot make an expired record fresh again. Also sets `graduation_age` to 25 hours. |
| `max_records_per_peer` | 256 | 1/16 of `max_records`, so sixteen peers would be needed to fill the store. |
| `mark_write_queue` | 1024 | Deep enough to absorb a burst of admissions without a durable write being dropped, bounded so a stalled backend cannot grow memory. |

These are shapes with starting values, exactly as this record said they would
be. They are to be measured against the testbed (ROADMAP T-19) or hardware
(T-15). What holds whatever the figures are: no single publisher can occupy
enough of the store to force eviction, and a mark outlives the record it guards.

### Where the state lives

A narrow `MarkStore` trait in `mycelium-core` (`load`, a monotonic `put`, a
conditional `remove_not_newer`), the `dht_marks` table and its SQL in
`mycelium-storage`, and the async bridge between them in `mycelium-node`. Core
stays storage-agnostic, which is what lets its own tests exercise every capacity
rule against an in-memory table.

**Two durable operations, both conditional, neither a delta.** Admission holds
the mark lock across no awaits, but a write handed to a thread can outlive the
caller that asked for it and two writes can land out of order:

- `put` writes the caller's whole mark, unless the stored `newest_published_at`
  is newer than the one being written.
- `remove_not_newer` deletes an id only while the stored mark is no newer than
  the one the caller saw, so a sweep whose write lands after a refresh cannot
  delete a live mark.

Each is a single SQL statement, so the condition and the write cannot come
apart.

**A merging write was tried first and was wrong.** Combining the incoming mark
with the stored one field by field — greater watermark, earlier `first_seen`,
establishment never un-set — tolerates reordering just as well, and makes every
write a delta that can never correct anything. Two defects followed from that,
and both were found by reviewing this record against the code:

1. Retention ends a publisher's lifetime. If it republishes, a merge carries the
   old lifetime's `first_seen` and `established` into the new one, so a restart
   restores an established publisher where the table holds a probationary one —
   establishment it never re-earned. An identity could bank it, fall silent past
   the whole replay window, republish, and come back protected.
2. Restoration demotes established marks beyond the protected region (see the
   configuration exception above), and a merge can never persist a demotion, so
   the demoted publisher was promoted again at the next start and a previously
   protected one demoted in its place.

Writing the whole mark, conditional on not going backwards, covers both and is
also self-correcting: a write that is lost costs nothing the publisher's next
record does not restore. An equal watermark writes, because a mark can be
evicted and the very same record re-admitted — neither stale nor a rollback,
since the mark and the record went together — and that is a new lifetime at an
unchanged timestamp.

An implementation that writes or deletes *unconditionally* is still wrong, and
will pass the obvious tests.

Writes are **queued** to a single writer task rather than awaited on the
admission path. Awaiting storage there meant three separate failures: a
cancelled admission could skip the write for a record it had already installed,
a stalled backend held the mark lock and with it every `Store` RPC, and
out-of-order writes could undo protection. Queue order is lock order, because
every send happens under the mark lock.

A deletion is never applied to an id the table holds — decided when the delete
runs, not when it was queued, because adoption and deferred retries both put an
id back without a write to order against.

**That check, and the whole contract, are properties of the engine's writer, not
of the backend.** The writer awaits each call before taking the next, so writes
reach storage in the order they were issued; two writes carrying the same
watermark both apply, and only that order decides which wins. A `MarkStore`
therefore serves **one** engine. Two engines over one backend have two writers
and no ordering between them, and the invariants above do not hold across them:
one engine's eviction can land after the other's restoration and erase a mark it
had adopted, and a deletion filtered against one engine's table says nothing
about the other's.

The embedder is what keeps that true, and only partly can. The node builds one
engine; the FFI refuses to register a second internet transport rather than
replace the first, because a replacement cannot be made safe without the old
engine being provably quiet, and the transport's `stop()` does not give that —
its connection drain is bounded and only warns, so a stuck handler can still be
admitting records when `stop()` returns. Freeing an FFI node handle drains the
mark writer before the engine goes with it, so the ordinary
free-then-recreate sequence starts clean.

**What nothing here enforces is that one engine owns a *database*.** Two node
handles over one database file are two engines, and `mycelium_node_new` does
not refuse the second; neither could it stop a second process opening the same
file. A drain that times out on the way out therefore leaves the hazard open.
Closing it properly means the deletion condition not resting on the watermark
alone — a revision the sweep must still match, so a row written by anyone since
is spared — which is a column and a migration. ROADMAP T-46 carries both that
and the replacement case.

### What the stored `established` flag means

Restoration demotes established marks beyond the protected region, and that
demotion is **not written back**. The stored flag therefore means "was
established when last written", not "is established now", and if capacity is
later raised those publishers load as established again without refreshing.

That is deliberate, and the alternative is worse. Writing demotions back means
restoration issuing writes, which this design has twice removed for good
reasons; and the other way to keep memory and storage in step — dropping the
excess established marks instead of demoting them — would delete rollback
protection inside the replay window rather than merely making it evictable.
Demotion is the better behaviour and this inconsistency is its price.

It is not a shortcut into the protected region: a row can only say `established`
if some earlier run granted it, which took a full graduation window of
continuous presence. What it does mean is that after a capacity reduction, which
publishers hold the protected region is stable but unrelated to their recent
behaviour, because `adopt` takes established marks first and the losers keep
competing at every start.

### Admission order, and two preconditions

Signature and NodeId binding, future timestamp, expiry, wildcard address, then —
under the mark lock — staleness against the resident record, the high-water
mark, the per-peer quota, and capacity. Each refusal has its own reason and its
own test.

Two preconditions sit before that order rather than in it, and both **fail
closed**:

- **The marks must have been read.** Admission restores them itself rather than
  trusting the embedder to have called `restore_marks` first, because dialling
  does not require `start()` — `connect_to` installs a read loop that serves
  `Store` requests, so records would otherwise be admitted against an empty
  table.
- **The marks must be readable.** An unreadable backend is refused
  (`MarksUnavailable`), not treated as an empty table. Flattening the two would
  make a storage error accept every replay the database could have refused.
  Retried on every admission, so the denial lasts exactly as long as the fault.

This is the direction this record already chose: a denial of new entries is a
far better failure than a silent rollback of an existing one.

### One residual deferred rather than fixed

A deletion that cannot be queued is remembered for retry in a bounded list, and
when that list overflows the oldest entries are dropped — leaving durable rows
that nothing in memory points at until the next restart reconciles them.

Two routes reach it, and the first analysis of this missed the second. Row by
row it is narrow: rows and deletions are produced in pairs, and under queue
saturation both are lost, so the store does not grow — growth needs the queue to
reject a deletion and then accept the write issued immediately after it,
repeatedly. **In bulk it is not narrow at all:** the retention sweep returns
every expired mark at once, so a single failed sweep carrying more than 4096
deletions overflows the list in one step and discards the surplus immediately.
On a node that has tracked many publishers, that is one bad moment rather than
thousands.

Closing it properly means on-demand reconciliation, which is new state in the
part of this design that has produced every defect found while implementing it.
It is ROADMAP work (T-44), not a silent gap.

### A second residual: a mark update is best effort, and the watermark can regress

The note above says a mark is never lowered. That is true of the table in
memory and **not quite true of the durable row**. A mark write that cannot be
queued — the writer's bounded queue full — is discarded rather than retried,
on the stated reasoning that a lost write is rewritten by the publisher's next
record. Within a run that holds, because the table in memory is already
correct. Across a restart it does not: the restored watermark is the last one
that reached storage, which can be lower than the one the previous run held.

A replay dated between those two values is then accepted, until the publisher's
next record — within one TTL — carries the watermark forward again.

**Three things lose a write, not one.** The first analysis of this named only a
saturated queue, which is the rarest of them:

1. The queue is full, so the write is never queued.
2. The backend refuses it. The error is logged and the write discarded, and a
   later flush still reports success, because the queue did drain.
3. The process ends without an orderly stop — which on a phone is the ordinary
   case, not the exceptional one, since the OS kills the app whenever it
   chooses. Everything still queued is lost, and `stop()`'s drain is exactly
   what does not run.

(3) is the one that matters in practice, and it is also the reason the marks are
persisted at all: ADR-016 chose durability because a phone daemon rarely lives
long. The same abruptness that makes in-memory marks useless also costs the
last few queued writes. What survives is every write the writer had reached,
which under normal load is all but the most recent.

Deletions *are* retried, and the asymmetry is deliberate: a lost write leaves
the memory table correct and something that will rewrite it, while a lost
deletion leaves a durable row with nothing in memory left to re-issue it. The
price of that choice is the regression above, and it is written here rather
than left for a reader to infer from "never lowered".

### A fourth residual: equal timestamps do not distinguish addresses

The rollback check refuses a record **strictly older** than the mark, and that
strictness is deliberate: a node that lost a record to capacity eviction has to
be able to re-learn the very record the mark was set from, and refusing an equal
timestamp would make a peer's current address unlearnable.

The cost is that the mark remembers *when*, not *what*. A publisher that signed
two records with the same `published_at` and **different addresses** has no
protection between them: once the record is evicted, either one is admissible,
and an attacker holding the other can install it and have it served. The mark
survives, and does not help.

Nothing in this implementation signs two addresses in one second —
`store_self` publishes one address per re-sign, every TTL/3 — so reaching this
needs a publisher that double-signed within a second, whether by a restart onto
a different port inside that second or by its own choice. It is narrow, and it
is a genuine hole in the unconditional claim rather than a theoretical one.

Closing it means remembering the record as well as the timestamp: a digest
beside the watermark, with an equal timestamp admissible only for the same
record. That is a column, a migration and a wider `Mark`, which is why it is
ROADMAP T-45 rather than part of this change.
