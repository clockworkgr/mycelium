# ADR-023: FFI Re-entrancy, Handle Ownership and the Live Display Name

## Status

Accepted (2026-11-16). **Implemented — ROADMAP T-01.**

## Context

ADR-018 decided what happens when an FFI function panics. T-01 names three more
defects at the same boundary that ADR-018 does not cover, and each needs a
decision that changes the C contract rather than only the Rust:

1. **Re-entrancy.** 49 call sites in 46 of the 64 exported functions call
   `runtime().block_on`, with nothing stopping a call from a thread that is
   already driving that runtime. T-01 described the symptom as a deadlock.
   Measured on tokio 1.50 with the multi-thread runtime this library builds, it
   is a panic — `Cannot start a runtime from within a runtime` — which before
   ADR-018's guard took the process down. The one in-process caller that can
   reach it is the callback registered by `mycelium_set_message_callback`,
   which runs on a spawned task.

2. **Handle ownership.** The handle was `Box::into_raw`, with the pointer also
   kept in a static `AtomicPtr` so the Dart layer could recover it after a
   Flutter engine restart. `mycelium_node_get_existing` therefore handed out a
   *borrowed* copy that the next `mycelium_node_free` turned into a dangling
   pointer, and `mycelium_api_handle_status` dereferenced the static with no
   ownership at all.

3. **`mycelium_set_node_display_name`.** It validated its argument, logged it
   and returned 0 without renaming anything, because `NodeConfig` is immutable
   after construction and the beacon task cloned `display_name` once before its
   loop. Every caller was told a rename had happened that had not.

## Decision

### Re-entrancy is refused, not accommodated

A blocking function called from a thread inside the runtime refuses the call
and does nothing else. The check runs before the body, so a refusal cannot
half-complete; the reason goes to `LAST_ERROR` naming the function.

The refusal is reported as the failure value for the function's own return
shape, like a caught panic, because that is the only channel a C signature
gives: `MYCELIUM_ERR_REENTRANT` (`-98`) from the 42 blocking functions that
return `i32`, `false` from `mycelium_node_start`, `-1.0` from
`mycelium_trust_score`, and nothing at all from `mycelium_node_stop` and
`mycelium_node_free`. Only the stored message distinguishes a refusal from a
panic in those four, which is the same limit ADR-018 accepts for its sentinels
and the reason the message names the function.

One refusal has a consequence beyond the return value: `mycelium_node_free`
blocks, because it drains the DHT mark writer (ADR-016). A refused free has
**not** released its reference, so the caller still owns the handle and must
free it from a thread outside the runtime. Leaking a reference is the right
outcome of the two available: dropping a node whose marks were never drained
is what ADR-016's drain exists to prevent.

The test is `tokio::runtime::Handle::try_current().is_ok()`, and it answers a
wider question than the one being asked. Blocking is legal inside
`spawn_blocking` and inside `block_in_place`, and measurement says tokio
exposes nothing that separates those from a future:

| context | `Handle::try_current()` | `task::try_id()` | nested `block_on` |
|---|---|---|---|
| plain / foreign thread | false | None | works |
| inside a future | true | None | **panics** |
| inside `spawn_blocking` | true | Some | works |
| inside `block_in_place` | true | None | works |

The future case and the `block_in_place` case are identical through every
public API and disagree in behaviour. So the refusal is deliberately
conservative: it also refuses two contexts where the call would have worked,
neither of which anything in this repository uses. A refusal is reported and
recoverable; the panic was neither. ADR-018's `catch_unwind` stays underneath
as the backstop for any context this prediction gets wrong.

Making the call *work* was the alternative, and it is available:
`block_in_place` makes blocking legal on a worker thread, and the nested
`block_on` then succeeds. It was rejected because it rewards a caller for doing
the thing its own documentation forbids, hides a worker-thread stall inside an
FFI call, and leaves the deadlock that re-entrancy really risks — a callback
that blocks on a lock its own caller holds — untouched and unreported.

### Every handle is an owning reference

The handle becomes `Arc::into_raw`. Every pointer this library returns — from
`mycelium_node_new` and from each `mycelium_node_get_existing` — is one
reference, and each must reach `mycelium_node_free` exactly once. The node is
destroyed when the last reference goes, so freeing one handle no longer
invalidates another. All handles to one node are the same address, because
`Arc::into_raw` points at the value rather than at a per-handle box, so
pointer comparison still identifies the node.

`mycelium_node_free` also unregisters the node: the registry stops handing out
references to something the caller has finished with, and its own reference is
released. The ADR-016 mark drain runs on **every** free rather than only on the
last reference, because "am I the last?" is a race that two concurrent frees
can both lose — and losing it loses the rollback protection the drain exists to
preserve. The drain is idempotent and bounded, so running it more than once
costs a bounded wait and nothing else.

The registry becomes `Mutex<Option<Arc<_>>>` and recovers from poisoning
rather than propagating it. What it guards is one `Option<Arc<_>>` that no
panic can leave half-written, and propagating a poison would convert a single
caught panic into an FFI that can never create or recover a node again — the
crash-to-wedge trade ADR-018 set out to avoid, arriving by another door.

### The display name becomes live state on the node

`Node` holds `display_name` behind a `std::sync::RwLock`, initialised from the
config. The beacon task reads it on each tick and `GET /v1/node/status` reads
it per request, so a rename reaches the mesh and the API together.
`NodeConfig::display_name` is the configured *initial* value and nothing reads
it after construction.

A synchronous lock, not tokio's: the setter is reached from the FFI, which must
not need the async runtime to rename a node — needing it would put the rename
behind the re-entrancy refusal above for no reason. No reader holds the guard
across an await.

A name longer than a beacon can carry is truncated on the wire, not refused.
The beacon's name field is length-prefixed with a single byte, so 255 bytes is
the limit, and truncation lands on a character boundary — cutting a multi-byte
sequence would put a replacement character on the end of the name every peer
displays, because the receiver decodes lossily. The consequence is a visible
divergence: the mesh shows the truncated name while `GET /v1/node/status`
reports the whole one. Accepted rather than validated, because
`mycelium_node_new` and the config file accept the same names, and a setter
stricter than the constructor would be the surprising one. (The byte-slice
truncation this replaced was a pre-existing defect in the beacon encoder, not
something the setter introduced; the setter is a new way to reach it.)

An empty rename is refused, which is the one case where the divergence above
would be total rather than a tail: a beacon's empty name field means "no
information" to a receiver, which keeps the name it already has, so accepting
an empty name would change what the API reports and nothing else, for good.
`mycelium_node_new` still accepts one, because a peer meeting this node for the
first time has no previous name to keep.

The rename is **not persisted**. The name arrives as an argument to
`mycelium_node_new` (or from the daemon's config) on every start, so the only
way to make a rename outlive the process today is to pass the new one there.
The alternative — writing it to the `config` table — was left out because it
would make the stored name authoritative over both the config file and the
constructor argument, and that precedence question deserves its own decision.

### A start and a stop do not interleave

Each transition moves several pieces of state — the `started` flag, the node's
own tasks, the API server's handle — and an interleaving leaves them
disagreeing: a start that reaches the API server just after a stop took its
handle leaves a server answering for a node being torn down. `mycelium_node_start`
and `mycelium_node_stop` therefore hold one lock for their whole duration, so
each completes before the other begins. It also subsumes the narrower case of
two concurrent starts both binding the API port.

This is a blocking lock held across a `block_on`, which is sound here because
both functions already block by contract and nothing else takes it. Both are
refused from a runtime thread anyway (above), so the lock is only ever held by
a caller that is allowed to block.

### A stopped node is finished, and the FFI says so

`Node::stop` cancels a `CancellationToken` that nothing resets, so a node that
has been stopped cannot be started again: `Node::start` would spawn tasks that
exit immediately and return `Ok`, and the FFI would report a successful start
of a node that is not running. `mycelium_node_start` therefore refuses a
stopped node with `false` and a message, before touching the started flag or
the API server.

That makes a real limitation visible rather than fixing it, and the way back —
a fresh handle over the same data directory — is a second DHT engine over the
same database, which is ROADMAP T-46's hazard. Nothing in the app calls
`mycelium_node_stop` today, so the limitation is latent; what matters is that
it now fails loudly rather than quietly.

## Consequences

**Easier:**

- A re-entrant call fails in a way the app can show and the developer can fix,
  instead of taking the process down.
- A handle recovered after a Flutter engine restart is safe to use and safe to
  free, in either order, and `api_handle_status` no longer races a free.
- Renaming a node works, and there is one answer to "what is this node called"
  rather than two that can disagree.

**Harder:**

- Callers must free every handle they obtain, including each one from
  `mycelium_node_get_existing`. A caller that leaks one keeps the node alive
  for the life of the process. The Dart layer takes exactly one reference per
  engine and frees it in `dispose`.
- **A Flutter engine that is killed rather than disposed leaks its reference,
  and nothing can reclaim it.** A new engine recovers a fresh reference, so
  each teardown that skips `dispose` adds one that no caller holds. The leak
  is deliberate, because the alternative is worse: freeing on engine teardown
  would *unregister* the node, and the next engine would then build a second
  node over the same data directory — two DHT engines with no ordering between
  their mark writers, which is the hazard ROADMAP T-46 exists for. What a
  stranded reference keeps alive is also smaller than it looks: the API server
  task holds its own `Arc<Node>`, so the node, its database and its tasks
  already outlive `mycelium_node_free` until `mycelium_node_stop` shuts the
  server down. The stranded reference keeps the thin handle struct and the
  counter. Nothing in the app calls `MyceliumService.dispose()` today, so the
  case is latent rather than live.
- The refusal is coarser than the hazard: an FFI call from a `spawn_blocking`
  thread is refused although it would have worked.
- A rename is lost on restart, silently, unless the caller also changes what it
  passes to `mycelium_node_new`.
- `Node` now has a field the config no longer governs after construction, which
  is one more place where "configured" and "current" can be confused.

## Alternatives Considered

1. **Let `block_in_place` make the nested `block_on` work.** Rejected above:
   it hides the stall and leaves the real deadlock unreported.
2. **Refuse every FFI call from a runtime thread, not only the blocking ones.**
   Simpler and uniform, and it would break `mycelium_last_error` and
   `mycelium_clear_error` from inside a message callback, which is exactly
   where a caller needs them.
3. **Keep the raw handle and make `node_get_existing` return a borrowed
   pointer, documented as not-to-be-freed.** That is the status quo with a
   comment; the ownership question is precisely what the Dart layer got wrong.
4. **A handle table with generation counters, so a stale handle is detected
   rather than being undefined behaviour.** Strictly better against a caller
   that frees twice, and it costs a lookup on every call plus a table whose
   size nothing bounds. Reference counting fixes the defect T-01 names; double
   frees remain the caller's contract, as they were with `Box`.
5. **Return a distinct "unsupported at runtime" code from
   `set_node_display_name`,** which T-01 allowed. Rejected because the
   interior mutability it needed turned out to be one lock and two call sites,
   and a permanent "this does not work" in a shipped ABI is worse than the
   work it saves.
