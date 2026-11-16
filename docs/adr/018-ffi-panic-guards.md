# ADR-018: Panic Guards at the FFI Boundary

## Status

Accepted (2026-11-12). **Implemented — ROADMAP T-01.**

## Context

`mycelium-ffi` exposes 64 `extern "C"` functions to Dart, and the workspace
contains no `catch_unwind` at all. A panic in any of them unwinds across the
FFI boundary, which is undefined behaviour: in practice the app aborts, and the
user loses whatever the node was doing — a handshake, a flood, a queued
message — with no diagnostic beyond a native crash.

The crate already has the machinery to report a failure. There is a
thread-local `LAST_ERROR`, `mycelium_last_error(out_buf, buf_len)` to read it
and `mycelium_clear_error()` to reset it, and the functions already return
`i32` codes or pointers. What is missing is the guard.

## Decision

Every `extern "C"` function is wrapped in `catch_unwind` by a macro — one
wrapper, applied uniformly, rather than 64 hand-written ones that will drift.
On a panic the guard stores the payload's message in `LAST_ERROR` and returns
the failure value for that signature: a negative code for `i32`, null for a
pointer, false for a bool. Dart then sees the same error shape it already
handles, and can read the message through `mycelium_last_error`.

**The process is not aborted.** Aborting is defensible — a panic means an
invariant broke, and continuing means acting on state nobody vouches for — but
on a mesh messenger the cost is concrete: the daemon dies mid-handshake, the
user's session state is whatever survived, and the user is told nothing. A
returned error is something the app can show and the user can retry; the panic
is still a bug, and the stored message is what makes it reportable instead of
invisible.

A middle course — sentinel for input-validation panics, abort for a poisoned
lock or known-inconsistent state — was rejected for now: it requires a
judgment per call site about which class a panic belongs to, and that judgment
is exactly the thing most likely to be wrong in a crate whose job is to not
trust its inputs.

## Consequences

**Easier:**

- Bad input from Dart cannot take the process down, and the reason reaches the
  app rather than a crash log.
- One macro to audit, and a new extern function that forgets the guard is a
  visible omission rather than a silent one.

**Harder:**

- A panic now leaves whatever invariant it broke in place, reachable by the
  next call. The guard converts a crash into a possibly-corrupt state, so a
  panic must still be treated as a defect to fix, not a handled condition.
- `catch_unwind` requires the closure's captures to be unwind-safe, so some
  handles will need `AssertUnwindSafe` with a reason, which is a place to hide
  a real aliasing problem.
- A guard that is never exercised is not a guard: the sentinels have to be
  tested per return shape, which means deliberately panicking across the
  boundary in tests.

## Alternatives Considered

1. **Catch, report, then abort.** Safest against acting on corrupt state, and
   it turns every input bug into a lost session with no message to the user.
2. **Classify panics and abort only on poisoned state.** Most precise; the
   classification is the fragile part.
3. **Guard only the functions taking pointers or buffers.** Covers the obvious
   panics and leaves the rest unguarded, which is the status quo with extra
   steps.
4. **`panic = "abort"` for the cdylib.** Removes the undefined behaviour
   without any wrapper, and gives up the ability to report anything.

---

## Note, 2026-11-16 (implemented, T-01)

Implemented as decided: one macro, `catch_unwind` in every exported body, the
message in `LAST_ERROR`, a failure value per signature, and no abort. Nine
things the decision did not anticipate, in the order they mattered. Four of
them are ways the guard could have aborted through its own machinery rather
than through the body — the recovery path, the payload's destructor, installing
the panic hook, and logging the panic it caught — which is the pattern worth
carrying to the next boundary: everything a guard touches once a panic is in
flight has to be incapable of panicking, and "it logs" is not an exception.

**The boundary is no longer undefined behaviour — it is a defined abort.** The
Context above says a panic unwinding out of an `extern "C"` function is
undefined behaviour. On current compilers (checked on rustc 1.92) it is not:
the compiler emits an abort shim, and an unguarded panic ends with
`thread caused non-unwinding panic. aborting.` and SIGABRT. Verified by
removing the guard from one test fixture and watching the test binary die on
signal 6. The decision stands unchanged — the app still vanishes with no
diagnostic, which is the cost the guard removes — but the reason to guard is
the lost session and the lost message, not UB.

**Two return shapes were missing.** The decision names `i32`, pointer and
`bool`. The 64 functions are 56 `i32`, 4 `void`, 2 pointer, 1 `bool` and 1
`f32` (`mycelium_trust_score`). `f32`'s failure value is `-1.0`, which is what
that function already documented for an error; a `void` function has no return
channel at all, so its only report is the stored message. The rule lives in one
trait with one implementation per shape, which is how the gap was found:
writing it down once made the two missing cases impossible to skip.

**A guard that records a panic can panic.** `store_caught_panic` runs *after*
`catch_unwind` has handed the payload back, so a panic raised inside it unwinds
out of the guard and across the boundary — the abort the guard exists to
prevent, reintroduced by the guard. The accessors it uses are therefore
non-panicking: `try_with` for a thread whose thread-locals are already
destroyed, `try_borrow_mut` rather than `borrow_mut`. The `RefCell` case is
belt-and-braces (unwinding has already dropped the frames that held the borrow,
as `test_a_panic_with_the_error_cell_borrowed_still_records_a_message`
confirms), but a recovery path is the wrong place to depend on that reasoning
staying true. The same applies to every lock in the crate: a caught panic can
poison one, so each recovers from poisoning instead of propagating it. A guard
that converted a crash into a permanently wedged FFI would be no improvement.

**The stored message carries a location, because nothing else will.** The
payload has the message but not the file and line, and on Android the default
hook's stderr report goes nowhere — `tracing-android` → logcat is the only
channel the app has. So a hook is installed once, chained in front of whatever
was there (the test harness's, in tests), recording `file:line` in a
thread-local for the guard to prepend. Each message reads
`panic in <function> at <file>:<line>: <payload>`, and the guard logs it
through `tracing` after catching it — not from the hook, for the reason two
paragraphs below.

**The payload is the one thing that can still cross the boundary.** It is
disposed of *after* `catch_unwind` has returned, so a `Drop` implementation
that panics there unwinds out of the guard and aborts — the guard defeated
through its own recovery path. `panic!` produces a `&'static str` or a
`String`, neither of which can panic on drop; anything else arrived through
`panic_any` with a destructor this crate knows nothing about, and is leaked
instead. Memory lost once per panic is the cheaper of the two failures, and a
panic is already a defect to fix.
`test_a_panic_payload_with_a_hostile_destructor_does_not_escape` aborts the
test binary without this (verified), which is also the clearest statement of
what the guarantee is worth: the boundary holds for *any* panic, not only for
the well-behaved ones.

**Installing the hook is itself a boundary crossing.** `take_hook` and
`set_hook` both panic when called from a thread that is already unwinding, and
a panic raised during unwinding aborts immediately and uncatchably — from the
function whose only job is to prevent that. The reachable shape is a Rust
destructor that calls into this library as the stack unwinds past it. So
installation is skipped entirely while `thread::panicking()`, outside the
`Once` so that what is lost is this one panic's location rather than every
later one. The test re-runs itself in a child process, because the `Once` is
process-global and any earlier guarded call would hide the defect; without the
check the child dies on SIGABRT (verified).

**Logging the panic has no safe place inside the hook.** A subscriber is
arbitrary code, and the hook runs while the thread is unwinding, where a second
panic aborts before any `catch_unwind` sees it. So the log happens in
`store_caught_panic`, after the catch, inside its own `catch_unwind`. Logging
only *unguarded* panics from the hook was tried, to keep a diagnostic for the
spawned tasks nobody joins, and it is worse than it looks: a subscriber that
panics is then reported *through that same subscriber*, and the recursion
aborts. That was measured, not reasoned about — the test with a deliberately
panicking subscriber failed exactly that way, having passed the design
review. What leaving it out costs is that a panic in a spawned task still
reaches no diagnostic on Android, which is where it was before and is not what
T-01 is about.

**A caught panic can leave a flag that outlives the thing it describes.**
`mycelium_node_start` sets `started` before it starts anything, and a second
start is a deliberate no-op. The error paths reset it by hand; the panic path
is a third way out that the hand-written resets did not cover, so the flag
would say "running" while nothing ran and every retry would answer success.
It is now an RAII reset armed immediately after the flag is taken and disarmed
the moment `Node::start` returns `Ok` — **not** at the end of the function,
which is where it went first and was wrong: by then the event loop, the beacon
and the transports are live, so a panic in the API-server phase would have
reset the flag and offered the caller a *second* `Node::start`, which
duplicates all three. Worse than the stuck flag the reset exists to prevent,
and found by the ADR review, not by the code review that had passed it. The
API server's own shutdown handle is likewise stored before anything logs about
it, since dropping it would leave the task running and the port bound with
nothing able to reach it.

That fix was still half of one. Committing the flag at `Ok` and nothing else
left a third state reachable: the node live, the API server unstarted, and
every retry answering "already started" — a running node the Flutter app, which
talks to it only through that server, could never reach again. So starting the
API server became its own idempotent step that *every* start attempt passes
through, including the duplicate-start path, serialized by the lifecycle lock
both call sites hold so two concurrent starts cannot both bind the port. The
general shape, arrived at over three attempts: **one commit point per piece of
state that can independently be true, each as late as the truth allows and no
later, and every entry point re-checks the ones it does not own.**

The stop path needed the opposite treatment, and shows the limit of flag
discipline. `Node::stop` logs, then cancels every task, then drains the
transports: a panic before the cancellation leaves the node running, one after
it leaves the node finished, and the correct value of the flag differs between
the two. Guessing either way gets the other wrong — "stuck started" tells the
app a dead node is running for the rest of the process, "cleared too early"
invites a second `Node::start` over live tasks. So the FFI stopped guessing: it
asks the node (`Node::is_stopped`, the cancellation token) on every exit from a
stop and stores what it finds. **Where a flag mirrors state something else
owns, reconcile with the owner rather than tracking the transitions.**

One hazard a guard cannot contain at all is a deadlock. Logging while holding a
lock means running arbitrary code — a tracing subscriber — underneath it, and a
subscriber that called back into this library would block on a non-reentrant
mutex with no panic to catch. The API-handle lock is therefore taken only to
inspect and to store, never across a server start or a log. The lifecycle lock
*is* held across logs, by design, so the residual stands there: **a subscriber
must not re-enter this library.** Stated rather than fixed, because the
alternatives are a reentrant lock or no serialization at all.

This is a general consequence of the decision worth stating: **a function that
was previously abort-or-succeed now has a third exit, and every flag or handle
it took on the way in needs an owner on that exit — committed as late as the
truth allows and no later.** The residual is that `Node::start` itself is not
transactional, so a panic *inside* it leaves some tasks spawned and the flag
correctly false; a retry then duplicates them. The FFI cannot fix that from
outside, and it is ROADMAP T-50.

**"A forgotten guard is a visible omission" needed something to make it true.**
The Consequences above claim it; nothing in the compiler checks it.
`test_every_exported_function_is_guarded` reads this crate's own source and
requires of every `pub extern "C" fn mycelium_*` that its body opens with a
guard, that the guard names the function it wraps, and that it is the blocking
flavour **exactly when** the body contains `runtime().block_on` — the
re-entrancy rule of ADR-023, which would otherwise be 46 call sites of
copy-paste. It also pins the exported surface at 64, since changing that moves
the header, the iOS symbol list and three xcconfig `-u` lists with it.

The audit grew a second half for the same reason: a declaration it cannot
parse would be exported *without* being audited, and the count would not
notice, because an unseen function cannot make a total wrong. `extern
"C-unwind"` is the live case — it makes unwinding legal across the boundary and
skips the guard in one step — so any line declaring an exported function the
parse does not recognise fails the test. A companion test checks that
`mycelium.h` declares exactly the exported set: a function missing from the
header is one `ffigen` never generates, which is how a hand-written Dart lookup
gets written in the first place.

Re-entrancy, handle ownership and the display name are decided in **ADR-023**;
this ADR covers only the panic guard. Tests: one deliberately panicking
`extern "C"` fixture per return shape (`#[cfg(test)]` only, so the shipped
library gains no panic triggers), the borrowed-cell case, the hostile payload,
the recovered poison, the restored start flag, the source audit and the header
parity check. Two of them re-run themselves in a child process, because what
they test is process-global — the `Once` that installs the hook, and the global
subscriber — so in a shared process an earlier test hides the defect.
