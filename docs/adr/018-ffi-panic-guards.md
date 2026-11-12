# ADR-018: Panic Guards at the FFI Boundary

## Status

Accepted (2026-11-12). **Implementation pending — ROADMAP T-01.**

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
