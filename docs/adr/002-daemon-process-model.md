# ADR-002: Standalone Daemon Process Model

## Status

Accepted

## Context

Currently the Mycelium node runs embedded in the Flutter app process via FFI. This means:
- Node dies when the app is killed
- Only the chat app can access the mesh
- BLE transport stops when app is backgrounded (on some devices)

The WebSocket API (ADR-001) enables multiple client apps, but the node must outlive any single app.

## Decision

The Mycelium node will run as a **separate standalone daemon process** on the device:

- **Android**: Native binary started as a separate process (eventually at boot via JobScheduler/WorkManager)
- **Desktop**: Standard daemon/service managed by the OS
- **Architecture**: The Rust `main.rs` daemon already exists — extend it with the API server

**Phased rollout:**
1. Phase 1 (current): Node runs in-app via FFI with WebSocket API server co-hosted
2. Phase 2: Extract to Android foreground service in a separate process
3. Phase 3: Full standalone daemon started at boot

The Flutter chat app transitions from FFI client to WebSocket client during this process.

## Consequences

**Easier:**
- Mesh stays connected even when the chat app is closed
- Multiple apps share one mesh identity and transport
- Desktop support with same daemon binary

**Harder:**
- Android process lifecycle management (keep-alive, battery optimization exemptions)
- IPC adds latency vs direct FFI (negligible for local WebSocket)
- Must handle daemon crashes and auto-restart
- Permission management: which apps can connect to the daemon

## Alternatives Considered

1. **Android foreground service (in-app)** — Simpler but still tied to app lifecycle. Selected as intermediate step.
2. **Each app embeds its own node** — Wastes resources, multiple BLE stacks conflict, no shared identity.
3. **System service via root** — Too invasive, not viable on stock Android.
