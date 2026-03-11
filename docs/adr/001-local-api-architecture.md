# ADR-001: Local WebSocket + REST API Architecture

## Status

Accepted

## Context

Mycelium needs to evolve from a single-purpose mesh messenger into a general-purpose mesh transport platform. Third-party apps should be able to send and receive arbitrary binary data over the mesh, tagged with a protocol ID. The chat app itself should use this same API (dogfooding).

Currently, the Flutter app communicates with the Rust node via direct C FFI calls. This tightly couples the chat UI to the node binary and prevents other apps from using the mesh transport.

## Decision

The Mycelium node will expose a **local API server** with two interfaces:

1. **REST API** (axum) — Full CRUD for messages, contacts, conversations, groups, network diagnostics. Request/response bodies use protobuf encoding (with optional JSON fallback).

2. **WebSocket API** (axum WebSocket) — Real-time event streaming and bidirectional data exchange. Apps connect and subscribe to protocol IDs. All frames are binary protobuf.

**Technology choices:**
- HTTP/WS server: `axum` with `tokio-tungstenite` (built-in via axum)
- Serialization: `prost` for protobuf, `prost-build` for codegen
- No gRPC runtime — raw protobuf over WebSocket and REST

**API server details:**
- Default bind: `127.0.0.1:9735` (localhost only)
- Authentication: Configurable (default: none, optional: API key or per-app tokens)
- New crate: `mycelium-api` in the workspace

**Protocol ID system:**
- Simple string format (e.g., `mycelium.chat.v1`, `com.example.game`)
- Apps declare protocols via WebSocket `Subscribe` message
- All data is E2E encrypted by Mycelium using existing Double Ratchet sessions
- Protocol discovery exchanged post-BLE-connection (not in BLE advertisements)

## Consequences

**Easier:**
- Any app can use the mesh transport (WebSocket client in any language)
- Debug panel can use the REST API instead of new FFI functions
- Desktop/web clients become possible without FFI
- Chat app migration validates the API design

**Harder:**
- Additional crate and dependency surface (axum, prost, tonic/prost-build)
- Serialization overhead vs direct FFI (negligible for local IPC)
- Must maintain backward compatibility as API evolves
- Two code paths during migration (FFI and WebSocket)

## Alternatives Considered

1. **Unix domain socket** — Lower overhead but less portable (no Windows support, harder from Flutter).
2. **Android Bound Service (AIDL)** — Android-only, doesn't solve cross-platform.
3. **gRPC via tonic** — Considered but adds gRPC runtime complexity. Protobuf over WebSocket is simpler and sufficient.
4. **JSON over WebSocket** — Simpler but inefficient for binary data. Protobuf chosen for type safety and compact encoding.
5. **Embedded SDK (library approach)** — Apps embed Rust library directly. Rejected: only one node should run per device, shared transport.
