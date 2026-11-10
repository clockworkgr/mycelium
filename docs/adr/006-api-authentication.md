# ADR-006: Bearer-Token Authentication for the Local API

## Status

Accepted (2026-09-04)

## Context

ADR-001 left authentication "configurable (default: none)". In practice the
API had no authentication at all, a permissive CORS layer, and no origin
check on the WebSocket. Any process on the device, and any web page open in
a browser on it, could read decrypted message history and send messages.
With `--supernode` the API is bound to all interfaces, so the same applied
to the whole network.

## Decision

- Every node generates a random 32-byte token on first start and stores it
  hex-encoded at `<data_dir>/api.token` with mode 0600. The daemon and the
  FFI path both create it; a config file may supply `api.auth_token`
  instead.
- Every REST request must carry `Authorization: Bearer <token>`. The
  WebSocket upgrade accepts the same header or `?token=<token>` (browser
  clients cannot set headers). Missing or wrong tokens get `401` with a
  `WWW-Authenticate: Bearer` challenge; comparison is constant-time.
- WebSocket upgrades that carry a browser `Origin` are refused unless the
  origin is loopback (`localhost`, `127.0.0.1`, `[::1]`, `null`), because
  browsers do not apply CORS to WebSockets.
- CORS allows only loopback origins (preflight requests need no token).
- The WebSocket `send` frame is answered with a `send_result` frame carrying
  the message id or the error, so clients no longer send blind.
- The Flutter app reads the token from its data directory and attaches it
  via an `http.BaseClient` wrapper and the WebSocket URL; the LuCI status
  page reads the token from `data_dir` on the router.
- `AppState::new` still defaults to no token so the integration tests can
  exercise routes directly; `start_server` logs a warning if no token is set.

## Consequences

**Easier:**
- Third-party local apps (ADR-001's goal) get a simple, documented secret to
  present; the LAN-exposed supernode API is no longer open.

**Harder:**
- Clients must locate the token file (or be handed the token). Plain HTTP is
  still used, so on a non-loopback bind the token is exposed to anyone who
  can sniff the link; TLS or an SSH tunnel is required for remote use.
- The token is per node, not per app; revoking one app means rotating the
  file for all.

## Alternatives Considered

1. **Per-app tokens** — Better isolation, but needs a registration flow and
   UI; can be layered on later without changing the header format.
2. **Unix domain socket with peer credentials** — Not available to Flutter on
   Android without extra plumbing, and does nothing for the supernode case.
3. **mTLS** — Heavy for a local API; revisit together with TLS for remote
   management.
