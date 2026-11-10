# ADR-004: Daemon Binary in Its Own Crate (`mycelium-daemon`)

## Status

Accepted (2026-09-04)

## Context

ADR-001 and ADR-002 define the product as a standalone daemon that exposes a
local REST + WebSocket API. Until this change the `mycelium-node` binary
(`crates/mycelium-node/src/main.rs`) started the mesh node but never started
the API server, because the API lives in `mycelium-api`, which depends on the
`mycelium-node` library. A binary inside `mycelium-node` cannot depend on
`mycelium-api` without a dependency cycle. As a result the `--port` flag, the
`[api]` config section, the supernode "API bound to 0.0.0.0" behaviour and the
whole OpenWRT LuCI dashboard (which polls the API) were dead for the daemon;
only the Flutter FFI path started the server.

The binary also re-declared the library modules with `mod` statements, so the
node's unit tests compiled and ran twice.

## Decision

- Add a new workspace crate `crates/mycelium-daemon` containing only the
  binary. It depends on `mycelium-node` (library), `mycelium-api`,
  `mycelium-crypto` and `mycelium-storage`.
- The binary keeps its historical name `mycelium-node` (`[[bin]] name`), so
  `cargo build --bin mycelium-node`, the Docker testbed, `openwrt/Makefile`
  and the init script are unchanged. `cargo run -p mycelium-daemon` runs it.
- The daemon starts the API server right after `Node::start()` when
  `api.enabled` is true, treats a bind failure as fatal, shuts the server
  down before stopping the node, and warns when the bind address is not
  loopback (the API has no authentication yet).
- The daemon honours `MYCELIUM_CONFIG`, `MYCELIUM_DATA_DIR`,
  `MYCELIUM_DISPLAY_NAME`, `MYCELIUM_PORT` and `MYCELIUM_SUPERNODE`
  environment variables (CLI flags win) so containers can configure it.
- The identity file is written with mode 0600 on Unix.
- `mycelium-node` becomes library-only.

## Consequences

**Easier:**
- The standalone daemon finally matches ADR-001/002: one binary serves the
  mesh and the API on desktop, in Docker and on routers.
- Test counts are exact (no duplicated unit-test binary).

**Harder:**
- One more crate to document and version.
- Scripts and docs that used `-p mycelium-node` for the binary had to change
  to `-p mycelium-daemon`.

## Alternatives Considered

1. **Put the binary in `mycelium-api`** — Works, but ties the daemon's name
   and CLI to the API crate and makes `cargo run -p mycelium-api` surprising.
2. **Move the API into `mycelium-node`** — Would pull axum/tower into every
   consumer of the node library, including the mobile FFI build.
