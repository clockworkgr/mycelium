//! Mycelium Local API Server
//!
//! Provides REST and WebSocket APIs for interacting with a Mycelium node.
//! See ADR-001 for architecture decisions.
//!
//! ## REST API
//!
//! All endpoints are under `/v1/` and return JSON responses.
//!
//! ## WebSocket API
//!
//! Connect to `/v1/ws` for real-time event streaming. Clients can subscribe
//! to specific protocol IDs to filter incoming messages.

pub mod routes;
pub mod server;
pub mod state;
pub mod types;
pub mod util;
pub mod ws;

pub use server::{build_router, start_server};
pub use state::AppState;
