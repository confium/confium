//! Async session coordinator for distributed threshold signing.
//!
//! The coordinator service enables globally distributed threshold
//! signers to participate when convenient — no simultaneity required.
//!
//! This crate provides the session state machine, commitment/share
//! buffering, audit logging, and a real TCP server + client for
//! network communication.
//!
//! See `TODO.roadmap/29-tc-coordinator-design.md` for the full spec.

#![forbid(unsafe_code)]
#![allow(missing_docs)]
#![allow(clippy::module_inception)]

pub mod abort;
pub mod admin;
pub mod alerts;
pub mod audit;
pub mod backpressure;
pub mod batch;
pub mod capabilities;
pub mod checkpoint;
pub mod client;
pub mod connection_stats;
pub mod coordinator;
pub mod diagnostics;
pub mod frost_integration;
pub mod grafana;
pub mod idempotency;
pub mod leader_election;
pub mod metrics;
pub mod metrics_aggregator;
pub mod middleware;
pub mod net;
pub mod net_server;
pub mod otlp;
pub mod policy;
pub mod rate_limiter;
pub mod reaper;
pub mod request_log;
pub mod scheduler;
pub mod session;
pub mod session_timeout;
pub mod store;
pub mod transport;
pub mod version_negotiation;

pub use audit::*;
pub use coordinator::*;
pub use session::*;
