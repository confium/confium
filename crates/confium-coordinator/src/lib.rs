//! Distributed threshold signing coordinator.
//!
//! The coordinator orchestrates threshold signing sessions across distributed
//! signers. It provides:
//!
//! - TCP server + client for network communication
//! - Multi-round protocol state machine
//! - Policy enforcement (time windows, rate limits, thresholds)
//! - Rate limiting, backpressure, circuit breaker
//! - Prometheus metrics, Grafana dashboards, OTLP tracing
//! - Health checks, graceful shutdown
//! - Persistent session store, WAL, event sourcing
//! - Admin API, diagnostics
//! - DKG coordination, share refresh

#![warn(unsafe_code)]
// The coordinator is internal infrastructure with 40+ modules extracted
// from confium-tc. Most struct fields and methods need doc comments;
// that's a dedicated effort tracked separately. Allow for now so the
// crate compiles cleanly.
#![allow(missing_docs)]

pub mod chaos_testing;
pub mod circuit_breaker;
pub mod config_validator;
pub mod coordinator;
pub mod coordinator_factory;
pub mod coordinator_proptest;
pub mod di_container;
pub mod distributed_lock;
pub mod dkg_coordinator;
pub mod event_sourced;
pub mod marketplace;
pub mod noise_transport;
pub mod perf_baseline;
pub mod plugin_manifest;
pub mod refresh_coordinator;
pub mod request_coalescing;
pub mod resilience_and_circuits;
pub mod retry;
pub mod round_coordinator;
pub mod saga;
pub mod shutdown;
pub mod wal;

pub mod async_event_store;
pub mod async_session_manager;
