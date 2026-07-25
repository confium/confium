//! Confium ecosystem demonstration programs.
//!
//! Each binary in `src/bin/` demonstrates one aspect of the ecosystem:
//!
//! - `threshold_signing` — 3-party FROST-ed25519 threshold signing session
//! - `plugin_load_and_hash` — plugin loading via the standard Confium loader
//! - `keystore_roundtrip` — compartmentalized key storage
//! - `audit_log_stream` — structured JSON audit events
//!
//! Run with: `cargo run -p confium-examples --bin <name>`
