//! `confium-log-server` — public transparency log server.
//!
//! Reference implementation of `log.confium.org`. An append-only
//! Merkle transparency log (RFC 6962 / RFC 9162) with first-class
//! support for certificate entries — every Confium-issued cert
//! (CNML, code-signing, SSH, document-signing, TLS) gets anchored
//! automatically and is queryable by fingerprint.
//!
//! ## Architecture
//!
//! Single binary, embedded SQLite storage, no external services to
//! operate. The Merkle tree is materialized incrementally on each
//! append; reads serve from in-memory cache.
//!
//! ## Quickstart
//!
//! ```sh
//! $ cargo run -p confium-log-server -- --db /var/lib/confium/log.db --listen 0.0.0.0:8080
//! # listening on http://0.0.0.0:8080
//! ```
//!
//! ## API
//!
//! ### Hash entries (generic)
//!
//! `POST /v1/append` — append a SHA-256 hash
//! `GET /v1/head` — current tree head
//! `GET /v1/proof/<sequence>` — inclusion proof
//! `GET /v1/consistency/<old_size>` — consistency proof
//!
//! ### Certificate entries (cert-aware)
//!
//! `POST /v1/certificates` — append a DER-encoded X.509 cert
//! `GET /v1/certificates/<fingerprint>` — lookup by SHA-256 fingerprint
//! `GET /v1/issuers/<issuer>/certificates` — list certs by issuer DN
//!
//! ### Bitcoin OTS anchoring
//!
//! `GET /v1/head/<sequence>/ots` — OTS proof for tree head at sequence
//!
//! ### Witness gossip
//!
//! `POST /v1/head/<sequence>/witness` — submit a witness countersignature
//! `GET /v1/head/<sequence>/witnesses` — list known witnesses for tree head

mod db;
#[cfg(feature = "postgres")]
mod db_pg;
mod merkle;
mod api;
mod cert;
mod witness;
mod ots_anchor;

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

use api::AppState;

/// Command-line arguments for the log server.
#[derive(Parser, Debug)]
#[command(name = "confium-log-server", version, about = "Public transparency log server for Confium")]
pub struct Args {
    /// Path to the SQLite database file. Created if missing.
    #[arg(long, default_value = "confium-log.db")]
    pub db: PathBuf,

    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub listen: String,

    /// Disable the periodic OTS anchor (useful for testing).
    #[arg(long)]
    pub no_ots: bool,

    /// Interval between OTS anchor submissions, in seconds.
    #[arg(long, default_value_t = 600)]
    pub ots_interval_secs: u64,

    /// Maximum entries per paged response.
    #[arg(long, default_value_t = 1000)]
    pub page_size: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "confium_log_server=info,tower_http=info".into()),
        )
        .init();

    let args = Args::parse();
    tracing::info!(?args.db, ?args.listen, "starting confium-log-server");

    let db = db::Database::open(&args.db)?;
    db.init_schema()?;
    let merkle = merkle::MerkleState::from_db(&db)?;
    let state = Arc::new(AppState {
        db,
        merkle: parking_lot::Mutex::new(merkle),
        page_size: args.page_size,
    });

    // Background OTS anchor task. Skipped when --no-ots is set.
    if !args.no_ots {
        let anchor_state = state.clone();
        tokio::spawn(async move {
            ots_anchor::run_anchor_loop(anchor_state, std::time::Duration::from_secs(args.ots_interval_secs)).await;
        });
    }

    let app = api::router(state);
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!("listening on http://{}", args.listen);
    axum::serve(listener, app).await?;
    Ok(())
}
