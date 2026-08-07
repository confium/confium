//! `confium-log-monitor` — third-party monitor for Confium transparency logs.
//!
//! Watches a transparency log endpoint (e.g. `log.confium.org`),
//! verifies internal consistency (every published tree head is a
//! valid continuation of every prior tree head), and verifies
//! external consistency (the log presents the same view to all
//! monitors). Detects:
//!
//! - **Fork attempts**: the log presents different tree heads to
//!   different monitors at the same tree size.
//! - **Bad signatures**: the log's published signature doesn't
//!   verify against the operational key.
//! - **Bad inclusion proofs**: an inclusion proof doesn't
//!   actually prove inclusion under the current root.
//! - **Bad consistency proofs**: a consistency proof between
//!   tree sizes M and N doesn't actually prove the trees are
//!   related.
//!
//! ## Quickstart
//!
//! ```sh
//! $ cargo run -p confium-log-monitor -- \
//!     --log-url http://log.confium.org \
//!     --state /var/lib/confium-monitor \
//!     --poll-interval 30
//! ```

mod client;
mod verify;
mod store;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "confium-log-monitor", version)]
pub struct Args {
    /// Base URL of the transparency log to monitor.
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    pub log_url: String,

    /// Directory for persistent state (cached tree heads, witness sigs).
    #[arg(long, default_value = "./confium-monitor-state")]
    pub state: PathBuf,

    /// Poll interval, in seconds.
    #[arg(long, default_value_t = 30)]
    pub poll_interval: u64,

    /// Run once and exit (don't loop). Useful for cron-based monitoring.
    #[arg(long)]
    pub once: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "confium_log_monitor=info".into()),
        )
        .init();

    let args = Args::parse();
    let client = client::LogClient::new(args.log_url.clone());
    let store = store::StateStore::open(&args.state)?;

    loop {
        if let Err(e) = run_cycle(&client, &store).await {
            tracing::error!(?e, "monitor cycle failed");
        }
        if args.once {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(args.poll_interval)).await;
    }
}

async fn run_cycle(client: &client::LogClient, store: &store::StateStore) -> Result<()> {
    let head = client.fetch_head().await?;
    tracing::info!(tree_size = head.tree_size, root = %head.root, "fetched head");

    let last_size = store.last_tree_size()?;
    if head.tree_size > last_size {
        // Verify consistency between last_size and head.tree_size.
        if last_size > 0 {
            let proof = client.fetch_consistency(last_size).await?;
            let last_root = store.last_root()?;
            verify::verify_consistency(&last_root, last_size, &head, &proof)?;
            tracing::info!(from = last_size, to = head.tree_size, "consistency verified");
        }
        // Cache the new head.
        store.put_head(&head)?;
    } else if head.tree_size < last_size {
        // Tree size went backwards — this is a fork or a database reset.
        tracing::error!(
            observed = head.tree_size,
            cached = last_size,
            "TREE SIZE WENT BACKWARDS — possible fork"
        );
    }

    Ok(())
}
