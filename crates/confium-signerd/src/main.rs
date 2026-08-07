//! `confium-signerd` — distributed threshold signing daemon.
//!
//! Connects to a coordinator and responds to signing requests.

mod config;
mod daemon;

use clap::Parser;
use config::DaemonConfig;
use daemon::SignerDaemon;
use std::path::PathBuf;

/// Command-line arguments.
#[derive(Parser, Debug)]
#[command(
    name = "confium-signerd",
    version,
    about = "Distributed threshold signing daemon"
)]
pub struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long)]
    config: PathBuf,

    /// Run in verbose mode (more tracing output).
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    let filter = tracing_subscriber::EnvFilter::new(if args.verbose {
        "debug"
    } else {
        "info"
    });

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);

    #[cfg(test)]
    let _ = subscriber.try_init();
    #[cfg(not(test))]
    let _ = {
        use tracing_subscriber::util::SubscriberInitExt;
        subscriber.init()
    };

    let config = match DaemonConfig::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {e}");
            std::process::exit(1);
        }
    };

    tracing::info!(
        addr = %config.coordinator_addr,
        signer = %config.signer_id,
        quorum = %config.quorum_id,
        scheme = %config.scheme,
        "starting signer daemon"
    );

    let daemon = SignerDaemon::new(config);
    let result = daemon.run();
    match result {
        daemon::RunResult::Disconnected => {
            tracing::info!("disconnected, shutting down");
        }
        daemon::RunResult::MaxRetriesExhausted => {
            tracing::error!("all reconnect attempts exhausted");
            std::process::exit(1);
        }
    }
}
