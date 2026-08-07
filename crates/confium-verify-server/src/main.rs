//! `confium-verify-server` — HTTP service for verifying threshold
//! signatures and transparency log inclusion proofs.

mod handlers;

use clap::Parser;
use handlers::AppState;

/// Command-line arguments.
#[derive(Parser, Debug)]
#[command(
    name = "confium-verify-server",
    version,
    about = "HTTP verification service for threshold signatures and proofs"
)]
struct Args {
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1")]
    addr: String,

    /// Bind port.
    #[arg(long, default_value_t = 8082)]
    port: u16,
}

fn build_router() -> axum::Router {
    axum::Router::new()
        .route("/verify/composite", axum::routing::post(handlers::verify_composite))
        .route("/verify/inclusion", axum::routing::post(handlers::verify_inclusion))
        .route("/healthz", axum::routing::get(handlers::healthz))
        .with_state(AppState)
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();

    let router = build_router();
    let bind = format!("{}:{}", args.addr, args.port);
    tracing::info!(addr = %bind, "verification service starting");

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to bind {bind}: {e}");
            std::process::exit(1);
        });
    axum::serve(listener, router).await.unwrap();
}
