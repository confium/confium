//! `confium-operator` — Kubernetes operator for Confium threshold
//! signing ceremonies.
//!
//! Watches for `ConfiumSigningCeremony` Custom Resources and
//! orchestrates the threshold DKG + sign lifecycle. The operator
//! runs as a Kubernetes Deployment; each ceremony is a CRD instance.
//!
//! ## CRD shape
//!
//! ```yaml
//! apiVersion: confium.org/v1alpha1
//! kind: ConfiumSigningCeremony
//! metadata:
//!   name: release-v2-signing
//! spec:
//!   scheme: cmp20
//!   threshold: 3
//!   partyCount: 5
//!   messageRef:
//!     configMap: release-artifact
//!     key: release.tar.gz
//!   outputRef:
//!     secret: release-signature
//! ```
//!
//! ## Status
//!
//! Scaffold: the CRD definition + controller loop are defined but
//! the actual Kubernetes client integration is stubbed. The scaffold
//! lets teams design their ceremony workflow against a stable API.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0
#![allow(dead_code)] // CRD/controller types not yet wired into the reconcile loop

mod controller;
mod crd;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "confium-operator",
    version,
    about = "Kubernetes operator for Confium threshold signing"
)]
pub struct Args {
    /// Path to the kubeconfig file. Defaults to in-cluster config.
    #[arg(long)]
    pub kubeconfig: Option<String>,

    /// Namespace to watch. Defaults to all namespaces.
    #[arg(long)]
    pub namespace: Option<String>,

    /// Run once and exit (don't reconcile loop).
    #[arg(long)]
    pub once: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "confium_operator=info".into()),
        )
        .init();

    let args = Args::parse();
    tracing::info!("starting confium-operator");

    let controller = controller::CeremonyController::new(args.namespace.clone());

    if args.once {
        controller.reconcile_once().await?;
    } else {
        controller.run().await?;
    }

    Ok(())
}
