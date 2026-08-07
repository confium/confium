//! Bitcoin OTS anchor loop.
//!
//! Periodically submits the current tree head to multiple
//! OpenTimestamps calendar servers. The OTS proofs are stored in
//! the database and served via `GET /v1/head/<N>/ots`.
//!
//! ## Frequency
//!
//! Every 10 minutes by default. OTS aggregation means the per-batch
//! Bitcoin cost is amortized across many log submitters; the actual
//! on-chain footprint is one OP_RETURN per calendar per hour.
//!
//! ## Calendar servers
//!
//! The default set mirrors what `opentimestamps-client` ships:
//!
//! - `https://a.pool.opentimestamps.org`
//! - `https://b.pool.opentimestamps.org`
//! - `https://a.eternity.college`
//! - `https://ots.btc.cat`
//!
//! A calendar failure is non-fatal — the anchor proceeds with
//! whichever calendars respond.

use std::sync::Arc;
use std::time::Duration;

use crate::api::AppState;

/// Run the OTS anchor loop in the background. Submits the current
/// tree root to calendar servers at the configured interval.
pub async fn run_anchor_loop(state: Arc<AppState>, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = anchor_once(&state).await {
            tracing::warn!(?e, "OTS anchor cycle failed");
        }
    }
}

/// One anchor cycle: snapshot the current tree head, submit to OTS
/// calendars, store the result. Returns Ok if at least one calendar
/// accepted.
async fn anchor_once(state: &Arc<AppState>) -> anyhow::Result<()> {
    let (tree_size, root) = {
        let merkle = state.merkle.lock();
        (merkle.len(), merkle.root())
    };

    tracing::info!(tree_size, root = %hex::encode(root), "anchoring tree head");

    // In a real deployment, this is where we'd POST the root to each
    // calendar and aggregate the OTS proofs. For the scaffold, we
    // record a placeholder proof so the API surface is testable
    // end-to-end without an external dependency.
    let placeholder_proof = build_placeholder_proof(tree_size, &root);
    state.db.store_ots_proof(tree_size, &root, &placeholder_proof, None)?;

    Ok(())
}

/// Build a placeholder OTS proof for testing. The real implementation
/// would parse the calendar server responses and assemble the proof
/// per the OTS wire format (RFC opentimestamps).
fn build_placeholder_proof(tree_size: u64, root: &[u8; 32]) -> Vec<u8> {
    let mut proof = Vec::new();
    proof.extend_from_slice(b"OTS-PLACEHOLDER/v1\n");
    proof.extend_from_slice(&tree_size.to_be_bytes());
    proof.extend_from_slice(root);
    proof
}
