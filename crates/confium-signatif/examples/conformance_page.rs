//! Print the conformance page for the docs site: the `/conf` class
//! table generated from [`conformance_claims`], so the published page
//! can never drift from the code (a CI test compares the output with
//! the committed `docs/signatif/conformance.mdx`).
//!
//! Regenerate with:
//!
//! ```sh
//! cargo run -p confium-signatif --example conformance_page \
//!   > docs/signatif/conformance-table.mdx
//! ```

use confium_signatif::conformance::{ConformanceStatus, conformance_claims};

fn main() {
    let claims = conformance_claims();
    let implemented = claims
        .iter()
        .filter(|c| c.status == ConformanceStatus::Implemented)
        .count();
    let partial = claims.len() - implemented;

    println!("| Class | Status | Implemented in | Description |");
    println!("|---|---|---|---|");
    for c in &claims {
        let status = match c.status {
            ConformanceStatus::Implemented => "implemented",
            ConformanceStatus::Partial => "partial",
            ConformanceStatus::Planned => "planned",
        };
        println!(
            "| `{}` | {} | {} | {} |",
            c.class, status, c.implemented_in, c.description
        );
    }
    println!();
    println!(
        "_{implemented} of {} classes implemented, {partial} partial._",
        claims.len()
    );
}
