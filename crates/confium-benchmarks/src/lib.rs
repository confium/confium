//! `confium-benchmarks` — criterion benches for the confium hot paths.
//!
//! Run all benches:
//! ```sh
//! cargo bench -p confium-benchmarks
//! ```
//!
//! Run a single bench:
//! ```sh
//! cargo bench -p confium-benchmarks --bench composite_verify
//! ```
//!
//! HTML reports land in `target/criterion/`. Open `report/index.html`
//! to see per-iteration timings, regression detection, and outlier
//! analysis.
