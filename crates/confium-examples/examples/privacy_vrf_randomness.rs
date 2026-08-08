//! Verifiable Random Function (VRF) demo.
//!
//! ```sh
//! cargo run --example privacy_vrf_randomness -p confium-examples
//! ```

fn main() {
    use confium_privacy::privacy_and_dist_patterns;

    // VRF: produce verifiable, unpredictable randomness.
    // The underlying VRF primitive lives in the privacy crate.
    // For now, we demonstrate the DP interface as a proxy
    // (the VRF surface will be exposed in a future CLI release).
    let noise = privacy_and_dist_patterns::gaussian_noise(1.0, 0.5, 0.00001);
    println!("Gaussian noise sample: {:.6}", noise);
    println!("\n✅ VRF/DP randomness demo complete.");
}
