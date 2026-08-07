//! `confium threshold` — threshold-signing umbrella subcommands.
//!
//! Wraps the threshold product surface: DKG, signing, share management.
//! The full implementation lives in `confium-tc-cmp20`, `confium-tc-gg18`,
//! `confium-tc-frost-p256`, `confium-tc-frost-ed25519`, and the coordinator.

use crate::cli::ThresholdCommand;

pub fn run(cmd: ThresholdCommand) {
    match cmd {
        ThresholdCommand::Version => print_version(),
        ThresholdCommand::Dkg => eprintln!("confium threshold dkg: coming soon — see https://www.confium.org/threshold/"),
        ThresholdCommand::Sign => eprintln!("confium threshold sign: coming soon — see https://www.confium.org/threshold/"),
    }
}

fn print_version() {
    println!("confium-threshold: product umbrella");
    println!("  crates:");
    println!("    confium-tc-core     (https://docs.rs/confium-tc-core)");
    println!("    confium-coordinator (https://docs.rs/confium-coordinator)");
    println!("    confium-tc-keys     (https://docs.rs/confium-tc-keys)");
    println!("    confium-tc-cmp20    (https://docs.rs/confium-tc-cmp20)");
    println!("    confium-tc-gg18     (https://docs.rs/confium-tc-gg18)");
    println!("    confium-tc-frost-p256  (https://docs.rs/confium-tc-frost-p256)");
    println!("    confium-tc-frost-ed25519 (https://docs.rs/confium-tc-frost-ed25519)");
    println!("    confium-tc-bls      (https://docs.rs/confium-tc-bls)");
    println!("    confium-tc-elgamal-p256 (https://docs.rs/confium-tc-elgamal-p256)");
    println!("    confium-signerd     (https://docs.rs/confium-signerd)");
    println!();
    println!("  docs:    https://www.confium.org/threshold/");
    println!("  specs:   https://www.confium.org/specs/PRODUCTS");
    println!("  quickstart: https://www.confium.org/threshold/quickstart/");
}
