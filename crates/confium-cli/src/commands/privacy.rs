//! `confium privacy` — privacy primitives umbrella subcommands.

use crate::cli::PrivacyCommand;

pub fn run(cmd: PrivacyCommand) {
    match cmd {
        PrivacyCommand::Version => print_version(),
        PrivacyCommand::Psi => eprintln!("confium privacy psi: coming soon — see https://www.confium.org/privacy/"),
        PrivacyCommand::Mpc => eprintln!("confium privacy mpc: coming soon — see https://www.confium.org/privacy/"),
        PrivacyCommand::Dp => eprintln!("confium privacy dp: coming soon — see https://www.confium.org/privacy/"),
    }
}

fn print_version() {
    println!("confium-privacy: product umbrella");
    println!("  crates:");
    println!("    confium-privacy    (https://docs.rs/confium-privacy)");
    println!("    confium-crypto-zk  (https://docs.rs/confium-crypto-zk)");
    println!("    confium-crypto-vss (https://docs.rs/confium-crypto-vss)");
    println!("    confium-ring       (https://docs.rs/confium-ring)");
    println!();
    println!("  docs:    https://www.confium.org/privacy/");
    println!("  specs:   https://www.confium.org/specs/PRODUCTS");
    println!("  quickstart: https://www.confium.org/privacy/quickstart/");
}
