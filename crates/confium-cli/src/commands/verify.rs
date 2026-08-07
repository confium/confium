//! `confium verify` — verification umbrella subcommands.

use crate::cli::VerifyCommand;

pub fn run(cmd: VerifyCommand) {
    match cmd {
        VerifyCommand::Version => print_version(),
        VerifyCommand::Composite => eprintln!("confium verify composite: coming soon — see https://www.confium.org/verify/"),
        VerifyCommand::Inclusion => eprintln!("confium verify inclusion: coming soon — see https://www.confium.org/verify/"),
        VerifyCommand::CertChain => eprintln!("confium verify cert-chain: coming soon — see https://www.confium.org/verify/"),
    }
}

fn print_version() {
    println!("confium-verify: product umbrella");
    println!("  crates:");
    println!("    confium-wasm          (@confium/confium-wasm on npm)");
    println!("    confium-verify-server (https://docs.rs/confium-verify-server)");
    println!("    confium-composite     (https://docs.rs/confium-composite)");
    println!("    confium-python        (PyPI: confium)");
    println!("    confium-node          (npm: confium-node)");
    println!("    confium-go            (github.com/confium/confium-go)");
    println!("    confium-ruby          (RubyGems: confium)");
    println!();
    println!("  docs:    https://www.confium.org/verify/");
    println!("  specs:   https://www.confium.org/specs/PRODUCTS");
    println!("  quickstart: https://www.confium.org/verify/quickstart/");
}
