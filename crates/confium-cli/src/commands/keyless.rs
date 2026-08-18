//! `confium keyless` — keyless signing umbrella subcommands.

use crate::cli::KeylessCommand;

pub fn run(cmd: KeylessCommand) {
    match cmd {
        KeylessCommand::Version => print_version(),
        KeylessCommand::Sign => {
            eprintln!("confium keyless sign: coming soon — see https://www.confium.org/keyless/")
        }
        KeylessCommand::Verify => {
            eprintln!("confium keyless verify: coming soon — see https://www.confium.org/keyless/")
        }
        KeylessCommand::Configure => {
            eprintln!(
                "confium keyless configure: coming soon — the OIDC issuer/subject allowlist format is being finalized; see https://www.confium.org/keyless/"
            )
        }
    }
}

fn print_version() {
    println!("confium-keyless: product umbrella");
    println!("  crates:");
    println!("    confium-oidc      (https://docs.rs/confium-oidc)");
    println!(
        "    confium-keyless   (https://docs.rs/confium-keyless)  [facade, TODO.restructure/20]"
    );
    println!();
    println!("  GitHub Action: https://github.com/confium/action");
    println!("  docs:          https://www.confium.org/keyless/");
    println!("  specs:         https://www.confium.org/specs/PRODUCTS");
    println!("  quickstart:    https://www.confium.org/keyless/quickstart/");
}
