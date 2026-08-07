//! `confium transparency` — transparency-log umbrella subcommands.
//!
//! Wraps the transparency product surface: log server, monitor, edge verifier.

use crate::cli::TransparencyCommand;

pub fn run(cmd: TransparencyCommand) {
    match cmd {
        TransparencyCommand::Version => print_version(),
        TransparencyCommand::Append => eprintln!("confium transparency append: coming soon — see https://www.confium.org/transparency/"),
        TransparencyCommand::Prove => eprintln!("confium transparency prove: coming soon — see https://www.confium.org/transparency/"),
        TransparencyCommand::Verify => eprintln!("confium transparency verify: coming soon — see https://www.confium.org/transparency/"),
    }
}

fn print_version() {
    println!("confium-transparency: product umbrella");
    println!("  crates:");
    println!("    confium-transparency  (https://docs.rs/confium-transparency)");
    println!("    confium-log-server    (https://docs.rs/confium-log-server)");
    println!("    confium-log-monitor   (https://docs.rs/confium-log-monitor)");
    println!("    confium-log-edge      (https://docs.rs/confium-log-edge)");
    println!();
    println!("  docs:    https://www.confium.org/transparency/");
    println!("  specs:   https://www.confium.org/specs/PRODUCTS");
    println!("  quickstart: https://www.confium.org/transparency/quickstart/");
}
