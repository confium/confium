//! `confium pki` — PKI umbrella subcommands.

use crate::cli::PkiCommand;

pub fn run(cmd: PkiCommand) {
    match cmd {
        PkiCommand::Version => print_version(),
        PkiCommand::ParseCert => eprintln!("confium pki parse-cert: coming soon — see https://www.confium.org/pki/"),
        PkiCommand::Verify => eprintln!("confium pki verify: coming soon — see https://www.confium.org/pki/"),
        PkiCommand::CompositeSign => eprintln!("confium pki composite-sign: coming soon — see https://www.confium.org/pki/"),
    }
}

fn print_version() {
    println!("confium-pki: product umbrella");
    println!("  crates:");
    println!("    confium-pki               (https://docs.rs/confium-pki)");
    println!("    confium-composite         (https://docs.rs/confium-composite)");
    println!("    confium-attributes        (https://docs.rs/confium-attributes)");
    println!("    confium-pkcs11-server     (https://docs.rs/confium-pkcs11-server)");
    println!("    confium-openssl-provider  (https://docs.rs/confium-openssl-provider)");
    println!("    confium-jce-provider      (https://docs.rs/confium-jce-provider)");
    println!("    confium-tls-signer        (https://docs.rs/confium-tls-signer)");
    println!();
    println!("  docs:    https://www.confium.org/pki/");
    println!("  specs:   https://www.confium.org/specs/PRODUCTS");
    println!("  quickstart: https://www.confium.org/pki/quickstart/");
}
