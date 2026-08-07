//! `confium pki` — PKI umbrella subcommands.

use crate::cli::{PkiCommand, PkiParseCertArgs};

pub fn run(cmd: PkiCommand) {
    let result: Result<(), String> = match cmd {
        PkiCommand::Version => {
            print_version();
            Ok(())
        }
        PkiCommand::ParseCert(args) => parse_cert(args),
        PkiCommand::CompositeSign => Err(
            "confium pki composite-sign: requires classical + PQ key files; see https://www.confium.org/pki/quickstart/".into(),
        ),
        PkiCommand::Verify => Err(
            "confium pki verify: see https://www.confium.org/pki/quickstart/".into(),
        ),
    };
    if let Err(e) = result {
        eprintln!("confium pki: {e}");
        std::process::exit(1);
    }
}

fn parse_cert(args: PkiParseCertArgs) -> Result<(), String> {
    let bytes = std::fs::read(&args.cert)
        .map_err(|e| format!("read {}: {e}", args.cert.display()))?;
    let cert = match args.format.as_str() {
        "der" => confium_pki::Certificate::from_der(&bytes)
            .map_err(|e| format!("parse DER: {e}"))?,
        "pem" => {
            let pem_str = std::str::from_utf8(&bytes)
                .map_err(|e| format!("PEM is not valid UTF-8: {e}"))?;
            confium_pki::Certificate::from_pem(pem_str)
                .map_err(|e| format!("parse PEM: {e}"))?
        }
        other => return Err(format!("unknown format: {other} (try der or pem)")),
    };
    println!("fingerprint (sha256): {}", cert.fingerprint_sha256());
    println!("serial (hex):         {}", hex::encode(cert.serial_bytes()));
    println!("not before:           {}", cert.not_before());
    println!("not after:            {}", cert.not_after());
    Ok(())
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
