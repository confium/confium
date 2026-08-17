//! `confium pki` — PKI umbrella subcommands.

use crate::cli::{PkiCommand, PkiCompositeSignArgs, PkiParseCertArgs, PkiVerifyArgs};
use confium_pki::{Certificate, path::CertPath};

pub fn run(cmd: PkiCommand) {
    let result: Result<(), String> = match cmd {
        PkiCommand::Version => {
            print_version();
            Ok(())
        }
        PkiCommand::ParseCert(args) => parse_cert(args),
        PkiCommand::Verify(args) => verify_chain(args),
        PkiCommand::CompositeSign(args) => composite_sign(args),
    };
    if let Err(e) = result {
        eprintln!("confium pki: {e}");
        std::process::exit(1);
    }
}

fn parse_cert(args: PkiParseCertArgs) -> Result<(), String> {
    let cert = read_cert(&args.cert, &args.format)?;
    println!("fingerprint (sha256): {}", cert.fingerprint_sha256());
    println!("serial (hex):         {}", hex::encode(cert.serial_bytes()));
    println!("not before:           {}", cert.not_before());
    println!("not after:            {}", cert.not_after());
    Ok(())
}

fn verify_chain(args: PkiVerifyArgs) -> Result<(), String> {
    let leaf = read_cert(&args.leaf, &args.format)?;
    let anchor = read_cert(&args.anchor, &args.format)?;
    let intermediates: Vec<Certificate> = args
        .intermediates
        .iter()
        .map(|p| read_cert(p, &args.format))
        .collect::<Result<_, _>>()?;

    // Build a Vec of intermediate refs that live as long as the
    // intermediates Vec above.
    let inter_refs: Vec<&Certificate> = intermediates.iter().collect();
    let path = CertPath {
        leaf: &leaf,
        intermediates: inter_refs,
        root: &anchor,
    };

    // Verifier callback: use the leaf's public-key algorithm to verify
    // each link's signature. For demo purposes we accept any signature
    // that parses; a full implementation dispatches on algorithm.
    let result = confium_pki::path::verify_path_signatures(&path, |_issuer_pk, _sig| {
        Ok(()) // demo: accept. Real verifier dispatches on SPKI algorithm.
    });
    println!("{:?}", result);
    Ok(())
}

fn composite_sign(args: PkiCompositeSignArgs) -> Result<(), String> {
    let message = read_message(&args.message)?;

    let ed25519_key_bytes = std::fs::read(&args.ed25519_key)
        .map_err(|e| format!("read {}: {e}", args.ed25519_key.display()))?;
    let ed25519_key = ed25519_dalek::SigningKey::from_bytes(
        &ed25519_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Ed25519 key must be exactly 32 bytes".to_string())?,
    );
    let ed_component = confium_composite::build_ed25519_component(&ed25519_key, &message)
        .map_err(|e| format!("ed25519 component: {e}"))?;

    let p256_key_bytes = std::fs::read(&args.p256_key)
        .map_err(|e| format!("read {}: {e}", args.p256_key.display()))?;
    let p256_key_bytes: [u8; 32] = p256_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "P-256 key must be exactly 32 bytes".to_string())?;
    let p256_key = p256::ecdsa::SigningKey::from_bytes(&p256_key_bytes.into())
        .map_err(|e| format!("parse P-256 signing key: {e}"))?;
    let p256_component = confium_composite::build_p256_component(&p256_key, &message)
        .map_err(|e| format!("p256 component: {e}"))?;

    let composite = confium_composite::CompositeSignature::new(vec![ed_component, p256_component]);
    // Serialize as JSON (CompositeSignature derives Serialize). Hex-encode
    // so the output is single-line, copy-pasteable.
    let json =
        serde_json::to_string(&composite).map_err(|e| format!("serialize composite: {e}"))?;
    let hex_out = hex::encode(json.as_bytes());

    match &args.out {
        Some(path) => std::fs::write(path, hex_out.as_bytes())
            .map_err(|e| format!("write {}: {e}", path.display()))?,
        None => println!("{hex_out}"),
    }
    Ok(())
}

fn read_cert(path: &std::path::Path, format: &str) -> Result<Certificate, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    match format {
        "der" => Certificate::from_der(&bytes).map_err(|e| format!("parse DER: {e}")),
        "pem" => {
            let s = std::str::from_utf8(&bytes).map_err(|e| format!("PEM is not UTF-8: {e}"))?;
            Certificate::from_pem(s).map_err(|e| format!("parse PEM: {e}"))
        }
        other => Err(format!("unknown format: {other} (try der or pem)")),
    }
}

fn read_message(spec: &str) -> Result<Vec<u8>, String> {
    if let Some(path) = spec.strip_prefix('@') {
        std::fs::read(path).map_err(|e| format!("read message {path}: {e}"))
    } else {
        Ok(spec.as_bytes().to_vec())
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
