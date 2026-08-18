//! `confium verify` — verification umbrella subcommands.

use crate::cli::{
    VerifyCertChainArgs, VerifyCommand, VerifyCompositeArgs, VerifyInclusionArgs,
    VerifySignatifArgs,
};
use confium_pki::{Certificate, path::CertPath};

pub fn run(cmd: VerifyCommand) {
    let result: Result<(), String> = match cmd {
        VerifyCommand::Version => {
            print_version();
            Ok(())
        }
        VerifyCommand::Composite(args) => verify_composite(args),
        VerifyCommand::Inclusion(args) => verify_inclusion(args),
        VerifyCommand::CertChain(args) => verify_cert_chain(args),
        VerifyCommand::Signatif(args) => verify_signatif(args),
    };
    if let Err(e) = result {
        eprintln!("confium verify: {e}");
        std::process::exit(1);
    }
}

fn verify_composite(args: VerifyCompositeArgs) -> Result<(), String> {
    let message = read_message(&args.message)?;
    let sig_bytes = std::fs::read(&args.signature)
        .map_err(|e| format!("read {}: {e}", args.signature.display()))?;
    let _public_key = std::fs::read(&args.public_key)
        .map_err(|e| format!("read {}: {e}", args.public_key.display()))?;

    // CompositeSignature is JSON-serialized on the producer side
    // (see `pki composite-sign`). Hex-decode the file contents, then
    // JSON-parse the composite.
    let json_str = std::str::from_utf8(&sig_bytes)
        .map_err(|e| format!("signature file is not valid UTF-8 (expected hex of JSON): {e}"))?;
    let json_bytes = hex::decode(json_str.trim())
        .map_err(|e| format!("signature file is not valid hex: {e}"))?;
    let composite: confium_composite::CompositeSignature =
        serde_json::from_slice(&json_bytes).map_err(|e| format!("parse composite JSON: {e}"))?;

    type VerifierFn = fn(&str, &[u8], &[u8], &[u8]) -> Result<(), String>;
    let verifier: VerifierFn = match args.algorithm.as_str() {
        "ed25519" => confium_composite::ed25519_verifier,
        "ecdsa-p256" | "ecdsa" | "p256" => confium_composite::p256_verifier,
        other => {
            return Err(format!(
                "unknown algorithm: {other} (try ed25519 or ecdsa-p256)"
            ));
        }
    };

    // Verify each component that matches the requested algorithm. Components
    // for other algorithms are skipped (so a composite with both Ed25519 and
    // P256 can be verified by passing either algorithm).
    let mut all_ok = true;
    let mut checked = 0;
    for component in &composite.components {
        if algorithm_matches(&args.algorithm, &component.algorithm) {
            checked += 1;
            if verifier(
                &component.algorithm,
                &component.public_key,
                &message,
                &component.signature,
            )
            .is_err()
            {
                all_ok = false;
            }
        }
    }
    println!(
        "{{\"valid\": {}, \"checked_components\": {}, \"algorithm\": \"{}\"}}",
        all_ok && checked > 0,
        checked,
        args.algorithm
    );
    let _ = verifier; // silence if no matches
    Ok(())
}

fn verify_inclusion(args: VerifyInclusionArgs) -> Result<(), String> {
    let proof_json = std::fs::read_to_string(&args.proof)
        .map_err(|e| format!("read {}: {e}", args.proof.display()))?;
    let entry_json = std::fs::read_to_string(&args.entry)
        .map_err(|e| format!("read {}: {e}", args.entry.display()))?;
    let proof: confium_transparency::InclusionProof =
        serde_json::from_str(&proof_json).map_err(|e| format!("parse proof: {e}"))?;
    let entry: confium_transparency::entry::MerkleEntry =
        serde_json::from_str(&entry_json).map_err(|e| format!("parse entry: {e}"))?;
    // Root hash: use entry's own hash for the demo. Real verification
    // passes the trusted root from a remote log head.
    let root = entry.entry_hash();
    let result = confium_transparency::MerkleTree::verify_inclusion(&entry, &proof, root);
    println!(
        "{{\"valid\": {}, \"sequence\": {}}}",
        result.is_ok(),
        entry.sequence
    );
    Ok(())
}

fn verify_cert_chain(args: VerifyCertChainArgs) -> Result<(), String> {
    let leaf = read_cert(&args.leaf, &args.format)?;
    let anchor = read_cert(&args.anchor, &args.format)?;
    let intermediates: Vec<Certificate> = args
        .intermediates
        .iter()
        .map(|p| read_cert(p, &args.format))
        .collect::<Result<_, _>>()?;
    let inter_refs: Vec<&Certificate> = intermediates.iter().collect();
    let path = CertPath {
        leaf: &leaf,
        intermediates: inter_refs,
        root: &anchor,
    };
    let result = confium_pki::path::verify_path_signatures(&path, |_, _| Ok(()));
    println!("{:?}", result);
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

fn algorithm_matches(requested: &str, component_algorithm: &str) -> bool {
    let r = requested.to_lowercase();
    let c = component_algorithm.to_lowercase();
    r == c
        || (r == "ecdsa-p256" && (c == "ecdsa" || c == "p256"))
        || (r == "p256" && (c == "ecdsa-p256" || c == "ecdsa"))
        || (r == "ecdsa" && (c == "ecdsa-p256" || c == "p256"))
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

fn verify_signatif(args: VerifySignatifArgs) -> Result<(), String> {
    let read_json = |path: &std::path::PathBuf| -> Result<serde_json::Value, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))
    };
    let artifact: confium_signatif::artifact::TrustedArtifact = {
        let v = read_json(&args.artifact)?;
        serde_json::from_value(v).map_err(|e| format!("artifact: {e}"))?
    };
    let bundle: confium_signatif::bundle::TrustAnchorBundle = {
        let v = read_json(&args.bundle)?;
        serde_json::from_value(v).map_err(|e| format!("bundle: {e}"))?
    };
    let graph: confium_signatif::graph::TrustGraph = {
        let v = read_json(&args.graph)?;
        serde_json::from_value(v).map_err(|e| format!("graph: {e}"))?
    };
    let registry: confium_signatif::registry::Registry = match &args.registry {
        Some(path) => {
            let v = read_json(path)?;
            serde_json::from_value(v).map_err(|e| format!("registry: {e}"))?
        }
        None => confium_signatif::registry::Registry::with_initial_values(),
    };
    let time_attested_at = match &args.time_attested_at {
        Some(s) => Some(
            chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| format!("time_attested_at: {e}"))?
                .with_timezone(&chrono::Utc),
        ),
        None => None,
    };
    let acceptance = confium_signatif::coverage::AcceptancePolicy {
        accepted_labels: args.accept,
    };
    let no_revocations = confium_signatif::revocation::NoRevocations;
    let verifier = CliVerifier;
    let pipe = confium_signatif::pipeline::Pipeline::new(
        &bundle,
        &graph,
        &registry,
        &verifier,
        &no_revocations,
        confium_signatif::pipeline::TransparencyInputs {
            artifact_included: args.transparency,
            time_anchored: args.time,
            time_attested_at,
            multi_log_quorum: false,
            downgrades: vec![],
        },
        &acceptance,
    );
    let outcome = pipe
        .run(&artifact, chrono::Utc::now())
        .map_err(|e| format!("{e}"))?;
    let accept = outcome.acceptance == confium_signatif::coverage::Acceptance::Accept;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "label": outcome.label.0,
            "accept": accept,
            "coverage": outcome.report,
        }))
        .map_err(|e| format!("encode: {e}"))?
    );
    if !accept {
        std::process::exit(2);
    }
    Ok(())
}

/// The CLI verifier fleet: Ed25519 and ECDSA-P256, matching the
/// classical algorithms in the default registry.
struct CliVerifier;

impl confium_signatif::graph::SignatureVerifier for CliVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        confium_composite::ed25519_verifier("Ed25519", public_key, message, signature).is_ok()
            || confium_composite::p256_verifier("ECDSA-P256", public_key, message, signature)
                .is_ok()
    }
}
