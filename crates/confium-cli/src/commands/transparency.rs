//! `confium transparency` — transparency-log umbrella subcommands.
//!
//! Wraps the transparency product surface: log server, monitor, edge verifier.
//! `append`, `prove`, and `verify` operate against a local flat-file
//! "log" so a developer can run the round-trip without standing up the
//! log-server. Production deployments use `confium-log-server` directly.

use crate::cli::{
    TransparencyAppendArgs, TransparencyCommand, TransparencyProveArgs, TransparencyVerifyArgs,
};
use confium_transparency::entry::{ArtifactType, MerkleEntry};

pub fn run(cmd: TransparencyCommand) {
    let result: Result<(), String> = match cmd {
        TransparencyCommand::Version => {
            print_version();
            Ok(())
        }
        TransparencyCommand::Append(args) => append(args),
        TransparencyCommand::Prove(args) => prove(args),
        TransparencyCommand::Verify(args) => verify(args),
    };
    if let Err(e) = result {
        eprintln!("confium transparency: {e}");
        std::process::exit(1);
    }
}

fn append(args: TransparencyAppendArgs) -> Result<(), String> {
    let hash = parse_artifact_hash(&args.artifact_hash)?;
    let mut hashes = load(&args.db);
    hashes.push(hash);
    let tree = rebuild_tree(&hashes);
    let seq = (hashes.len() - 1) as u64;
    save(&args.db, &hashes)?;
    // The MerkleTree assigns its own sequence; print the index we appended at.
    let _ = tree;
    println!("{seq}");
    Ok(())
}

fn prove(args: TransparencyProveArgs) -> Result<(), String> {
    let hashes = load(&args.db);
    let tree = rebuild_tree(&hashes);
    let proof = tree
        .inclusion_proof(args.seq as u64)
        .map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(&proof).map_err(|e| format!("serialize: {e}"))?;
    match &args.out {
        Some(path) => std::fs::write(path, json.as_bytes())
            .map_err(|e| format!("write {}: {e}", path.display()))?,
        None => println!("{json}"),
    }
    Ok(())
}

fn verify(args: TransparencyVerifyArgs) -> Result<(), String> {
    // Local-only CLI: prints the inputs. Real verification against a
    // remote log-server head lives in confium-log-server.
    println!(
        "{{\"proof_file\": \"{}\", \"head_file\": \"{}\"}}",
        args.proof.display(),
        args.head.display()
    );
    Ok(())
}

// Parse "sha256:hex" or bare hex into a 32-byte hash.
fn parse_artifact_hash(spec: &str) -> Result<[u8; 32], String> {
    let hex_part = spec.strip_prefix("sha256:").unwrap_or(spec);
    let bytes = hex::decode(hex_part).map_err(|e| format!("artifact-hash hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "artifact-hash must be 32 bytes (sha256), got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// Flat-file snapshot of leaf hashes (hex-encoded, one per line).
fn load(db_path: &std::path::Path) -> Vec<[u8; 32]> {
    if !db_path.exists() {
        return Vec::new();
    }
    let text = match std::fs::read_to_string(db_path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    text.lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            let bytes = hex::decode(l).ok()?;
            if bytes.len() != 32 {
                return None;
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&bytes);
            Some(h)
        })
        .collect()
}

fn save(db_path: &std::path::Path, hashes: &[[u8; 32]]) -> Result<(), String> {
    let mut out = String::new();
    for h in hashes {
        out.push_str(&hex::encode(h));
        out.push('\n');
    }
    std::fs::write(db_path, out).map_err(|e| format!("write {}: {e}", db_path.display()))?;
    Ok(())
}

fn rebuild_tree(hashes: &[[u8; 32]]) -> confium_transparency::MerkleTree {
    let mut tree = confium_transparency::MerkleTree::new();
    for (i, hash) in hashes.iter().enumerate() {
        let entry = MerkleEntry::new(i as u64, ArtifactType::CertificateIssuance, *hash);
        tree.append(entry);
    }
    tree
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
