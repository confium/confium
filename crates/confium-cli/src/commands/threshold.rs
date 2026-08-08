//! `confium threshold` — threshold-signing umbrella subcommands.
//!
//! Wraps the threshold product surface: DKG, signing, share management.
//! The full implementation lives in `confium-tc-cmp20`, `confium-tc-gg18`,
//! `confium-tc-frost-p256`, `confium-tc-frost-ed25519`, and the coordinator.

use crate::cli::{
    ThresholdCommand, ThresholdDkgArgs, ThresholdMigrateSharesArgs, ThresholdRefreshArgs,
    ThresholdSignArgs,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ShareEnvelope {
    scheme: String,
    threshold: u32,
    party_count: u32,
    public_key: String,
    shares: Vec<String>,
}

pub fn run(cmd: ThresholdCommand) {
    let result: Result<(), String> = match cmd {
        ThresholdCommand::Version => {
            print_version();
            Ok(())
        }
        ThresholdCommand::Dkg(args) => dkg(args),
        ThresholdCommand::Sign(args) => sign(args),
        ThresholdCommand::Refresh(args) => refresh(args),
        ThresholdCommand::Recover => Err(
            "confium threshold recover: recovery API is in development. See https://www.confium.org/threshold/".into(),
        ),
        ThresholdCommand::MigrateShares(args) => migrate_shares(args),
    };
    if let Err(e) = result {
        eprintln!("confium threshold: {e}");
        std::process::exit(1);
    }
}

// Legacy 0.2.x share file shape.
#[derive(Deserialize)]
struct LegacyShare {
    x: serde_json::Number,
    y: String,
    #[serde(default)]
    public_key: Option<String>,
}

fn migrate_shares(args: ThresholdMigrateSharesArgs) -> Result<(), String> {
    let input_json = std::fs::read_to_string(&args.input)
        .map_err(|e| format!("read {}: {e}", args.input.display()))?;

    // 0.2.x share files were either a single object or an array of objects.
    // Handle both shapes.
    let legacy_shares: Vec<LegacyShare> = if input_json.trim_start().starts_with('[') {
        serde_json::from_str(&input_json)
            .map_err(|e| format!("parse legacy array: {e}"))?
    } else {
        let single: LegacyShare = serde_json::from_str(&input_json)
            .map_err(|e| format!("parse legacy object: {e}"))?;
        vec![single]
    };

    // Synthesize a public key if not provided. In a real migration you
    // would already have the joint public key from your DKG ceremony;
    // for the migration tool we preserve it if present, otherwise emit
    // a placeholder and warn.
    let public_key = legacy_shares
        .iter()
        .find_map(|s| s.public_key.clone())
        .unwrap_or_else(|| {
            eprintln!("warning: no public_key in legacy file; using placeholder. Replace with the actual joint public key.");
            "00".repeat(33)
        });

    // Encode each legacy share as a hex string of the JSON {"x":..., "y":...}.
    // The modern share envelope stores opaque blobs; the scheme crate
    // decides how to decode them. For CMP20 the underlying format is
    // scheme-specific.
    let shares: Vec<String> = legacy_shares
        .iter()
        .map(|s| {
            let x = s.x.as_u64().unwrap_or(0);
            hex::encode(&[
                ((x >> 56) & 0xff) as u8,
                ((x >> 48) & 0xff) as u8,
                ((x >> 40) & 0xff) as u8,
                ((x >> 32) & 0xff) as u8,
                ((x >> 24) & 0xff) as u8,
                ((x >> 16) & 0xff) as u8,
                ((x >> 8) & 0xff) as u8,
                (x & 0xff) as u8,
            ]) + &s.y
        })
        .collect();

    let envelope = ShareEnvelope {
        scheme: args.scheme.clone(),
        threshold: args.threshold,
        party_count: args.parties,
        public_key,
        shares,
    };

    let json = serde_json::to_string_pretty(&envelope)
        .map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(&args.out, json.as_bytes())
        .map_err(|e| format!("write {}: {e}", args.out.display()))?;
    eprintln!("migrated {} shares → {}", legacy_shares.len(), args.out.display());
    Ok(())
}

fn refresh(args: ThresholdRefreshArgs) -> Result<(), String> {
    let shares_json = std::fs::read_to_string(&args.shares)
        .map_err(|e| format!("read {}: {e}", args.shares.display()))?;
    let envelope: ShareEnvelope = serde_json::from_str(&shares_json)
        .map_err(|e| format!("parse {}: {e}", args.shares.display()))?;

    if envelope.scheme.to_uppercase() != "CMP20" {
        return Err(format!(
            "refresh only supports CMP20; got scheme '{}'",
            envelope.scheme
        ));
    }

    let share_blobs: Vec<Vec<u8>> = envelope
        .shares
        .iter()
        .map(|h| hex::decode(h).map_err(|e| format!("share hex: {e}")))
        .collect::<Result<_, _>>()?;

    // Generate refresh contributions for each party.
    let contributions =
        confium_tc_cmp20::refresh::generate_refresh_contributions(envelope.threshold, envelope.party_count);

    // Verify zero-sum invariant (sum of all contributions = 0).
    if !confium_tc_cmp20::refresh::verify_zero_sum(&contributions) {
        return Err("refresh contributions failed zero-sum verification".into());
    }

    // Apply each contribution to the corresponding share.
    let refreshed: Vec<String> = share_blobs
        .iter()
        .enumerate()
        .map(|(i, share)| {
            let updated =
                confium_tc_cmp20::refresh::apply_to_share(share, i as u32, &contributions);
            hex::encode(&updated)
        })
        .collect();

    let new_envelope = ShareEnvelope {
        scheme: envelope.scheme,
        threshold: envelope.threshold,
        party_count: envelope.party_count,
        public_key: envelope.public_key, // unchanged
        shares: refreshed,
    };
    let json = serde_json::to_string_pretty(&new_envelope)
        .map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(&args.out, json.as_bytes())
        .map_err(|e| format!("write {}: {e}", args.out.display()))?;
    eprintln!(
        "refreshed {} shares → {} (public key unchanged)",
        new_envelope.shares.len(),
        args.out.display()
    );
    Ok(())
}

fn dkg(args: ThresholdDkgArgs) -> Result<(), String> {
    let scheme = args.scheme.as_str();
    let (public_key, shares): (Vec<u8>, Vec<Vec<u8>>) = match scheme {
        "cmp20" => {
            let kg = confium_tc_cmp20::inprocess::keygen(args.threshold, args.parties as usize)
                .map_err(|e| e.to_string())?;
            (kg.public_key, kg.shares)
        }
        "gg18" => {
            let kg = confium_tc_gg18::inprocess::keygen(args.threshold, args.parties as usize)
                .map_err(|e| e.to_string())?;
            (kg.public_key, kg.shares)
        }
        other => return Err(format!("unknown scheme: {other} (try cmp20 or gg18)")),
    };

    let envelope = ShareEnvelope {
        scheme: scheme.to_uppercase(),
        threshold: args.threshold,
        party_count: args.parties,
        public_key: hex::encode(&public_key),
        shares: shares.iter().map(hex::encode).collect(),
    };
    let json =
        serde_json::to_string_pretty(&envelope).map_err(|e| format!("serialize: {e}"))?;
    match &args.out {
        Some(path) => std::fs::write(path, json.as_bytes())
            .map_err(|e| format!("write {}: {e}", path.display()))?,
        None => println!("{json}"),
    }
    Ok(())
}

fn sign(args: ThresholdSignArgs) -> Result<(), String> {
    let shares_json = std::fs::read_to_string(&args.shares)
        .map_err(|e| format!("read {}: {e}", args.shares.display()))?;
    let envelope: ShareEnvelope = serde_json::from_str(&shares_json)
        .map_err(|e| format!("parse {}: {e}", args.shares.display()))?;

    let share_blobs: Vec<Vec<u8>> = envelope
        .shares
        .iter()
        .map(|h| hex::decode(h).map_err(|e| format!("share hex: {e}")))
        .collect::<Result<_, _>>()?;

    let message = read_message(&args.message)?;

    let sig: Vec<u8> = match envelope.scheme.to_lowercase().as_str() {
        "cmp20" => confium_tc_cmp20::inprocess::sign(&share_blobs, envelope.threshold, &message)
            .map_err(|e| e.to_string())?,
        "gg18" => confium_tc_gg18::inprocess::sign(&share_blobs, envelope.threshold, &message)
            .map_err(|e| e.to_string())?,
        other => return Err(format!("unknown scheme in envelope: {other}")),
    };

    let sig_hex = hex::encode(&sig);
    match &args.out {
        Some(path) => std::fs::write(path, sig_hex.as_bytes())
            .map_err(|e| format!("write {}: {e}", path.display()))?,
        None => println!("{sig_hex}"),
    }
    Ok(())
}

fn read_message(spec: &str) -> Result<Vec<u8>, String> {
    if let Some(path) = spec.strip_prefix('@') {
        std::fs::read(path).map_err(|e| format!("read message {path}: {e}"))
    } else {
        Ok(spec.as_bytes().to_vec())
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
