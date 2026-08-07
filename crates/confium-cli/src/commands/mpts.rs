//! `confium mpts` — NIST MPTS test harness subcommand.

use crate::cli::MptsArgs;
use std::io::Write;

pub fn run(args: MptsArgs) {
    let result: Result<(), String> = run_harness(args);
    if let Err(e) = result {
        eprintln!("confium mpts: {e}");
        std::process::exit(1);
    }
}

fn run_harness(args: MptsArgs) -> Result<(), String> {
    use sha2::{Digest, Sha256};

    let mut results = Vec::with_capacity(args.rounds as usize);
    let test_message = b"mpts-test-vector";

    eprintln!("Running {rounds} rounds of {scheme} T={threshold} N={n}",
        rounds = args.rounds,
        scheme = args.scheme,
        threshold = args.threshold,
        n = args.party_count);

    for round in 0..args.rounds {
        let start = std::time::Instant::now();

        let (public_key, sig) = match args.scheme.as_str() {
            "cmp20" => {
                let kg = confium_tc_cmp20::inprocess::keygen(args.threshold, args.party_count as usize)
                    .map_err(|e| e.to_string())?;
                let sig = confium_tc_cmp20::inprocess::sign(&kg.shares, args.threshold, test_message)
                    .map_err(|e| e.to_string())?;
                (kg.public_key, sig)
            }
            "gg18" => {
                let kg = confium_tc_gg18::inprocess::keygen(args.threshold, args.party_count as usize)
                    .map_err(|e| e.to_string())?;
                let sig = confium_tc_gg18::inprocess::sign(&kg.shares, args.threshold, test_message)
                    .map_err(|e| e.to_string())?;
                (kg.public_key, sig)
            }
            "frost-p256" => {
                let kp = confium_tc_frost_p256::generate_keypair();
                let signed = confium_tc_frost_p256::sign_message(&kp, test_message)
                    .map_err(|e| e.to_string())?;
                (kp.to_verifying_key().to_sec1_bytes().to_vec(), signed.fixed_bytes.to_vec())
            }
            "frost-ed25519" => {
                let shares = confium_tc_frost_ed25519::inprocess::keygen(args.threshold, args.party_count as usize)
                    .map_err(|e| e.to_string())?;
                let sig = confium_tc_frost_ed25519::inprocess::sign(&shares, args.threshold, test_message)
                    .map_err(|e| e.to_string())?;
                (vec![], sig)
            }
            other => return Err(format!("unknown scheme: {other}")),
        };

        let elapsed = start.elapsed();
        results.push(serde_json::json!({
            "round": round,
            "scheme": args.scheme,
            "threshold": args.threshold,
            "party_count": args.party_count,
            "elapsed_ms": elapsed.as_millis(),
            "public_key_length": public_key.len(),
            "signature_length": sig.len(),
            "message_hash": hex::encode(Sha256::digest(test_message)),
        }));
    }

    let report = serde_json::json!({
        "scheme": args.scheme,
        "threshold": args.threshold,
        "party_count": args.party_count,
        "rounds": args.rounds,
        "results": results,
    });

    let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    match &args.report {
        Some(path) => {
            std::fs::write(path, json.as_bytes()).map_err(|e| format!("write {path}: {e}"))?;
            eprintln!("Report written to {path}");
        }
        None => {
            std::io::stdout().write_all(json.as_bytes()).map_err(|e| e.to_string())?;
            println!();
        }
    }

    Ok(())
}
