//! `confium tc` — threshold-cryptography subcommands.
//!
//! Wraps the in-process DKG + sign drivers from `confium-tc-cmp20` and
//! `confium-tc-gg18`, plus the FROST-P256 Shamir primitives and
//! ElGamal-P256 threshold encryption. Output is JSON to stdout (or
//! `--out FILE`) so it composes with `jq`, shell pipes, and other
//! CLIs.

use std::io::{Read, Write};
use std::path::Path;

use crate::cli::{
    TcCommand, TcEncapsulateArgs, TcKeygenArgs, TcKeypairArgs, TcSignArgs, TcSplitArgs,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ShareEnvelope {
    scheme: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    threshold: Option<u32>,
    party_count: u32,
    public_key: String,
    shares: Vec<String>,
}

pub fn run(cmd: TcCommand) {
    let result: Result<(), String> = match cmd {
        TcCommand::Keygen(args) => keygen(args),
        TcCommand::Sign(args) => sign(args),
        TcCommand::Keypair(args) => keypair(args),
        TcCommand::Split(args) => split(args),
        TcCommand::Encapsulate(args) => encapsulate(args),
    };
    if let Err(e) = result {
        eprintln!("confium tc: {e}");
        std::process::exit(1);
    }
}

fn keygen(args: TcKeygenArgs) -> Result<(), String> {
    let (public_key, shares): (Vec<u8>, Vec<Vec<u8>>) = match args.scheme.as_str() {
        "cmp20" => {
            let kg = confium_tc_cmp20::inprocess::keygen(args.threshold, args.party_count as usize)
                .map_err(|e| e.to_string())?;
            (kg.public_key, kg.shares)
        }
        "gg18" => {
            let kg = confium_tc_gg18::inprocess::keygen(args.threshold, args.party_count as usize)
                .map_err(|e| e.to_string())?;
            (kg.public_key, kg.shares)
        }
        other => return Err(format!("unknown scheme: {other}")),
    };

    let envelope = ShareEnvelope {
        scheme: args.scheme.to_uppercase(),
        threshold: Some(args.threshold),
        party_count: args.party_count,
        public_key: hex::encode(&public_key),
        shares: shares.iter().map(hex::encode).collect(),
    };
    let json = serde_json::to_string_pretty(&envelope).map_err(|e| format!("serialize: {e}"))?;
    write_output(&args.out, json.as_bytes())
}

fn sign(args: TcSignArgs) -> Result<(), String> {
    let shares_json =
        std::fs::read_to_string(&args.shares).map_err(|e| format!("read {}: {e}", args.shares))?;
    let envelope: ShareEnvelope =
        serde_json::from_str(&shares_json).map_err(|e| format!("parse {}: {e}", args.shares))?;

    let share_blobs: Vec<Vec<u8>> = envelope
        .shares
        .iter()
        .map(|h| hex::decode(h).map_err(|e| format!("share hex: {e}")))
        .collect::<Result<_, _>>()?;

    let message = read_message(&args.message)?;

    let sig: Vec<u8> = match args.scheme.as_str() {
        "cmp20" => confium_tc_cmp20::inprocess::sign(&share_blobs, args.threshold, &message)
            .map_err(|e| e.to_string())?,
        "gg18" => confium_tc_gg18::inprocess::sign(&share_blobs, args.threshold, &message)
            .map_err(|e| e.to_string())?,
        other => return Err(format!("unknown scheme: {other}")),
    };

    write_output(&args.out, &sig)
}

fn keypair(args: TcKeypairArgs) -> Result<(), String> {
    use confium_tc_frost_p256::generate_keypair;
    let kp = generate_keypair();
    let sk: [u8; 32] = kp.to_signing_key().to_bytes().into();
    let pk = kp.to_verifying_key().to_sec1_bytes();
    let envelope = serde_json::json!({
        "private_key": hex::encode(sk),
        "public_key": hex::encode(pk),
    });
    let json = serde_json::to_string_pretty(&envelope).map_err(|e| format!("serialize: {e}"))?;
    write_output(&args.out, json.as_bytes())
}

fn split(args: TcSplitArgs) -> Result<(), String> {
    use confium_tc_frost_p256::{
        scalar::{scalar_from_bytes, scalar_to_bytes},
        shamir::{Share, split_secret},
    };
    let secret_bytes = read_hex_or_file(&args.secret)?;
    if secret_bytes.len() != 32 {
        return Err(format!(
            "secret must be 32 bytes, got {}",
            secret_bytes.len()
        ));
    }
    let arr: [u8; 32] = secret_bytes.as_slice().try_into().unwrap();
    let secret =
        scalar_from_bytes(&arr).ok_or_else(|| "secret is not a valid P-256 scalar".to_string())?;
    let shares = split_secret(&secret, args.threshold, args.party_count);
    let envelope = serde_json::json!({
        "threshold": args.threshold,
        "party_count": args.party_count,
        "shares": shares.iter().map(|s| {
            let y_bytes: [u8; 32] = scalar_to_bytes(&s.y).into();
            serde_json::json!({"x": s.x, "y_bytes": hex::encode(y_bytes)})
        }).collect::<Vec<_>>(),
    });
    let json = serde_json::to_string_pretty(&envelope).map_err(|e| format!("serialize: {e}"))?;
    write_output(&args.out, json.as_bytes())
}

fn encapsulate(args: TcEncapsulateArgs) -> Result<(), String> {
    use confium_tc_elgamal_p256::{PublicKey, encapsulate};
    let pk_bytes = read_hex_or_file(&args.public_key)?;
    let pk = PublicKey { bytes: pk_bytes };
    let (ct, ss) = encapsulate(&pk).map_err(|e| e.to_string())?;
    let envelope = serde_json::json!({
        "ciphertext": {
            "c1": hex::encode(ct.c1),
            "c2": hex::encode(ct.c2),
        },
        "shared_secret": hex::encode(ss),
    });
    let json = serde_json::to_string_pretty(&envelope).map_err(|e| format!("serialize: {e}"))?;
    write_output(&args.out, json.as_bytes())
}

fn read_message(path: &Option<String>) -> Result<Vec<u8>, String> {
    match path {
        Some(p) => std::fs::read(p).map_err(|e| format!("read {p}: {e}")),
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("stdin: {e}"))?;
            Ok(buf)
        }
    }
}

fn read_hex_or_file(input: &str) -> Result<Vec<u8>, String> {
    if let Some(stripped) = input.strip_prefix('@') {
        let raw = std::fs::read(stripped).map_err(|e| format!("read {stripped}: {e}"))?;
        // Treat file contents as hex if it ends in whitespace, else binary.
        let trimmed = String::from_utf8_lossy(&raw).trim().to_string();
        if trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            hex::decode(&trimmed).map_err(|e| format!("hex: {e}"))
        } else {
            Ok(raw)
        }
    } else {
        hex::decode(input).map_err(|e| format!("hex: {e}"))
    }
}

fn write_output(out: &Option<String>, bytes: &[u8]) -> Result<(), String> {
    match out {
        Some(path) => {
            if let Some(parent) = Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
                }
            }
            std::fs::write(path, bytes).map_err(|e| format!("write {path}: {e}"))?;
        }
        None => {
            std::io::stdout()
                .write_all(bytes)
                .map_err(|e| format!("stdout: {e}"))?;
            // Add a trailing newline for terminal friendliness if the
            // output looks like JSON.
            if bytes.starts_with(b"{") {
                let _ = std::io::stdout().write_all(b"\n");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_hex_or_file_accepts_hex_directly() {
        let bytes = read_hex_or_file("deadbeef").unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn read_hex_or_file_rejects_bad_hex() {
        assert!(read_hex_or_file("nothex").is_err());
    }

    #[test]
    fn write_output_writes_file_with_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deep/out.json");
        write_output(&Some(path.to_str().unwrap().to_string()), b"hello").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
    }
}
