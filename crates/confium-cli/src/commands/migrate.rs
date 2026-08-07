// `confium migrate` — migration toolkit for single-key → threshold transitions.

use crate::cli::{MigrateAction, MigrateArgs};
use confium_tc_frost_p256::p256;
use confium_tc_frost_p256::p256::elliptic_curve::PrimeField;
use confium_tc_frost_p256::{keys, shamir};
use serde_json::json;

pub fn run(args: MigrateArgs) {
    let code = match args.action {
        MigrateAction::SingleToThreshold(sub) => {
            migrate_single_to_threshold(&sub.secret, sub.threshold, sub.party_count, sub.out.as_deref())
        }
        MigrateAction::Inspect(sub) => inspect_secret(&sub.secret),
    };
    if code != 0 {
        std::process::exit(code);
    }
}

fn migrate_single_to_threshold(
    secret_hex: &str,
    threshold: u32,
    party_count: u32,
    out: Option<&str>,
) -> i32 {
    let secret_bytes = match decode_hex_or_file(secret_hex) {
        Ok(b) => {
            if b.len() != 32 {
                eprintln!("Error: secret must be 32 bytes, got {}", b.len());
                return 1;
            }
            b
        }
        Err(e) => {
            eprintln!("Error reading secret: {e}");
            return 1;
        }
    };

    let secret = match bytes_to_scalar(&secret_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    let public_key = keys::public_key_for(&secret);
    let shares = shamir::split_secret(&secret, threshold, party_count);

    let share_json: Vec<serde_json::Value> = shares
        .iter()
        .map(|s| {
            json!({
                "party_idx": s.x,
                "share_hex": hex::encode(scalar_to_bytes(&s.y)),
            })
        })
        .collect();

    let pk_bytes = keys::public_key_sec1(&public_key);
    let output = json!({
        "scheme": "FROST-P256",
        "threshold": threshold,
        "party_count": party_count,
        "public_key_sec1_hex": hex::encode(&pk_bytes),
        "shares": share_json,
    });

    let formatted = serde_json::to_string_pretty(&output).unwrap();

    match out {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &formatted) {
                eprintln!("Error writing output: {e}");
                return 1;
            }
            eprintln!("Wrote {party_count} shares (T={threshold}) to {path}");
        }
        None => println!("{formatted}"),
    }
    0
}

fn inspect_secret(secret_hex: &str) -> i32 {
    let secret_bytes = match decode_hex_or_file(secret_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading secret: {e}");
            return 1;
        }
    };

    let public = match bytes_to_scalar(&secret_bytes) {
        Ok(s) => keys::public_key_for(&s),
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    let pk_bytes = keys::public_key_sec1(&public);
    let info = json!({
        "secret_size_bytes": secret_bytes.len(),
        "curve": "P-256",
        "public_key_sec1_hex": hex::encode(&pk_bytes),
        "public_key_uncompressed": pk_bytes.len() == 65,
    });

    println!("{}", serde_json::to_string_pretty(&info).unwrap());
    0
}

fn decode_hex_or_file(input: &str) -> Result<Vec<u8>, String> {
    if let Some(path) = input.strip_prefix('@') {
        std::fs::read(path).map_err(|e| format!("read {path}: {e}"))
    } else {
        hex::decode(input).map_err(|e| format!("hex decode: {e}"))
    }
}

fn bytes_to_scalar(bytes: &[u8]) -> Result<p256::Scalar, String> {
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let arr: [u8; 32] = bytes.try_into().map_err(|_| "wrong length".to_string())?;
    let ct = p256::Scalar::from_repr(arr.into());
    Option::<p256::Scalar>::from(ct).ok_or_else(|| "invalid scalar (out of range)".into())
}

fn scalar_to_bytes(s: &p256::Scalar) -> [u8; 32] {
    s.to_repr().into()
}
