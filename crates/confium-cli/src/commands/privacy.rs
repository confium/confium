//! `confium privacy` — privacy primitives umbrella subcommands.

use crate::cli::{PrivacyCommand, PrivacyDpArgs, PrivacyPsiArgs};

pub fn run(cmd: PrivacyCommand) {
    let result: Result<(), String> = match cmd {
        PrivacyCommand::Version => {
            print_version();
            Ok(())
        }
        PrivacyCommand::Psi(args) => psi(args),
        PrivacyCommand::Dp(args) => dp(args),
        PrivacyCommand::Mpc => Err(
            "confium privacy mpc: multi-process orchestration required; see https://www.confium.org/privacy/".into(),
        ),
    };
    if let Err(e) = result {
        eprintln!("confium privacy: {e}");
        std::process::exit(1);
    }
}

fn psi(args: PrivacyPsiArgs) -> Result<(), String> {
    let set_a = read_set(&args.set_a)?;
    let set_b = read_set(&args.set_b)?;
    let salt = read_salt(&args.salt)?;

    if args.cardinality_only {
        let count =
            confium_privacy::privacy_and_dist_patterns::psi_cardinality(&set_a, &set_b, &salt);
        println!("{count}");
    } else {
        let intersection =
            confium_privacy::privacy_and_dist_patterns::psi_hash_based(&set_a, &set_b, &salt);
        for item in intersection {
            if let Ok(s) = std::str::from_utf8(&item) {
                println!("{s}");
            } else {
                println!("{}", hex::encode(&item));
            }
        }
    }
    Ok(())
}

fn dp(args: PrivacyDpArgs) -> Result<(), String> {
    let perturbed = match args.distribution.as_str() {
        "laplace" => confium_privacy::privacy_and_dist_patterns::dp_query(
            args.value,
            args.sensitivity,
            args.epsilon,
        ),
        "gaussian" => {
            let noise = confium_privacy::privacy_and_dist_patterns::gaussian_noise(
                args.sensitivity,
                args.epsilon,
                args.delta,
            );
            args.value + noise
        }
        other => {
            return Err(format!(
                "unknown distribution: {other} (try laplace or gaussian)"
            ));
        }
    };
    println!(
        "{{\"original\": {}, \"perturbed\": {}, \"epsilon\": {}, \"distribution\": \"{}\"}}",
        args.value, perturbed, args.epsilon, args.distribution
    );
    Ok(())
}

fn read_set(path: &std::path::Path) -> Result<Vec<Vec<u8>>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(text
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.as_bytes().to_vec())
        .collect())
}

fn read_salt(path: &std::path::Path) -> Result<Vec<u8>, String> {
    if path.to_string_lossy() == "/dev/urandom" {
        // 16 bytes of fresh randomness for the demo.
        let mut buf = vec![0u8; 16];
        use std::io::Read;
        let mut f =
            std::fs::File::open("/dev/urandom").map_err(|e| format!("open /dev/urandom: {e}"))?;
        f.read_exact(&mut buf)
            .map_err(|e| format!("read /dev/urandom: {e}"))?;
        return Ok(buf);
    }
    std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))
}

fn print_version() {
    println!("confium-privacy: product umbrella");
    println!("  crates:");
    println!("    confium-privacy    (https://docs.rs/confium-privacy)");
    println!("    confium-crypto-zk  (https://docs.rs/confium-crypto-zk)");
    println!("    confium-crypto-vss (https://docs.rs/confium-crypto-vss)");
    println!("    confium-ring       (https://docs.rs/confium-ring)");
    println!();
    println!("  docs:    https://www.confium.org/privacy/");
    println!("  specs:   https://www.confium.org/specs/PRODUCTS");
    println!("  quickstart: https://www.confium.org/privacy/quickstart/");
}
