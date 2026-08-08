//! Fuzz target: composite signature verification.
//!
//! Exercises the composite verifier with arbitrary byte input split
//! into message + signature components. The target must not panic.
//!
//! Run standalone (stable):
//!     cargo run --bin fuzz_composite_verify
//!
//! Integrate with cargo-fuzz (nightly) by wrapping in:
//!     libfuzzer_sys::fuzz_target!(|data: &[u8]| { composite_verify_target(data); });

use confium_composite::{ComponentSignature, CompositeSignature, ED25519, ed25519_verifier};

fn composite_verify_target(data: &[u8]) {
    if data.len() < 66 {
        return;
    }
    let pk_len = 32usize;
    let sig_len = 64usize;
    let (pk_bytes, rest) = data.split_at(pk_len);
    let (sig_bytes, msg) = rest.split_at(sig_len);

    let component = ComponentSignature {
        algorithm: ED25519.to_string(),
        public_key: pk_bytes.to_vec(),
        signature: sig_bytes.to_vec(),
    };
    let composite = CompositeSignature::new(vec![component]);

    let _ = composite.verify(msg, |alg, pk, m, sig| ed25519_verifier(alg, pk, m, sig));
}

fn main() {
    let mut rng_data = vec![0u8; 256];
    for round in 0..100_000u64 {
        for (i, b) in rng_data.iter_mut().enumerate() {
            *b = ((round * 31 + i as u64 * 17) & 0xFF) as u8;
        }
        composite_verify_target(&rng_data);
    }
    println!("composite_verify: 100000 rounds completed, no panics");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_input_does_not_panic() {
        composite_verify_target(&[0; 10]);
    }

    #[test]
    fn exact_boundary_does_not_panic() {
        composite_verify_target(&[0; 96]);
    }

    #[test]
    fn large_input_does_not_panic() {
        composite_verify_target(&[0xFF; 1024]);
    }
}
