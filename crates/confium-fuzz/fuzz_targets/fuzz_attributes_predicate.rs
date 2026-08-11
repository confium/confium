//! Fuzz target: attribute DSL parser + evaluator.
//!
//! Exercises the predicate DSL with adversarial input. The parser
//! has a depth guard (MAX_DSL_DEPTH = 32) that this target probes.
//! Parser or evaluator must not panic on any input — syntax errors
//! must surface as ParseError, not a panic.

use confium_attributes::{SignerAttributes, evaluate, parse};

fn attributes_predicate_target(data: &[u8]) {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };
    let predicate = match parse(s) {
        Ok(p) => p,
        Err(_) => return,
    };
    // Build a synthetic signer so the evaluator has something to walk.
    // Empty signers list also exercises the no-match path.
    let _ = evaluate(&predicate, &[]);
    let signer = SignerAttributes::new();
    let _ = evaluate(&predicate, &[&signer]);
}

fn main() {
    let mut rng_data = vec![0u8; 128];
    for round in 0..100_000u64 {
        for (i, b) in rng_data.iter_mut().enumerate() {
            *b = ((round * 29 + i as u64 * 7) & 0xFF) as u8;
        }
        attributes_predicate_target(&rng_data);
    }
    println!("attributes_predicate: 100000 rounds completed, no panics");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_does_not_panic() {
        attributes_predicate_target(&[]);
    }

    #[test]
    fn garbage_does_not_panic() {
        attributes_predicate_target(&[b'('; 64]);
        attributes_predicate_target(&[b'('; 1024]);
    }

    #[test]
    fn deeply_nested_does_not_panic() {
        // 256 nested and() calls — exceeds MAX_DSL_DEPTH (32), should
        // return DepthExceeded, not panic.
        let mut s = String::new();
        for _ in 0..256 {
            s.push_str("and(");
        }
        s.push_str("any(\"x\")");
        for _ in 0..256 {
            s.push(')');
        }
        attributes_predicate_target(s.as_bytes());
    }

    #[test]
    fn valid_predicate_does_not_panic() {
        let s = br#"and(any("dept"), min_count("role", 2))"#;
        attributes_predicate_target(s);
    }
}
