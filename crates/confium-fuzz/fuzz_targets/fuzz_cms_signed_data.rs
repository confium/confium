//! Fuzz target: CMS SignedData JSON deserialization + verification.
//!
//! Exercises the CMS verifier with adversarial JSON. The target
//! must not panic on any byte sequence — malformed JSON should
//! surface as a serde_json::Error, not a panic.

use confium_pki::cms::{SignedData, verify_signed_data};

fn cms_signed_data_target(data: &[u8]) {
    let sd: SignedData = match serde_json::from_slice(data) {
        Ok(sd) => sd,
        Err(_) => return,
    };
    // Verifier callback always returns Ok; the fuzz surface is the
    // verifier's internal logic (resolve_signer_certificate, signed-bytes
    // computation, etc.) not the callback's correctness.
    let _ = verify_signed_data(&sd, b"", |_signer_idx, _pk, _data, _sig| Ok(()));
}

fn main() {
    let mut rng_data = vec![0u8; 256];
    for round in 0..100_000u64 {
        for (i, b) in rng_data.iter_mut().enumerate() {
            *b = ((round * 41 + i as u64 * 19) & 0xFF) as u8;
        }
        cms_signed_data_target(&rng_data);
    }
    println!("cms_signed_data: 100000 rounds completed, no panics");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_does_not_panic() {
        cms_signed_data_target(&[]);
    }

    #[test]
    fn garbage_does_not_panic() {
        cms_signed_data_target(&[0xFF; 64]);
    }

    #[test]
    fn valid_minimal_signed_data_does_not_panic() {
        let json = br#"{
            "version": 1,
            "digest_algorithms": [],
            "encap_content_info": {"content_type": "1.2.840.113549.1.7.1", "content": null},
            "certificates": [],
            "signer_infos": []
        }"#;
        cms_signed_data_target(json);
    }

    #[test]
    fn malformed_json_does_not_panic() {
        cms_signed_data_target(b"{not valid json");
        cms_signed_data_target(b"null");
        cms_signed_data_target(b"[]");
        cms_signed_data_target(br#"{"version": "not a number"}"#);
    }
}
