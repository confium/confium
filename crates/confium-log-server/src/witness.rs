//! Witness gossip protocol.
//!
//! A **witness** is an independent third party that countersigns
//! tree heads published by the log. Monitors verify that every
//! witness sees the same tree head for the same tree size — if
//! the log presents different heads to different witnesses, the
//! monitor detects the split.
//!
//! ## Wire format
//!
//! A witness signature is over:
//!
//! ```text
//! "ConfiumWitness/v1" || tree_size_be(8 bytes) || root_hash(32 bytes)
//! ```
//!
//! Witness IDs are arbitrary strings. A typical witness uses its
//! domain name (`witness.example.com`) so monitors can fetch the
//! witness's published policy separately.

use sha2::{Digest, Sha256};

/// Build the canonical signing message for a `(tree_size, root_hash)`
/// pair. Witnesses sign this; monitors verify it.
pub fn witness_signing_message(tree_size: u64, root_hash: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(b"ConfiumWitness/v1".len() + 8 + 32);
    msg.extend_from_slice(b"ConfiumWitness/v1");
    msg.extend_from_slice(&tree_size.to_be_bytes());
    msg.extend_from_slice(root_hash);
    msg
}

/// Convenience: SHA-256 of the signing message. Some witnesses sign
/// the digest; some sign the raw message. The monitor must know
/// which the witness uses (per the witness's published policy).
pub fn witness_signing_digest(tree_size: u64, root_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(witness_signing_message(tree_size, root_hash));
    let digest: [u8; 32] = h.finalize().into();
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_message_has_fixed_shape() {
        let root = [0xaa; 32];
        let prefix = b"ConfiumWitness/v1";
        let msg = witness_signing_message(42, &root);
        assert_eq!(msg.len(), prefix.len() + 8 + 32);
        assert_eq!(&msg[..prefix.len()], prefix);
        assert_eq!(&msg[prefix.len()..prefix.len() + 8], &42u64.to_be_bytes());
        assert_eq!(&msg[prefix.len() + 8..], &root);
    }

    #[test]
    fn digest_is_deterministic() {
        let root = [0x42; 32];
        assert_eq!(
            witness_signing_digest(1, &root),
            witness_signing_digest(1, &root)
        );
    }

    #[test]
    fn different_tree_sizes_produce_different_messages() {
        let root = [0x00; 32];
        assert_ne!(
            witness_signing_message(1, &root),
            witness_signing_message(2, &root)
        );
    }
}
