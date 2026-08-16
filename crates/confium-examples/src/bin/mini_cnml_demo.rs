//! Mode 3 demonstration: 3-tier threshold certificate hierarchy (mini CNML).
//!
//! Shows the pieces a Mode 3 deployment composes:
//!
//! 1. Root quorum (simulated via P-256 threshold)
//! 2. IA quorum (separate keypair)
//! 3. End-entity cert signed by IA
//! 4. Transparency log records all artifacts
//!
//! Run with: `cargo run --example mini_cnml_demo`

use chrono::TimeZone;
use confium_tc_frost_p256::{keys, shamir, sign};
use confium_transparency::{
    entry::{ArtifactType, MerkleEntry},
    merkle::MerkleTree,
};

fn fixed_entry(seq: u64, hash_byte: u8, atype: ArtifactType) -> MerkleEntry {
    let mut e = MerkleEntry::new(seq, atype, [hash_byte; 32]);
    e.timestamp = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    e
}

fn pk_prefix(bytes: &[u8]) -> String {
    let hex_str = hex::encode(bytes);
    if hex_str.len() >= 32 {
        format!("{}...", &hex_str[..32])
    } else {
        hex_str
    }
}

fn main() {
    println!("=== Confium Mode 3: Mini CNML (3-tier) Demo ===\n");

    let mut tree = MerkleTree::new();
    let mut seq = 0u64;

    // Tier 1: Root quorum (BIML-style)
    println!("Tier 1: BIML Root Quorum (5-of-7)");
    let root_keypair = keys::generate_keypair();
    let root_shares = shamir::split_secret(&root_keypair.secret_scalar, 5, 7);
    let subset: Vec<&shamir::Share> = root_shares.iter().take(5).collect();
    let _recovered = shamir::recover_secret(&subset).expect("recover");
    let root_pk_bytes = keys::public_key_sec1(&root_keypair.public_key);
    println!("  Root public key: {}", pk_prefix(&root_pk_bytes));
    println!("  7 shares generated, 5-of-7 threshold");
    let entry = fixed_entry(seq, 0x10, ArtifactType::CertificateIssuance);
    seq += 1;
    tree.append(entry);
    println!("  Transparency log: entry {} appended", seq - 1);
    println!();

    // Tier 2: IA quorum (2-of-3, signed by root)
    println!("Tier 2: IA Quorum (2-of-3), signed by root");
    let ia_keypair = keys::generate_keypair();
    let ia_shares = shamir::split_secret(&ia_keypair.secret_scalar, 2, 3);
    let _ia_subset: Vec<&shamir::Share> = ia_shares.iter().take(2).collect();
    let ia_pk_bytes = keys::public_key_sec1(&ia_keypair.public_key);
    let ia_signed_by_root = sign::sign_message(&root_keypair, &ia_pk_bytes).expect("sign");
    println!("  IA public key: {}", pk_prefix(&ia_pk_bytes));
    println!(
        "  Signed by root: {} bytes DER",
        ia_signed_by_root.der_bytes.len()
    );
    let entry = fixed_entry(seq, 0x20, ArtifactType::CertificateIssuance);
    seq += 1;
    tree.append(entry);
    println!("  Transparency log: entry {} appended", seq - 1);
    println!();

    // Tier 3: End-entity (manufacturer instance cert, signed by IA)
    println!("Tier 3: Manufacturer Instance Cert, signed by IA");
    let instrument_serial = b"FM-2026-A-SN0001";
    let instance_signed = sign::sign_message(&ia_keypair, instrument_serial).expect("sign");
    println!(
        "  Instrument serial: {}",
        String::from_utf8_lossy(instrument_serial)
    );
    println!(
        "  Signed by IA: {} bytes DER",
        instance_signed.der_bytes.len()
    );
    let entry = fixed_entry(seq, 0x30, ArtifactType::CertificateIssuance);
    seq += 1;
    tree.append(entry);
    println!("  Transparency log: entry {} appended", seq - 1);
    println!();

    // Verify transparency log
    println!("Transparency log verification:");
    let root_hash = tree.root();
    println!("  Tree root: {}", hex::encode(root_hash));
    println!("  {} entries logged", tree.len());
    println!();

    // Verify every inclusion proof
    println!("Inclusion proofs:");
    for i in 0..seq {
        let entry_ref = tree.entry(i).expect("entry");
        let proof = tree.inclusion_proof(i).expect("proof");
        MerkleTree::verify_inclusion(entry_ref, &proof, root_hash).expect("verify");
        println!("  Entry {}: PROOF VALID ({} steps)", i, proof.steps.len());
    }
    println!();

    println!("=== Demo complete. Mini CNML 3-tier hierarchy operational. ===");
    println!();
    println!("In a real deployment:");
    println!("  - Root quorum is operated by BIML (annual ceremony)");
    println!("  - IA quorum is operated by each national Issuing Authority");
    println!("  - End-entity certs are signed by IA on type approval");
    println!("  - All artifacts published in public transparency log");
    println!("  - Bitcoin OTS anchors tree roots periodically");
}
