//! Local RFC 6962 transparency log.
//!
//! ```sh
//! cargo run --example transparency_local_log -p confium-examples
//! ```

use confium_transparency::MerkleTree;
use confium_transparency::entry::{ArtifactType, MerkleEntry};

fn main() {
    let mut tree = MerkleTree::new();

    // Append 3 entries
    for i in 0..3u8 {
        let hash = [i; 32];
        let entry = MerkleEntry::new(i as u64, ArtifactType::CertificateIssuance, hash);
        let seq = tree.append(entry);
        println!("Appended entry at sequence {}", seq);
    }

    // Get the root
    let root = tree.root();
    println!("Tree root: {}", hex::encode(root));

    // Generate inclusion proof for sequence 1
    let proof = tree.inclusion_proof(1).expect("proof");
    println!("Inclusion proof for seq 1: {} steps", proof.steps.len());

    // Verify
    let entry = tree.entry(1).expect("entry");
    let result = MerkleTree::verify_inclusion(entry, &proof, tree.root());
    println!("Verification: {:?}", result);

    println!("\n✅ Transparency log round-trip complete.");
}
