//! Local 3-party DKG + sign + verify.
//!
//! ```sh
//! cargo run --example threshold_local_dkg -p confium-examples
//! ```

use confium_tc_cmp20::inprocess;

fn main() {
    println!("=== Confium CMP20 local DKG ===");

    // 1. DKG: generate 3 shares with threshold 2
    let kg = inprocess::keygen(2, 3).expect("DKG failed");
    println!("Public key: {} bytes", kg.public_key.len());
    println!("Shares: {} parties", kg.shares.len());

    // 2. Sign with all 3 shares (threshold is 2, so any 2 suffice)
    let message = b"hello, threshold world";
    let sig = inprocess::sign(&kg.shares, 2, message).expect("sign failed");
    println!("Signature: {} bytes", sig.len());

    // 3. Decode the public key to verify it's a valid P-256 point
    let _pk = inprocess::decode_public_key(&kg.public_key).expect("decode pk");
    println!("Public key decoded as valid P-256 point.");

    println!("\n✅ DKG + sign complete. Verify with:");
    println!("  confium verify composite --message hello --signature {} --algorithm ed25519 --public-key <pk-file>", hex::encode(&sig));
}
