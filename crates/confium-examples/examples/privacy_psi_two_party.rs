//! Two-party Private Set Intersection (hash-based).
//!
//! ```sh
//! cargo run --example privacy_psi_two_party -p confium-examples
//! ```

fn main() {
    let set_a: Vec<Vec<u8>> = vec![b"alice".to_vec(), b"bob".to_vec(), b"carol".to_vec()];
    let set_b: Vec<Vec<u8>> = vec![b"bob".to_vec(), b"carol".to_vec(), b"dave".to_vec()];
    let salt = b"shared-secret-salt";

    let intersection = confium_privacy::privacy_and_dist_patterns::psi_hash_based(&set_a, &set_b, salt);

    println!("Intersection:");
    for item in &intersection {
        println!("  {}", String::from_utf8_lossy(item));
    }

    let count = confium_privacy::privacy_and_dist_patterns::psi_cardinality(&set_a, &set_b, salt);
    println!("Cardinality: {}", count);
    println!("\n✅ PSI complete.");
}
