//! Keystore roundtrip demonstration.
//!
//! Creates a keystore (memory backend), puts a secret key, retrieves it,
//! enumerates entries. Demonstrates the Store pillar: compartmentalized
//! public/private spaces, backend trait.
//!
//! ```sh
//! cargo run --example keystore-roundtrip
//! ```

fn main() {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║   Confium Keystore Demonstration                     ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();

    // The keystore FFI is in confium-store. Here we show the Rust API.
    use confium_store::backend::{Compartment, Options, StoreBackend};

    // Open a memory backend
    let backend = confium_store::backends::memory::MemoryBackend;
    let mut store = backend.open(&Options::new()).unwrap_or_else(|_| {
        println!("Failed to open memory backend.");
        std::process::exit(1);
    });

    println!("Opened memory backend: {} compartments", 2);
    println!();

    let module = "my_app";
    let app = "v1.0";
    let key_id = "signing_key_1";
    let secret: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    let identity = "alice@example.com";
    let public: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04];
    let signature: Vec<u8> = vec![0xAA, 0xBB, 0xCC, 0xDD];

    // Put a secret
    let secret_ptr = Box::into_raw(Box::new(secret.clone())) as *mut std::ffi::c_void;
    match store.put_secret(module, app, key_id, secret_ptr) {
        Ok(()) => println!(
            "  ✓ Put secret '{}' ({} bytes) into private compartment",
            key_id,
            secret.len()
        ),
        Err(e) => println!("  ✗ Put secret failed: {}", e),
    }

    // Get it back
    match store.get_secret(module, app, key_id) {
        Ok(ptr) => {
            let len = 6; // we know the length for this demo
            let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
            println!(
                "  ✓ Retrieved secret '{}' ({} bytes): {:02x?}",
                key_id,
                bytes.len(),
                bytes
            );
        }
        Err(e) => println!("  ✗ Get secret failed: {}", e),
    }

    // Put a public key with identity signature
    let pub_ptr = Box::into_raw(Box::new(public.clone())) as *mut std::ffi::c_void;
    match store.put_public(module, app, identity, pub_ptr, &signature) {
        Ok(()) => println!(
            "  ✓ Put public key for '{}' ({} bytes) + signature",
            identity,
            public.len()
        ),
        Err(e) => println!("  ✗ Put public failed: {}", e),
    }

    // Enumerate private compartment
    match store.enumerate(module, app, Compartment::Private) {
        Ok(entries) => {
            println!("  ✓ Private compartment has {} entries", entries.len());
            for (_e, id) in &entries {
                println!("    • {}", id);
            }
        }
        Err(e) => println!("  ✗ Enumerate private failed: {}", e),
    }

    // Enumerate public compartment
    match store.enumerate(module, app, Compartment::Public) {
        Ok(entries) => {
            println!("  ✓ Public compartment has {} entries", entries.len());
            for (_e, id) in &entries {
                println!("    • {}", id);
            }
        }
        Err(e) => println!("  ✗ Enumerate public failed: {}", e),
    }

    // Wrong module/app returns nothing
    match store.get_secret("wrong_module", "wrong_app", key_id) {
        Ok(_) => println!("  ✗ Should have failed for wrong module/app"),
        Err(e) => println!("  ✓ Wrong module/app correctly rejected: {}", e),
    }

    println!();
    println!("  Compartments are isolated:");
    println!("    Private: keyed by (module, app, key_id)");
    println!("    Public:  keyed by (module, app, identity)");
    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║   Confium: compartmentalized key storage.            ║");
    println!("╚══════════════════════════════════════════════════════╝");
}
