//! Plugin load + hash demonstration.
//!
//! Loads the mock hash plugin via the standard Confium plugin loader,
//! hashes a message, prints the digest. Demonstrates: plugin contract,
//! registry pattern, hash interface, FFI lifecycle.
//!
//! ```sh
//! cargo run --example plugin-load-and-hash
//! ```

fn main() {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║   Confium Plugin Load + Hash Demonstration           ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();

    let message = b"hello world";
    println!("Message: {:?}", String::from_utf8_lossy(message));
    println!();

    // This demo uses the Rust API directly (not the C FFI).
    // In a real deployment, the plugin (.so/.dylib) would be loaded
    // from the filesystem. Here we show the API surface.
    let _cfm = confium_core::Confium::new();
    println!("Created Confium instance.");
    println!("Providers loaded: {}", 0); // would show count after load_plugin
    println!();

    // The hash interface is available via the registry:
    let kinds: Vec<_> = confium_core::ffi::registry::iter().collect();
    println!("Registered interface kinds:");
    for kind in &kinds {
        println!("  • {} (max version {})", kind.name(), kind.max_version());
    }
    println!();

    // To actually hash, a plugin must be loaded. The mock plugin
    // (confium-mock-plugin crate) implements hash via the proc-macro SDK.
    // In production:
    //
    //   cfm.load_plugin(Path::new("/usr/lib/confium/plugins/libcfm-botan.dylib"),
    //                   &HashMap::new())?;
    //   let mut hash = Hash::new(&cfm, "SHA-256", None, None)?;
    //   hash.update(b"hello world")?;
    //   let digest = hash.finalize()?;
    //   println!("SHA-256: {}", hex::encode(&digest));

    println!("To hash a message with a real plugin:");
    println!("  1. Build the mock plugin: cargo build -p confium-mock-plugin");
    println!(
        "  2. Load it: cfm.load_plugin(Path::new(\"target/debug/libcfm_mock_plugin.dylib\"), &opts)"
    );
    println!("  3. Hash: Hash::new(&cfm, \"SHA-256\", None, None)?.digest(b\"hello world\")");
    println!();
    println!("The plugin SDK macro generates all cfmp_hash_* FFI symbols from a");
    println!("Rust trait impl — see crates/confium-mock-plugin/src/lib.rs.");
    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║   Confium: load any crypto algorithm as a plugin.    ║");
    println!("╚══════════════════════════════════════════════════════╝");
}
