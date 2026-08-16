//! Mode 2 demonstration: PKCS#11 server dispatch to threshold protocol.
//!
//! Shows the `confium-pkcs11-server` dispatch layer routing a fake
//! C_Sign() call through a mock threshold quorum. Real deployment
//! would have the dispatcher call out to coordinator + threshold signers
//! via the network.
//!
//! Run with: `cargo run --example pkcs11_server_demo`

use confium_pkcs11_server::{
    dispatch::{Pkcs11Server, QuorumDispatcher},
    slot::{SlotId, SlotInfo},
    token::TokenInfo,
};

/// In-process mock dispatcher. Real deployment would call coordinator +
/// threshold signers over the network.
struct DemoDispatcher;

impl QuorumDispatcher for DemoDispatcher {
    fn sign(&self, _slot: SlotId, data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.iter().map(|b| !b).collect())
    }

    fn decrypt(&self, _slot: SlotId, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        Ok(ciphertext.to_vec())
    }

    fn generate_keypair(&self, _slot: SlotId) -> Result<Vec<u8>, String> {
        Ok(vec![0x42u8; 32])
    }
}

fn main() {
    println!("=== Confium Mode 2: PKCS#11 Server Dispatch Demo ===\n");

    println!("Step 1: Initializing PKCS#11 server with demo quorum dispatcher...");
    let mut server = Pkcs11Server::new(Box::new(DemoDispatcher));
    println!();

    println!("Step 2: Registering quorum 'enterprise-root' (3-of-5) at slot 1...");
    server.register_quorum(
        SlotId(1),
        SlotInfo::for_quorum("enterprise-root"),
        TokenInfo::for_quorum(
            SlotId(1),
            "enterprise-root",
            3,
            5,
            "FROST-P256",
            "coordinator.acme.corp:443",
        ),
    );
    println!("  Slot 1: Confium quorum 'enterprise-root'");
    println!("  Token: FROST-P256, 3-of-5 threshold");
    println!();

    println!("Step 3: Application calls C_Sign(slot=1, data='hello world')...");
    let signature = server.c_sign(SlotId(1), b"hello world").expect("sign");
    println!("  Signature returned ({} bytes)", signature.len());
    println!("  Bytes: {}", hex::encode(&signature));
    println!();

    println!("Step 4: Application calls C_Decrypt(slot=1, ciphertext='secret')...");
    let plaintext = server.c_decrypt(SlotId(1), b"secret").expect("decrypt");
    println!("  Plaintext: {:?}", String::from_utf8_lossy(&plaintext));
    println!();

    println!("Step 5: Application calls C_GenerateKeyPair(slot=1) — triggers DKG...");
    let pubkey = server.c_generate_keypair(SlotId(1)).expect("generate");
    println!("  Public key ({} bytes)", pubkey.len());
    println!();

    println!("Step 6: Server status...");
    println!("  Registered slots: {}", server.slot_count());
    println!();

    println!("=== Demo complete. PKCS#11 dispatch layer operational. ===");
    println!();
    println!("In a real deployment:");
    println!("  1. App links libconfium_pkcs11.so as its PKCS#11 module");
    println!("  2. PKCS#11 calls (C_Sign, C_Decrypt) flow to dispatcher");
    println!("  3. Dispatcher routes to coordinator + threshold quorum");
    println!("  4. Threshold signature returned to app as if from single HSM");
    println!("  5. App (OpenSSL, OpenSSH, nginx, etc.) works unchanged");
}
