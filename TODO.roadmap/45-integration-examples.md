# 45 — Integration examples

## Purpose

Show, end-to-end, what using Confium looks like for each deployment mode.

## Examples

All examples live in `crates/confium-examples/src/bin/`. Each is a
standalone binary runnable via `cargo run --example <name>`.

### Mode 1: Peer-to-peer threshold signing

**Existing**: `threshold_signing.rs` — 3-party FROST-ed25519 via in-proc transport.

**Add (Mode 1 expansion)**:
- `peer_signing_p256.rs` — 3-party FROST-P256 via TCP transport
- `peer_encryption.rs` — Threshold ElGamal encryption + decryption
- `peer_reshare.rs` — Add/remove a peer via share re-sharing
- `peer_mpc.rs` — Multi-party computation example (sum of secret inputs)

### Mode 2: PKI replacement

**Add**:
- `pkcs11_dropin.rs` — Run `confium-pkcs11-server` alongside OpenSSL, sign via threshold
- `enterprise_code_signing.rs` — 3-of-5 release agents sign a software update
- `pqc_migration.rs` — Composite (Ed25519 + ML-DSA-65) signing ceremony
- `tls_threshold_signer.rs` — TLS handshake signature via threshold quorum

### Mode 3: Certificate PKI

**Existing**: OIML CNML integration is the flagship example. Lives in
the CNML project itself, not in `confium-examples`.

**Add (CNML-style demo)**:
- `mini_cnml.rs` — Minimal 3-tier hierarchy (root → IA → end-entity)
  with scoped delegation, async signing, transparency log
- `director_rotation.rs` — BIML-style annual ceremony (sync + async)
- `lab_test_report_escrow.rs` — TL signs, encrypts to IA, IA decrypts,
  IA issues cert

### Cross-mode

- `escrow_to_friends.rs` — Mode 1 social recovery using threshold escrow
- `revocation_service.rs` — Mode 2/3 revocation service with 24h delay
- `transparency_log_walkthrough.rs` — Append + verify + OTS anchor

## Example template

```rust
// crates/confium-examples/src/bin/<name>.rs

//! <What this example demonstrates>
//!
//! Run with: `cargo run --example <name>`

use confium_core::*;
use confium_tc::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Set up the actors / quorums
    // 2. Run the protocol
    // 3. Print results
    // 4. Verify the outcome (signature verifies, decryption matches, etc.)
    Ok(())
}
```

## Documentation

Each example has:
- Doc comment explaining what it demonstrates
- One-paragraph README in the examples directory
- Output that's readable by a non-developer (use println!, not debug)

## Demo script

`demo.sh` at repo root runs the headline examples in sequence:

```sh
#!/bin/bash
set -e
echo "== Mode 1: Threshold signing =="
cargo run --example threshold_signing
echo ""
echo "== Mode 2: PKCS#11 drop-in =="
cargo run --example pkcs11_dropin
echo ""
echo "== Mode 3: Mini CNML =="
cargo run --example mini_cnml
```

## Anti-goals

- **Not** production CLI polish — examples are for demonstration, not daily use
- **Not** browser/mobile demos — separate work (confium-wasm, mobile bridges)
- **Not** full CNML deployment — that lives in the CNML project

## References

- `TODO.roadmap/23-ecosystem-demonstration.md` — original demo plan
- `TODO.roadmap/26-confium-framework.md` — three modes
