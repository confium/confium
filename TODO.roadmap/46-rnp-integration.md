# 46 — RNP integration

## Purpose

Confium uses RNP (via `~/src/rnp/rnp-rs`) for OpenPGP operations:

- Verifying publisher signatures on registry plugins
- Director identity keys on YubiKey OpenPGP applet (alternative to PIV)
- OpenPGP-format message signing/verification for Thunderbird-compat flows
- CMS-like OpenPGP envelopes for some Mode 3 deployments

## Current state

`~/src/rnp/rnp-rs` covers ~250 of librnp's ~309 public functions. Three
Confium-driven BUGREPORTs were filed and **all three are now fixed**:

| Bug | Status | Commit |
|---|---|---|
| `BUGREPORT.detached-revocation-signature-helper.md` | ✅ Fixed | `ed268d5` — `generate_revocation_certificate()` free functions + RevocationCode string fix |
| `BUGREPORT.pqc-keypair-with-signing-and-encryption-subkeys.md` | ✅ Fixed | `ed268d5` — `KeyBuilder::add_subkey`, `add_pqc_encryption_subkey`, `add_pqc_signing_subkey` |
| `BUGREPORT.threshold-share-key-import.md` | ✅ Fixed | `ed268d5` — `ThresholdSigner` trait in `src/threshold.rs` |

## Confium integration points

### 1. Registry plugin signature verification

When a user runs `confium install <plugin>@<version>`, the registry
client downloads the plugin artifact + publisher PGP signature. Confium
uses rnp-rs to:

```rust
let ctx = rnp::Context::new()?;
let signed = std::fs::read("plugin.tar.gz")?;
let sig = std::fs::read("plugin.tar.gz.asc")?;
let result = rnp::verify(&ctx, &signed)?;
if !result.any_valid() {
    return Err(InstallError::SignatureInvalid);
}
```

### 2. Director identity on YubiKey OpenPGP applet

`confium-store-openpgp-card` provides the OpenPGP card backend interface.
The card performs signing operations via OpenPGP card spec; rnp-rs handles
the OpenPGP packet format for messages signed by these identity keys.

### 3. CMS-like OpenPGP messages

For Mode 2 enterprise email signing (S/MIME alternative), Confium can
emit OpenPGP-signed messages via rnp-rs that Thunderbird can verify
natively (Thunderbird uses librnp internally).

### 4. PQC migration via composite keys

rnp-rs now supports `KeyBuilder::add_pqc_encryption_subkey` and
`add_pqc_signing_subkey` (per BUGREPORT 55). Confium's PQC migration
path can use these for OpenPGP PQC keypair generation:

```rust
let key = rnp::KeyBuilder::new(rnp::Algorithm::EcP256)
    .userid("director@biml.org")
    .add_pqc_encryption_subkey(rnp::PqcEncAlgorithm::MlKem768)?
    .add_pqc_signing_subkey(rnp::PqcSigAlgorithm::MlDsa65)?
    .build(&ctx)?;
```

### 5. Revocation certificate generation

`rnp::generate_revocation_certificate()` (BUGREPORT 54 fix) is used by
Confium's `confium-patterns` (revocation) for OpenPGP key revocation flows
inspired by Thunderbird's IMAP-based revocation escrow.

## Dependency tracking

`rnp-rs` is a workspace-level dependency of `confium-registry` and
planned for `confium-patterns` (revocation). Path dependency:

```toml
# In confium/ workspace Cargo.toml
[workspace.dependencies]
rnp = { path = "../rnp/rnp-rs" }
```

For crates.io publishing, switch to:
```toml
rnp = "0.2"
```

(once rnp-rs publishes to crates.io).

## Anti-goals

- **Not** reimplementing OpenPGP in Rust — Confium uses librnp via rnp-rs
- **Not** supporting Sequoia or other OpenPGP libraries — Confium standardizes on RNP for Thunderbird compatibility
- **Not** building PGP key servers — uses keys.openpgp.org and WKD

## References

- `~/src/rnp/rnp-rs/README.adoc` — rnp-rs documentation
- `~/src/rnp/rnp-rs/BUGREPORT.*.md` — Confium-filed bugs (all fixed)
- `TODO.roadmap/41-thunderbird-patterns-integration.md`
