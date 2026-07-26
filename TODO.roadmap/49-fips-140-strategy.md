# 49 — FIPS 140-3 strategy

## Why FIPS 140-3

Many Confium target deployments (US federal PKI, regulated industries)
require FIPS 140-3 validated cryptography. Mode 2 (PKI replacement)
particularly benefits: enterprise customers can't deploy without FIPS.

## FIPS 140-3 vs Confium

FIPS 140-3 validates cryptographic *modules*, not applications. Confium
is a framework — it composes modules. The strategy:

### Option A: Use a validated crypto backend

Confium doesn't implement cryptographic primitives (mostly); it composes
validated ones. Path:

- Use a FIPS-validated build of `rustls`/`ring`/`aws-lc` for primitives
- Use a FIPS-validated HSM (YubiKey, Thales, Utimaco) for key storage
- Confium's threshold protocols run on top

This means Confium itself doesn't need to be FIPS-validated; the
underlying modules are.

### Option B: Submit Confium itself for FIPS validation

Long-term: when Confium's own threshold protocols (FROST, CMP20, etc.)
are widely deployed and stable, submit the entire module for FIPS 140-3
validation under the "Security Functions" category.

Cost: $100K-$300K + 12-24 months.

## Validated backends

| Backend | FIPS Status | Confium Integration |
|---|---|---|
| **AWS-LC** | FIPS 140-3 validated (Cert #4665) | `confium-tc-frost-p256`, `confium-tc-elgamal-p256` use `p256` which can use AWS-LC |
| **OpenSSL 3.0 FIPS provider** | FIPS 140-3 validated | `confium-openssl-provider` runs alongside the OpenSSL FIPS provider |
| **BoringCrypto (Google)** | FIPS 140-2 validated | Path via BoringSSL-rs |
| **ring** | Working on FIPS 140-3 submission | Currently used by rustls |
| **HSMs** | All major HSMs FIPS-validated | `confium-store-pkcs11` integrates |

## FIPS mode

Confium supports a "FIPS mode" via manifest:

```toml
[fips_mode]
enabled = true
approved_algorithms_only = true
disallowed = ["Ed25519", "RSA-1024", "MD5"]
backend = "aws-lc"
```

In FIPS mode, the coordinator refuses to create sessions for
non-approved algorithms. The `confium-core` engine fails to load
plugins that declare non-approved interfaces.

## Approved algorithms

Per FIPS 140-3 + SP 800-140C:

| Algorithm | FIPS Standard | Confium Crate |
|---|---|---|
| AES-256-GCM | SP 800-38D | (via aes-gcm) |
| SHA-256, SHA-384, SHA-512 | FIPS 180 | (via sha2) |
| HMAC | FIPS 198 | (via hmac) |
| ECDSA P-256 | FIPS 186-5 | (via p256) |
| RSA-2048+ | FIPS 186-5 | (via rsa) |
| ML-KEM (Kyber) | FIPS 203 | `confium-tc-ml-kem` |
| ML-DSA (Dilithium) | FIPS 204 | `confium-tc-frost-ml-dsa-65` |
| SLH-DSA (SPHINCS+) | FIPS 205 | (future) |

Note: Ed25519 is **not** FIPS-approved despite being widely used.
FIPS deployments must use ECDSA P-256 instead. This affects
Mode 2 deployments.

## Boundary

The "cryptographic module" boundary for FIPS 140-3 in a Confium
deployment is typically:

- The HSM (validated module)
- OR the process running Confium + OpenSSL FIPS provider (validated module)
- Confium itself sits outside the boundary, calling into the validated module

This is the standard pattern for cryptographic software that composes
validated modules.

## Self-test

FIPS 140-3 requires power-up self-tests:
- Known Answer Tests (KAT) for each approved algorithm
- Software integrity check (HMAC over the module binary)

Confium supports self-tests via `confium-core::fips::self_test()`:

```rust
use confium_core::fips;
let result = fips::self_test()?;
if !result.all_passed() {
    panic!("FIPS self-test failed: {:?}", result.failures);
}
```

## Status

- [ ] FIPS mode manifest option (`crates/confium-deployment`)
- [ ] Algorithm allowlist enforcement (`crates/confium-core`)
- [ ] Self-test framework (`crates/confium-core`)
- [ ] AWS-LC backend integration (`crates/confium-tc-frost-p256`, others)
- [ ] FIPS 140-3 validation submission (future, post-deployment)

## Anti-goals

- **Not** reimplementing crypto primitives (Confium uses validated crates)
- **Not** validating Confium itself short-term (too expensive, too early)
- **Not** disabling non-FIPS algorithms entirely (they remain available
  for non-FIPS deployments)

## References

- `TODO.roadmap/08-security-model.md`
- `TODO.roadmap/35-pq-composite-signatures.md`
- [NIST FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/upd1/final)
- [NIST SP 800-140C](https://csrc.nist.gov/pubs/sp/800/140/c/upd1/final)
