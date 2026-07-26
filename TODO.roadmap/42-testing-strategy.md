# 42 — Testing strategy

## Philosophy

Confium is a security framework. Tests are not optional — they're the
contract that lets us claim correctness. Every crate ships with:

- Unit tests (per module, in `#[cfg(test)] mod tests`)
- Integration tests (in `tests/` directory, exercising public API)
- Cross-crate composition tests
- NIST MPTS vector tests (algorithm crates)
- Adversarial/Byzantine tests (TC algorithm crates)

## Test tiers

### Tier 1: Unit tests

Per-module, focus on:
- Type construction and accessors
- Edge cases (empty, max-size, invalid inputs)
- Round-trip serialization (TOML, JSON, DER)
- Error variants

Target: 70%+ coverage of new code.

### Tier 2: Integration tests

In `tests/` directory of each crate. Exercise the public API as a
consumer would:

```rust
// tests/integration.rs
use confium_cert::Certificate;

#[test]
fn parse_real_certificate() {
    let pem = std::fs::read_to_string("tests/fixtures/leaf.pem").unwrap();
    let cert = Certificate::from_pem(&pem).unwrap();
    assert!(cert.fingerprint_sha256().len() > 0);
}
```

### Tier 3: Cross-crate composition

Lives in a top-level `tests/` directory or in `confium-examples`.
Tests full flows like:

- Generate keypair → split into shares → recover → sign → verify
- Encrypt to threshold KEM → AEAD encrypt → store → recover → decrypt
- Generate cert → CSR → issue signed cert → verify path

### Tier 4: NIST MPTS vectors

For algorithm crates. Run against official test vectors from NIST
MPTS submission. Lives in `confium-test-harness`.

### Tier 5: Adversarial (Byzantine)

For TC algorithm crates. Test misbehaving parties:

- Drop round-2 messages
- Tamper with commitments
- Submit invalid shares

Each scheme should either complete or abort with signed proof of
misbehavior.

## Current test count

| Crate | Tests | Coverage |
|---|---|---|
| confium-pki | 43 | cert + delegation + cms + xmldsig (consolidated) |
| confium-deployment | 14 | manifest + identity (consolidated) |
| confium-tc | 74 | session + coordinator + reshare + kem (consolidated) |
| confium-tc-frost-p256 | 25 | **real P256 Shamir + ECDSA + integration** |
| confium-transparency | 19 | Merkle + ots + ers (consolidated) |
| confium-attributes | 9 | predicate AST + DSL |
| confium-patterns | 7 | escrow + revocation (consolidated) |
| confium-composite | 3 | multi-alg aggregation |
| confium-store-openpgp-card | 2 | mock backend |
| confium-tc-elgamal-p256 | 3 | **real threshold ElGamal** |
| confium-pkcs11-server | 2 | dispatch |
| confium-tls-signer | 1 | threshold callback |
| confium-tc-ecies-p256 | 4 | **real ECDH + AES-256-GCM** |
| confium-tc-bls | 2 | aggregate |
| confium-tc-ml-kem | 2 | param sizes |
| confium-tc-frost-ml-dsa-65 | 3 | sizes |
| confium-ring | 3 | structure |
| confium-tc-fhe-bfv | 3 | params |
| confium-config | 6 | manifest |
| confium-jce-provider | 2 | java alg |
| confium-openssl-provider | 3 | provider info |
| ... (existing crates) | ~300+ | ... |
| **Total** | **688+** | growing |

## Test infrastructure

### CI gating

`ci.yml` enforces:
- `cargo test --workspace` must pass on every PR
- Test coverage must not decrease (via `cargo-tarpaulin`)
- Critical paths (key generation, signing, verification) must have
  integration tests

### Fixtures

Per-crate `tests/fixtures/` directories hold:
- Real X.509 certificates (from公开 CA)
- Real OpenPGP keys (test keys generated for the framework)
- Real CNML documents (samples from OIML project)
- NIST MPTS vector files

### Property-based testing

For algorithm crates, use `proptest` to verify:
- Shamir reconstruction works for any (t, n) combination
- Lagrange interpolation is correct for any subset
- Canonicalization is idempotent
- AEAD encryption is reversible

## Anti-goals

- **Not** mocking the crypto itself (mocks only for transport, storage, hardware)
- **Not** testing internal functions (only public API + key invariants)
- **Not** skipping tests for "trivial" code — trivial code can have subtle bugs

## References

- `TODO.roadmap/09-nist-evaluation-harness.md` — Tier 4 (vectors)
- `TODO.roadmap/04-threshold-cryptography.md` — Tier 5 (Byzantine)
