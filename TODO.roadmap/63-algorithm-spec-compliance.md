# 63 — Algorithm specification compliance

## Scope

Every algorithm in Confium must comply with an authoritative spec:

- NIST FIPS publications (for FIPS algorithms)
- IETF RFCs (for internet-standard algorithms)
- Academic papers (for research algorithms)
- ISO/IEC standards (for industry-standard algorithms)

This document tracks the spec source for each Confium algorithm.

## Compliance matrix

### Hash algorithms

| Algorithm | Spec | Confium Source | Status |
|---|---|---|---|
| SHA-256 | FIPS 180-4 | `sha2` crate | ✅ Real |
| SHA-384 | FIPS 180-4 | `sha2` crate | ✅ Real |
| SHA-512 | FIPS 180-4 | `sha2` crate | ✅ Real |
| SHA-3 | FIPS 202 | `sha3` crate | Available via dep |
| SHAKE-128/256 | FIPS 202 | `sha3` crate | Available via dep |

### Symmetric algorithms

| Algorithm | Spec | Confium Source | Status |
|---|---|---|---|
| AES-128/256 | FIPS 197 | `aes` crate | Available |
| AES-GCM | SP 800-38D | `aes-gcm` crate | ✅ Real (in ECIES) |
| AES-CBC | SP 800-38A | `aes` crate | Available |
| ChaCha20-Poly1305 | RFC 8439 | `chacha20poly1305` crate | Available |

### MAC algorithms

| Algorithm | Spec | Confium Source | Status |
|---|---|---|---|
| HMAC-SHA-256 | FIPS 198 | `hmac` crate | ✅ Real |
| HMAC-SHA-512 | FIPS 198 | `hmac` crate | ✅ Real |
| Poly1305 | RFC 8439 | `poly1305` crate | Available |

### Signature algorithms (single-party)

| Algorithm | Spec | Confium Source | Status |
|---|---|---|---|
| Ed25519 | RFC 8032 | `ed25519-dalek` | ✅ Real (composite) |
| ECDSA P-256 | FIPS 186-5 | `p256` crate | ✅ Real (frost-p256) |
| ECDSA P-384 | FIPS 186-5 | `p384` crate | Available |
| RSA-PSS | RFC 8017 | `rsa` crate | Available |
| RSA-PKCS1v1.5 | RFC 8017 | `rsa` crate | Available |

### Post-quantum (single-party)

| Algorithm | Spec | Confium Source | Status |
|---|---|---|---|
| ML-KEM (Kyber) | FIPS 203 | `pqcrypto` crate | Interface |
| ML-DSA (Dilithium) | FIPS 204 | `pqcrypto` crate | Interface |
| SLH-DSA (SPHINCS+) | FIPS 205 | `pqcrypto` crate | Future |

### Threshold signature algorithms

| Algorithm | Spec | Confium Crate | Status |
|---|---|---|---|
| FROST-Ed25519 | draft-irtf-cfrg-frost-13 | `confium-tc-frost-ed25519` | ✅ Shipped |
| FROST-P256 | draft-irtf-cfrg-frost-13 | `confium-tc-frost-p256` | ✅ Real Shamir+ECDSA |
| CMP20 ECDSA P-256 | CMP20 paper | `confium-tc-cmp20` | ✅ Shipped |
| GG18 ECDSA | Gennaro-Goldfeder 2018 | `confium-tc-gg18` | ✅ Shipped |
| FROST-ML-DSA-65 | Boneh et al. 2024 | `confium-tc-frost-ml-dsa-65` | Research |
| BLS threshold | Boneh-Lynn-Shacham + RFC draft | `confium-tc-bls` | Interface |

### Threshold encryption algorithms

| Algorithm | Spec | Confium Crate | Status |
|---|---|---|---|
| Threshold ElGamal-P256 | Standard ElGamal + Shamir | `confium-tc-elgamal-p256` | ✅ Real |
| Threshold ECIES-P256 | Standard ECIES + Shamir | `confium-tc-ecies-p256` | ✅ Real |
| Threshold ML-KEM | FIPS 203 + threshold variant | `confium-tc-ml-kem` | Research |
| Threshold BFV FHE | BFV paper + threshold | `confium-tc-fhe-bfv` | Research |

### KEM (key encapsulation)

| Algorithm | Spec | Confium Source | Status |
|---|---|---|---|
| ML-KEM-512/768/1024 | FIPS 203 | `pqcrypto` crate | Interface |
| HPKE | RFC 9180 | `hpke` crate | Available |

### KDF (key derivation)

| Algorithm | Spec | Confium Source | Status |
|---|---|---|---|
| HKDF | RFC 5869 | `hkdf` crate | ✅ Real (in ECIES) |
| PBKDF2 | RFC 8018 | `pbkdf2` crate | Available |
| scrypt | RFC 7914 | `scrypt` crate | Available |
| Argon2 | RFC 9106 | `argon2` crate | Available |

### Random number generation

| Algorithm | Spec | Confium Source | Status |
|---|---|---|---|
| OS CSPRNG | NIST SP 800-90A | `rand_core::OsRng` | ✅ Real |
| Mock RNG (testing) | n/a | Internal | ✅ Real (test only) |

## Spec tracking

For each algorithm, the corresponding crate's `lib.rs` MUST reference
the authoritative spec:

```rust
//! FROST threshold signature over ECDSA P-256.
//!
//! Spec: draft-irtf-cfrg-frost-13
//! Spec: FIPS 186-5 (for the underlying ECDSA)
```

## NIST MPTS vector compliance

For each threshold algorithm, the crate's `tests/vectors/` directory
contains NIST MPTS conformance vectors. Tests run against these vectors
to verify spec compliance.

## Anti-goals

- **Not** inventing new algorithms — Confium only implements published specs
- **Not** "improving" on standard algorithms — strict spec adherence
- **Not** supporting deprecated algorithms (MD5, SHA-1, RSA-1024) for new use

## References

- [NIST FIPS publications](https://csrc.nist.gov/publications/fips)
- [NIST MPTS](https://csrc.nist.gov/projects/threshold-cryptography)
- `TODO.roadmap/49-fips-140-strategy.md`
- `TODO.roadmap/35-pq-composite-signatures.md`
