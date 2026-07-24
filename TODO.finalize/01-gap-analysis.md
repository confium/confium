# 01 — Gap analysis: Confium vs current cryptographic practice

## Source of truth

Investigated `/Users/mulgogi/src/rnp/rnp` (RNP 0.18.1, released 2025-11-21).
RNP is the consumer of Confium's design and the canonical reference for
"latest cryptographic practice" in this ecosystem.

RNP supports the algorithm set defined by **RFC 9580 (OpenPGP crypto-refresh)**,
plus the **PQC extensions** standardized in the draft `draft-ietf-openpgp-pqc`
(Kyber-composite KEMs, Dilithium-composite signatures, SPHINCS+).

## RNP algorithm coverage (verified in `src/lib/rnp.cpp`)

### Hashes (11)

MD5, SHA-1, RIPEMD-160, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256,
SHA3-512, SM3, CRC-24 (CRC for armored headers)

### Symmetric (12)

IDEA, Triple-DES, CAST5, Blowfish, AES-128/192/256, Twofish,
Camellia-128/192/256, SM4

### AEAD (3)

EAX, OCB, (GCM exposed via OpenSSL backend for crypto-refresh)

### Public-key algorithms (~25)

- RSA (encrypt-only, sign-only, both)
- DSA, ElGamal
- ECDH, ECDSA (NIST P-256/384/521, Brainpool, secp256k1, SM2 P-256)
- EdDSA (legacy form), Ed25519, Ed448
- X25519, X448 (curve25519/448)
- SM2 (Chinese national standard)

### PQC public-key (14, gated on `ENABLE_PQC` + `ENABLE_CRYPTO_REFRESH`)

**Composite KEMs (Kyber + classical):**

- Kyber768 + X25519
- Kyber1024 + X448
- Kyber768 + P-384
- Kyber1024 + P-521
- Kyber768 + BrainpoolP384r1
- Kyber1024 + BrainpoolP512r1

**Composite signatures (Dilithium + classical):**

- Dilithium3 + Ed25519
- Dilithium5 + Ed448
- Dilithium3 + P-384
- Dilithium5 + P-521
- Dilithium3 + BrainpoolP384r1
- Dilithium5 + BrainpoolP512r1

**Standalone PQC signatures (SPHINCS+):**

- SLH-DSA-SHAKE-128f
- SLH-DSA-SHAKE-128s
- SLH-DSA-SHAKE-256s

### Supporting primitives

- HKDF (`crypto/hkdf*.{cpp,hpp}`)
- S2K (OpenPGP string-to-key: simple, salted, iterated+salted)
- RNG (Botan/OpenSSL)
- MPI (multi-precision integer)
- Memory security primitives (`mem.cpp`, `mem_ossl.cpp`)

## Confium coverage today

| Capability         | Status         | Notes                                            |
|--------------------|----------------|--------------------------------------------------|
| Plugin loader      | Implemented    | `src/ffi/plugin.rs`, v0 vtable                   |
| Hash interface     | Implemented    | `src/ffi/hash.rs`, `src/hash.rs` — single class  |
| Symmetric cipher   | **Missing**    |                                                  |
| AEAD               | **Missing**    |                                                  |
| KEM                | **Missing**    |                                                  |
| Signature          | **Missing**    |                                                  |
| KDF                | **Missing**    |                                                  |
| RNG                | **Missing**    |                                                  |
| Key serialization  | **Missing**    |                                                  |
| Keystore           | **Missing**    |                                                  |
| Sensitive memory   | **Missing**    | (issue #4 — Sensitive first cut only)            |
| Error source chain | **Stubbed**    | `cfm_err_get_source` is `unimplemented!()`        |
| Plugin unload      | **Stubbed**    | `cfm_plugin_unload` is `unimplemented!()`         |
| Module repository  | **Missing**    | (Phase 1 item from issue #1)                     |

## Architectural issues blocking scale

1. **OCP violation in `create_plugin_interface`** (`src/ffi/plugin.rs`): adding
   a new interface type requires editing the `PluginInterface` enum and the
   `match name { "hash" => ..., _ => continue }` arm. With ~10 new interfaces
   to add, this becomes unmaintainable.

2. **Interface enum is closed**: each new interface must be matched in
   `find_interface`, `get_interface`, `Hash::try_clone`'s interface-downcast
   pattern.

3. **No common traits** for crypto operations: each interface reinvents
   "load symbol, build vtable, dispatch" independently.

## Plan

The TODO.finalize series implements the foundation (TODO #2 registry
refactor) first, then layers each crypto interface as an independent
plugin-discoverable module. By the end of the series, Confium has an
OCP-compliant plugin framework capable of hosting every algorithm class
RNP supports. Concrete algorithm *implementations* live in separate plugin
repos (Botan plugin, OpenSSL plugin, PQC plugin, etc.) — out of scope for
this repo.

## What is NOT in scope

- Concrete crypto algorithm implementations (Botan plugin etc.)
- Threshold cryptography (Phase 3, issue #12)
- Keystore persistence format design (Phase 2, issue #11 — large)
- Network module repository (Phase 1 #1, Phase 3 #12)

These are tracked in their respective issues and TODOs.
