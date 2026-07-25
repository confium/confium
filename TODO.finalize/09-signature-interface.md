# 09 — Asymmetric signature interface

## Why

Asymmetric signatures are the most-used public-key operation in
OpenPGP. RNP supports ~25 signature algorithms including RSA, ECDSA,
EdDSA, Ed25519, SM2, plus PQC: 6 Dilithium-composite variants and 3
SPHINCS+ variants.

## Goal

New FFI interface named `"signature"`, symbol prefix `cfmp_sig_`.

## Wire protocol

```c
uint32_t cfmp_sig_signer_create(
    const Confium *cfm,
    FFISigner **out,
    const char *algorithm,         // "Ed25519", "Dilithium3-Ed25519", "SLH-DSA-SHAKE-128s"
    const void *secret_key, uint32_t sk_len,   // serialized key (TODO #11)
    const Option *opts);

uint32_t cfmp_sig_verifier_create(
    const Confium *cfm,
    FFIVerifier **out,
    const char *algorithm,
    const void *public_key, uint32_t pk_len,
    const Option *opts);

uint32_t cfmp_sig_set_hash(FFISigner *s, const char *hash_name);
uint32_t cfmp_sig_update(FFISigner *s, const uint8_t *data, uint32_t len);
uint32_t cfmp_sig_sign_finalize(FFISigner *s, uint8_t *sig, uint32_t sig_max, uint32_t *sig_len);

uint32_t cfmp_sig_verifier_update(FFIVerifier *v, const uint8_t *data, uint32_t len);
uint32_t cfmp_sig_verify_finalize(FFIVerifier *v, const uint8_t *sig, uint32_t sig_len);

uint32_t cfmp_sig_keypair_generate(
    const Confium *cfm,
    const char *algorithm,
    uint32_t seed_entropy,        // hint; plugin reads RNG
    uint8_t *public_key_out, uint32_t pk_max, uint32_t *pk_len,
    uint8_t *secret_key_out, uint32_t sk_max, uint32_t *sk_len);

void cfmp_sig_signer_destroy(FFISigner *s);
void cfmp_sig_verifier_destroy(FFIVerifier *v);
```

## Algorithms

### Classical

```
RSA-1024/2048/3072/4096
DSA
ECDSA-P256, -P384, -P521, -secp256k1, -brainpool256r1, -brainpool384r1, -brainpool512r1
EdDSA, Ed25519, Ed448
SM2
```

### PQC (composite + standalone)

```
Dilithium3-Ed25519
Dilithium5-Ed448
Dilithium3-P384
Dilithium5-P521
Dilithium3-BrainpoolP384r1
Dilithium5-BrainpoolP512r1
SLH-DSA-SHAKE-128f
SLH-DSA-SHAKE-128s
SLH-DSA-SHAKE-256s
```

## Files

- New: `src/ffi/signature.rs`
- New: `src/signature.rs` (Rust wrappers `Signer`, `Verifier`)

## Notes

- Key serialization is shared with the KEM interface — both depend on
  TODO #11 (key serialization interface).
- `set_hash` lets RSA/DSA/ECDSA signatures specify the hash; Ed25519
  and PQC signatures ignore it.
- Composite signatures (Dilithium3-Ed25519) are atomic from Confium's
  perspective: one key, one signature, one verify call. The plugin
  internally produces the classical and PQC signatures and concatenates
  them per RFC draft-ietf-openpgp-pqc.

## Test plan

- NIST CAVP vectors for ECDSA / Ed25519 / RSA-PSS
- Dilithium NIST KAT vectors (post-quantum standardization)
- RFC 8032 Ed25519 test vectors
- Composite round-trip: sign → verify → original OK
- Wrong-key rejection: verify with non-matching pubkey fails

## Dependency

- TODO #02 (registry)
- TODO #04 (foundation)
- TODO #11 (key serialization) for parameter passing
