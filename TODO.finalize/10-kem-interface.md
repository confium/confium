# 10 — KEM interface (key encapsulation)

## Why

Key Encapsulation Mechanisms are the modern way to do public-key
encryption: hybrid encryption built on KEM + DEM (AEAD). RFC 9580
uses X25519/Ed25519/ECDH as KEMs; the PQC draft adds 6 Kyber-composite
KEMs.

## Goal

New FFI interface named `"kem"`, symbol prefix `cfmp_kem_`.

## Wire protocol

```c
uint32_t cfmp_kem_encapsulator_create(
    const Confium *cfm,
    FFIKemEncapsulator **out,
    const char *algorithm,
    const void *recipient_pubkey, uint32_t pk_len,
    const Option *opts);

uint32_t cfmp_kem_encapsulate(
    FFIKemEncapsulator *e,
    uint8_t *ciphertext_out, uint32_t ct_max, uint32_t *ct_len,
    uint8_t *shared_secret_out, uint32_t ss_max, uint32_t *ss_len);

uint32_t cfmp_kem_decapsulator_create(
    const Confium *cfm,
    FFIKemDecapsulator **out,
    const char *algorithm,
    const void *recipient_seckey, uint32_t sk_len,
    const Option *opts);

uint32_t cfmp_kem_decapsulate(
    FFIKemDecapsulator *d,
    const uint8_t *ciphertext, uint32_t ct_len,
    uint8_t *shared_secret_out, uint32_t ss_max, uint32_t *ss_len);

uint32_t cfmp_kem_shared_secret_size(
    const char *algorithm, uint32_t *out);

uint32_t cfmp_kem_keypair_generate(...);

void cfmp_kem_encapsulator_destroy(FFIKemEncapsulator *e);
void cfmp_kem_decapsulator_destroy(FFIKemDecapsulator *d);
```

The split into encapsulator/decapsulator (rather than
encrypter/decrypter) matches the NIST PQC API and the standard ML-KEM
shape.

## Algorithms

### Classical KEMs

```
RSAES-PKCS1-v1_5                  (legacy)
RSAES-OAEP-SHA256
ECDH-P256, ECDH-P384, ECDH-P521
ECDH-X25519, ECDH-X448
ECDH-BrainpoolP256r1, -P384r1, -P512r1
SM2-Encryption
```

### PQC KEMs (composite, all Kyber768/1024 + classical)

```
Kyber768-X25519
Kyber1024-X448
Kyber768-P384
Kyber1024-P521
Kyber768-BrainpoolP384r1
Kyber1024-BrainpoolP512r1
```

## Files

- New: `src/ffi/kem.rs`
- New: `src/kem.rs` (`KemEncapsulator`, `KemDecapsulator`)

## Notes

- For pure-ML-KEM (FIPS 203), define separate algorithm names
  `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`. RFC 9580-pqc only
  standardizes the composite forms above.
- Composite KEM = run classical KEM + ML-KEM, XOR the shared secrets,
  return concatenated ciphertext. This is the
  NIST-PQC-selected approach.
- `cfm_kem_shared_secret_size` lets the caller size the buffer for the
  shared secret before calling `encapsulate`. The composite sizes are
  the sum of (classical, ML-KEM) shared secret sizes (typically 32+32
  = 64).

## Test plan

- ML-KEM KAT vectors from NIST PQC standardization
- X25519 RFC 7748 test vectors
- Composite round-trip: encapsulator's shared secret == decapsulator's
- Wrong-seckey decapsulation fails
- Deterministic encapsulation with seeded RNG (test mode only)

## Dependency

- TODO #02 (registry)
- TODO #04 (foundation)
- TODO #11 (key serialization)
