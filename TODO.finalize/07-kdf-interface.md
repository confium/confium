# 07 — KDF interface

## Why

Key derivation functions (HKDF, PBKDF2, Argon2, Scrypt, OpenPGP S2K)
are foundational for key management. RFC 9580 mandates Argon2 support
for S2K; RNP supports HKDF and the OpenPGP S2K family.

## Goal

New FFI interface named `"kdf"`, symbol prefix `cfmp_kdf_`.

## Wire protocol

```c
uint32_t cfmp_kdf_create(
    const Confium *cfm,
    FFIKdf **out,
    const char *algorithm,         // "HKDF-SHA256", "PBKDF2-HMAC-SHA512", "Argon2id", "Scrypt", "S2K"
    const Option *opts);
uint32_t cfmp_kdf_set_salt(FFIKdf *k, const uint8_t *salt, uint32_t len);
uint32_t cfmp_kdf_set_iterations(FFIKdf *k, uint32_t n);
uint32_t cfmp_kdf_set_memory_cost(FFIKdf *k, uint64_t bytes);  // Argon2/Scrypt
uint32_t cfmp_kdf_set_parallelism(FFIKdf *k, uint32_t lanes);
uint32_t cfmp_kdf_set_hash(FFIKdf *k, const char *hash_name);  // underlying hash for HKDF/PBKDF2
uint32_t cfmp_kdf_derive(
    FFIKdf *k,
    const uint8_t *input, uint32_t input_len,
    uint8_t *out, uint32_t out_len);
void     cfmp_kdf_destroy(FFIKdf *k);
```

The setters are KDF-family-specific. A plugin rejects a setter that
doesn't apply to its algorithm with `Error::WrongType` or a new
`Error::OptionNotApplicable`.

## Files

- New: `src/ffi/kdf.rs`
- New: `src/kdf.rs`
- Edit: `src/ffi/mod.rs`, `src/lib.rs`

## Algorithms

```
HKDF-SHA256, HKDF-SHA512, HKDF-SHA3-256, HKDF-SHA3-512
PBKDF2-HMAC-SHA256, PBKDF2-HMAC-SHA512
Argon2id, Argon2i, Argon2d            (RFC 9106)
Scrypt                                (RFC 7914)
S2K-Simple, S2K-Salted, S2K-Iterated  (OpenPGP)
S2K-Argon2                            (RFC 9580)
```

## Notes

- HKDF requires an underlying hash interface. Confium resolves this by
  asking the plugin to look up `"hash"` providers via the standard
  Confium registry — no special cross-interface plumbing at the core
  level.
- Argon2 needs `set_memory_cost` and `set_parallelism` which HKDF
  ignores. The plugin decides which setters apply.

## Test plan

- HKDF RFC 5869 test vectors
- PBKDF2 RFC 6070 test vectors
- Argon2 RFC 9106 test vectors
- S2K round-trip determinism

## Dependency

- TODO #02 (registry)
- TODO #04 (foundation)
- Implicit dependency on hash interface (already in place)
