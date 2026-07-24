# 08 — RNG interface

## Why

Cryptographically-secure random number generation is the foundation
of all key generation and side-channel defenses. RNP uses
Botan/OpenSSL RNG; Confium has no RNG abstraction.

This is the simplest interface (no key material, no parameters) and
doubles as a registry-pattern exemplar.

## Goal

New FFI interface named `"rng"`, symbol prefix `cfmp_rng_`.

## Wire protocol

```c
uint32_t cfmp_rng_create(
    const Confium *cfm,
    FFIRng **out,
    const char *algorithm,         // "System", "ChaCha20DRBG", "HMAC-DRBG-SHA256"
    const Option *opts);
uint32_t cfmp_rng_reseed(FFIRng *r, const uint8_t *entropy, uint32_t len);
uint32_t cfmp_rng_add_entropy(FFIRng *r, const uint8_t *entropy, uint32_t len);
uint32_t cfmp_rng_generate(FFIRng *r, uint8_t *out, uint32_t out_len);
void     cfmp_rng_destroy(FFIRng *r);
```

## Algorithms

```
System              // OS CSPRNG (getrandom/BCryptGenRandom)
ChaCha20DRBG        // NIST SP 800-90A
HMAC-DRBG-SHA256    // NIST SP 800-90A
HMAC-DRBG-SHA512
Hash-DRBG           // less common
```

## Files

- New: `src/ffi/rng.rs`
- New: `src/rng.rs`
- Edit: `src/ffi/mod.rs`, `src/lib.rs`

## Notes

- `cfm_rng_generate` returning success must yield exactly `out_len`
  bytes of cryptographically-strong output.
- The `"System"` algorithm must always be available if any plugin
  implements this interface — Confium should not have a fallback RNG
  baked into core.
- For `Error::InsufficientEntropy` (rare, only for DRBGs seeded with
  too little entropy), add a new error variant.

## Test plan

- NIST SP 800-90A KAT vectors for ChaCha20DRBG and HMAC-DRBG.
- Statistical tests on System RNG output (chi-square, runs test) —
  these are smoke tests, not proofs.
- Reseed flushes internal state: calling `generate` after `reseed`
  with a known entropy value yields the algorithm's known answer.

## Dependency

- TODO #02 (registry)
- TODO #04 (foundation)

## Exemplar purpose

RNG is the simplest interface: stateless params, no key material,
trivial wire protocol. After the registry refactor lands, RNG is the
first new interface added — proves the registry pattern works
end-to-end before the more complex interfaces (symmetric, AEAD,
signature) are layered on.
