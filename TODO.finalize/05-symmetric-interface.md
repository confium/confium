# 05 — Symmetric cipher interface

## Why

RNP supports 12 symmetric ciphers (IDEA, 3DES, CAST5, Blowfish, AES-128/192/256,
Twofish, Camellia-128/192/256, SM4). Confium has zero cipher support.

This is the second interface (after hash) that any consumer of Confium
needs.

## Goal

New FFI interface named `"symmetric"` with the wire-symbol prefix
`cfmp_cipher_`. Loaded dynamically like `"hash"`.

## Wire protocol

Plugin exports:

```c
uint32_t cfmp_cipher_create(
    const Confium *cfm,
    FFICipher **out,
    const char *algorithm,        // "AES-256", "ChaCha20", ...
    const void *key, uint32_t key_len,
    const void *iv,  uint32_t iv_len,
    const Option *opts);
uint32_t cfmp_cipher_block_size(const FFICipher *c, uint32_t *out);
uint32_t cfmp_cipher_key_size(const FFICipher *c, uint32_t *out);
uint32_t cfmp_cipher_iv_size(const FFICipher *c, uint32_t *out);
uint32_t cfmp_cipher_update(FFICipher *c, const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len);
uint32_t cfmp_cipher_finalize(FFICipher *c, uint8_t *out, uint32_t out_max, uint32_t *out_len);
uint32_t cfmp_cipher_reset(FFICipher *c);
void     cfmp_cipher_destroy(FFICipher *c);
```

Cipher modes (CFB, CBC, CTR, ECB, OCB-via-AEAD) are selected via `opts`
or by the algorithm name suffix. Mode-specific behaviors belong in the
plugin, not Confium.

## Files

- New: `src/ffi/cipher.rs` — FFI entry points + symbol-table struct
- New: `src/cipher.rs` — `Cipher` Rust wrapper (parallels `src/hash.rs`)
- Edit: `src/ffi/mod.rs` — `pub mod cipher;`
- Edit: `src/lib.rs` — `pub mod cipher;`
- New: `src/cipher/tests.rs` — unit tests with a mock plugin

## Algorithms Confium should advertise as supported

Match RNP's set (case-insensitive, hyphen-or-underscore-tolerant):

```
AES-128, AES-192, AES-256
AES-128-CFB, AES-192-CFB, AES-256-CFB
AES-128-CTR, AES-192-CTR, AES-256-CTR
ChaCha20
ChaCha20-Poly1305   (forwarded to AEAD interface)
Camellia-128, -192, -256
Twofish
SM4
3DES
CAST5
Blowfish
IDEA                (legacy, opt-in via feature flag?)
```

The plugin decides which subset it implements. Confium rejects
unsupported names with `Error::UnsupportedAlgorithm`.

## Tests

Mock plugin (in `tests/mock-cipher-plugin/`) implements all
`cfmp_cipher_*` symbols against a trivial XOR + counter, just enough to
exercise the wire contract. This pattern will be reused for every
subsequent interface.

## Dependency

- TODO #02 (registry) so adding this module is additive-only.
- TODO #04 (foundation) for shared `lookup`, `AlgorithmName`.

## Out of scope

- Actual cipher implementations (live in the Botan plugin repo).
- AEAD (separate interface, TODO #06).
