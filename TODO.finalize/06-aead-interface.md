# 06 — AEAD interface

## Why

AEAD modes (EAX, OCB, GCM, ChaCha20-Poly1305) are required by RFC 9580
SEIPDv2 packet format and by any modern encryption API. RNP supports
all three OpenPGP AEAD modes.

## Goal

New FFI interface named `"aead"`, plugin symbol prefix `cfmp_aead_`.

## Wire protocol

```c
uint32_t cfmp_aead_create(
    const Confium *cfm,
    FFIAead **out,
    const char *algorithm,         // "AES-256-GCM", "OCB", "EAX", "ChaCha20-Poly1305"
    const void *key, uint32_t key_len,
    const Option *opts);
uint32_t cfmp_aead_set_nonce(FFIAead *a, const uint8_t *nonce, uint32_t len);
uint32_t cfmp_aead_associated_data_update(FFIAead *a, const uint8_t *in, uint32_t len);
uint32_t cfmp_aead_encrypt_update(FFIAead *a, const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len);
uint32_t cfmp_aead_decrypt_update(FFIAead *a, const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len);
uint32_t cfmp_aead_finalize(FFIAead *a, uint8_t *tag, uint32_t tag_max, uint32_t *tag_len);
uint32_t cfmp_aead_verify_tag(FFIAead *a, const uint8_t *tag, uint32_t tag_len);
uint32_t cfmp_aead_destroy(FFIAead *a);
```

`encrypt_update` and `decrypt_update` are split because direction
matters for the internal state machine and for tag verification.

## Files

- New: `src/ffi/aead.rs`
- New: `src/aead.rs`
- Edit: `src/ffi/mod.rs`, `src/lib.rs`
- New: tests with mock AEAD plugin (XOR + HMAC-tag simulation)

## Algorithms

```
AES-128-GCM, AES-192-GCM, AES-256-GCM
AES-128-OCB, AES-192-OCB, AES-256-OCB    (RFC 9580 default)
AES-128-EAX, AES-192-EAX, AES-256-EAX
ChaCha20-Poly1305
SM4-GCM, SM4-OCB                          (rare, optional)
```

## Test plan

- Round-trip encrypt → decrypt yields original plaintext.
- Tag verification fails on bit-flip.
- AD-only path doesn't change ciphertext.
- Nonce size constraints respected (GCM: 12 bytes; OCB: 12 or 15; EAX: 16).

## Dependency

- TODO #02 (registry)
- TODO #04 (foundation)

## Out of scope

- Nonce-misuse-resistant AEAD (SIV, GCM-SIV). Add later as separate
  algorithm name if needed.
