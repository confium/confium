# 11 — Key serialization interface

## Why

Every asymmetric interface (signature, KEM, keystore) needs to consume
and produce serialized keys. The serialization format depends on the
use case (PEM/DER for general crypto, OpenPGP packets for OpenPGP,
raw bytes for raw ML-KEM, etc.).

Centralizing this as its own interface lets Confium transport
algorithm-agnostic key blobs between plugins and across
language boundaries.

## Goal

New FFI interface named `"keyfmt"`, symbol prefix `cfmp_keyfmt_`.

## Wire protocol

```c
uint32_t cfmp_keyfmt_parse(
    const Confium *cfm,
    const char *format,             // "OpenPGP", "PKCS#8-PEM", "PKCS#8-DER", "Raw"
    const char *algorithm_hint,     // e.g. "Kyber768-X25519" (some formats omit)
    const uint8_t *bytes, uint32_t len,
    FFIKey **out);

uint32_t cfmp_keyfmt_serialize(
    const FFIKey *key,
    const char *format,
    uint8_t *out, uint32_t out_max, uint32_t *out_len);

uint32_t cfmp_keyfmt_kind(const FFIKey *key, uint32_t *out);  // public/secret/both
uint32_t cfmp_keyfmt_algorithm(const FFIKey *key, const char **algorithm_out);
uint32_t cfmp_keyfmt_public(const FFIKey *key, FFIKey **public_only_out);
void cfmp_keyfmt_destroy(FFIKey *key);
```

## Formats

```
OpenPGP                  // RFC 9580 packet format (RNP's native)
PKCS#8-PEM, PKCS#8-DER   // RFC 5208 / 5958
PKCS#1-PEM, PKCS#1-DER   // RSA-specific legacy
SPKI-PEM, SPKI-DER       // SubjectPublicKeyInfo
JWK                      // RFC 7517
Raw                      // algorithm-specific byte string
OpenSSH                  // RFC 4253 + extensions
```

## Files

- New: `src/ffi/keyfmt.rs`
- New: `src/keyfmt.rs` (`Key`, `KeyKind`)

## Notes

- The plugin is responsible for parsing AND serializing. It owns the
  format ↔ algorithm mapping.
- For OpenPGP, the plugin reads RFC 9580 packets and extracts
  algorithm-specific key bytes — likely defers to an existing library
  (e.g. Sequoia) inside the plugin.
- `keyfmt_public` strips secret material: required for keystore
  public/private compartmentalization (TODO #12).

## Test plan

- Parse → serialize round-trip preserves bytes
- `keyfmt_public` strips secret material (no seckey bytes after call)
- Wrong-format rejection
- Composite key parsing (Kyber768-X25519) yields correct algorithm name

## Dependency

- TODO #02 (registry)
- TODO #04 (foundation)
- Hard dependency for TODO #09 (signature), #10 (KEM), #12 (keystore)
