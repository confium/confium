# 12 — Keystore interface

## Why

Phase 2 of the project roadmap (issue #11). The keystore is what
makes Confium a *trust store* framework — not just a crypto engine.
Compartmentalized public and private spaces, micro-managed access,
identity-based public key distribution.

## Goal

New FFI interface named `"keystore"`, symbol prefix `cfmp_keystore_`.

## Design

Two compartments per (module_id, app_id) pair:

- **Public**: distributed, signed, identity-indexed
- **Private**: per-device, key-id-indexed, optionally hardware-backed

```c
uint32_t cfmp_keystore_create(
    const Confium *cfm,
    FFIKeystore **out,
    const char *backend,            // "filesystem", "memory", "pkcs11", "tpm"
    const Option *opts);            // path, slot, pin, etc.

uint32_t cfmp_keystore_put_secret(
    FFIKeystore *ks,
    const char *module_id,
    const char *app_id,
    const char *key_id,
    const FFIKey *secret_key);

uint32_t cfmp_keystore_get_secret(
    FFIKeystore *ks,
    const char *module_id,
    const char *app_id,
    const char *key_id,
    FFIKey **out);

uint32_t cfmp_keystore_put_public(
    FFIKeystore *ks,
    const char *module_id,
    const char *app_id,
    const char *identity,           // email, hash, etc.
    const FFIKey *public_key,
    const void *signature, uint32_t sig_len);

uint32_t cfmp_keystore_get_public(
    FFIKeystore *ks,
    const char *module_id,
    const char *app_id,
    const char *identity,
    FFIKey **out);

uint32_t cfmp_keystore_enumerate(
    FFIKeystore *ks,
    const char *module_id,
    const char *app_id,
    uint32_t compartment,           // 0 = public, 1 = private
    FFIKeyIterator **out);

uint32_t cfmp_keystore_key_iterator_next(FFIKeyIterator *it, FFIKey **out);
uint32_t cfmp_keystore_key_iterator_destroy(FFIKeyIterator *it);

void cfmp_keystore_destroy(FFIKeystore *ks);
```

## Backends

```
memory          // in-process HashMap (dev / test)
filesystem      // RFC 9580 keyring files, compartmentalized dirs
pkcs11          // HSM/smartcard (future)
tpm             // TPM 2.0 (future)
```

## Files

- New: `src/ffi/keystore.rs`
- New: `src/keystore.rs`
- New: `src/keystore/compartment.rs` (public/private enum)
- New: `src/keystore/identity.rs` (identity types: email, key-id, hash)

## Notes

- Depends on TODO #11 (keyfmt) for `FFIKey`.
- Public-key distribution design from the project README:
  identity-based signature scheme where the public key is the user's
  unique info (e.g. email). To `put_public`, you supply the identity +
  signature. Verifier checks identity signature before trusting.
- Private-key access gated by `(module_id, app_id, key_id)` triple.

## Persistence format

Defer to plugin. Default filesystem plugin uses RFC 9580 packet format
per `keyfmt` interface. Versioning handled by `keyfmt`.

## Test plan

- Put / get round-trip in memory backend
- Public/private compartments isolated (private key from public
  compartment is empty)
- Wrong module_id/app_id/key_id triple returns `Error::ValueNotFound`
- Identity signature mismatch on `put_public` returns
  `Error::IdentitySignatureInvalid`

## Dependency

- TODO #02 (registry)
- TODO #11 (keyfmt)

## Out of scope here

- pkcs11 / TPM backends (separate plugin repos)
- Threshold distribution of private keys (Phase 3, issue #12)
- Module repository (search/install of plugins, issue #1)
