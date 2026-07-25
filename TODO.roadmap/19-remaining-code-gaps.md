# 19 — Remaining code gaps

## Unimplemented functions

1. `cfm_plugin_unload` — still `unimplemented!()` at crates/confium-core/src/ffi/plugin.rs:302. Needs: remove plugin from providers vec, call finalize_plugin, drop Rc<Library>.
2. `Confium::load_plugin` Rust API — still `unimplemented!()` at lib.rs:194. The C FFI path works; the Rust API path doesn't.

## Stubs to fill

3. Hardware store backends (PKCS#11, TPM, Cloud KMS) — all return `NotImplemented` for put/get/enumerate. Need real crypto operations.
4. GG18 Paillier MtA — range proofs + homomorphic computation not implemented (documented as simplified path).
5. Plugin SDK `#[plugin_interface]` — only generates hash v0 FFI. Need: cipher, aead, kdf, rng, signature, kem, keyfmt, keystore variants.

## Missing crates

6. `confium-sandbox-process` — out-of-process sandbox via IPC (TODO #15/16 sibling).

## Integration

7. `rnp-rs` integration — replace direct libloading FFI in confium-registry::verify with the rnp-rs crate once published.
8. confium-ruby: expose cipher, aead, kdf, rng, signature, kem, keyfmt, keystore, tc interfaces (TODO.finalize #14).
