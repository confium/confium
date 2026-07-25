# 24 — Architecture improvements and remaining work

## DRY violation: provider resolution boilerplate

Every interface module (hash.rs, rng.rs, cipher.rs, aead.rs, kdf.rs,
signature.rs, kem.rs, keyfmt.rs) duplicates ~100 lines of:

```rust
fn find_provider<'a>(cfm: &'a Confium, name: &str) -> Option<&'a Provider> { ... }
fn get_provider<'a>(cfm: &'a Confium, name: &str) -> Result<&'a Provider> { ... }
fn try_new(cfm, providers, name, opts) -> Result<T> { ... }
pub fn new(cfm, name, provider_name, opts) -> Result<T> { ... }
```

With 8 interfaces, that's ~800 lines of copy-paste. Extract into a
generic `resolve_provider::<T>()` helper in `confium-core::provider`.

## Error code unification

Error codes are scattered:
- confium-core: 1-100
- confium-store: 0x1000-0x1032
- confium-tc: 0x1000-0x1042
- confium-sandbox-wasm: 0x2000+
- confium-sandbox-process: 0x2100+

confium-store and confium-tc overlap at 0x1000. Document or renumber.

## Sealed trait for PluginInterface

Replace `Box<dyn Any>` downcast with a sealed `PluginInterface` trait.
Better type safety, compile-time checking, matches the user's "no
respond_to" rule (the Rust analog is Any::downcast_ref which is
runtime type checking).

## Additional work items

- rnp-rs integration: replace direct libloading FFI in verify.rs
- FROST/GG18/CMP20 spec test vectors (NIST KAT)
- confium-ruby: expose all new interfaces
- Performance benchmarks: overhead vs direct library
- Documentation site: Antora at docs.confium.org
- Hardware backends: real PKCS#11/TPM/cloud operations
- Pedersen/Feldman DKG, Shoup threshold RSA
- Browser extension bridge via confiumd
