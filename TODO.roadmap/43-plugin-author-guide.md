# 43 — Plugin author guide

## Audience

Developers implementing new algorithms or transports for Confium.
Examples:

- A new threshold signature scheme (e.g., threshold SLH-DSA)
- A new transport (e.g., gRPC-based transport)
- A new store backend (e.g., HashiCorp Vault)
- A new envelope format (e.g., JWS)

## Plugin contract (recap)

Every Confium plugin exports these C symbols:

```c
uint32_t cfmp_interface_version(void);
uint32_t cfmp_initialize(...);
uint32_t cfmp_finalize(...);
uint32_t cfmp_query_interfaces(uint8_t *out, size_t out_max, size_t *out_len);
uint32_t cfmp_query_dependencies(...);
uint32_t cfmp_metadata(struct CFMPluginMetadata *out);
```

Plus per-interface functions (e.g., `cfmp_hash_*`, `cfmp_tc_session_*`).

## Adding a new threshold signing scheme

### 1. Pick the crate name

`confium-tc-<scheme>-<curve>` (e.g., `confium-tc-frost-ml-dsa-65`).

### 2. Implement the algorithm

Real algorithm crate, e.g.:

```rust
// crates/confium-tc-frost-ml-dsa-65/src/lib.rs
pub const ALGORITHM: &str = "FROST-ML-DSA-65";

pub struct ThresholdPublicKey { ... }
pub struct Share { ... }
pub struct Commitment { ... }
pub struct SignatureShare { ... }
pub struct AggregatedSignature { ... }

pub fn dkg(...) -> Result<DkgResult, FrostError> { ... }
pub fn sign_round_1(...) -> Result<Commitment, FrostError> { ... }
pub fn sign_round_2(...) -> Result<SignatureShare, FrostError> { ... }
pub fn aggregate(...) -> Result<AggregatedSignature, FrostError> { ... }
pub fn verify(pk: &ThresholdPublicKey, sig: &AggregatedSignature, msg: &[u8]) -> Result<(), FrostError> { ... }
```

### 3. Implement the FFI

Export `cfmp_tc_session_*` functions that delegate to the algorithm:

```rust
#[unsafe(no_mangle)]
pub extern "C" fn cfmp_tc_session_create(...) -> u32 { ... }
```

### 4. Tests

See `TODO.roadmap/42-testing-strategy.md`. Required:
- DKG produces valid public key + shares
- T-of-N signatures verify under standard tools
- Byzantine party triggers identifiable abort

### 5. Plugin manifest

```toml
[plugin]
name = "confium-tc-frost-ml-dsa-65"
version = "0.1.0"
vendor = "Ribose Inc."
license = "BSD-2-Clause"
interfaces = ["tc-signature"]
algorithm_id = "FROST-ML-DSA-65"
dependencies = []
```

### 6. Registry entry

Publish to the Confium plugin registry so users can `confium install`:

```toml
[[plugins]]
name = "confium-tc-frost-ml-dsa-65"
version = "0.1.0"
publisher = "ribose"
artifact_url = "https://github.com/confium/confium/releases/download/..."
artifact_hash = "sha256:..."
sigs = ["sigs/0.1.0.asc"]
```

## Adding a new transport

Implement the `Transport` and `Listener` traits from `confium-net`:

```rust
pub trait Transport: Send + Sync {
    fn send(&self, msg: &[u8]) -> Result<(), TransportError>;
    fn receive(&self) -> Result<Vec<u8>, TransportError>;
    fn close(&self) -> Result<(), TransportError>;
}

pub trait Listener: Send + Sync {
    fn accept(&self) -> Result<Box<dyn Transport>, TransportError>;
}
```

Register via `register_transport!` macro (link-time, like interfaces).

## Adding a new store backend

Implement `StoreBackend` trait from `confium-store`:

```rust
pub trait StoreBackend: Send + Sync {
    fn store(&self, key_id: &str, plaintext: &[u8]) -> Result<(), StoreError>;
    fn load(&self, key_id: &str) -> Result<Vec<u8>, StoreError>;
    fn delete(&self, key_id: &str) -> Result<(), StoreError>;
    fn list(&self) -> Result<Vec<String>, StoreError>;
}
```

Register via `register_backend!` macro.

## Existing patterns to follow

- `confium-tc-frost-p256` — real algorithm crate with Shamir + Lagrange + ECDSA
- `confium-tc-frost-ed25519` — full FROST-ed25519 (already shipped)
- `confium-store-openpgp-card` — hardware backend with mock for testing
- `confium-pkcs11-server` — Mode 2 dispatch layer

## Anti-patterns to avoid

- **Don't** implement crypto primitives from scratch — use established crates
  (`p256`, `ed25519-dalek`, `aes-gcm`, `sha2`, `ring`)
- **Don't** vendor random number generators — use Confium's `rng` interface
- **Don't** panic on bad input — return proper `Result<_, Error>`
- **Don't** add `unsafe` code without `// SAFETY:` justification
- **Don't** use `unwrap()` / `expect()` in production code paths (tests only)

## References

- `TODO.roadmap/03-plugin-contract.md`
- `TODO.roadmap/04-threshold-cryptography.md`
- `TODO.roadmap/06-module-registry.md`
