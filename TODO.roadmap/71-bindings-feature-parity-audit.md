# 71. Bindings Feature Parity Audit

**Status:** Active. Living document — update whenever a new subsystem
lands in any of the bindings (Rust / Ruby / WASM).

**Purpose:** ensure the three language surfaces of Confium (native Rust,
Ruby via `confium-ruby`, browser/Node.js via `@confium/confium-wasm`)
expose the right operations to the right audiences. The goal is *not*
100% mirror — each surface has a different job. The goal is *coverage of
each surface's intended job*.

## The three surfaces and their jobs

| Surface | Primary job | Anti-goal |
|---|---|---|
| **Rust native** (canonical) | Issuer, signer, threshold session participant, coordinator, server. Everything. | — |
| **Ruby (`confium-ruby`)** | Server-side automation of CNML workflows: issue certs, wrap in CMS, anchor in transparency, verify composite sigs, evaluate attribute predicates. | Browser anything; per-call hot loops (use Rust). |
| **WASM (`@confium/confium-wasm`)** | Browser/Node.js **verifier** only. Verify composite sigs, validate cert paths, verify CMS, verify transparency proofs, evaluate attribute predicates. | Issuing, signing, holding key material, network sessions. |

**Why WASM is verify-only:** the threshold-cryptography threat model
requires key material to never leave a controlled environment. Browsers
cannot be a controlled environment. Putting signing in WASM violates
the model. Verifying in WASM is fine because verification needs only
public keys.

## Subsystem coverage matrix

Legend: ✅ = shipped, 🚧 = scaffolded/stubbed, ❌ = missing, ➖ = N/A by design.

| Subsystem | Rust crate(s) | Ruby | WASM | Notes |
|---|---|---|---|---|
| Engine core (hash, rng, cipher, aead, kdf, kem, keyfmt, signature) | `confium-core` | ❌ | ❌ | Ruby/WASM should use crypto primitives directly via their respective crates (`sha2`, `rand`, `aes-gcm`, etc.), not the plugin engine. The plugin engine is for plugin authors. |
| Composite signatures (verify) | `confium-composite` | ✅ | ✅ | |
| Composite signatures (sign Ed25519 component) | `confium-composite::build_ed25519_component` | ✅ | ➖ | Sign stays server-side. |
| Transparency: Merkle tree (build, root) | `confium-transparency::merkle` | ✅ | ✅ | |
| Transparency: Inclusion proof verify | `confium-transparency::merkle` | ✅ | ✅ | |
| Transparency: OTS anchoring | `confium-transparency::ots` | ❌ | ➖ | Server-side;Ruby TBD. |
| Transparency: ERS archival | `confium-transparency::ers` | ❌ | ➖ | Server-side; Ruby TBD. |
| Attributes DSL (parse + evaluate) | `confium-attributes` | ✅ | ✅ | |
| Attributes DSL (round-trip serialize) | — | ❌ | ❌ | Currently no serde on `Predicate` (recursive type). See [TODO.roadmap/38](38-attribute-based-threshold.md). |
| X.509 cert (parse) | `confium-pki::cert` | ❌ | ❌ | Phase 1C. |
| X.509 cert (build / sign) | `confium-pki::cert::builder` | ❌ | ➖ | Server-side; Ruby Phase 1C. |
| X.509 cert path validation | `confium-pki::path` | ❌ | ❌ | Phase 1C. |
| CSR (parse / build) | `confium-pki::csr` | ❌ | ➖ | Phase 1C. |
| CMS SignedData (verify) | `confium-pki::cms` | ❌ | ❌ | Phase 1C. |
| CMS SignedData (build / sign) | `confium-pki::cms` | ❌ | ➖ | Phase 1C Ruby. |
| XMLDSig + Exclusive C14N | `confium-pki::xmldsig` | ❌ | ❌ | Phase 1C. |
| Cert delegation templates | `confium-pki::delegation` | ❌ | ➖ | Phase 1D. |
| TC session primitives | `confium-tc` | ❌ | ➖ | Ruby Phase 1D. WASM never. |
| FROST-ed25519 (3-round signing) | `confium-tc-frost-ed25519` | ❌ | ➖ | Ruby Phase 1D. |
| FROST-P256 (Shamir + ECDSA) | `confium-tc-frost-p256` | ❌ | ➖ | Ruby Phase 1D. |
| CMP20 threshold ECDSA | `confium-tc-cmp20` | ❌ | ➖ | Ruby Phase 1D. |
| GG18 threshold ECDSA | `confium-tc-gg18` | ❌ | ➖ | Ruby Phase 1D. |
| Threshold ElGamal-P256 | `confium-tc-elgamal-p256` | ❌ | ➖ | Ruby Phase 1D. |
| Threshold ECIES-P256 | `confium-tc-ecies-p256` | ❌ | ➖ | Ruby Phase 1D. |
| Async session coordinator | `confium-tc::coordinator` | ❌ | ➖ | Ruby Phase 1D. |
| Share re-sharing + Herzberg refresh | `confium-tc::reshare` | ❌ | ➖ | Ruby Phase 1D. |
| Threshold KEM | `confium-tc-kem` | ❌ | ➖ | Ruby Phase 1D. |
| Threshold BLS | `confium-tc-bls` | ❌ | ➖ | Ruby Phase 1D. |
| Threshold ML-KEM / ML-DSA / FHE / ring | `confium-tc-ml-kem` etc. | ❌ | ➖ | Research; later phase. |
| Identity (manufacturer, lab, IA, BIML) | `confium-deployment::identity` | ❌ | ❌ | Phase 1C. |
| Config / deployment manifest | `confium-deployment::manifest` | ❌ | ➖ | Phase 1C Ruby. |
| Deployment validation | `confium-deployment::validate` | ❌ | ➖ | Phase 1C Ruby. |
| PKCS#11 server dispatch | `confium-pkcs11-server` | ➖ | ➖ | C ABI; not for Ruby/WASM. |
| OpenSSL 3.0 provider | `confium-openssl-provider` | ➖ | ➖ | C ABI; not for Ruby/WASM. |
| JCE provider | `confium-jce-provider` | ➖ | ➖ | Java; not for Ruby/WASM. |
| TLS 1.3 signer | `confium-tls-signer` | ➖ | ➖ | Server-side callback; not for Ruby/WASM. |
| Network transports (TCP, QUIC, WS) | `confium-net-*` | ➖ | ➖ | Coordinator internals. |
| Coordinator TCP server/client | `confium-tc::coordinator::net*` | ➖ | ➖ | Coordinator internals. |
| Store backends (PKCS11, TPM, cloud, OpenPGP card) | `confium-store-*` | ❌ | ➖ | Ruby Phase 1E. WASM never. |
| Sandbox (WASM, process) | `confium-sandbox-*` | ➖ | ➖ | Tooling; not for Ruby/WASM. |
| Escrow (threshold key backup) | `confium-escrow` | ❌ | ➖ | Ruby Phase 1E. |
| Revocation service | `confium-revocation-service` | ❌ | ➖ | Ruby Phase 1E. |

## Coverage as of 2026-07-27

**Ruby (`confium-ruby` v0.1.0):**
- ✅ Composite (verify + sign Ed25519 + ECDSA-P256 components + keypair gen)
- ✅ Transparency Merkle tree (append + root + inclusion proof + verify)
- ✅ Attributes (parse + evaluate)
- ✅ PKI::Certificate (parse PEM/DER + inspect + validity)
- ✅ PKI::CSR (parse + round-trip)
- ✅ PKI::CMS::SignedData (JSON wire format + signature verification for Ed25519 + ECDSA-P256)
- ✅ PKI::XMLDSig (Canonical XML + Exclusive C14N)
- ✅ Identity::Actor + actor_types
- ✅ Config::Manifest (parse + validate)
- ✅ TC::FrostP256 (Shamir split + Lagrange recover + ECDSA sign)
- ✅ TC::ElGamalP256 (encapsulate + partial_decrypt + aggregate)
- 78 specs passing including a CNML-style end-to-end integration spec
- RBS type signatures in `sig/confium.rbs` + Steepfile for type checking
- Cross-platform native gem build via rake-compiler-dock (5 platforms)
- CI on Ruby 3.1-3.4 across Linux/macOS/Windows

**WASM (`@confium/confium-wasm` v0.3.0-dev):**
- ✅ Composite (verify Ed25519 + ECDSA-P256)
- ✅ Transparency Merkle tree (append + root + inclusion proof + verify)
- ✅ Transparency standalone tree-head verifier (Phase 2C)
- ✅ Attributes (parse + evaluate)
- ✅ PKI::Certificate (parse + validity)
- ✅ PKI::CMS::SignedData (JSON wire format)
- CI builds for `--target web`, `--target nodejs`, `--target bundler`
- 9 wasm-bindgen-test cases passing

**Gaps by surface (post-v0.1.0 Ruby, post-2C WASM):**

Ruby — next priorities (v0.2.0):
1. Multi-party TC session orchestration (FROST/CMP20/GG18 ceremonies)
2. Async Coordinator client (drives `confium-tc::coordinator`)
3. CMS signature VERIFICATION (currently we only parse, not verify signatures)
4. ECDSA-P256 component in Composite (sign + verify)
5. RBS type signatures in `sig/`
6. Cross-platform binary gems via `rake-compiler-dock`

WASM — next priorities (v0.3.0 release):
1. CMS signature verification with caller-supplied verifier callback
2. Certificate path validation (`Confium::PKI::PathValidator` equivalent)
3. Node.js adapter (replace `getrandom` `js` feature with native `crypto.webcrypto`)
4. `wasm-pack build --target bundler` pipeline + npm publish workflow
5. ML-DSA-65 / SLH-DSA verifier hooks (caller-supplied, no native PQ in WASM blob)

## Related docs

- [72-ruby-bindings-roadmap.md](72-ruby-bindings-roadmap.md) — per-phase Ruby work plan
- [73-wasm-bindings-roadmap.md](73-wasm-bindings-roadmap.md) — per-phase WASM work plan
- [74-bindings-architecture-principles.md](74-bindings-architecture-principles.md) — code-quality rules (OCP, DRY, MECE, no `send`/`instance_variable_get`/`respond_to?`, autoload)
- [46-rnp-integration.md](46-rnp-integration.md) — OpenPGP backend
