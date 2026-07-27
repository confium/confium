# 72. Ruby Bindings Roadmap

**Status:** Phase 1A + 1B shipped (PRs #13, #14 merged). Phase 1C next.

**Principle:** every Ruby class wraps a single Rust crate (or a tightly
related group). The Ruby class is the *idiomatic* surface; the Rust
crate is the *canonical* implementation. The Ruby extension is built
via `rb_sys` + `magnus` (parsanol-ruby pattern), compiled at `gem install`
time. No FFI gem, no C ABI plumbing for new subsystems.

## Phasing

### Phase 1A — scaffold + transparency ✅ (shipped, PR #13)

- `Confium::Native.version` / `.loaded?` / `Confium.core_version`
- `Confium::Transparency::MerkleTree` — append, root, length, empty?
- `Confium::Transparency::InclusionProof` — sequence, steps, verify
- 10 specs in `spec/confium/transparency_spec.rb`

### Phase 1B — composite + attributes ✅ (shipped, PR #14)

- `Confium::Composite.generate_ed25519_keypair`
- `Confium::Composite.sign_ed25519(private_key, message)`
- `Confium::Composite::Signature.new(components)` + `#verify(message)` + `#component_count` + `#algorithms`
- `Confium::Composite::VerificationResult` + `#all_verified?` + `#per_component`
- `Confium::Attributes.parse(dsl_expr)` + `Predicate#satisfied_by?(signers)`
- `Confium::Attributes::Signer.new` + `#add(key, value)` + `#has?(key)` + `#values(key)`
- 17 specs across `spec/confium/composite_spec.rb` and `attributes_spec.rb`

### Phase 1C — PKI + deployment (next)

Goal: Ruby can drive a CNML certificate workflow end-to-end (issue →
wrap in CMS → anchor in transparency tree).

| Module | Wraps | Methods |
|---|---|---|
| `Confium::PKI::Certificate` | `confium_pki::cert` | `.parse(der_or_pem)`, `#subject`, `#issuer`, `#not_before`, `#not_after`, `#public_key`, `#fingerprint`, `#valid_at?(time)` |
| `Confium::PKI::Certificate::Builder` | `confium_pki::cert::builder` | `.new`, `#subject=`, `#issuer=`, `#valid_for(timespan)`, `#public_key=`, `#sign(private_key)`, `#to_der`, `#to_pem` |
| `Confium::PKI::PathValidator` | `confium_pki::path` | `.validate(leaf, intermediates:, root:)` |
| `Confium::PKI::CSR` | `confium_pki::csr` | `.parse`, `.new(subject)`, `#sign(private_key)`, `#to_pem` |
| `Confium::PKI::CMS::SignedData` | `confium_pki::cms` | `.parse(der)`, `#verify(certs)`, `#signers`, `#content`, `.sign(content, private_key, certificate)` |
| `Confium::Identity::Actor` | `confium_deployment::identity` | `.new(role:, id:, attributes:)`, accessors for role / id / attributes |
| `Confium::Identity::Role` | enum mirror | constants `MANUFACTURER`, `LAB`, `IA`, `BIML`, etc. |
| `Confium::Config::Manifest` | `confium_deployment::manifest` | `.parse(toml)`, `#validate`, `#actors`, `#threshold` |
| `Confium::Config::Validator` | `confium_deployment::validate` | `.new(manifest)`, `#errors`, `#valid?` |

Specs target: ~30 examples. New `spec/confium/pki_spec.rb`,
`spec/confium/identity_spec.rb`, `spec/confium/config_spec.rb`.

### Phase 1D — threshold cryptography

Goal: Ruby can drive TC signing sessions and the async coordinator.

| Module | Wraps | Methods |
|---|---|---|
| `Confium::TC::Session` | `confium_tc::session` | extend existing stub |
| `Confium::TC::Party` | `confium_tc::party` | full API |
| `Confium::TC::Share` | `confium_tc::share` | full API |
| `Confium::TC::Coordinator` | `confium_tc::coordinator` | extend existing stub |
| `Confium::TC::FrostEd25519` | `confium_tc_frost_ed25519` | round 1/2/3 + combine |
| `Confium::TC::FrostP256` | `confium_tc_frost_p256` | Shamir split + Lagrange combine |
| `Confium::TC::Cmp20` | `confium_tc_cmp20` | full session |
| `Confium::TC::Gg18` | `confium_tc_gg18` | full session |
| `Confium::TC::ElGamalP256` | `confium_tc_elgamal_p256` | encapsulate / partial_decrypt / aggregate |
| `Confium::TC::Reshare` | `confium_tc::reshare` | Herzberg refresh |
| `Confium::TC::Kem` | `confium_tc_kem` | threshold KEM |

Specs target: ~50 examples.

### Phase 1E — stores, escrow, revocation

| Module | Wraps | Methods |
|---|---|---|
| `Confium::Store::OpenpgpCard` | `confium_store_openpgp_card` | card-id, sign, decrypt, generate-keypair |
| `Confium::Store::Pkcs11` | `confium_store_pkcs11` | session, sign, decrypt |
| `Confium::Store::Tpm` | `confium_store_tpm` | seal, unseal |
| `Confium::Store::Cloud` | `confium_store_cloud` | KMS dispatch |
| `Confium::Escrow` | `confium_escrow` | threshold key backup |
| `Confium::Revocation` | `confium_revocation_service` | threshold revocation |

Specs target: ~20 examples.

### Phase 1F — release

- Cut `confium-ruby` v0.1.0 with all Phase 1C + a subset of 1D
- Cross-platform native gems via `rake-compiler-dock`
- RubyGems publish workflow in `.github/workflows/`
- Documentation: API reference (RBS in `sig/`), tutorial, CNML how-to

## Per-class invariants

Each Ruby class in `confium-ruby`:

1. **Wraps exactly one Rust struct** via `magnus::typed_data::Obj<T>`.
2. **Holds state in `std::cell::RefCell<T>`** when the underlying Rust
   type requires `&mut self` for any operation.
3. **Exposes binary data as `Encoding::ASCII_8BIT` Strings**, not Arrays
   of integers. (Crypto data is bytes.)
4. **Raises `ArgumentError`** for malformed input, `RuntimeError` for
   domain errors. No string-error `raise`.
5. **Has at least one RSpec example per public method** + one edge case
   per validation rule.
6. **Comes with an RBS signature** (Phase 1F) under `sig/confium/<subsystem>.rbs`.

## Anti-patterns to avoid

(See [74-bindings-architecture-principles.md](74-bindings-architecture-principles.md)
for the full list with rationale.)

- Using `Object#send` to call private methods.
- Using `instance_variable_get` / `instance_variable_set` to peek into
  another object.
- Using `respond_to?` for type checks (use `is_a?` or design the type
  hierarchy so the check isn't needed).
- Using `require_relative` for internal library code — autoload only.
- Re-implementing crypto in Ruby; always delegate to the Rust crate.
- Exposing mutable references to internal state without `#freeze` or
  `#dup` where appropriate.
