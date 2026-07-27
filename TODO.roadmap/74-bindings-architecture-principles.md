# 74. Bindings Architecture Principles

**Status:** normative. Every PR touching `confium-ruby` or
`confium-wasm` must adhere to these rules. Reviewers reject violations.

The principles below apply on top of the workspace-wide rules in
`CLAUDE.md`. They are scoped specifically to the Ruby and WASM binding
surfaces.

## 1. Open/Closed Principle (OCP) — extend, don't modify

Every new algorithm, cert extension, transparency-log entry type, or
attribute predicate operator must be **additive**. Existing classes
stay closed for modification; new behavior goes in new files, new
classes, or new feature flags.

How this shows up:

- **Ruby:** new subsystem = new `lib/confium/<subsystem>.rb` autoload
  entry + new `ext/confium_native/src/<subsystem>.rs` module. The init
  function in `lib.rs` gets one new line: `<subsystem>::init(ruby, confium)?`.
- **WASM:** new verifier = new `src/<verifier>.rs` module, gated by a
  new `verify-*` Cargo feature. Existing modules don't change.

Anti-pattern: adding an `algorithm` argument to an existing method that
gates a code branch. Instead, add a new method (e.g.
`sign_p256_component` next to `sign_ed25519_component`).

## 2. DRY — single source of truth

- The Rust crate is the source of truth. Ruby and WASM wrap it; they
  never re-implement crypto.
- The C ABI in `confium-core/ffi/` is the **only** external C/C++ API.
  Ruby and WASM bind to Rust directly via magnus / wasm-bindgen; they do
  **not** bind to the C ABI.
- Byte-shape conventions (binary `String` in Ruby, `Uint8Array` in JS)
  are defined once in this doc and reused everywhere.

## 3. MECE — each concern lives in exactly one place

- `Confium::Transparency::MerkleTree` owns Merkle operations. No
  other class adds Merkle methods.
- `Confium::Composite` owns PQ-composite signatures.
- `Confium::Attributes` owns predicate parsing + evaluation.
- Cross-subsystem helpers (e.g. "anchor this certificate in a Merkle
  tree") live in the *consumer* (an integration gem or a script), not
  in either of the underlying classes.

## 4. Model-driven, semantically-driven

- Classes are named after domain concepts (`Certificate`, `Signer`,
  `InclusionProof`), not after implementation artifacts
  (`CertWrapper`, `SignerHandle`, `ProofObj`).
- Methods are named after domain actions (`#verify`, `#sign`,
  `#append`, `#evaluate`), not after RPC verbs (`#do_verify`,
  `#call_sign`).
- Errors are typed (`Confium::VerificationError`,
  `Confium::ParseError`), not string-raised.

## 5. Type safety — no `send`, no `instance_variable_get`, no `respond_to?`

These rules are non-negotiable across all Confium Ruby code:

| Anti-pattern | Why forbidden | What to do instead |
|---|---|---|
| `obj.send(:private_method)` | Bypasses encapsulation; defeats the type system; breaks under refactoring. | Add a public method, or rethink the boundary. |
| `obj.instance_variable_get(:@foo)` | Reaches into another object's state; breaks invariants. | Add a public reader (`attr_reader :foo`) or rethink ownership. |
| `obj.instance_variable_set(:@foo, val)` | Same as above + mutates state without the object's consent. | Add a public writer or a constructor argument. |
| `obj.respond_to?(:foo)` | Duck-typing that hides type errors until runtime. | Use `is_a?` for type checks, or design the type hierarchy so the check isn't needed. |
| `require_relative "foo"` inside library code | Tight coupling to load order; breaks lazy loading; circular-dep risk. | Use Ruby `autoload`. Define entries in the immediate parent namespace's file. Create the file if it doesn't exist. |

The autoload pattern in `lib/confium.rb`:

```ruby
module Confium
  autoload :Transparency, "confium/transparency"
  autoload :Composite,    "confium/composite"
  autoload :Attributes,   "confium/attributes"
  # ... one line per top-level child ...
end
```

Each `lib/confium/<child>.rb` then opens its module and registers
autoloads for its own children:

```ruby
# lib/confium/transparency.rb
module Confium::Transparency
  autoload :MerkleTree,      "confium/transparency/merkle_tree"
  autoload :InclusionProof,  "confium/transparency/inclusion_proof"
end
```

The native Rust extension is required once by `lib/confium.rb` (the
top-level entry). The classes themselves are defined in Rust via
magnus — autoload entries for them point at the Ruby-side pure-Ruby
companion modules (e.g. `Confium::Transparency` module body) where
documentation helpers and class-method shims live.

## 6. Performance — within 2× of native Rust

- Ruby / WASM methods that wrap a single Rust call must be measured.
  Anything above 2× native needs justification.
- Hashing, signing, verifying — benchmark in `benchmark/` directory
  per crate. Run on every PR that touches a hot path.
- WASM release profile: LTO + opt-level=3 + codegen-units=1.
- Ruby release profile: same. Avoid debug builds in published gems.

## 7. Specs / tests

- Every public method has at least one spec.
- Every validation path (input malformed, wrong shape, wrong size) has
  at least one spec.
- Every algorithm variant has at least one happy-path spec.
- Cross-language round-trip spec: a value produced by Rust is consumed
  by Ruby / WASM and vice versa. Caught at the integration-test layer.

## 8. No silent fallbacks

- If a method needs a feature that's not compiled in, it raises a clear
  error pointing at the missing Cargo feature.
- If a verifier callback for an unknown algorithm isn't supplied, the
  composite verifier reports a per-component failure (does not silently
  pass).
- If a binary input isn't 32 bytes (or whatever the expected size is),
  raise `ArgumentError` with the actual and expected sizes.

## 9. Documentation

- Every public Ruby class has a YARD docstring (RBS annotations later).
- Every public WASM class has a `///` doc comment that wasm-bindgen
  surfaces to TypeScript.
- This roadmap tracks what's left; [71](71-bindings-feature-parity-audit.md)
  tracks what's done.

## 10. Backwards compatibility

- Once a class ships in a tagged release, its public API is frozen. Add
  new methods; don't change existing signatures.
- Deprecate with one minor version's notice (`warn "[DEPRECATION] ..."`
  in the old method).
- Never re-publish the same version with different code.
