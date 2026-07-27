# 012 — Enumerable mixins

**Category**: Usability
**Severity**: Medium
**Effort**: Small (1 PR)

## Problem

Confium Ruby collections don't include `Enumerable`. Users can't do:

```ruby
tree.each { |entry| ... }
tree.map { ... }
result.per_component.each { ... }
shares.first(3)  # works, but tree.select { ... } doesn't
```

## Acceptance criteria

- [ ] `Confium::Transparency::MerkleTree` includes `Enumerable`,
     yields each leaf entry's `artifact_hash` bytes.
- [ ] `Confium::Composite::VerificationResult#per_component` returns an
     object that includes `Enumerable`, yields `(index, result)` pairs.
- [ ] `Confium::PKI::CMS::SignedData#each_certificate` — yields each
     certificate DER bytes.
- [ ] `Confium::TC::FrostP256::ShareSet` (new value object returned by
     `.split_secret`) includes `Enumerable`, yields each `Share`.
- [ ] Specs cover: `count`, `map`, `select`, `first(n)`, `to_a`.

## Anti-patterns

- Re-implementing iteration methods that `Enumerable` already gives you.
- Returning an `Array` instead of a typed collection — loses the type
  information.

## Approach

Pure-Ruby companion modules registered via `autoload`. The native
extension defines the data-holding classes; pure-Ruby modules in
`lib/confium/<subsystem>_mixin.rb` reopen them and `include Enumerable`.

Required autoload structure (each file must exist):

```
lib/confium.rb
  autoload :Transparency, "confium/transparency"

lib/confium/transparency.rb
  module Confium::Transparency
    # reopen MerkleTree (defined in the native extension) and include Enumerable
    require "confium_native/confium_native"  # ensure the class is loaded first
    class MerkleTree
      include Enumerable
      def each(&block)
        return to_enum(:each) unless block_given?
        (0...length).each { |i| yield inclusion_proof(i) }
      end
    end
  end
```

The `require "confium_native/..."` is the ONE allowed require (it loads
the Rust extension). All other internal loads use `autoload`.

## Related

- [016-hello-world-examples.md](016-hello-world-examples.md) — examples
  will use these idioms.
