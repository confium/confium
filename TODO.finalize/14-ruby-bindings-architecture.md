# 14 — confium-ruby architecture refactor

## Why

The Ruby bindings at `confium-ruby/` are currently flat (`lib/confium.rb`
+ `lib/confium/*.rb`) and use `require_relative` per the global ban.
The bindings need to grow to cover every new Confium interface
(sym, AEAD, KDF, RNG, signature, KEM, keystore), so a clean
autoload-based architecture must come first.

## Why autoload (per global rules)

`require_relative` puts every loaded file on the global `$LOAD_PATH`
eagerly, which:

1. Couples load order to file path
2. Makes monkey-patching easy and silent
3. Doesn't match the Ruby idiom for gems

`autoload` defers file load until first reference, lets each
namespace own its children's load paths, and works with zeitwerk-style
conventions.

## Goal

Each `Confium::<Child>` module autoloads its files via entries in the
**immediate parent's** namespace file. No `require_relative` anywhere
in `lib/`.

## Layout

```
lib/
  confium.rb               # opens module Confium; autoloads top-level children
  confium/
    ffi.rb                 # module Confium::FFI; autoloads FFI::*
    ffi/
      library.rb           # Confium::FFI::Library
      error.rb             # Confium::FFI::Error
      options.rb           # Confium::FFI::Options
    crypto/
      provider.rb          # Confium::Crypto::Provider
    crypto.rb              # module Confium::Crypto; autoloads Crypto::*
    digest.rb              # Confium::Digest (already exists)
    cipher.rb              # new
    aead.rb                # new
    kdf.rb                 # new
    rng.rb                 # new
    signature.rb           # new
    kem.rb                 # new
    keystore.rb            # new
    keyfmt.rb              # new
    sensitive.rb           # new (wraps Rust Sensitive<T> for byte buffers)
    version.rb             # Confium::VERSION (already exists)
```

## Pattern

```ruby
# lib/confium.rb
module Confium
  autoload :VERSION, "confium/version"
  autoload :FFI, "confium/ffi"
  autoload :Crypto, "confium/crypto"
  autoload :Digest, "confium/digest"
  autoload :Cipher, "confium/cipher"
  autoload :AEAD, "confium/aead"
  autoload :KDF, "confium/kdf"
  autoload :RNG, "confium/rng"
  autoload :Signature, "confium/signature"
  autoload :KEM, "confium/kem"
  autoload :Keyfmt, "confium/keyfmt"
  autoload :Keystore, "confium/keystore"
  autoload :Sensitive, "confium/sensitive"
end
```

```ruby
# lib/confium/ffi.rb
module Confium
  module FFI
    autoload :Library, "confium/ffi/library"
    autoload :Error, "confium/ffi/error"
    autoload :Options, "confium/ffi/options"
  end
end
```

## Forbidden patterns (per global rules)

After refactor, grep should return zero hits:

```
grep -rn 'require_relative' lib/      # MUST be empty
grep -rn 'require "confium' lib/      # MUST be empty
grep -rn 'send(' lib/                 # MUST be empty (or only external API)
grep -rn 'instance_variable_set\|instance_variable_get' lib/  # empty
grep -rn 'respond_to?' lib/           # empty (use is_a? or type-tag enum)
```

## Type checks without `respond_to?`

Per the global rule, use `is_a?`:

```ruby
# bad
def write(buf)
  raise unless buf.respond_to?(:read)
  ...
end

# good
def write(buf)
  raise TypeError, "expected IO, got #{buf.class}" unless buf.is_a?(IO)
  ...
end
```

Or — better — define interfaces as Ruby modules and `include` them,
then check `is_a?(Confium::Crypto::Buffer)`.

## OCP: plugin discovery in Ruby

Mirroring the Rust registry pattern from TODO #02, each new Ruby
module (Cipher, AEAD, etc.) registers itself with `Confium::Crypto`
rather than being listed in a central case statement. Pattern:

```ruby
module Confium
  module Crypto
    @interfaces = {}

    def self.register(name, klass)
      @interfaces[name] = klass
    end

    def self.lookup(name)
      @interfaces.fetch(name) do
        raise ArgumentError, "unknown interface #{name.inspect}"
      end
    end
  end
end

module Confium
  module Digest
    Confium::Crypto.register("hash", self)
    ...
  end
end
```

## Files touched

- Edit: `lib/confium.rb`
- Edit: `lib/confium/cfm.rb`, `lib/confium/digest.rb`, `lib/confium/lib.rb`, `lib/confium/version.rb`
- New: `lib/confium/ffi.rb` (namespace file)
- New: `lib/confium/crypto.rb` (namespace file)
- New: per-interface files (one per TODO #05-#12 interface)

## Test plan

- `bundle exec rspec` green for existing `confium_digest_spec.rb`
- New spec files per interface as those interfaces are implemented
- Lint spec: grep the forbidden patterns and assert empty
- `bundle exec rubocop` clean

## Dependency

- TODOs #02 through #11 should land in Rust first; the Ruby wrappers
  just bind to whatever Rust exposes.
- TODO #22 (this refactor) should land before TODO #14 (exposing new
  interfaces in Ruby) — order: refactor core autoload, then add new
  bindings.
