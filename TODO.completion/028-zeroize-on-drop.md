# 028 — Zeroize-on-drop for sensitive byte returns

**Category**: Security
**Severity**: High
**Effort**: Medium (1 PR + crate republish)

## Problem

When a Ruby consumer calls `Confium::TC::FrostP256.generate_keypair`,
the private_key is a Ruby `String` living in the GC heap. The Rust side
allocated it, copied it, and then dropped the original. The Ruby copy
sits in memory until GC sweeps it — which for `String` in MRI can
take a long time and is non-deterministic.

For a P-256 signing key sitting in process memory unzeroed, this is a
defensible-security failure.

## Acceptance criteria

- [ ] A `Confium::SecureBytes` Ruby class wraps sensitive byte data.
  - Implements `#clear` (immediate zeroize + deallocate).
  - Implements `#bytes` (non-destructive read).
  - Implements `#bytes!` (destructive read — returns bytes, then
     zeroes).
  - Implements `#to_s` (returns a **copy**, leaves original intact).
  - Finalizer calls `#clear` so even forgotten instances get zeroed
     eventually.
- [ ] Every sensitive return value (private_key bytes, Shamir shares,
     decryption keys) wraps the result in `SecureBytes`.
- [ ] Spec: after `#clear`, `bytes` raises.
- [ ] Spec: after `#bytes!`, the instance is empty.

## Anti-patterns

- "The OS will zeroize" — false; virtual memory + swap + core dumps
  leak keys.
- Requiring the user to `#clear` manually — the finalizer must do it.

## Approach

```ruby
# lib/confium/secure_bytes.rb
class Confium
  class SecureBytes
    def initialize(bytes)
      @bytes = bytes.dup.force_encoding(Encoding::ASCII_8BIT)
    end
    def bytes; @bytes; end
    def bytes!; copy = @bytes.dup; clear; copy; end
    def clear
      @bytes&.clear
      @bytes = nil
    end
    def to_s; bytes.dup; end
    def finalize; clear; end
  end
end
```

The Rust side returns a `Vec<u8>` that magnus wraps as Array, not
String. The Ruby side dups the data into a `SecureBytes` wrapping
a `String` so the sensitive bytes live in the `SecureBytes` instance,
not the Array (which Ruby may share, copy, etc. unpredictably).

## Related

- [026-input-size-caps.md](026-input-size-caps.md) — pre-req to avoid
  accidental huge allocations during zeroize.
- [001-typed-error-hierarchy.md](001-typed-error-hierarchy.md) —
  `SecureBytes#clear` can raise a `Confium::ClearedError` if `#bytes`
  is called after clear.
