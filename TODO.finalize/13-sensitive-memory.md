# 13 — Sensitive / Secret memory

## Why

GitHub issue #4 (open since 2021). Confidential secrets (private
keys, RNG output, AEAD keys) should not linger in process memory
longer than necessary, and ideally should be encrypted at rest in
RAM to defend against rowhammer-class attacks.

## Goal

Two types, implemented in two phases:

### Phase 1: `Sensitive<T>` (this TODO)

Wraps a `T: Default` and zeroizes it on `Drop`. Pulls in the
`zeroize` crate (BSD-3-Clause, already in the cargo-deny allowlist).

```rust
pub struct Sensitive<T: Zeroize + Default> {
    inner: T,
}

impl<T: Zeroize + Default> Sensitive<T> {
    pub fn new(value: T) -> Self { ... }
    pub fn as_ref(&self) -> &T { &self.inner }
    pub fn as_mut(&mut self) -> &mut T { &mut self.inner; }
    pub fn into_inner(mut self) -> T { ... }
}

impl<T: Zeroize + Default> Drop for Sensitive<T> {
    fn drop(&mut self) { self.inner.zeroize(); }
}
```

Uses `zeroize::Zeroize` (no `ZeroizeOnDrop` derive needed; we control
Drop).

### Phase 2: `Secret<T>` (deferred to a later TODO)

Encrypts the inner value at rest in RAM with an AEAD key derived from
a per-process random key. Decrypted only when explicitly borrowed.
This is significantly more complex (requires RNG, AEAD, careful
plaintext handling) and deserves its own TODO.

## Where Sensitive<T> is used in Confium core

- `Hash::new`'s `Hash` struct owns `*mut FFIHash` — already manually
  destroyed in Drop. Don't wrap.
- Future `Signer`'s `secret_key` bytes — wrap as `Sensitive<Vec<u8>>`.
- Future `KemDecapsulator`'s `secret_key` — same.
- Future `Kdf::derive`'s output before handing to caller — wrap.
- Keystore's in-memory private compartment — values wrapped.

## Files

- New: `src/sensitive.rs`
- New: `src/sensitive/tests.rs`
- Edit: `src/lib.rs` — `pub mod sensitive;`
- Edit: `Cargo.toml` — `zeroize = "1.8"` (BSD-3-Clause)
- Edit: `deny.toml` — verify BSD-3-Clause already allowed (it is)

## Test plan

- `sensitive_zeroizes_on_drop`: take `Sensitive<Vec<u8>>`, get raw
  pointer, drop, assert memory is zero.
- `sensitive_into_inner_does_not_zeroize`: `into_inner()` returns the
  value intact, caller now owns the lifetime.
- `sensitive_as_mut_allows_mutation`: borrow + mutate works.
- Run tests under valgrind / memcheck to confirm zeroize calls are
  reaching the actual memory (not optimized out by the compiler).
  `zeroize::Zeroize` uses an opaque `extern "Rust"` fn to defeat
  optimizers — should be safe.

## Dependency

- None. Pure-Rust, no plugin interaction.

## Acceptance

- `cargo build` / `clippy` / `deny` all clean.
- One new direct dep: `zeroize`. Verify it's still maintained.
- Used by at least one consumer (e.g. the future Signer struct) — or
  defer that to TODO #09.
