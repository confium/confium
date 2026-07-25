# 03 — FFI error source chain (closes #3)

## Why

GitHub issue #3 (open since 2021) specifies the FFI error-handling
contract. Five of the six functions are implemented in
`src/ffi/error.rs`. `cfm_err_get_source` is `unimplemented!()` at
`src/ffi/error.rs:51`. The C ABI for walking snafu's error chain is
the only missing piece.

## Goal

`cfm_err_get_source(err, src)` returns `*mut Error` for the next error
in the chain, or NULL if `err` has no source. Caller destroys the
returned `Error` via `cfm_err_destroy`.

## Design

`crate::error::Error` is a snafu-derived enum. Snafu implements
`std::error::Error` for it, which provides `.source()` returning
`Option<&(dyn std::error::Error + 'static)>`.

The only variants of `crate::error::Error` that carry a `source` field
are:

- `InvalidUTF8 { source: std::str::Utf8Error }`
- `PluginLoadFailed { source: libloading::Error }`
- `PluginSymbolError { source: libloading::Error }`

The source types (`Utf8Error`, `libloading::Error`) are themselves
`std::error::Error`. To expose them through Confium's FFI we need to
wrap them in our own `Error` so they get our `code()` impl.

### Wrapping strategy

Introduce a new internal `Error` variant:

```rust
#[snafu(display("Underlying error: {}", inner))]
#[snafu(visibility(pub(crate)))]
Wrapped {
    inner: Box<dyn std::error::Error + Send + Sync + 'static>,
}
```

Add to `ErrorCode`:

```rust
WRAPPED = 100, // re-exported source error
```

`cfm_err_get_source` walks one step:

```rust
#[unsafe(no_mangle)]
pub extern "C" fn cfm_err_get_source(
    err: *const Error,
    src: *mut *mut Error,
) -> u32 {
    err_check_not_null!(err);
    err_check_not_null!(src);
    unsafe { *src = std::ptr::null_mut(); }
    let Some(source) = std::error::Error::source(&*err) else {
        return 0;
    };
    // Wrap the source so the caller can use the same Error API.
    let wrapped = crate::error::WrappedSnafu
        .build()
        // Box<dyn Error> requires Send+Sync; some sources (Utf8Error)
        // satisfy this. For those that don't, format!() into a string.
        ...;
    // ... allocate, return via *src
    0
}
```

The Send+Sync constraint on the boxed source is the only wrinkle.
`std::str::Utf8Error` is `Send + Sync`; `libloading::Error` is
`Send + Sync`. All current sources satisfy it. If a future source
doesn't, we can stringify.

## Files touched

- `src/error.rs` — add `Wrapped` variant, `WrappedSnafu` struct,
  `ErrorCode::WRAPPED`, `error_code` match arm.
- `src/ffi/error.rs` — implement `cfm_err_get_source`.
- `src/error.rs::tests` — unit tests for `Wrapped` and `source()`.
- `src/ffi/error.rs::tests` — integration-style tests for
  `cfm_err_get_source` walking each known source-carrying variant.

## Tests

1. `error::tests::wrapped_displays_inner` — `Wrapped { source: utf8 }`
   formats correctly.
2. `error::tests::source_chain_walks_one_step` — calling
   `std::error::Error::source()` on `InvalidUTF8` returns the
   `Utf8Error`.
3. `ffi::error::tests::cfm_err_get_source_returns_null_for_sourceless` —
   e.g. `NullPointer` has no source, returns NULL.
4. `ffi::error::tests::cfm_err_get_source_returns_wrapped_for_chained` —
   e.g. `InvalidUTF8` returns a non-NULL wrapped source that the
   caller must destroy.

## Acceptance

- CI green (the parsanol-style pipeline added in the modernization PR).
- `cargo test` covers the chain-walking for every variant with a
  `source` field.
- CHANGELOG entry under `0.2.1`.
- GitHub issue #3 closed with a comment linking to the implementing
  commit.
