//! Fuzz target: error source chain.
//!
//! Constructs several `Error` variants from fuzz input and walks the
//! `std::error::Error::source()` chain on each, asserting the walk
//! terminates (no infinite recursion) and never panics. Also exercises the
//! FFI accessors (`cfm_err_get_source`, `cfm_err_get_code`,
//! `cfm_err_destroy`) used to surface the chain across the C boundary.

#![no_main]

use std::ptr;

use confium_core::error::Error;
use confium_core::ffi::error::{cfm_err_destroy, cfm_err_get_code, cfm_err_get_source};
use libfuzzer_sys::fuzz_target;
use snafu::GenerateImplicitData;

fuzz_target!(|data: &[u8]| {
    // Split the corpus at the first NUL so the leading segment can carry a
    // name while the tail feeds derived values (codes, etc.).
    let split = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let (head, tail) = data.split_at(split);
    let name = String::from_utf8_lossy(head).into_owned();
    let tail_str = String::from_utf8_lossy(tail).into_owned();

    // Variant carrying a source chain: InvalidUTF8. Build the invalid byte
    // sequence from the fuzz input itself so the fuzzer can explore corner
    // cases, falling back to a canonical invalid sequence when the input
    // happens to be valid UTF-8.
    let invalid_bytes = invalid_utf8_bytes(head);
    walk_rust_chain(&invalid_utf8_error(&invalid_bytes));
    walk_ffi_chain(invalid_utf8_error(&invalid_bytes));

    // Variants without a typed source: arbitrary fuzz-derived names/codes.
    let unknown = Error::UnknownProvider { name: name.clone() };
    walk_rust_chain(&unknown);

    let code = tail.first().copied().unwrap_or(0) as u32;
    let internal = Error::PluginInternalError { name, code };
    walk_rust_chain(&internal);

    let unsupported = Error::UnsupportedAlgorithm { name: tail_str };
    walk_rust_chain(&unsupported);
    walk_ffi_chain(unsupported);
});

/// Return a byte sequence that is guaranteed to fail UTF-8 validation.
/// If `bytes` already contains invalid UTF-8, use it verbatim; otherwise
/// substitute a canonical invalid sequence.
fn invalid_utf8_bytes(bytes: &[u8]) -> Vec<u8> {
    if std::str::from_utf8(bytes).is_err() {
        bytes.to_vec()
    } else {
        vec![0xFFu8, 0xFE, 0xFD]
    }
}

/// Build an `Error::InvalidUTF8` from a byte sequence that is guaranteed
/// to fail UTF-8 validation. The caller is responsible for ensuring
/// `bytes` is invalid (see [`invalid_utf8_bytes`]).
fn invalid_utf8_error(bytes: &[u8]) -> Error {
    let utf8_err = std::str::from_utf8(bytes).expect_err("bytes must be invalid UTF-8");
    Error::InvalidUTF8 {
        backtrace: snafu::Backtrace::generate(),
        source: utf8_err,
    }
}

/// Walk the `std::error::Error::source()` chain for `err` up to a small
/// bounded depth. Any panic in the chain (infinite recursion, dangling
/// pointer dereference, etc.) surfaces as a fuzzer finding.
fn walk_rust_chain(err: &Error) {
    let mut current: Option<&dyn std::error::Error> = Some(err);
    for _ in 0..32 {
        match current.and_then(std::error::Error::source) {
            Some(next) => current = Some(next),
            None => break,
        }
    }
}

/// Box `err` and step through `cfm_err_get_source` (which boxes a
/// `Wrapped` variant per hop), freeing each hop via `cfm_err_destroy`.
/// Also exercises `cfm_err_get_code` on a freshly boxed error. Any panic
/// in the FFI chain walk (use-after-free, null deref, infinite recursion)
/// surfaces as a fuzzer finding.
fn walk_ffi_chain(err: Error) {
    let mut ptr: *mut Error = Box::into_raw(Box::new(err));
    for _ in 0..32 {
        let mut next: *mut Error = ptr::null_mut();
        // `cfm_err_get_source` reads `*ptr` and writes through `&mut next`.
        // The pointer is valid for the duration of the call (boxed above
        // or produced by the previous iteration).
        let rc = cfm_err_get_source(ptr, &mut next);
        if rc != 0 {
            break;
        }
        if next.is_null() {
            break;
        }
        // `cfm_err_destroy` reclaims the boxed `Error` at `ptr`.
        cfm_err_destroy(ptr);
        ptr = next;
    }
    cfm_err_destroy(ptr);

    // Exercise the code accessor on a freshly boxed error.
    let probe = Error::NullPointer {
        param: "probe",
        backtrace: snafu::Backtrace::generate(),
    };
    let probe_ptr = Box::into_raw(Box::new(probe));
    let mut code: u32 = 0;
    let rc = cfm_err_get_code(probe_ptr, &mut code);
    debug_assert_eq!(rc, 0, "cfm_err_get_code must succeed");
    cfm_err_destroy(probe_ptr);
    let _ = code;
}
