//! `From<...> for PyErr` implementations for the Confium upstream error types.
//!
//! All Confium error types implement [`std::fmt::Display`] via `thiserror`.
//! The blanket impl below converts each one into a Python
//! `ValueError` carrying the error's `Display` string. This removes the
//! repeated `.map_err(|e| PyValueError::new_err(e.to_string()))` boilerplate
//! from every callsite — callers can just use `?`.
//!
//! Pattern:
//!   ```ignore
//!   let inner: confium_pki::cert::Certificate = RustCert::from_der(bytes)?;
//!   ```
//!
//! Error context that's currently prefixed at callsites ("composite:
//! invalid envelope: ...") is dropped. The Python method name remains in
//! the traceback, which is sufficient for debugging.

use pyo3::{exceptions::PyValueError, PyErr};

/// Macro: implement `From<E> for PyErr` for one error type. All upstream
/// Confium error types expose `Display` via `thiserror`.
macro_rules! impl_py_err_from {
    ($($t:ty),* $(,)?) => {
        $(
            impl From<$t> for PyErr {
                fn from(e: $t) -> Self {
                    PyValueError::new_err(e.to_string())
                }
            }
        )*
    };
}

impl_py_err_from! {
    confium_pki::cert::CertError,
    confium_pki::cms::envelope::CmsError,
    confium_pki::cms::der_encode::DerError,
    confium_transparency::merkle::MerkleError,
    confium_attributes::dsl::ParseError,
    confium_composite::CompositeError,
}