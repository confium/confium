//! Error translation between `cryptoki`'s error type and the Store's
//! [`Error`](confium_store::error::Error).
//!
//! The PKCS#11 backend surfaces failures through the Store's existing
//! error variants rather than introducing a parallel PKCS#11-specific
//! enum. The mapping is:
//!
//! | `cryptoki::error::Error`                  | Store variant          |
//! |-------------------------------------------|------------------------|
//! | anything carrying a "value not found"     | [`ValueNotFound`]      |
//! |   signal (object handle lookup misses)    |                        |
//! | everything else                           | [`Wrapped`]            |
//!
//! The `Wrapped` message carries the `cryptoki` Display string so the
//! operator sees the underlying PKCS#11 return code.
//!
//! [`ValueNotFound`]: confium_store::error::Error::ValueNotFound
//! [`Wrapped`]: confium_store::error::Error::Wrapped

use confium_store::error::{Error, Result};

/// Translate a `cryptoki` failure into a Store [`Error`].
///
/// This is a trait rather than a free function so that future PKCS#11
/// sub-types (e.g. a session-pool wrapper) can override the mapping
/// without rewriting call sites. Today there is a single blanket impl
/// for `cryptoki::error::Error`.
pub trait IntoStoreError {
    /// Convert into a Store [`Result::Err`].
    fn into_store_error(self, ctx: &str) -> Error;
}

impl IntoStoreError for cryptoki::error::Error {
    /// Map a `cryptoki` error. The `ctx` string is prepended to the
    /// message so the caller can record where in the open/operation
    /// flow the failure occurred (e.g. "open session", "login").
    fn into_store_error(self, ctx: &str) -> Error {
        // PKCS#11 signals a missing object via `CKR_OBJECT_HANDLE_INVALID`
        // (cryptoki surfaces it as `Error::Pkcs11(RvError::ObjectHandleInvalid, _)`).
        // That is the canonical "value not found" signal from a
        // `C_FindObjects` / `C_DestroyObject` miss, so we map it to the
        // Store's `ValueNotFound`. Everything else is wrapped with the
        // cryptoki Display string so the operator sees the underlying
        // PKCS#11 return code.
        match &self {
            cryptoki::error::Error::Pkcs11(rv, _) => {
                if matches!(rv, cryptoki::error::RvError::ObjectHandleInvalid) {
                    return Error::ValueNotFound;
                }
                Error::Wrapped {
                    message: format!("{ctx}: {self}"),
                }
            }
            _ => Error::Wrapped {
                message: format!("{ctx}: {self}"),
            },
        }
    }
}

/// Convenience: map a `cryptoki` result into a Store result, tagging
/// the failure with the supplied context string.
pub(crate) fn map_cryptoki<T>(
    r: std::result::Result<T, cryptoki::error::Error>,
    ctx: &str,
) -> Result<T> {
    r.map_err(|e| e.into_store_error(ctx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;
    use cryptoki::error::{Error as CkError, RvError};

    #[test]
    fn non_found_error_becomes_wrapped_with_context() {
        // Construct a representative error using a real cryptoki
        // variant. `Pkcs11(RvError, Function)` is the shape every
        // PKCS#11 return-code failure takes; pick a non-"not found"
        // RvError so the wrapped branch is exercised.
        let err = CkError::Pkcs11(RvError::GeneralError, Function::Login);
        let mapped = err.into_store_error("login");
        assert!(matches!(mapped, Error::Wrapped { .. }));
        let msg = match mapped {
            Error::Wrapped { message } => message,
            _ => unreachable!(),
        };
        assert!(msg.starts_with("login"), "context is prepended: {msg}");
    }

    #[test]
    fn object_handle_invalid_maps_to_value_not_found() {
        // `CKR_OBJECT_HANDLE_INVALID` is the PKCS#11 signal for a
        // missing object; the Store surfaces it as `ValueNotFound`.
        let err = CkError::Pkcs11(RvError::ObjectHandleInvalid, Function::FindObjects);
        let mapped = err.into_store_error("find object");
        assert!(matches!(mapped, Error::ValueNotFound), "got {mapped:?}");
    }

    #[test]
    fn map_cryptoki_ok_passthrough() {
        let r: std::result::Result<u32, CkError> = Ok(42);
        let mapped = map_cryptoki(r, "ctx").expect("ok passthrough");
        assert_eq!(mapped, 42);
    }
}
