//! Error model for the Store crate.
//!
//! Mirrors the conventions in `confium-core::error`: a snafu enum with an
//! `ErrorCode` repr-u32 mirror used to surface a stable numeric result
//! through the FFI boundary. The Store crate owns its own error type so it
//! can be compiled and linked independently of the Engine (the Store is a
//! Confium plugin in its own right, and its backends are registered inside
//! this crate).

use snafu::Backtrace;
use snafu::Snafu;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(display("NULL pointer on parameter '{}'", param))]
    NullPointer {
        param: &'static str,
        backtrace: Backtrace,
    },
    #[snafu(display("Invalid UTF-8"))]
    InvalidUTF8 {
        backtrace: Backtrace,
        source: std::str::Utf8Error,
    },

    #[snafu(display("Value not found"))]
    ValueNotFound,
    #[snafu(display("Invalid compartment: {}", value))]
    InvalidCompartment { value: u32 },
    #[snafu(display("Feature not implemented: {}", what))]
    NotImplemented { what: &'static str },

    #[snafu(display("Unknown backend: '{}'", name))]
    UnknownBackend { name: String },

    #[snafu(display("Invalid path component: '{}'", component))]
    InvalidPath { component: String },

    #[snafu(display("Identity signature invalid"))]
    IdentitySignatureInvalid,

    #[snafu(display("I/O error: {}", source))]
    Io {
        source: std::io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Wrapped error: {}", message))]
    Wrapped { message: String },
}

impl Error {
    pub fn code(&self) -> u32 {
        error_code(self)
    }
}

/// Numeric result codes returned through the FFI. The encoding starts at
/// `0x1000` to leave room for the Engine's error namespace (whose codes
/// begin at 1) — the Store is a separate crate and must not collide.
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum ErrorCode {
    UNKNOWN = 0x1000,
    NULL_POINTER = 0x1001,
    INVALID_UTF8 = 0x1002,

    VALUE_NOT_FOUND = 0x1010,
    INVALID_COMPARTMENT = 0x1011,
    NOT_IMPLEMENTED = 0x1012,

    UNKNOWN_BACKEND = 0x1020,

    INVALID_PATH = 0x1031,
    IO = 0x1032,

    IDENTITY_SIGNATURE_INVALID = 0x1030,

    WRAPPED = 0x1100,
}

fn error_code(error: &Error) -> u32 {
    match error {
        Error::NullPointer { .. } => ErrorCode::NULL_POINTER.into(),
        Error::InvalidUTF8 { .. } => ErrorCode::INVALID_UTF8.into(),

        Error::ValueNotFound => ErrorCode::VALUE_NOT_FOUND.into(),
        Error::InvalidCompartment { .. } => ErrorCode::INVALID_COMPARTMENT.into(),
        Error::NotImplemented { .. } => ErrorCode::NOT_IMPLEMENTED.into(),

        Error::UnknownBackend { .. } => ErrorCode::UNKNOWN_BACKEND.into(),

        Error::InvalidPath { .. } => ErrorCode::INVALID_PATH.into(),
        Error::Io { .. } => ErrorCode::IO.into(),

        Error::IdentitySignatureInvalid => ErrorCode::IDENTITY_SIGNATURE_INVALID.into(),

        Error::Wrapped { .. } => ErrorCode::WRAPPED.into(),
    }
}

impl From<ErrorCode> for u32 {
    #[inline]
    fn from(code: ErrorCode) -> u32 {
        code as u32
    }
}

impl From<Error> for u32 {
    #[inline]
    fn from(err: Error) -> u32 {
        error_code(&err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snafu::GenerateImplicitData;

    #[test]
    fn value_not_found_code() {
        let err = Error::ValueNotFound;
        assert_eq!(err.code(), ErrorCode::VALUE_NOT_FOUND as u32);
    }

    #[test]
    fn not_implemented_carries_context() {
        let err = Error::NotImplemented {
            what: "filesystem backend",
        };
        assert!(format!("{err}").contains("filesystem backend"));
        assert_eq!(err.code(), ErrorCode::NOT_IMPLEMENTED as u32);
    }

    #[test]
    fn null_pointer_has_param_in_display() {
        let err = Error::NullPointer {
            param: "ks",
            backtrace: Backtrace::generate(),
        };
        assert!(format!("{err}").contains("ks"));
    }
}
