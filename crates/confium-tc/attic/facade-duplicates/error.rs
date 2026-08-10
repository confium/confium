//! Error type for the threshold-cryptography crate.
//!
//! Mirrors the snafu-based pattern used by `confium-core`. FFI entry
//! points in [`crate::ffi`] map these into the numeric `u32` return
//! codes the C ABI expects.

use snafu::Backtrace;
use snafu::Snafu;

use crate::registry::TcSchemeKind;

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
    #[snafu(display("Interior NUL byte in C string"))]
    NulByte {
        backtrace: Backtrace,
        source: std::ffi::NulError,
    },

    #[snafu(display("Party index {} out of range (party count {})", idx, count))]
    PartyIndexOutOfRange {
        idx: usize,
        count: usize,
        backtrace: Backtrace,
    },
    #[snafu(display("Party list is empty"))]
    EmptyPartyList { backtrace: Backtrace },
    #[snafu(display("Threshold {} is below the minimum of 1", threshold))]
    ThresholdTooSmall {
        threshold: u32,
        backtrace: Backtrace,
    },
    #[snafu(display("Threshold {} exceeds party count {}", threshold, party_count))]
    ThresholdTooLarge {
        threshold: u32,
        party_count: usize,
        backtrace: Backtrace,
    },
    #[snafu(display("Duplicate party id '{}'", id))]
    DuplicatePartyId { id: String, backtrace: Backtrace },
    #[snafu(display("this_party_idx {} out of range (party count {})", idx, party_count))]
    ThisPartyIdxOutOfRange {
        idx: usize,
        party_count: usize,
        backtrace: Backtrace,
    },

    #[snafu(display("Unknown threshold scheme '{}'", name))]
    SchemeNotFound { name: String, backtrace: Backtrace },
    #[snafu(display("Session is not complete"))]
    SessionNotComplete { backtrace: Backtrace },
    #[snafu(display("Session is already complete"))]
    SessionAlreadyComplete { backtrace: Backtrace },
    #[snafu(display("Round counter overflowed at round {}", round))]
    RoundOverflow { round: u8, backtrace: Backtrace },
    #[snafu(display("Session is not a DKG session (kind {:?})", kind))]
    NotADkgSession {
        kind: TcSchemeKind,
        backtrace: Backtrace,
    },

    #[snafu(display("Share scheme mismatch: expected '{}', got '{}'", expected, actual))]
    ShareSchemeMismatch {
        expected: String,
        actual: String,
        backtrace: Backtrace,
    },
    #[snafu(display("Share bytes truncated: need {} bytes, have {}", needed, have))]
    ShareTruncated {
        needed: usize,
        have: usize,
        backtrace: Backtrace,
    },
    #[snafu(display("Share scheme name is not valid UTF-8"))]
    ShareInvalidScheme { backtrace: Backtrace },

    #[snafu(display("Insufficient buffer"))]
    InsufficientBuffer { backtrace: Backtrace },
    #[snafu(display("Scheme plugin returned error code {}", code))]
    SchemeInternalError { code: u32, backtrace: Backtrace },
}

impl Error {
    /// Stable numeric code for this error, returned through the FFI.
    pub fn code(&self) -> u32 {
        error_code(self)
    }
}

/// Numeric error codes for the `cfm_tc_*` ABI. These are deliberately
/// disjoint from the core engine's codes (which start at 1) so a
/// caller can disambiguate the source — TC codes begin at 0x1000.
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum ErrorCode {
    UNKNOWN = 0x1000,
    NULL_POINTER = 0x1001,
    INVALID_UTF8 = 0x1002,
    NUL_BYTE = 0x1003,

    PARTY_INDEX_OUT_OF_RANGE = 0x1010,
    EMPTY_PARTY_LIST = 0x1011,
    THRESHOLD_TOO_SMALL = 0x1012,
    THRESHOLD_TOO_LARGE = 0x1013,
    DUPLICATE_PARTY_ID = 0x1014,
    THIS_PARTY_IDX_OUT_OF_RANGE = 0x1015,

    SCHEME_NOT_FOUND = 0x1020,
    SESSION_NOT_COMPLETE = 0x1021,
    SESSION_ALREADY_COMPLETE = 0x1022,
    ROUND_OVERFLOW = 0x1023,
    NOT_A_DKG_SESSION = 0x1024,

    SHARE_SCHEME_MISMATCH = 0x1030,
    SHARE_TRUNCATED = 0x1031,
    SHARE_INVALID_SCHEME = 0x1032,

    INSUFFICIENT_BUFFER = 0x1040,
    SCHEME_INTERNAL_ERROR = 0x1041,
}

fn error_code(error: &Error) -> u32 {
    match error {
        Error::NullPointer { .. } => ErrorCode::NULL_POINTER.into(),
        Error::InvalidUTF8 { .. } => ErrorCode::INVALID_UTF8.into(),
        Error::NulByte { .. } => ErrorCode::NUL_BYTE.into(),

        Error::PartyIndexOutOfRange { .. } => ErrorCode::PARTY_INDEX_OUT_OF_RANGE.into(),
        Error::EmptyPartyList { .. } => ErrorCode::EMPTY_PARTY_LIST.into(),
        Error::ThresholdTooSmall { .. } => ErrorCode::THRESHOLD_TOO_SMALL.into(),
        Error::ThresholdTooLarge { .. } => ErrorCode::THRESHOLD_TOO_LARGE.into(),
        Error::DuplicatePartyId { .. } => ErrorCode::DUPLICATE_PARTY_ID.into(),
        Error::ThisPartyIdxOutOfRange { .. } => ErrorCode::THIS_PARTY_IDX_OUT_OF_RANGE.into(),

        Error::SchemeNotFound { .. } => ErrorCode::SCHEME_NOT_FOUND.into(),
        Error::SessionNotComplete { .. } => ErrorCode::SESSION_NOT_COMPLETE.into(),
        Error::SessionAlreadyComplete { .. } => ErrorCode::SESSION_ALREADY_COMPLETE.into(),
        Error::RoundOverflow { .. } => ErrorCode::ROUND_OVERFLOW.into(),
        Error::NotADkgSession { .. } => ErrorCode::NOT_A_DKG_SESSION.into(),

        Error::ShareSchemeMismatch { .. } => ErrorCode::SHARE_SCHEME_MISMATCH.into(),
        Error::ShareTruncated { .. } => ErrorCode::SHARE_TRUNCATED.into(),
        Error::ShareInvalidScheme { .. } => ErrorCode::SHARE_INVALID_SCHEME.into(),

        Error::InsufficientBuffer { .. } => ErrorCode::INSUFFICIENT_BUFFER.into(),
        Error::SchemeInternalError { .. } => ErrorCode::SCHEME_INTERNAL_ERROR.into(),
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

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_is_disjoint_from_core() {
        // Core codes start at 1; TC codes start at 0x1000.
        let err = SchemeNotFoundSnafu {
            name: "x".to_string(),
        }
        .build();
        assert!(err.code() >= 0x1000);
    }

    #[test]
    fn null_pointer_code() {
        let err = NullPointerSnafu { param: "x" }.build();
        assert_eq!(err.code(), ErrorCode::NULL_POINTER as u32);
    }
}
