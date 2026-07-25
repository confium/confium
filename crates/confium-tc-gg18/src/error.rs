//! Error helpers for the GG18 scheme crate.

use confium_tc::error::Error as TcError;

/// GG18 sub-codes (0x50xx).
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum Gg18ErrorCode {
    BAD_SHARE = 0x5001,
    VSS_VERIFY_FAILED = 0x5002,
    BELOW_THRESHOLD = 0x5010,
    BAD_ROUND_MESSAGE = 0x5020,
    BAD_PARTIAL_SIGNATURE = 0x5030,
    INTERNAL = 0x50FF,
}

impl From<Gg18ErrorCode> for u32 {
    #[inline]
    fn from(c: Gg18ErrorCode) -> u32 {
        c as u32
    }
}

/// Build a framework [`TcError`] carrying a GG18 sub-code.
pub fn scheme_error(code: Gg18ErrorCode) -> TcError {
    confium_tc::error::SchemeInternalSnafu {
        code: u32::from(code),
    }
    .build()
}

pub type Result<T> = std::result::Result<T, TcError>;
