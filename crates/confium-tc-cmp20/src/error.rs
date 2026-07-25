//! Error helpers for the CMP20 scheme crate.

use confium_tc::error::Error as TcError;

/// CMP20 sub-codes (0x60xx). Distinct from GG18's 0x50xx so callers can
/// disambiguate the source scheme from a numeric code alone.
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum Cmp20ErrorCode {
    BAD_SHARE = 0x6001,
    VSS_VERIFY_FAILED = 0x6002,
    BELOW_THRESHOLD = 0x6010,
    BAD_ROUND_MESSAGE = 0x6020,
    BAD_PARTIAL_SIGNATURE = 0x6030,
    /// Identifiable abort: a specific peer posted an inconsistent
    /// partial signature. The carry payload identifies the offending
    /// party by its 1-based roster index in the low byte.
    IDENTIFIED_BYZANTINE = 0x6040,
    INTERNAL = 0x60FF,
}

impl From<Cmp20ErrorCode> for u32 {
    #[inline]
    fn from(c: Cmp20ErrorCode) -> u32 {
        c as u32
    }
}

/// Build a framework [`TcError`] carrying a CMP20 sub-code.
pub fn scheme_error(code: Cmp20ErrorCode) -> TcError {
    confium_tc::error::SchemeInternalSnafu {
        code: u32::from(code),
    }
    .build()
}

pub type Result<T> = std::result::Result<T, TcError>;
