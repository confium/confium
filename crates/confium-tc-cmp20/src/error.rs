//! Error helpers for the CMP20 scheme crate.

use confium_tc::error::Error as TcError;

/// CMP20 sub-codes (0x60xx). Distinct from GG18's 0x50xx so callers can
/// disambiguate the source scheme from a numeric code alone.
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum Cmp20ErrorCode {
    /// A share blob failed to deserialize or had the wrong magic / version.
    /// Caller action: regenerate shares via DKG; the on-disk format may
    /// have been corrupted or written by a different scheme.
    BAD_SHARE = 0x6001,
    /// A party's VSS commitment did not verify against the polynomial
    /// shares it claims to distribute. Indicates a malformed or
    /// malicious share submission.
    /// Caller action: treat the contributing party as Byzantine.
    VSS_VERIFY_FAILED = 0x6002,
    /// Fewer than T shares were supplied for a sign / decapsulation
    /// session. The threshold was set during DKG; supplying fewer
    /// shares is a programming error, not a network fault.
    /// Caller action: collect more shares before retrying.
    BELOW_THRESHOLD = 0x6010,
    /// A round message failed to deserialize or had an unexpected
    /// sender / round number. Indicates protocol desynchronization
    /// (one party is on a different round than the others) or a
    /// buggy / malicious peer.
    /// Caller action: abort the session; do not retry with the same
    /// message feed.
    BAD_ROUND_MESSAGE = 0x6020,
    /// A partial signature was malformed (wrong length, out-of-range
    /// scalar) but the offending party is not identified. This is the
    /// non-identifiable-abort path; if identifiable abort is enabled,
    /// [`IDENTIFIED_BYZANTINE`](Self::IDENTIFIED_BYZANTINE) is emitted
    /// instead.
    BAD_PARTIAL_SIGNATURE = 0x6030,
    /// Identifiable abort: a specific peer posted an inconsistent
    /// partial signature. The carry payload identifies the offending
    /// party by its 1-based roster index in the low byte.
    IDENTIFIED_BYZANTINE = 0x6040,
    /// Internal error — a panic-equivalent condition was caught and
    /// converted to an error return. Indicates a bug in the CMP20
    /// implementation; please open an issue.
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
