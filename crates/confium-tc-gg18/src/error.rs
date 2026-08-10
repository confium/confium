//! Error helpers for the GG18 scheme crate.

use confium_tc::error::Error as TcError;

/// GG18 sub-codes (0x50xx). Distinct from CMP20's 0x60xx so callers can
/// disambiguate the source scheme from a numeric code alone.
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum Gg18ErrorCode {
    /// A share blob failed to deserialize or had the wrong magic / version.
    /// Caller action: regenerate shares via DKG; the on-disk format may
    /// have been corrupted or written by a different scheme.
    BAD_SHARE = 0x5001,
    /// A party's VSS commitment did not verify against the polynomial
    /// shares it claims to distribute. Indicates a malformed or
    /// malicious share submission.
    /// Caller action: treat the contributing party as Byzantine.
    VSS_VERIFY_FAILED = 0x5002,
    /// Fewer than T shares were supplied for a sign / decapsulation
    /// session. The threshold was set during DKG; supplying fewer
    /// shares is a programming error, not a network fault.
    /// Caller action: collect more shares before retrying.
    BELOW_THRESHOLD = 0x5010,
    /// A round message failed to deserialize or had an unexpected
    /// sender / round number. GG18 has 4 rounds; a message from the
    /// wrong round indicates protocol desynchronization or a buggy
    /// peer.
    /// Caller action: abort the session; do not retry with the same
    /// message feed.
    BAD_ROUND_MESSAGE = 0x5020,
    /// A partial signature was malformed (wrong length, out-of-range
    /// scalar). GG18 does not support identifiable abort; if you need
    /// to attribute the failure to a specific peer, use CMP20 instead.
    BAD_PARTIAL_SIGNATURE = 0x5030,
    /// Internal error — a panic-equivalent condition was caught and
    /// converted to an error return. Indicates a bug in the GG18
    /// implementation; please open an issue.
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
