//! Error type for the FROST-ed25519 scheme plugin.
//!
//! The framework's [`confium_tc::Error::SchemeInternalError`] carries a
//! single `u32` code; this module gives those codes stable, disambiguating
//! values so a caller (or test) can tell a malformed commitment apart from
//! a bad Lagrange weight. Codes are reported through the FFI as
//! `0x1041 | sub`, where `sub` is the [`FrostError::code`] of the
//! underlying cause — they share the
//! [`confium_tc::error::ErrorCode::SCHEME_INTERNAL_ERROR`] envelope but
//! the low bits identify the FROST-specific failure.

use snafu::Snafu;

/// Sub-range of error codes used by this scheme. The framework reports
/// these via [`confium_tc::Error::SchemeInternalError`]'s `code` field.
/// They begin at `0x2100` to avoid colliding with future schemes.
pub const FROST_ERROR_BASE: u32 = 0x2100;

/// FROST-specific failure modes. Each variant maps to a distinct code so
/// a failure cause can be identified without string-matching.
#[derive(Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum FrostError {
    /// A round-1 commitment failed to decode or decompress.
    #[snafu(display("invalid commitment from party '{party}': {reason}"))]
    InvalidCommitment {
        party: String,
        reason: &'static str,
        code: u32,
    },

    /// A round-2 share response failed to decode.
    #[snafu(display("invalid share response from party '{party}': {reason}"))]
    InvalidShareResponse {
        party: String,
        reason: &'static str,
        code: u32,
    },

    /// Fewer than T distinct parties contributed to a signing round.
    #[snafu(display("below threshold: {have} contributing parties, need {need}"))]
    BelowThreshold { have: u32, need: u32, code: u32 },

    /// A party's commitment list is missing a required participant.
    #[snafu(display("missing commitment for party '{party}'"))]
    MissingCommitment { party: String, code: u32 },

    /// A party's share response failed verification against its commitment
    /// — proof of byzantine / malicious behavior.
    #[snafu(display("party '{party}' produced an invalid share response (byzantine)"))]
    InvalidShareSignature { party: String, code: u32 },

    /// The aggregate signature failed verification. Indicates either a
    /// broken implementation or coalition-level misbehavior.
    #[snafu(display("aggregate signature failed verification"))]
    AggregateVerificationFailed { code: u32 },

    /// The local share supplied to a signing session is malformed.
    #[snafu(display("local share is malformed: {reason}"))]
    MalformedShare { reason: &'static str, code: u32 },

    /// A VSS share received during DKG failed to verify against its
    /// sender's commitment polynomial.
    #[snafu(display("VSS share from party '{party}' failed verification (byzantine)"))]
    VssShareVerificationFailed { party: String, code: u32 },

    /// The roster is empty or has no party index for this party.
    #[snafu(display("roster configuration error: {reason}"))]
    RosterConfig { reason: &'static str, code: u32 },

    /// A message could not be parsed at all.
    #[snafu(display("malformed wire message: {reason}"))]
    MalformedMessage { reason: &'static str, code: u32 },

    /// The session was driven past its last round.
    #[snafu(display("round overflow at round {round}"))]
    RoundOverflow { round: u8, code: u32 },

    /// `result()` was called before the session completed.
    #[snafu(display("session is not complete"))]
    SessionNotComplete { code: u32 },
}

impl FrostError {
    /// Stable sub-code for this error. Combined with
    /// [`FROST_ERROR_BASE`] it forms the value reported through the
    /// framework's `SchemeInternalError`.
    pub fn code(&self) -> u32 {
        match self {
            FrostError::InvalidCommitment { code, .. }
            | FrostError::InvalidShareResponse { code, .. }
            | FrostError::BelowThreshold { code, .. }
            | FrostError::MissingCommitment { code, .. }
            | FrostError::InvalidShareSignature { code, .. }
            | FrostError::AggregateVerificationFailed { code, .. }
            | FrostError::MalformedShare { code, .. }
            | FrostError::VssShareVerificationFailed { code, .. }
            | FrostError::RosterConfig { code, .. }
            | FrostError::MalformedMessage { code, .. }
            | FrostError::RoundOverflow { code, .. }
            | FrostError::SessionNotComplete { code, .. } => *code,
        }
    }

    /// Convert into the framework's `SchemeInternalError` with this
    /// scheme's code in the low bits. Used at every session → framework
    /// boundary.
    pub fn framework(self) -> confium_tc::Error {
        confium_tc::error::SchemeInternalSnafu {
            code: FROST_ERROR_BASE | self.code(),
        }
        .build()
    }
}

pub type Result<T> = std::result::Result<T, FrostError>;

// --- code constants --------------------------------------------------------
//
// Distinct sub-codes so the failure cause is identifiable by number.

pub const CODE_INVALID_COMMITMENT: u32 = 0x01;
pub const CODE_INVALID_SHARE_RESPONSE: u32 = 0x02;
pub const CODE_BELOW_THRESHOLD: u32 = 0x03;
pub const CODE_MISSING_COMMITMENT: u32 = 0x04;
pub const CODE_INVALID_SHARE_SIG: u32 = 0x05;
pub const CODE_AGG_VERIFY_FAILED: u32 = 0x06;
pub const CODE_MALFORMED_SHARE: u32 = 0x07;
pub const CODE_VSS_VERIFY_FAILED: u32 = 0x08;
pub const CODE_ROSTER_CONFIG: u32 = 0x09;
pub const CODE_MALFORMED_MESSAGE: u32 = 0x0A;
pub const CODE_ROUND_OVERFLOW: u32 = 0x0B;
pub const CODE_SESSION_NOT_COMPLETE: u32 = 0x0C;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_disjoint() {
        let codes = [
            CODE_INVALID_COMMITMENT,
            CODE_INVALID_SHARE_RESPONSE,
            CODE_BELOW_THRESHOLD,
            CODE_MISSING_COMMITMENT,
            CODE_INVALID_SHARE_SIG,
            CODE_AGG_VERIFY_FAILED,
            CODE_MALFORMED_SHARE,
            CODE_VSS_VERIFY_FAILED,
            CODE_ROSTER_CONFIG,
            CODE_MALFORMED_MESSAGE,
            CODE_ROUND_OVERFLOW,
            CODE_SESSION_NOT_COMPLETE,
        ];
        let mut sorted = codes;
        sorted.sort_unstable();
        for w in sorted.windows(2) {
            assert_ne!(w[0], w[1], "error sub-codes must be distinct");
        }
    }

    #[test]
    fn framework_code_carries_base() {
        let e = FrostError::BelowThreshold {
            have: 1,
            need: 2,
            code: CODE_BELOW_THRESHOLD,
        };
        let fw = e.framework();
        let reported = match fw {
            confium_tc::Error::SchemeInternalError { code, .. } => code,
            _ => panic!("expected SchemeInternalError"),
        };
        assert_eq!(reported, FROST_ERROR_BASE | CODE_BELOW_THRESHOLD);
    }
}
