//! Error code catalog — typed error codes for all coordinator errors.
//!
//! Provides a stable, programmatic error code for each error type.
//! Clients can switch on error codes for automated error handling
//! (retry, escalate, ignore) without parsing error messages.

use serde::{Deserialize, Serialize};

/// A stable error code identifying the error category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Session not found.
    SessionNotFound,
    /// Session in wrong state for the operation.
    InvalidSessionState,
    /// Threshold not met.
    ThresholdNotMet,
    /// Duplicate submission from a signer.
    DuplicateSubmission,
    /// Session unlock window expired.
    SessionExpired,
    /// Unauthorized signer.
    UnauthorizedSigner,
    /// Signing engine failure.
    SigningFailed,
    /// Rate limited.
    RateLimited,
    /// Backpressure: at capacity.
    AtCapacity,
    /// Backpressure timeout.
    BackpressureTimeout,
    /// Policy denied the request.
    PolicyDenied,
    /// Share integrity check failed.
    InvalidShare,
    /// Network error.
    NetworkError,
    /// Configuration error.
    ConfigError,
    /// Store (persistence) error.
    StoreError,
    /// Internal error.
    Internal,
}

impl ErrorCode {
    /// Numeric code for this error.
    pub fn code(&self) -> u32 {
        match self {
            Self::SessionNotFound => 1001,
            Self::InvalidSessionState => 1002,
            Self::ThresholdNotMet => 1003,
            Self::DuplicateSubmission => 1004,
            Self::SessionExpired => 1005,
            Self::UnauthorizedSigner => 1006,
            Self::SigningFailed => 1007,
            Self::RateLimited => 2001,
            Self::AtCapacity => 2002,
            Self::BackpressureTimeout => 2003,
            Self::PolicyDenied => 3001,
            Self::InvalidShare => 4001,
            Self::NetworkError => 5001,
            Self::ConfigError => 6001,
            Self::StoreError => 7001,
            Self::Internal => 9001,
        }
    }

    /// Whether this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ThresholdNotMet | Self::NetworkError | Self::BackpressureTimeout
        )
    }

    /// Whether this error indicates a client error (4xx equivalent).
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::SessionNotFound
                | Self::InvalidSessionState
                | Self::DuplicateSubmission
                | Self::UnauthorizedSigner
                | Self::PolicyDenied
                | Self::InvalidShare
        )
    }

    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::SessionNotFound => "The requested session does not exist.",
            Self::InvalidSessionState => {
                "The session is not in the required state for this operation."
            }
            Self::ThresholdNotMet => "Not enough shares have been submitted to meet the threshold.",
            Self::DuplicateSubmission => "This signer has already submitted to this session.",
            Self::SessionExpired => "The session's unlock window has elapsed.",
            Self::UnauthorizedSigner => "This signer is not authorized for the quorum.",
            Self::SigningFailed => "The threshold signing engine produced an error.",
            Self::RateLimited => "Too many requests. Slow down and retry later.",
            Self::AtCapacity => "The coordinator is at maximum session capacity.",
            Self::BackpressureTimeout => "The operation timed out due to backpressure.",
            Self::PolicyDenied => "A policy rule denied the request.",
            Self::InvalidShare => "The submitted share failed integrity verification.",
            Self::NetworkError => "A network I/O error occurred.",
            Self::ConfigError => "Configuration is invalid or incomplete.",
            Self::StoreError => "A persistence backend error occurred.",
            Self::Internal => "An unexpected internal error occurred.",
        }
    }

    /// Look up an error code by its numeric value.
    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            1001 => Some(Self::SessionNotFound),
            1002 => Some(Self::InvalidSessionState),
            1003 => Some(Self::ThresholdNotMet),
            1004 => Some(Self::DuplicateSubmission),
            1005 => Some(Self::SessionExpired),
            1006 => Some(Self::UnauthorizedSigner),
            1007 => Some(Self::SigningFailed),
            2001 => Some(Self::RateLimited),
            2002 => Some(Self::AtCapacity),
            2003 => Some(Self::BackpressureTimeout),
            3001 => Some(Self::PolicyDenied),
            4001 => Some(Self::InvalidShare),
            5001 => Some(Self::NetworkError),
            6001 => Some(Self::ConfigError),
            7001 => Some(Self::StoreError),
            9001 => Some(Self::Internal),
            _ => None,
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.code(), self.description())
    }
}

/// A structured error response carrying an error code and message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedError {
    /// The error code.
    pub code: ErrorCode,
    /// Numeric code (for convenience).
    pub numeric_code: u32,
    /// Human-readable message.
    pub message: String,
    /// Whether this error is retryable.
    pub retryable: bool,
}

impl TypedError {
    /// Create a new typed error.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            numeric_code: code.code(),
            message: message.into(),
            retryable: code.is_retryable(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique() {
        let codes = [
            ErrorCode::SessionNotFound,
            ErrorCode::InvalidSessionState,
            ErrorCode::ThresholdNotMet,
            ErrorCode::DuplicateSubmission,
            ErrorCode::SessionExpired,
            ErrorCode::UnauthorizedSigner,
            ErrorCode::SigningFailed,
            ErrorCode::RateLimited,
            ErrorCode::AtCapacity,
            ErrorCode::BackpressureTimeout,
            ErrorCode::PolicyDenied,
            ErrorCode::InvalidShare,
            ErrorCode::NetworkError,
            ErrorCode::ConfigError,
            ErrorCode::StoreError,
            ErrorCode::Internal,
        ];
        let mut seen = std::collections::HashSet::new();
        for code in &codes {
            assert!(seen.insert(code.code()), "duplicate code: {}", code.code());
        }
    }

    #[test]
    fn from_code_round_trips() {
        for original in [
            ErrorCode::SessionNotFound,
            ErrorCode::ThresholdNotMet,
            ErrorCode::RateLimited,
            ErrorCode::Internal,
        ] {
            let recovered = ErrorCode::from_code(original.code()).unwrap();
            assert_eq!(original, recovered);
        }
    }

    #[test]
    fn from_code_unknown_returns_none() {
        assert!(ErrorCode::from_code(9999).is_none());
    }

    #[test]
    fn retryable_codes_correct() {
        assert!(ErrorCode::ThresholdNotMet.is_retryable());
        assert!(ErrorCode::NetworkError.is_retryable());
        assert!(!ErrorCode::SessionNotFound.is_retryable());
        assert!(!ErrorCode::SigningFailed.is_retryable());
    }

    #[test]
    fn client_error_classification() {
        assert!(ErrorCode::SessionNotFound.is_client_error());
        assert!(ErrorCode::PolicyDenied.is_client_error());
        assert!(!ErrorCode::NetworkError.is_client_error());
        assert!(!ErrorCode::Internal.is_client_error());
    }

    #[test]
    fn descriptions_are_non_empty() {
        for code in [
            ErrorCode::SessionNotFound,
            ErrorCode::SigningFailed,
            ErrorCode::Internal,
        ] {
            assert!(!code.description().is_empty());
        }
    }

    #[test]
    fn display_includes_code_and_description() {
        let s = format!("{}", ErrorCode::ThresholdNotMet);
        assert!(s.contains("1003"));
        assert!(s.contains("threshold"));
    }

    #[test]
    fn typed_error_carries_metadata() {
        let err = TypedError::new(ErrorCode::RateLimited, "too many requests");
        assert_eq!(err.code, ErrorCode::RateLimited);
        assert_eq!(err.numeric_code, 2001);
        assert!(!err.retryable); // rate limited is NOT retryable
        assert_eq!(err.message, "too many requests");
    }

    #[test]
    fn typed_error_serializes() {
        let err = TypedError::new(ErrorCode::Internal, "unexpected");
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("internal"));
        assert!(json.contains("9001"));
        assert!(json.contains("unexpected"));
    }

    #[test]
    fn error_code_serializes_as_snake_case() {
        let json = serde_json::to_string(&ErrorCode::SessionExpired).unwrap();
        assert!(json.contains("session_expired"));
    }
}
