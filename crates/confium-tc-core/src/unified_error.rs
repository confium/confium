//! Unified error hierarchy — single error tree for all coordinator errors.

use std::fmt;

/// The root error type for the entire confium-tc coordinator.
#[derive(Debug)]
pub enum UnifiedError {
    Session(SessionErrorKind),
    Policy(PolicyErrorKind),
    Network(NetworkErrorKind),
    Crypto(CryptoErrorKind),
    Store(StoreErrorKind),
    Config(ConfigErrorKind),
    RateLimited { retry_after_secs: u64 },
    Backpressure { active: usize, max: usize },
    Unauthorized { reason: String },
    NotFound { resource: String },
    Internal { message: String },
}

#[derive(Debug)]
pub enum SessionErrorKind {
    NotFound(String),
    InvalidState {
        session: String,
        current: String,
        expected: String,
    },
    ThresholdNotMet {
        have: usize,
        need: u32,
    },
    DuplicateSubmission {
        signer: String,
    },
    Expired(String),
    SigningFailed(String),
}

#[derive(Debug)]
pub enum PolicyErrorKind {
    Denied { rule: String, reason: String },
}

#[derive(Debug)]
pub enum NetworkErrorKind {
    ConnectionFailed(String),
    ProtocolError(String),
    Timeout,
}

#[derive(Debug)]
pub enum CryptoErrorKind {
    InvalidSignature,
    InvalidShare,
    InvalidProof,
    InvalidKey,
}

#[derive(Debug)]
pub enum StoreErrorKind {
    IoError(String),
    SerializationError(String),
    KeyNotFound(String),
}

#[derive(Debug)]
pub enum ConfigErrorKind {
    InvalidValue {
        field: String,
        value: String,
        expected: String,
    },
    MissingField(String),
    FileError(String),
}

impl fmt::Display for UnifiedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(e) => write!(f, "session error: {e:?}"),
            Self::Policy(e) => write!(f, "policy error: {e:?}"),
            Self::Network(e) => write!(f, "network error: {e:?}"),
            Self::Crypto(e) => write!(f, "crypto error: {e:?}"),
            Self::Store(e) => write!(f, "store error: {e:?}"),
            Self::Config(e) => write!(f, "config error: {e:?}"),
            Self::RateLimited { retry_after_secs } => {
                write!(f, "rate limited, retry after {retry_after_secs}s")
            }
            Self::Backpressure { active, max } => write!(f, "at capacity: {active}/{max}"),
            Self::Unauthorized { reason } => write!(f, "unauthorized: {reason}"),
            Self::NotFound { resource } => write!(f, "not found: {resource}"),
            Self::Internal { message } => write!(f, "internal: {message}"),
        }
    }
}

impl std::error::Error for UnifiedError {}

/// Error code for programmatic handling.
impl UnifiedError {
    pub fn code(&self) -> u32 {
        match self {
            Self::Session(SessionErrorKind::NotFound(_)) => 1001,
            Self::Session(SessionErrorKind::InvalidState { .. }) => 1002,
            Self::Session(SessionErrorKind::ThresholdNotMet { .. }) => 1003,
            Self::Session(SessionErrorKind::DuplicateSubmission { .. }) => 1004,
            Self::Session(SessionErrorKind::Expired(_)) => 1005,
            Self::Session(SessionErrorKind::SigningFailed(_)) => 1007,
            Self::Policy(_) => 3001,
            Self::Network(NetworkErrorKind::ConnectionFailed(_)) => 5001,
            Self::Network(NetworkErrorKind::ProtocolError(_)) => 5002,
            Self::Network(NetworkErrorKind::Timeout) => 5003,
            Self::Crypto(CryptoErrorKind::InvalidSignature) => 4001,
            Self::Crypto(CryptoErrorKind::InvalidShare) => 4002,
            Self::Crypto(CryptoErrorKind::InvalidProof) => 4003,
            Self::Crypto(CryptoErrorKind::InvalidKey) => 4004,
            Self::Store(_) => 7001,
            Self::Config(_) => 6001,
            Self::RateLimited { .. } => 2001,
            Self::Backpressure { .. } => 2002,
            Self::Unauthorized { .. } => 1006,
            Self::NotFound { .. } => 1001,
            Self::Internal { .. } => 9001,
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Session(SessionErrorKind::ThresholdNotMet { .. })
                | Self::Network(NetworkErrorKind::Timeout)
                | Self::RateLimited { .. }
                | Self::Backpressure { .. }
        )
    }

    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::Session(SessionErrorKind::NotFound(_))
                | Self::Session(SessionErrorKind::DuplicateSubmission { .. })
                | Self::Session(SessionErrorKind::Expired(_))
                | Self::Policy(_)
                | Self::Unauthorized { .. }
                | Self::NotFound { .. }
        )
    }

    pub fn category(&self) -> &'static str {
        match self {
            Self::Session(_) => "session",
            Self::Policy(_) => "policy",
            Self::Network(_) => "network",
            Self::Crypto(_) => "crypto",
            Self::Store(_) => "store",
            Self::Config(_) => "config",
            Self::RateLimited { .. } => "rate_limit",
            Self::Backpressure { .. } => "backpressure",
            Self::Unauthorized { .. } => "auth",
            Self::NotFound { .. } => "not_found",
            Self::Internal { .. } => "internal",
        }
    }
}

// Convenience constructors
impl UnifiedError {
    pub fn session_not_found(id: &str) -> Self {
        Self::Session(SessionErrorKind::NotFound(id.into()))
    }
    pub fn rate_limited(retry_after: u64) -> Self {
        Self::RateLimited {
            retry_after_secs: retry_after,
        }
    }
    pub fn unauthorized(reason: &str) -> Self {
        Self::Unauthorized {
            reason: reason.into(),
        }
    }
    pub fn not_found(resource: &str) -> Self {
        Self::NotFound {
            resource: resource.into(),
        }
    }
    pub fn internal(message: &str) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}

pub type UnifiedResult<T> = Result<T, UnifiedError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let e = UnifiedError::session_not_found("s1");
        assert!(format!("{e}").contains("s1"));
    }

    #[test]
    fn error_code() {
        assert_eq!(UnifiedError::session_not_found("x").code(), 1001);
        assert_eq!(UnifiedError::rate_limited(30).code(), 2001);
        assert_eq!(UnifiedError::internal("test").code(), 9001);
    }

    #[test]
    fn retryable_classification() {
        assert!(UnifiedError::rate_limited(30).is_retryable());
        assert!(UnifiedError::session_not_found("x").is_client_error());
        assert!(!UnifiedError::internal("x").is_client_error());
        assert!(!UnifiedError::session_not_found("x").is_retryable());
    }

    #[test]
    fn category() {
        assert_eq!(UnifiedError::session_not_found("x").category(), "session");
        assert_eq!(UnifiedError::internal("x").category(), "internal");
    }

    #[test]
    fn backpressure_error() {
        let e = UnifiedError::Backpressure {
            active: 10,
            max: 10,
        };
        assert!(e.is_retryable());
        assert!(!e.is_client_error());
        assert_eq!(e.code(), 2002);
    }

    #[test]
    fn crypto_error_codes() {
        assert_eq!(
            UnifiedError::Crypto(CryptoErrorKind::InvalidSignature).code(),
            4001
        );
        assert_eq!(
            UnifiedError::Crypto(CryptoErrorKind::InvalidShare).code(),
            4002
        );
    }

    #[test]
    fn convenience_constructors() {
        let e = UnifiedError::unauthorized("bad token");
        assert!(e.is_client_error());
        assert_eq!(e.code(), 1006);
    }

    #[test]
    fn result_type_alias() {
        let r: UnifiedResult<i32> = Err(UnifiedError::internal("fail"));
        assert!(r.is_err());
    }
}
