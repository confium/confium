use snafu::Backtrace;
use snafu::Snafu;

#[derive(Snafu, Debug)]
#[snafu(visibility(pub(crate)))]
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

    #[snafu(display("Wrong type (expected '{}')", expected))]
    WrongType {
        expected: &'static str,
        backtrace: Backtrace,
    },
    #[snafu(display("Value not found"))]
    ValueNotFound,
    #[snafu(display("Insufficient buffer"))]
    InsufficientBuffer,

    #[snafu(display("Unknown provider: '{}'", name))]
    UnknownProvider { name: String },

    #[snafu(display("Plugin '{}' failed to load", name))]
    PluginLoadFailed {
        name: String,
        source: libloading::Error,
    },
    #[snafu(display("Plugin '{}' symbol error: '{}'", name, String::from_utf8_lossy(&symbol[0..symbol.len() - 1])))]
    PluginSymbolError {
        name: String,
        symbol: &'static [u8],
        source: libloading::Error,
    },
    #[snafu(display("Plugin '{}' interface version unsupported", name))]
    PluginInterfaceVersionUnsupported { name: String },
    #[snafu(display("Plugin '{}' name collision", name))]
    PluginNameCollision { name: String },
    #[snafu(display("Plugin '{}' missing interface '{}'", name, ifname))]
    PluginMissingInterface { name: String, ifname: String },
    #[snafu(display("Plugin '{}' internal error {}", name, code))]
    PluginInternalError { name: String, code: u32 },

    #[snafu(display("Unsupported algorithm '{}'", name))]
    UnsupportedAlgorithm { name: String },

    /// Wraps the underlying `std::error::Error::source()` of another
    /// Confium error so it can be returned through the FFI as the next
    /// step in the error chain. The source's Display string is preserved
    /// — typed recovery requires inspecting the parent error's variant.
    #[snafu(display("Underlying error: {}", message))]
    Wrapped { message: String },
}

impl Error {
    pub fn code(&self) -> u32 {
        error_code(self)
    }
}

#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum ErrorCode {
    UNKNOWN = 1,
    NULL_POINTER = 2,
    INVALID_UTF8 = 3,

    WRONG_TYPE = 10,
    VALUE_NOT_FOUND = 11,
    INSUFFICIENT_BUFFER = 12,

    UNKNOWN_PROVIDER = 13,

    PLUGIN_LOAD_FAILED = 20,
    PLUGIN_SYMBOL_ERROR = 21,
    PLUGIN_INITIALIZATION_FAILED = 22,
    PLUGIN_INTERFACE_VERSION_UNSUPPORTED = 23,
    PLUGIN_NAME_COLLISION = 24,
    PLUGIN_MISSING_INTERFACE = 25,
    PLUGIN_INTERNAL_ERROR = 26,

    UNSUPPORTED_ALGORITHM = 50,

    /// Returned when the error is a `Wrapped` variant — i.e. an FFI-exposed
    /// step in a source chain rather than a first-class Confium error.
    WRAPPED = 100,
}

fn error_code(error: &Error) -> u32 {
    match error {
        Error::NullPointer { .. } => ErrorCode::NULL_POINTER.into(),
        Error::InvalidUTF8 { .. } => ErrorCode::INVALID_UTF8.into(),

        Error::WrongType { .. } => ErrorCode::WRONG_TYPE.into(),
        Error::ValueNotFound => ErrorCode::VALUE_NOT_FOUND.into(),
        Error::InsufficientBuffer => ErrorCode::INSUFFICIENT_BUFFER.into(),

        Error::UnknownProvider { .. } => ErrorCode::UNKNOWN_PROVIDER.into(),

        Error::PluginLoadFailed { .. } => ErrorCode::PLUGIN_LOAD_FAILED.into(),
        Error::PluginSymbolError { .. } => ErrorCode::PLUGIN_SYMBOL_ERROR.into(),
        Error::PluginInterfaceVersionUnsupported { .. } => {
            ErrorCode::PLUGIN_INTERFACE_VERSION_UNSUPPORTED.into()
        }
        Error::PluginNameCollision { .. } => ErrorCode::PLUGIN_NAME_COLLISION.into(),
        Error::PluginMissingInterface { .. } => ErrorCode::PLUGIN_MISSING_INTERFACE.into(),
        Error::PluginInternalError { .. } => ErrorCode::PLUGIN_INTERNAL_ERROR.into(),

        Error::UnsupportedAlgorithm { .. } => ErrorCode::UNSUPPORTED_ALGORITHM.into(),

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
    fn wrapped_displays_inner_message() {
        let err = Error::Wrapped {
            message: "boom".to_string(),
        };
        assert_eq!(format!("{err}"), "Underlying error: boom");
        assert_eq!(err.code(), ErrorCode::WRAPPED as u32);
    }

    #[test]
    fn invalid_utf8_source_walks_to_utf8error() {
        // Build the bad bytes from a non-byte-literal source so
        // clippy's invalid-UTF-8 literal lint doesn't fire.
        let n: u8 = 0xFF;
        let bad = [n, n];
        let utf8_err = std::str::from_utf8(&bad).unwrap_err();
        let err = Error::InvalidUTF8 {
            backtrace: Backtrace::generate(),
            source: utf8_err,
        };
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "InvalidUTF8 must expose a source");
    }

    #[test]
    fn null_pointer_has_no_source() {
        let err = Error::NullPointer {
            param: "x",
            backtrace: Backtrace::generate(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }
}
