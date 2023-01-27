use snafu::Backtrace;
use snafu::Snafu;

#[derive(Snafu, Debug)]
#[snafu(visibility = "pub(crate)")]
pub enum Error {
    #[snafu(display("Null pointer on parameter '{}'", param))]
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
}

impl Error {
    pub fn code(&self) -> u32 {
        error_code(&self)
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
