//! Error model exposed to plugin authors.
//!
//! Confium plugins return a `u32` status code from each FFI entry point.
//! `0` means success; any other value is one of the canonical codes from
//! [`ErrorCode`]. Plugin authors do not want to memorize those numbers —
//! they want to return their own error type and let the SDK convert.
//!
//! [`PluginError`] is the SDK-side enum plugin authors implement `From`
//! for (or use directly). It carries the canonical [`ErrorCode`] so the
//! macro-generated entry points can `map_or_else` it into the wire `u32`
//! exactly the way the core crate does.

use std::ffi::c_void;

/// Canonical error codes returned across the Confium FFI surface.
///
/// These mirror `confium_core::error::ErrorCode` exactly — same names,
/// same numeric values — so a plugin's status code is meaningful to the
/// loader without a translation layer. (The cross-crate link is not
/// resolvable here because `confium-api` does not depend on
/// `confium-core`.)
///
/// Never reorder or renumber existing variants: they are wire-stable.
/// New variants may only be appended.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
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

    /// The plugin encountered an error that does not map to one of the
    /// canonical codes. The plugin should still produce a useful
    /// `Display` string for logging, but the loader has no typed
    /// recovery path.
    PLUGIN_GENERIC = 27,
}

impl ErrorCode {
    /// Numeric wire value the loader expects. Equal to the discriminant.
    pub fn into_wire(self) -> u32 {
        self as u32
    }
}

impl From<ErrorCode> for u32 {
    fn from(code: ErrorCode) -> Self {
        code.into_wire()
    }
}

/// Plugin-side error type. Carries a canonical [`ErrorCode`] plus a
/// human-readable message for logging; only the code crosses the FFI.
#[derive(Debug)]
pub struct PluginError {
    code: ErrorCode,
    message: String,
}

impl PluginError {
    /// Construct a new error with the given code and message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Shorthand for a generic error with no specific code.
    pub fn msg(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::PLUGIN_GENERIC, message)
    }

    /// Canonical code that will be returned to the loader.
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// Human-readable message. For logging only — does not cross the FFI.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Convert into the wire `u32` status code the loader expects.
    pub fn into_wire(self) -> u32 {
        self.code.into_wire()
    }
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code_as_str(), self.message)
    }
}

impl std::error::Error for PluginError {}

impl PluginError {
    fn code_as_str(&self) -> &'static str {
        match self.code {
            ErrorCode::UNKNOWN => "unknown",
            ErrorCode::NULL_POINTER => "null_pointer",
            ErrorCode::INVALID_UTF8 => "invalid_utf8",
            ErrorCode::WRONG_TYPE => "wrong_type",
            ErrorCode::VALUE_NOT_FOUND => "value_not_found",
            ErrorCode::INSUFFICIENT_BUFFER => "insufficient_buffer",
            ErrorCode::UNKNOWN_PROVIDER => "unknown_provider",
            ErrorCode::PLUGIN_LOAD_FAILED => "plugin_load_failed",
            ErrorCode::PLUGIN_SYMBOL_ERROR => "plugin_symbol_error",
            ErrorCode::PLUGIN_INITIALIZATION_FAILED => "plugin_initialization_failed",
            ErrorCode::PLUGIN_INTERFACE_VERSION_UNSUPPORTED => {
                "plugin_interface_version_unsupported"
            }
            ErrorCode::PLUGIN_NAME_COLLISION => "plugin_name_collision",
            ErrorCode::PLUGIN_MISSING_INTERFACE => "plugin_missing_interface",
            ErrorCode::PLUGIN_INTERNAL_ERROR => "plugin_internal_error",
            ErrorCode::UNSUPPORTED_ALGORITHM => "unsupported_algorithm",
            ErrorCode::PLUGIN_GENERIC => "plugin_generic",
        }
    }
}

/// Result alias for plugin-side fallible operations.
pub type PluginResult<T> = std::result::Result<T, PluginError>;

/// Helper used by the macro-generated entry points to flatten a
/// [`PluginResult<()>`] into the wire `u32` the loader expects.
///
/// Plugins do not normally call this directly — the macros do.
#[doc(hidden)]
pub fn to_wire_code<T>(result: PluginResult<T>) -> u32 {
    match result {
        Ok(_) => 0,
        Err(e) => e.into_wire(),
    }
}

/// Helper used by the macro-generated entry points to construct a
/// `*mut c_void` plugin instance handle from a boxed Rust value.
///
/// Re-exports [`crate::OpaqueHandle::new`] so macro output doesn't need
/// to fully-qualify the path.
#[doc(hidden)]
pub fn box_state<T>(value: T) -> *mut c_void {
    crate::OpaqueHandle::new(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_into_wire_matches_discriminant() {
        assert_eq!(ErrorCode::UNKNOWN.into_wire(), 1);
        assert_eq!(ErrorCode::PLUGIN_GENERIC.into_wire(), 27);
        assert_eq!(ErrorCode::UNSUPPORTED_ALGORITHM.into_wire(), 50);
    }

    #[test]
    fn plugin_error_carries_code_and_message() {
        let e = PluginError::new(ErrorCode::INSUFFICIENT_BUFFER, "need 32 bytes");
        assert_eq!(e.code(), ErrorCode::INSUFFICIENT_BUFFER);
        assert_eq!(e.message(), "need 32 bytes");
        let s = format!("{e}");
        assert!(s.contains("insufficient_buffer"));
        assert!(s.contains("need 32 bytes"));
    }

    #[test]
    fn to_wire_code_success_is_zero() {
        let r: PluginResult<()> = Ok(());
        assert_eq!(to_wire_code(r), 0);
    }

    #[test]
    fn to_wire_code_failure_is_error_code() {
        let r: PluginResult<()> = Err(PluginError::new(ErrorCode::NULL_POINTER, "x"));
        assert_eq!(to_wire_code(r), ErrorCode::NULL_POINTER.into_wire());
    }
}
