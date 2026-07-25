//! Error type for the process sandbox crate.
//!
//! Mirrors the snafu-based pattern used across confium crates. All
//! public [`Sandbox`](crate::Sandbox) / [`SandboxInstance`](crate::SandboxInstance)
//! operations surface these via [`Result`].
//!
//! Error codes share the sandbox block (`0x2000..`), offset to a
//! distinct sub-range (`0x2100..`) so they do not collide with the
//! WASM sandbox codes when both are in play.

use snafu::Backtrace;
use snafu::Snafu;

#[derive(Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum Error {
    /// The plugin path passed to [`Sandbox::load_module`](crate::Sandbox::load_module)
    /// was not valid UTF-8.
    #[snafu(display("plugin path was not valid UTF-8: {}", source))]
    InvalidPath {
        source: std::str::Utf8Error,
        backtrace: Backtrace,
    },
    /// Spawning the plugin subprocess failed (binary missing, no
    /// execute permission, etc.).
    #[snafu(display("failed to spawn plugin subprocess: {}", source))]
    Spawn {
        source: std::io::Error,
        backtrace: Backtrace,
    },
    /// Writing a request frame to the plugin's stdin failed.
    #[snafu(display("failed to write request to plugin stdin: {}", source))]
    WriteRequest {
        source: std::io::Error,
        backtrace: Backtrace,
    },
    /// Reading a response frame from the plugin's stdout failed (EOF,
    /// truncated length header, etc.).
    #[snafu(display("failed to read response from plugin stdout: {}", source))]
    ReadResponse {
        source: std::io::Error,
        backtrace: Backtrace,
    },
    /// A response frame was malformed JSON, or did not match the
    /// expected protocol shape.
    #[snafu(display("malformed plugin protocol message: {}", reason))]
    Protocol {
        reason: String,
        backtrace: Backtrace,
    },
    /// The plugin reported an error for the call.
    #[snafu(display("plugin returned error for '{}': {}", method, message))]
    PluginError {
        method: String,
        message: String,
        backtrace: Backtrace,
    },
    /// An argument value could not be marshaled to/from the protocol
    /// (e.g. `Value::Bytes` on a path that only carries scalars).
    #[snafu(display("argument type mismatch for function '{}'", function))]
    ArgumentType {
        function: String,
        backtrace: Backtrace,
    },
    /// The requested function is not exported by the plugin.
    #[snafu(display("plugin function '{}' not found", function))]
    FunctionNotFound {
        function: String,
        backtrace: Backtrace,
    },
}

impl Error {
    /// Numeric error code for the process sandbox ABI. Disjoint from
    /// core (1..), TC (0x1000..), and the WASM sandbox (0x2000..);
    /// process sandbox codes begin at 0x2100.
    pub fn code(&self) -> u32 {
        match self {
            Error::InvalidPath { .. } => 0x2100,
            Error::Spawn { .. } => 0x2101,
            Error::WriteRequest { .. } => 0x2102,
            Error::ReadResponse { .. } => 0x2103,
            Error::Protocol { .. } => 0x2104,
            Error::PluginError { .. } => 0x2105,
            Error::ArgumentType { .. } => 0x2106,
            Error::FunctionNotFound { .. } => 0x2107,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use snafu::GenerateImplicitData;

    #[test]
    fn error_codes_are_in_process_range() {
        let err = Error::Protocol {
            reason: "x".to_string(),
            backtrace: Backtrace::generate(),
        };
        assert!(err.code() >= 0x2100);
        assert!(err.code() < 0x2200);
    }

    #[test]
    fn codes_are_disjoint_from_wasm_sandbox() {
        // WASM sandbox uses 0x2000..; process sandbox must not collide.
        let err = Error::PluginError {
            method: "m".to_string(),
            message: "boom".to_string(),
            backtrace: Backtrace::generate(),
        };
        assert!(err.code() >= 0x2100);
    }

    #[test]
    fn spawn_code_is_stable() {
        let err = Error::Spawn {
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
            backtrace: Backtrace::generate(),
        };
        assert_eq!(err.code(), 0x2101);
    }
}
