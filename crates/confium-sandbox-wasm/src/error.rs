//! Error type for the WASM sandbox crate.
//!
//! Mirrors the snafu-based pattern used across confium crates. All
//! public [`crate::Sandbox`] / [`crate::SandboxInstance`] operations
//! surface these via [`Result`](crate::Result).

use snafu::Backtrace;
use snafu::Snafu;

/// Boxed error source — any host-side error fits here.
pub type SourceError = Box<dyn std::error::Error + Send + Sync>;

/// Wrap a wasmtime error (which does NOT impl `std::error::Error` in
/// wasmtime 27 — it's `anyhow::Error`-style) into something that does,
/// so it can flow through snafu's source field.
#[derive(Debug)]
pub struct WasmtimeError(pub String);

impl std::fmt::Display for WasmtimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WasmtimeError {}

impl WasmtimeError {
    /// Construct from anything wasmtime returns (which all impl
    /// `Display`).
    pub fn from_display<E: std::fmt::Display>(e: E) -> SourceError {
        Box::new(WasmtimeError(e.to_string()))
    }
}

#[derive(Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(display("WASM module compilation failed: {}", source))]
    ModuleCompile {
        source: SourceError,
        backtrace: Backtrace,
    },
    #[snafu(display("WASM module instantiation failed: {}", source))]
    Instantiation {
        source: SourceError,
        backtrace: Backtrace,
    },
    #[snafu(display("WASM function '{}' not found", function))]
    FunctionNotFound {
        function: String,
        backtrace: Backtrace,
    },
    #[snafu(display("WASM function '{}' invocation failed: {}", function, source))]
    Invocation {
        function: String,
        source: SourceError,
        backtrace: Backtrace,
    },
    #[snafu(display("Export '{}' not found in WASM instance", export))]
    ExportNotFound {
        export: String,
        backtrace: Backtrace,
    },
    #[snafu(display("Argument type mismatch for function '{}'", function))]
    ArgumentType {
        function: String,
        backtrace: Backtrace,
    },
    #[snafu(display("Capability denied: {}", reason))]
    CapabilityDenied {
        reason: String,
        backtrace: Backtrace,
    },
    #[snafu(display("Host import '{}' failed: {}", import, reason))]
    HostImport {
        import: String,
        reason: String,
        backtrace: Backtrace,
    },
    #[snafu(display("Wasmtime engine error: {}", source))]
    Engine {
        source: SourceError,
        backtrace: Backtrace,
    },
}

impl Error {
    /// Numeric error code for the WASM sandbox ABI. Disjoint from
    /// core (1..) and TC (0x1000..) codes; sandbox codes begin at
    /// 0x2000.
    pub fn code(&self) -> u32 {
        match self {
            Error::ModuleCompile { .. } => 0x2000,
            Error::Instantiation { .. } => 0x2001,
            Error::FunctionNotFound { .. } => 0x2002,
            Error::Invocation { .. } => 0x2003,
            Error::ExportNotFound { .. } => 0x2004,
            Error::ArgumentType { .. } => 0x2005,
            Error::CapabilityDenied { .. } => 0x2006,
            Error::HostImport { .. } => 0x2007,
            Error::Engine { .. } => 0x2008,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_disjoint_from_core_and_tc() {
        // Sandbox codes begin at 0x2000 (core = 1.., TC = 0x1000..).
        let err = FunctionNotFoundSnafu {
            function: "x".to_string(),
        }
        .build();
        assert!(err.code() >= 0x2000);
        assert!(err.code() < 0x3000);
    }

    #[test]
    fn capability_denied_code() {
        let err = CapabilityDeniedSnafu {
            reason: "test".to_string(),
        }
        .build();
        assert_eq!(err.code(), 0x2006);
    }
}
