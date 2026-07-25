//! Error model for the registry client.
//!
//! Mirrors the snafu-based conventions used across the workspace
//! (`confium-core`, `confium-store`). Public so callers can match on the
//! concrete variants when surfacing CLI messages.

use snafu::Snafu;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(display("registry entry not found: {path}"))]
    NotFound { path: String },

    #[snafu(display("failed to parse TOML at {path}: {source}"))]
    TomlParse {
        path: String,
        source: toml::de::Error,
    },

    #[snafu(display("failed to serialize TOML: {source}"))]
    TomlSerialize { source: toml::ser::Error },

    #[snafu(display("registry fetch failed for {path}: {message}"))]
    Fetch { path: String, message: String },

    #[snafu(display("plugin '{name}' not found in registry index"))]
    PluginNotFound { name: String },

    #[snafu(display("version '{version}' not found for plugin '{name}'"))]
    VersionNotFound { name: String, version: String },

    #[snafu(display("I/O error: {message}: {source}"))]
    Io {
        message: String,
        source: std::io::Error,
    },

    #[snafu(display("artifact download failed: {message}"))]
    Download { message: String },

    #[snafu(display("hash mismatch for {name}-{version}: expected {expected}, got {actual}"))]
    HashMismatch {
        name: String,
        version: String,
        expected: String,
        actual: String,
    },

    #[snafu(display("no trusted publisher signed plugin '{name}'"))]
    UntrustedPlugin { name: String },

    #[snafu(display("failed to load RNP library: {message}"))]
    RnpLoad { message: String },

    #[snafu(display("RNP signature verification failed: {message}"))]
    RnpVerify { message: String },

    #[snafu(display("signature file '{path}' is not ASCII-armored or binary PGP"))]
    SignatureFormat { path: String },

    #[snafu(display("public key file '{path}' is not a valid OpenPGP public key"))]
    PublicKeyFormat { path: String },

    #[snafu(display("invalid PGP signature: {message}"))]
    SignatureInvalid { message: String },

    #[snafu(display("PGP verification subprocess failed: {message}"))]
    VerificationSubprocess { message: String },

    #[snafu(display("invalid registry path: {path}"))]
    InvalidPath { path: String },

    #[snafu(display("plugin '{name}' is not installed"))]
    NotInstalled { name: String },

    #[snafu(display("config error: {message}"))]
    Config { message: String },
}

impl Error {
    /// Convenience constructor for the I/O variant that pairs an
    /// `io::Error` with a human-readable explanation.
    pub fn io(source: std::io::Error, message: impl Into<String>) -> Self {
        Error::Io {
            message: message.into(),
            source,
        }
    }
}
