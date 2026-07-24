//! Errors for the Registry client crate.
//!
//! External error types (ureq, toml, io) are stringified into a `message`
//! field. Carrying the concrete upstream error through snafu's source
//! machinery across several distinct crates produces brittle derive
//! chains; the human-readable message preserves enough context for
//! diagnostics without coupling our error enum to every upstream
//! `Error` type.

use snafu::Snafu;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum Error {
    /// The registry base URL could not be parsed or normalized.
    #[snafu(display("Invalid registry URL '{}': {}", url, message))]
    InvalidRegistryUrl { url: String, message: String },

    /// A plugin name failed validation. Plugin names must be lowercase,
    /// hyphenated, and contain no path separators or `..` segments.
    #[snafu(display("Invalid plugin name '{}': {}", name, reason))]
    InvalidPluginName { name: String, reason: String },

    /// A version string failed validation.
    #[snafu(display("Invalid version '{}': {}", version, message))]
    InvalidVersion { version: String, message: String },

    /// A publisher name failed validation. Publisher names must be
    /// lowercase identifiers with no path separators or `..` segments.
    #[snafu(display("Invalid publisher name '{}': {}", name, reason))]
    InvalidPublisherName { name: String, reason: String },

    /// An HTTP request failed at the transport layer.
    #[snafu(display("Fetch failed for '{}': {}", url, message))]
    Fetch { url: String, message: String },

    /// An HTTP request returned a non-success status.
    #[snafu(display("HTTP {} for '{}'", status, url))]
    HttpStatus { url: String, status: u16 },

    /// A response body could not be parsed as TOML.
    #[snafu(display("TOML parse failed for '{}': {}", what, message))]
    TomlParse { what: String, message: String },

    /// The master index or a per-plugin index did not contain a required
    /// entry (e.g. the requested plugin or version is unknown).
    #[snafu(display("{} not found: {}", what, detail))]
    NotFound { what: String, detail: String },

    /// A required field was missing from a TOML document.
    #[snafu(display("Missing field '{}' in {}", field, what))]
    MissingField { what: String, field: String },

    /// A local filesystem operation failed.
    #[snafu(display("I/O error for '{}': {}", path, message))]
    Io { path: String, message: String },

    /// The trust store rejected an artifact because no trusted publisher
    /// signed it. The `signers` list carries the publisher names that did
    /// sign (may be empty). Callers may override via `allow_untrusted` for
    /// development.
    #[snafu(display(
        "Untrusted plugin '{}': no signature from a trusted publisher (signers: {:?})",
        name,
        signers
    ))]
    UntrustedPlugin { name: String, signers: Vec<String> },
}

impl Error {
    /// Convert any boxed error into the message string used across this
    /// crate's variants.
    pub(crate) fn stringify<E>(err: E) -> String
    where
        E: std::fmt::Display,
    {
        err.to_string()
    }
}
