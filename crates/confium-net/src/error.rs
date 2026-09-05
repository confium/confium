//! Errors for the Network crate.

use snafu::Backtrace;
use snafu::Snafu;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum Error {
    /// The transport URL could not be parsed.
    #[snafu(display("Invalid transport URL '{}'", url))]
    InvalidUrl {
        url: String,
        source: url::ParseError,
        backtrace: Backtrace,
    },

    /// The URL scheme is not registered with any transport kind.
    #[snafu(display("Unknown transport scheme '{}'", scheme))]
    UnknownScheme {
        scheme: String,
        backtrace: Backtrace,
    },

    /// The URL was structurally valid but missing a part this scheme
    /// requires (host, port, path, etc.).
    #[snafu(display("Malformed '{}' URL '{}': {}", scheme, url, reason))]
    MalformedUrl {
        scheme: String,
        url: String,
        reason: &'static str,
        backtrace: Backtrace,
    },

    /// The peer closed the transport cleanly.
    #[snafu(display("Transport closed by peer"))]
    Closed { backtrace: Backtrace },

    /// A transport implementation reported an I/O-level failure
    /// (connect refused, handshake abort, mid-stream protocol error).
    /// The transport is unusable after this.
    #[snafu(display("Transport I/O error: {}", source))]
    Io {
        source: std::io::Error,
        backtrace: Backtrace,
    },

    /// The receive buffer was smaller than the next queued message.
    /// The caller should retry with a larger buffer. The required size
    /// is reported so the caller can size accordingly.
    #[snafu(display("Buffer too small: needed {} bytes", needed))]
    BufferTooSmall { needed: usize, backtrace: Backtrace },

    /// The mock transport was configured to simulate a dropped message.
    #[snafu(display("Message dropped by mock transport"))]
    MockDrop { backtrace: Backtrace },

    /// A built-in transport rejected an operation it does not support
    /// (e.g. `listen` on a client-only transport).
    #[snafu(display("Operation '{}' not supported by '{}'", op, scheme))]
    Unsupported {
        op: &'static str,
        scheme: String,
        backtrace: Backtrace,
    },
}
