//! Errors for the test harness.
//!
//! Snafu-based, mirroring the pattern used across the workspace. Vector
//! parsing, runner, and reporting all funnel through [`Error`].

use snafu::Backtrace;
use snafu::Snafu;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(display("Malformed test vector: {}", message))]
    Vector {
        message: String,
        backtrace: Backtrace,
    },

    #[snafu(display("Underlying threshold-cryptography error: {}", source))]
    Tc {
        #[snafu(backtrace)]
        source: confium_tc::Error,
    },

    #[snafu(display("Session did not complete after {} rounds", rounds))]
    SessionDidNotComplete { rounds: u8, backtrace: Backtrace },

    #[snafu(display("JSON serialization error: {}", source))]
    Json {
        source: serde_json::Error,
        backtrace: Backtrace,
    },
}

impl From<confium_tc::Error> for Error {
    fn from(source: confium_tc::Error) -> Self {
        Error::Tc { source }
    }
}

impl From<serde_json::Error> for Error {
    fn from(source: serde_json::Error) -> Self {
        Error::Json {
            source,
            backtrace: Backtrace::capture(),
        }
    }
}
