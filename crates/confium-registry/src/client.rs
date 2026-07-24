//! HTTP client for the static-site registry.
//!
//! The registry is a set of static files served over HTTPS. This module
//! wraps [`ureq`] and returns the response body as bytes, normalizing
//! transport and HTTP-status failures into [`Error`].

use crate::error::{Error, HttpStatusSnafu, Result};
use std::io::Read;
use ureq::Agent;

/// A thin HTTP client configured for the Confium registry.
///
/// The agent caches the connection pool and default headers. It is cheap
/// to clone (the underlying agent is shared).
#[derive(Clone)]
pub struct Client {
    agent: Agent,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Build a client with Confium's default settings.
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(30))
            .build();
        Self { agent }
    }

    /// Build a client from a pre-configured [`ureq::Agent`]. Useful for
    /// tests that want custom timeouts or transports.
    pub fn with_agent(agent: Agent) -> Self {
        Self { agent }
    }

    /// Fetch `url` and return the response body as bytes.
    ///
    /// Non-2xx responses become [`Error::HttpStatus`]; transport-layer
    /// failures become [`Error::Fetch`]; body reads become [`Error::Io`].
    pub fn get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let response = self.agent.get(url).call().map_err(|e| Error::Fetch {
            url: url.to_string(),
            message: Error::stringify(e),
        })?;

        let status = response.status();
        if !(200..300).contains(&status) {
            return HttpStatusSnafu { url, status }.fail();
        }

        let mut reader = response.into_reader();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).map_err(|e| Error::Io {
            path: url.to_string(),
            message: Error::stringify(e),
        })?;
        Ok(buf)
    }

    /// Fetch `url` and return the body as a UTF-8 string.
    pub fn get_text(&self, url: &str) -> Result<String> {
        let bytes = self.get_bytes(url)?;
        String::from_utf8(bytes).map_err(|e| Error::Fetch {
            url: url.to_string(),
            message: format!("response was not valid UTF-8: {}", e),
        })
    }
}
