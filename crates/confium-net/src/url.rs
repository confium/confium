//! Transport URL parsing.
//!
//! Transport URLs identify a peer or listening endpoint for a
//! multi-party protocol session:
//!
//! - `inproc://<name>` — in-process channel keyed by name
//! - `mock://<name>` — deterministic mock transport
//! - `tcp://<host>:<port>` — future `confium-net-tcp` crate
//! - `tcp+tls://<host>:<port>` — future TLS-wrapped TCP
//! - `quic://<host>:<port>` — future `confium-net-quic` crate
//! - `quic4://<host>:<port>` — IPv4-only QUIC
//! - `quic6://<host>:<port>` — IPv6-only QUIC
//! - `ws://<host>:<port>/<path>` — future `confium-net-ws` crate
//! - `wss://<host>:<port>/<path>` — future TLS-wrapped WebSocket
//!
//! This module owns the list of *recognized* scheme names so that
//! adding a new transport in a separate crate does not require editing
//! the parser — only registering a [`crate::TransportKind`] that
//! advertises the scheme. Schemes not in [`KNOWN_SCHEMES`] are rejected
//! early with a clear error, rather than silently passing through as
//! "no transport registered".

use snafu::ResultExt;
use snafu::ensure;
use url::Url;

use crate::Result;
use crate::error::InvalidUrlSnafu;
use crate::error::UnknownSchemeSnafu;

/// Every scheme Confium knows about, built-in or reserved for a
/// planned sibling crate. A URL whose scheme is not in this list is
/// rejected at parse time.
///
/// Adding a new transport crate that introduces a new scheme means
/// appending to this list — a single-line edit, not a structural
/// change to the parser.
pub const KNOWN_SCHEMES: &[&str] = &[
    "inproc", "mock", "tcp", "tcp+tls", "noise", "quic", "quic4", "quic6", "ws", "wss",
];

/// A parsed transport URL.
///
/// Thin wrapper around [`url::Url`] that guarantees the scheme is one
/// Confium recognizes.
#[derive(Debug, Clone)]
pub struct TransportUrl {
    inner: Url,
}

impl TransportUrl {
    /// Parse and validate a transport URL string.
    pub fn parse(input: &str) -> Result<Self> {
        let url = Url::parse(input).context(InvalidUrlSnafu {
            url: input.to_string(),
        })?;
        ensure!(
            KNOWN_SCHEMES.contains(&url.scheme()),
            UnknownSchemeSnafu {
                scheme: url.scheme().to_string(),
            }
        );
        Ok(Self { inner: url })
    }

    /// The URL scheme, e.g. `"inproc"`, `"tcp"`.
    pub fn scheme(&self) -> &str {
        self.inner.scheme()
    }

    /// The host of the URL, if present. `inproc` and `mock` URLs encode
    /// their channel name here (the part after `://`).
    pub fn host(&self) -> Option<&str> {
        self.inner.host_str()
    }

    /// The port of the URL, if specified.
    pub fn port(&self) -> Option<u16> {
        self.inner.port()
    }

    /// The path component (after the host), including a leading `/`.
    /// Empty for schemes like `inproc` that carry no path.
    pub fn path(&self) -> &str {
        self.inner.path()
    }

    /// The bare channel name for `inproc`/`mock` URLs: the host with no
    /// port and no path. Returns `None` for schemes that are not
    /// name-based.
    pub fn channel_name(&self) -> Option<&str> {
        match self.scheme() {
            "inproc" | "mock" => self.inner.host_str(),
            _ => None,
        }
    }

    /// Borrow the underlying [`url::Url`].
    pub fn as_url(&self) -> &Url {
        &self.inner
    }
}

impl std::fmt::Display for TransportUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_inproc_url() {
        let u = TransportUrl::parse("inproc://session-42").unwrap();
        assert_eq!(u.scheme(), "inproc");
        assert_eq!(u.channel_name(), Some("session-42"));
        assert_eq!(u.port(), None);
    }

    #[test]
    fn parses_mock_url() {
        let u = TransportUrl::parse("mock://round-3").unwrap();
        assert_eq!(u.scheme(), "mock");
        assert_eq!(u.channel_name(), Some("round-3"));
    }

    #[test]
    fn parses_tcp_url_with_port() {
        let u = TransportUrl::parse("tcp://1.2.3.4:443").unwrap();
        assert_eq!(u.scheme(), "tcp");
        assert_eq!(u.host(), Some("1.2.3.4"));
        assert_eq!(u.port(), Some(443));
        assert!(u.channel_name().is_none());
    }

    #[test]
    fn parses_tcp_tls_url() {
        let u = TransportUrl::parse("tcp+tls://example.com:443").unwrap();
        assert_eq!(u.scheme(), "tcp+tls");
    }

    #[test]
    fn parses_quic_url() {
        let u = TransportUrl::parse("quic://node.example:8443").unwrap();
        assert_eq!(u.scheme(), "quic");
        assert_eq!(u.port(), Some(8443));
    }

    #[test]
    fn parses_ws_and_wss_urls() {
        let ws = TransportUrl::parse("ws://example.com:80/sess").unwrap();
        assert_eq!(ws.scheme(), "ws");
        assert_eq!(ws.path(), "/sess");
        let wss = TransportUrl::parse("wss://example.com/sess").unwrap();
        assert_eq!(wss.scheme(), "wss");
    }

    #[test]
    fn rejects_unknown_scheme() {
        let err = TransportUrl::parse("ftp://example.com").unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::UnknownScheme { ref scheme, .. } if scheme == "ftp"
        ));
    }

    #[test]
    fn rejects_malformed_url() {
        let err = TransportUrl::parse("not a url at all").unwrap_err();
        assert!(matches!(err, crate::error::Error::InvalidUrl { .. }));
    }

    #[test]
    fn accepts_inproc_with_empty_host() {
        // url::Url parses "inproc://" but leaves the host absent; the
        // parser still accepts it (channel_name yields None), which the
        // inproc transport will reject at connect/listen time. Here we
        // just confirm parsing does not panic.
        let u = TransportUrl::parse("inproc://").unwrap();
        assert_eq!(u.channel_name(), None);
    }

    #[test]
    fn display_round_trips() {
        let s = "inproc://session-42";
        let u = TransportUrl::parse(s).unwrap();
        assert_eq!(u.to_string(), s);
    }
}
