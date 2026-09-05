//! Registry kind for `noise://` URLs.

use confium_net::registry::TransportKind;
use url::Url;

use confium_net::Listener;
use confium_net::Result;
use confium_net::Transport;

use crate::transport::NoiseListener;
use crate::transport::NoiseTransport;
use crate::transport::parse_url;

/// Owns the `noise` scheme: Noise_XX over TCP with optional key
/// provisioning (`key=`) and peer pinning (`pinned=`).
pub struct NoiseTransportKind;

impl TransportKind for NoiseTransportKind {
    fn schemes(&self) -> &'static [&'static str] {
        &["noise"]
    }

    fn connect(&self, url: &Url) -> Result<Box<dyn Transport>> {
        let params = parse_url(url)?;
        NoiseTransport::connect(&params).map(|t| Box::new(t) as Box<dyn Transport>)
    }

    fn listen(&self, url: &Url) -> Result<Box<dyn Listener>> {
        let params = parse_url(url)?;
        NoiseListener::new(params).map(|l| Box::new(l) as Box<dyn Listener>)
    }
}
