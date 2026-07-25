//! Open/closed transport-kind registry.
//!
//! Each transport (`inproc`, `mock`, and future `tcp`/`quic`/`ws`
//! crates) submits a [`TransportKind`] implementation via the
//! [`register_transport!`] macro. The public [`crate::connect`] and
//! [`crate::listen`] entry points iterate registered kinds to find the
//! one whose `schemes()` contains the URL's scheme.
//!
//! Adding a new transport means adding a crate that calls
//! `register_transport!` — no edits to existing code, mirroring the
//! `confium-core::ffi::registry` pattern used for crypto interfaces.

use url::Url;

use crate::Listener;
use crate::Result;
use crate::Transport;

/// Factory for a family of transport schemes.
///
/// One implementation per transport backend. The implementation
/// advertises which URL schemes it owns and constructs connected
/// [`Transport`] handles or [`Listener`]s for them.
pub trait TransportKind: Sync {
    /// URL schemes this kind owns, e.g. `["inproc"]` or
    /// `["tcp", "tcp+tls"]`. Claimed schemes must be in
    /// [`crate::url::KNOWN_SCHEMES`].
    fn schemes(&self) -> &'static [&'static str];

    /// Open a connected transport to the peer identified by `url`.
    fn connect(&self, url: &Url) -> Result<Box<dyn Transport>>;

    /// Begin listening for inbound connections at the address in
    /// `url`. Transports that cannot listen (client-only) return
    /// [`crate::error::Error::Unsupported`].
    fn listen(&self, url: &Url) -> Result<Box<dyn Listener>>;
}

/// Wrapper around `&'static dyn TransportKind` so the kind can be
/// registered with `inventory` and discovered at link time.
pub struct RegisteredTransport {
    pub kind: &'static dyn TransportKind,
}

inventory::collect!(RegisteredTransport);

/// Iterator over all transport kinds registered at link time.
pub fn iter() -> impl Iterator<Item = &'static dyn TransportKind> {
    inventory::iter::<RegisteredTransport>().map(|r| r.kind)
}

/// Find the registered kind that owns `scheme`, if any.
pub fn find(scheme: &str) -> Option<&'static dyn TransportKind> {
    iter().find(|k| k.schemes().contains(&scheme))
}

/// Submit a transport kind to the link-time registry.
///
/// ```no_run
/// use confium_net::{TransportKind, register_transport};
/// # use confium_net::{Listener, Result, Transport};
/// # use url::Url;
/// # struct MyKind;
/// # impl TransportKind for MyKind {
/// #     fn schemes(&self) -> &'static [&'static str] { &["my"] }
/// #     fn connect(&self, _: &Url) -> Result<Box<dyn Transport>> { unreachable!() }
/// #     fn listen(&self, _: &Url) -> Result<Box<dyn Listener>> { unreachable!() }
/// # }
/// register_transport!(MyKind);
/// ```
#[macro_export]
macro_rules! register_transport {
    ($kind:ident) => {
        ::inventory::submit! {
            $crate::registry::RegisteredTransport { kind: &$kind }
        }
    };
}
