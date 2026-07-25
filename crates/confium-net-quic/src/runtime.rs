//! Shared async runtime for all QUIC handles in this process.
//!
//! Quinn is fully async; the [`confium_net::Transport`] /
//! [`confium_net::Listener`] traits are blocking. Rather than impose an
//! async runtime on every Confium caller, all QUIC transport/listener
//! handles share a single process-wide tokio runtime and drive their
//! async work via `block_on`.
//!
//! A single shared runtime avoids the subtle stalls that arise when
//! two endpoints on two separate runtimes exchange UDP packets while
//! each runtime is parked inside its own `block_on`: with separate
//! runtimes, neither endpoint's driver task runs unless its own
//! `block_on` is on the stack, so a peer's packet can sit unprocessed
//! in a kernel buffer until the owning thread happens to re-enter
//! `block_on`. With one runtime, the multi-thread scheduler keeps
//! every endpoint's driver task making progress regardless of which
//! handle is currently in `block_on`.

use std::sync::Arc;
use std::sync::OnceLock;

/// A handle to the shared runtime. Cloning is cheap (Arc).
#[derive(Clone)]
pub(crate) struct Handle {
    rt: Arc<tokio::runtime::Runtime>,
}

/// Wraps the `OnceLock` payload so we can stash a construction error
/// without relying on the unstable `get_or_try_init` API.
type SharedResult = std::result::Result<Arc<tokio::runtime::Runtime>, std::io::Error>;

static SHARED: OnceLock<Arc<SharedResult>> = OnceLock::new();

impl Handle {
    /// Return the process-wide shared runtime, constructing it on
    /// first use.
    pub(crate) fn new() -> std::io::Result<Self> {
        let cell = SHARED.get_or_init(|| {
            let result = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map(Arc::new);
            Arc::new(result)
        });
        match cell.as_ref() {
            Ok(rt) => Ok(Self { rt: Arc::clone(rt) }),
            Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
        }
    }

    /// Run `fut` to completion on this runtime, blocking the caller.
    pub(crate) fn block_on<F, T>(&self, fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        self.rt.block_on(fut)
    }
}
