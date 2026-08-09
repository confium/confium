#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::redundant_explicit_links)]
#![allow(rustdoc::private_intra_doc_links)]
#![allow(rustdoc::invalid_html_tags)]

//! confiumd — long-running Confium daemon.
//!
//! Exposes the full Confium API over JSON-RPC 2.0 with length-prefixed
//! framing. Clients connect via TCP or Unix socket.
//!
//! See `TODO.roadmap/16-confiumd-daemon.md` for the design and
//! roadmap.

pub mod dispatch;
pub mod error;
pub mod methods;
pub mod protocol;
pub mod server;
#[cfg(test)]
pub mod test_util;

pub use error::{DaemonError, RpcError};
pub use server::Server;
