//! Built-in transports.
//!
//! Each module registers itself with the link-time registry via
//! [`crate::register_transport!`]. Importing this module pulls both
//! built-in transports into the link graph; consumers that want only
//! one can import the submodule directly.

pub mod inproc;
pub mod mock;
