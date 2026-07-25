//! Test utilities shared across the crate's unit tests.

#![cfg(test)]

use std::cell::RefCell;
use std::rc::Rc;

use confium_core::Confium;
use confium_core::audit::AuditLogger;

use crate::server::SharedConfium;

/// Build a `SharedConfium` with the audit logger disabled, so tests
/// don't touch the filesystem or spam stderr.
pub fn test_confium() -> SharedConfium {
    Rc::new(RefCell::new(Confium::new_with_audit(
        AuditLogger::disabled(),
    )))
}
