//! Version information functions.

use pyo3::prelude::*;

/// Returns the Python binding version (from CARGO_PKG_VERSION).
#[pyfunction]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Returns the underlying confium-core engine version.
#[pyfunction]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
