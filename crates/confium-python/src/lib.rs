//! Confium Python bindings — entry point.
//!
//! Wraps the Confium Rust engine via PyO3. Initial release exposes
//! version information. Composite signature verification and
//! transparency log operations will be added incrementally.

use pyo3::prelude::*;

pub mod version;

/// Register the Python module.
#[pymodule]
fn confium(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    m.add_function(wrap_pyfunction!(version::version, m)?)?;
    m.add_function(wrap_pyfunction!(version::core_version, m)?)?;

    Ok(())
}
