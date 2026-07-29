//! Confium Python bindings — entry point.
//!
//! Exposes:
//!
//! - `confium.version()`, `confium.core_version()` — version info
//! - `confium.composite.CompositeSignature` — composite signature verify
//! - `confium.transparency.MerkleTree` — RFC 6962 transparency log
//!
//! Built-in verifiers cover Ed25519 and ECDSA-P256. ML-DSA / SLH-DSA
//! will land alongside the upstream Rust verifiers.

// PyO3 0.22's `#[pymethods]` and `#[pymodule]` macros emit unsafe-op-
// in-unsafe-fn under edition 2024. The macro output is correct; the
// warnings are upstream noise pending a PyO3 0.23+ bump.
#![allow(unsafe_op_in_unsafe_fn)]

use pyo3::prelude::*;

pub mod attributes;
pub mod composite;
pub mod deployment;
pub mod pki;
pub mod transparency;
pub mod version;
pub mod xmldsig;

/// Register the Python module.
#[pymodule]
fn confium(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    m.add_function(wrap_pyfunction!(version::version, m)?)?;
    m.add_function(wrap_pyfunction!(version::core_version, m)?)?;

    attributes::register_module(py, m)?;
    composite::register_module(py, m)?;
    deployment::register_module(py, m)?;
    pki::register_module(py, m)?;
    transparency::register_module(py, m)?;
    xmldsig::register_module(py, m)?;

    Ok(())
}
