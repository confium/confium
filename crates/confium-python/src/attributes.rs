//! Attribute-based threshold predicate DSL bindings.
//!
//! Exposes [`confium_attributes`] to Python:
//!
//! - [`Predicate`] — parse + evaluate attribute predicates like
//!   `min_count("role:director", 5)` and
//!   `and(min_distinct("region", 3), any("expertise"))`.
//! - [`SignerAttributes`] — a signer's attribute map.
//!
//! Python usage:
//!   ```python
//!   from confium import attributes
//!
//!   pred = attributes.Predicate.parse('min_count("role:director", 3)')
//!   signers = [
//!       attributes.SignerAttributes({"role:director": ["yes"]}),
//!       attributes.SignerAttributes({"role:director": ["yes"]}),
//!       attributes.SignerAttributes({"role:director": ["yes"]}),
//!   ]
//!   assert pred.evaluate(signers) is True
//!   ```

use pyo3::Bound;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};

use confium_attributes::{
    Predicate as RustPredicate, SignerAttributes as RustSignerAttributes,
    evaluate as rust_evaluate, parse as rust_parse,
};
use std::collections::{HashMap, HashSet};

/// An attribute-based predicate (parsed from the DSL).
#[pyclass(name = "Predicate")]
pub struct PyPredicate {
    inner: RustPredicate,
}

/// A signer's attribute map.
///
/// Constructed from a Python dict mapping attribute name → list of
/// string values:
///   `SignerAttributes({"region": ["europe"], "role:director": ["yes"]})`
#[pyclass(name = "SignerAttributes")]
pub struct PySignerAttributes {
    inner: RustSignerAttributes,
}

#[pymethods]
impl PyPredicate {
    /// Parse a DSL expression.
    ///
    /// Grammar:
    ///   - `min_count("attr", N)` — at least N signers have `attr`
    ///   - `min_distinct("attr", N)` — at least N distinct values of `attr`
    ///   - `none("attr")` — no signer has `attr`
    ///   - `any("attr")` — at least one signer has `attr`
    ///   - `all("attr")` — every signer has `attr`
    ///   - `and(P1, P2, ...)`, `or(...)`, `not(P)` — boolean composition
    #[staticmethod]
    fn parse(src: &str) -> PyResult<Self> {
        let inner = rust_parse(src).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("predicate parse error: {e}"))
        })?;
        Ok(Self { inner })
    }

    /// Evaluate this predicate against a list of `SignerAttributes`.
    fn evaluate(&self, signers: &Bound<'_, PyList>) -> PyResult<bool> {
        let mut owned: Vec<RustSignerAttributes> = Vec::with_capacity(signers.len());
        for item in signers.iter() {
            let s: PyRef<'_, PySignerAttributes> = item.extract()?;
            owned.push(s.inner.clone());
        }
        let refs: Vec<&RustSignerAttributes> = owned.iter().collect();
        Ok(rust_evaluate(&self.inner, &refs))
    }

    fn __repr__(&self) -> String {
        format!("Predicate({:?})", self.inner)
    }
}

#[pymethods]
impl PySignerAttributes {
    /// Construct from a dict of attribute name → list of values.
    #[new]
    #[pyo3(signature = (attrs=None))]
    fn new(attrs: Option<Bound<'_, PyDict>>) -> PyResult<Self> {
        let mut inner = RustSignerAttributes::new();
        if let Some(d) = attrs {
            for (key, value) in d.iter() {
                let k: String = key.extract()?;
                let list: Bound<'_, PyList> = value.extract().map_err(|_| {
                    pyo3::exceptions::PyTypeError::new_err(format!(
                        "attribute '{k}' value must be a list of strings"
                    ))
                })?;
                let mut set = HashSet::new();
                for v in list.iter() {
                    let s: String = v.extract()?;
                    set.insert(s);
                }
                inner.attrs.insert(k, set);
            }
        }
        Ok(Self { inner })
    }

    /// Add a value to an attribute (mutates in place).
    fn add(&mut self, key: &str, value: &str) {
        self.inner.add(key, value);
    }

    /// Does this signer have attribute `key`?
    fn has(&self, key: &str) -> bool {
        self.inner.has(key)
    }

    /// Values for `key` as a list (may be empty).
    fn values<'py>(&self, py: Python<'py>, key: &str) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty_bound(py);
        for v in self.inner.values(key) {
            list.append(v)?;
        }
        Ok(list)
    }

    fn __repr__(&self) -> String {
        format!("SignerAttributes(attrs={})", self._summary())
    }
}

impl PySignerAttributes {
    fn _summary(&self) -> String {
        let mut keys: Vec<&String> = self.inner.attrs.keys().collect();
        keys.sort();
        keys.iter()
            .map(|k| {
                let count = self.inner.attrs.get(*k).map(|s| s.len()).unwrap_or(0);
                format!("{k}[{count}]")
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

// Test-only helper exposed for the test suite; not part of the public API.
/// Register the `attributes` submodule.
pub(crate) fn register_module(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new_bound(py, "attributes")?;
    m.add_class::<PyPredicate>()?;
    m.add_class::<PySignerAttributes>()?;
    // Examples table — mirrors the DSL grammar in the Rust crate.
    let examples: HashMap<&str, &str> = [
        ("min_count", r#"min_count("role:director", 5)"#),
        ("min_distinct", r#"min_distinct("region", 3)"#),
        ("none", r#"none("nationality:cn")"#),
        ("any", r#"any("expertise")"#),
        ("all", r#"all("role:director")"#),
        (
            "and",
            r#"and(min_count("role:director", 5), min_distinct("region", 3))"#,
        ),
        ("or", r#"or(any("backup"), any("primary"))"#),
        ("not", r#"not(none("role:director"))"#),
    ]
    .into_iter()
    .collect();
    let ex_dict = PyDict::new_bound(py);
    for (k, v) in examples {
        ex_dict.set_item(k, PyString::new_bound(py, v))?;
    }
    m.add("EXAMPLES", ex_dict)?;
    parent.add_submodule(&m)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {}
}
