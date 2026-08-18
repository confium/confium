//! SIGNATIF framework verification.
//!
//! Exposes the [`confium_signatif`] verification pipeline to Python:
//! verify a trusted artifact against a trust anchor bundle, trust
//! graph, and scheme registry, producing the objective coverage
//! report, the classification label, and the acceptance decision.
//!
//! Python usage:
//!   ```python
//!   from confium import signatif
//!
//!   result = signatif.verify_trusted_artifact(
//!       artifact, bundle, graph, registry=None,
//!       transparency_included=True, time_anchored=True,
//!       time_attested_at=None, multi_log_quorum=False,
//!       accepted_labels=["verified"],
//!   )
//!   if result["accept"]:
//!       print(result["label"], result["coverage"]["paths_found"])
//!   ```

use pyo3::prelude::*;
use pyo3::types::PyDict;

use confium_signatif::artifact::TrustedArtifact;
use confium_signatif::bundle::TrustAnchorBundle;
use confium_signatif::coverage::AcceptancePolicy;
use confium_signatif::graph::{SignatureVerifier, TrustGraph};
use confium_signatif::pipeline::{Pipeline, TransparencyInputs};
use confium_signatif::registry::Registry;
use confium_signatif::revocation::NoRevocations;

/// The Python-facing verifier fleet: Ed25519 and ECDSA-P256, the
/// classical algorithms of the default registry.
struct PyVerifier;

impl SignatureVerifier for PyVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        confium_composite::ed25519_verifier("Ed25519", public_key, message, signature).is_ok()
            || confium_composite::p256_verifier("ECDSA-P256", public_key, message, signature)
                .is_ok()
    }
}

/// Verify a SIGNATIF trusted artifact through the full pipeline.
///
/// Args:
///     artifact: trusted-artifact dict (as serialized by the Rust
///         `TrustedArtifact`).
///     bundle: trust-anchor-bundle dict.
///     graph: trust-graph dict (nodes + delegation edges).
///     registry: scheme registry dict; defaults to the initial values.
///     transparency_included: transparency inclusion was verified.
///     time_anchored: an external time anchor was verified.
///     time_attested_at: RFC 3339 time from a verified time authority.
///     multi_log_quorum: the M-of-K multi-log quorum was met.
///     accepted_labels: classification labels this verifier accepts.
///
/// Returns a dict with `coverage`, `label`, and `accept`.
#[pyfunction]
#[pyo3(signature = (
    artifact,
    bundle,
    graph,
    registry = None,
    transparency_included = false,
    time_anchored = false,
    time_attested_at = None,
    multi_log_quorum = false,
    accepted_labels = None,
))]
pub fn verify_trusted_artifact(
    py: Python<'_>,
    artifact: &Bound<'_, PyDict>,
    bundle: &Bound<'_, PyDict>,
    graph: &Bound<'_, PyDict>,
    registry: Option<&Bound<'_, PyDict>>,
    transparency_included: bool,
    time_anchored: bool,
    time_attested_at: Option<String>,
    multi_log_quorum: bool,
    accepted_labels: Option<Vec<String>>,
) -> PyResult<PyObject> {
    let to_value = |d: &Bound<'_, PyDict>| -> PyResult<serde_json::Value> {
        pythonize_dict(d)
    };
    let artifact_v = to_value(artifact)?;
    let bundle_v = to_value(bundle)?;
    let graph_v = to_value(graph)?;

    let artifact: TrustedArtifact = serde_json::from_value(artifact_v)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("artifact: {e}")))?;
    let bundle: TrustAnchorBundle = serde_json::from_value(bundle_v)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("bundle: {e}")))?;
    let graph: TrustGraph = serde_json::from_value(graph_v)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("graph: {e}")))?;
    let registry: Registry = match registry {
        Some(d) => serde_json::from_value(pythonize_dict(d)?)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("registry: {e}")))?,
        None => Registry::with_initial_values(),
    };
    let time_attested_at = match &time_attested_at {
        None => None,
        Some(s) => Some(
            chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("time_attested_at: {e}")))?
                .with_timezone(&chrono::Utc),
        ),
    };
    let acceptance = AcceptancePolicy {
        accepted_labels: accepted_labels.unwrap_or_default(),
    };
    let no_revocations = NoRevocations;
    let pipe = Pipeline::new(
        &bundle,
        &graph,
        &registry,
        &PyVerifier,
        &no_revocations,
        TransparencyInputs {
            artifact_included: transparency_included,
            time_anchored,
            time_attested_at,
            multi_log_quorum,
            downgrades: vec![],
        },
        &acceptance,
    );
    let outcome = pipe
        .run(&artifact, chrono::Utc::now())
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{e}")))?;
    let accept = outcome.acceptance == confium_signatif::coverage::Acceptance::Accept;
    let coverage_json = serde_json::to_value(&outcome.report)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("encode: {e}")))?;
    let out = PyDict::new_bound(py);
    out.set_item("label", outcome.label.0)?;
    out.set_item("accept", accept)?;
    out.set_item("coverage", json_to_py(py, &coverage_json)?)?;
    Ok(out.into())
}

/// JSON value -> Python object.
fn json_to_py(py: Python<'_>, v: &serde_json::Value) -> PyResult<PyObject> {
    use pyo3::types::PyList;
    let out: PyObject = match v {
        serde_json::Value::Null => py.None().into(),
        serde_json::Value::Bool(b) => b.to_object(py),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_object(py)
            } else {
n.as_f64().unwrap_or_default().to_object(py)
            }
        }
        serde_json::Value::String(s) => s.to_object(py),
        serde_json::Value::Array(arr) => {
            let list = PyList::empty_bound(py);
            for item in arr {
                list.append(json_to_py(py, item)?)?;
            }
            list.into_any().unbind().into()
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new_bound(py);
            for (k, val) in map {
                dict.set_item(k, json_to_py(py, val)?)?;
            }
            dict.into_any().unbind().into()
        }
    };
    Ok(out)
}

/// Best-effort dict -> JSON conversion via serde round-trip through a
/// string, avoiding a pythonize dependency.
fn pythonize_dict(d: &Bound<'_, PyDict>) -> PyResult<serde_json::Value> {
    // Walk key-value pairs directly.
    let mut map = serde_json::Map::new();
    for (k, v) in d.iter() {
        let key: String = k
            .extract()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("key: {e}")))?;
        let value = pyobject_to_json(&v)?;
        map.insert(key, value);
    }
    Ok(serde_json::Value::Object(map))
}

fn pyobject_to_json(v: &Bound<'_, pyo3::types::PyAny>) -> PyResult<serde_json::Value> {
    if v.is_none() {
        return Ok(serde_json::Value::Null);
    }
    if let Ok(b) = v.extract::<bool>() {
        return Ok(serde_json::Value::Bool(b));
    }
    if let Ok(i) = v.extract::<i64>() {
        return Ok(serde_json::Value::from(i));
    }
    if let Ok(f) = v.extract::<f64>() {
        return Ok(serde_json::Value::from(f));
    }
    if let Ok(s) = v.extract::<String>() {
        return Ok(serde_json::Value::String(s));
    }
    if let Ok(list) = v.downcast::<pyo3::types::PyList>() {
        let mut arr = Vec::with_capacity(list.len());
        for item in list.iter() {
            arr.push(pyobject_to_json(&item)?);
        }
        return Ok(serde_json::Value::Array(arr));
    }
    if let Ok(dict) = v.downcast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (k, val) in dict.iter() {
            let key: String = k
                .extract()
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("key: {e}")))?;
            map.insert(key, pyobject_to_json(&val)?);
        }
        return Ok(serde_json::Value::Object(map));
    }
    Err(pyo3::exceptions::PyValueError::new_err(
        "unsupported value type in framework object",
    ))
}

/// Register the `confium.signatif` submodule.
pub fn register_module(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new_bound(py, "signatif")?;
    sub.add_function(wrap_pyfunction!(verify_trusted_artifact, &sub)?)?;
    m.add_submodule(&sub)
}

