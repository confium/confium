//! `Certificate` + `CMS::SignedData` — PKI verifiers for the browser/Node.js
//! surface.

use confium_pki::{
    cert::Certificate as RustCert,
    cms::SignedData as RustSignedData,
};
use wasm_bindgen::prelude::*;

/// Parsed X.509 v3 certificate. Construct via [`Certificate::from_der`] or
/// [`Certificate::from_pem`]; inspect validity window, fingerprint, serial.
#[wasm_bindgen]
pub struct Certificate {
    inner: RustCert,
}

#[wasm_bindgen]
impl Certificate {
    /// Parse a certificate from DER bytes (`Uint8Array`).
    #[wasm_bindgen(constructor)]
    pub fn from_der(der: &[u8]) -> Result<Certificate, JsValue> {
        let inner = RustCert::from_der(der)
            .map_err(|e| JsValue::from_str(&format!("DER parse error: {e}")))?;
        Ok(Self { inner })
    }

    /// Parse a certificate from PEM (RFC 7468) text.
    pub fn from_pem(pem: &str) -> Result<Certificate, JsValue> {
        let inner = RustCert::from_pem(pem)
            .map_err(|e| JsValue::from_str(&format!("PEM parse error: {e}")))?;
        Ok(Self { inner })
    }

    /// SHA-256 fingerprint as a lowercase hex string.
    #[wasm_bindgen(getter)]
    pub fn fingerprint_sha256(&self) -> String {
        self.inner.fingerprint_sha256()
    }

    /// Serial number as a lowercase hex string.
    #[wasm_bindgen(getter)]
    pub fn serial_hex(&self) -> String {
        let bytes = self.inner.serial_bytes();
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{:02x}", b));
        }
        out
    }

    /// DER bytes (`Uint8Array`).
    #[wasm_bindgen]
    pub fn to_der(&self) -> Vec<u8> {
        self.inner.to_der()
    }

    /// Whether the certificate is within its validity window at the given
    /// epoch-millisecond timestamp.
    #[wasm_bindgen]
    pub fn is_within_validity(&self, epoch_ms: f64) -> bool {
        let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(epoch_ms as i64)
            .unwrap_or_else(|| chrono::Utc::now());
        self.inner.is_within_validity(now)
    }
}

/// CMS SignedData JSON model — wraps `confium_pki::cms::SignedData`.
///
/// Construct via [`SignedData::from_json`] (the canonical wire format) and
/// inspect signer / certificate / content fields. Verification of the
/// signatures themselves happens at a higher layer (the verifier is
/// caller-supplied because each signer algorithm needs its own callback).
#[wasm_bindgen]
pub struct SignedData {
    inner: RustSignedData,
}

#[wasm_bindgen]
impl SignedData {
    /// Parse SignedData from its canonical JSON form.
    #[wasm_bindgen(constructor)]
    pub fn from_json(json: &str) -> Result<SignedData, JsValue> {
        let inner: RustSignedData = serde_json::from_str(json)
            .map_err(|e| JsValue::from_str(&format!("SignedData JSON parse error: {e}")))?;
        Ok(Self { inner })
    }

    /// Round-trip back to canonical JSON.
    #[wasm_bindgen]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsValue::from_str(&format!("serialize: {e}")))
    }

    /// Number of signer infos.
    #[wasm_bindgen(getter)]
    pub fn signer_count(&self) -> usize {
        self.inner.signer_infos.len()
    }

    /// Content type OID.
    #[wasm_bindgen(getter)]
    pub fn content_type(&self) -> String {
        self.inner.encap_content_info.content_type.clone()
    }

    /// Number of attached X.509 certificates.
    #[wasm_bindgen(getter)]
    pub fn certificate_count(&self) -> usize {
        self.inner.certificates.len()
    }

    /// Get the DER bytes of the certificate at `index`, or `undefined` if
    /// out of range.
    #[wasm_bindgen]
    pub fn certificate_at(&self, index: usize) -> Option<Vec<u8>> {
        self.inner.certificates.get(index).cloned()
    }

    /// Get the encapsulated content bytes, or `None` if detached.
    #[wasm_bindgen]
    pub fn content(&self) -> Option<Vec<u8>> {
        self.inner.encap_content_info.content.clone()
    }
}
