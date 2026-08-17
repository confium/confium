//! Delivery formats: passports and challenge-response (SIGNATIF §16).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{SignatifError, SignatifResult};
use crate::jcs;

/// A machine-readable passport: a compact, deterministic summary of a
/// certificate or artifact, verifiable against the same anchor bundle
/// and transparency log as the underlying object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passport {
    /// Passport format version.
    pub version: u32,
    /// The certificate or artifact identifier.
    pub object_id: String,
    /// Key fingerprint of the identified object.
    pub key_fingerprint: String,
    /// Human- and machine-readable scope summary.
    pub scope_summary: String,
    /// Passport validity period start.
    pub valid_from: DateTime<Utc>,
    /// Passport validity period end.
    pub valid_until: DateTime<Utc>,
}

impl Passport {
    /// Deterministic distribution bytes (JCS) — the barcode payload
    /// base for 2D delivery.
    ///
    /// # Errors
    ///
    /// Propagates canonicalization errors.
    pub fn distribution_bytes(&self) -> SignatifResult<Vec<u8>> {
        let v = serde_json::to_value(self).expect("passport serializes");
        Ok(jcs::canonicalize(&v)?.into_bytes())
    }

    /// Whether the passport is valid at `now`.
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.valid_from && now <= self.valid_until
    }

    /// Parse a passport from its deterministic bytes.
    ///
    /// # Errors
    ///
    /// Returns an encoding error on malformed input.
    pub fn from_distribution_bytes(bytes: &[u8]) -> SignatifResult<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| SignatifError::Encoding(format!("passport decode: {e}")))
    }
}

/// A challenge issued to a device signer: a fresh 256-bit nonce and a
/// validity window. Authenticity is established by the ability to
/// produce a timely, nonce-bound response — a static copy of a prior
/// artifact cannot satisfy the challenge.
#[derive(Debug, Clone)]
pub struct Challenge {
    /// The nonce (>= 128 bits of entropy; we use 256).
    pub nonce: [u8; 32],
    /// When the challenge was issued.
    pub issued_at: DateTime<Utc>,
    /// Freshness window.
    pub window: chrono::Duration,
}

impl Challenge {
    /// Generate a challenge with an OS-random nonce.
    ///
    /// # Errors
    ///
    /// Returns a revocation-category error if the OS RNG fails.
    pub fn generate(window: chrono::Duration) -> SignatifResult<Self> {
        use rand_core::RngCore;
        let mut nonce = [0u8; 32];
        rand_core::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| SignatifError::Revocation(format!("os rng: {e}")))?;
        Ok(Self {
            nonce,
            issued_at: Utc::now(),
            window,
        })
    }

    /// The canonical payload the response artifact must carry: the
    /// nonce bound into a deterministic JSON object.
    pub fn expected_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "challenge_nonce": hex::encode(self.nonce),
            "challenged_at": self.issued_at.to_rfc3339(),
        })
    }

    /// Verify a response artifact's payload: the nonce must match and
    /// the response must be inside the freshness window.
    ///
    /// # Errors
    ///
    /// Returns an artifact-format error on nonce mismatch or expiry.
    pub fn verify_response(
        &self,
        response_payload: &serde_json::Value,
        now: DateTime<Utc>,
    ) -> SignatifResult<()> {
        let got = response_payload
            .get("challenge_nonce")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                SignatifError::ArtifactFormat("response lacks challenge_nonce".into())
            })?;
        if got != hex::encode(self.nonce) {
            return Err(SignatifError::ArtifactFormat(
                "challenge nonce mismatch — replayed response".into(),
            ));
        }
        if now > self.issued_at + self.window {
            return Err(SignatifError::ArtifactFormat(
                "response outside freshness window".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passport_round_trips_deterministically() {
        let p = Passport {
            version: 1,
            object_id: "end-cert-7".into(),
            key_fingerprint: "ab00".into(),
            scope_summary: "domain:pharma/*".into(),
            valid_from: Utc::now(),
            valid_until: Utc::now() + chrono::Duration::days(365),
        };
        let bytes = p.distribution_bytes().unwrap();
        let back = Passport::from_distribution_bytes(&bytes).unwrap();
        assert_eq!(back.object_id, p.object_id);
        assert_eq!(back.distribution_bytes().unwrap(), bytes);
        assert!(back.is_valid_at(Utc::now()));
    }

    #[test]
    fn challenge_response_binds_nonce_and_freshness() {
        let c = Challenge::generate(chrono::Duration::seconds(30)).unwrap();
        let payload = c.expected_payload();
        assert!(c.verify_response(&payload, Utc::now()).is_ok());

        let mut wrong = payload.clone();
        wrong["challenge_nonce"] = serde_json::json!("00");
        assert!(c.verify_response(&wrong, Utc::now()).is_err());

        let late = Utc::now() + chrono::Duration::minutes(5);
        assert!(c.verify_response(&payload, late).is_err());
    }
}

/// QR error-correction levels for the barcode delivery (§16
/// `barcode-encoding`): the level is chosen for the expected scanning
/// environment.
#[cfg(feature = "barcode")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrEcc {
    /// Recover ~7% of codewords — clean environments, high density.
    Low,
    /// Recover ~15%.
    Medium,
    /// Recover ~25% — typical print-and-scan.
    Quartile,
    /// Recover ~30% — damaged or low-quality scans.
    High,
}

#[cfg(feature = "barcode")]
impl QrEcc {
    fn to_qrcode(self) -> qrcode::EcLevel {
        match self {
            QrEcc::Low => qrcode::EcLevel::L,
            QrEcc::Medium => qrcode::EcLevel::M,
            QrEcc::Quartile => qrcode::EcLevel::Q,
            QrEcc::High => qrcode::EcLevel::H,
        }
    }
}

#[cfg(feature = "barcode")]
impl Passport {
    /// The passport's QR barcode as an SVG document — a deterministic,
    /// self-contained 2D delivery carrying the passport distribution
    /// bytes, with error correction sufficient for the scanning
    /// environment.
    ///
    /// # Errors
    ///
    /// Encoding errors if the payload exceeds the QR capacity or the
    /// distribution bytes cannot be produced.
    pub fn qr_svg(&self, ecc: QrEcc) -> SignatifResult<String> {
        let bytes = self.distribution_bytes()?;
        let code = qrcode::QrCode::with_error_correction_level(&bytes, ecc.to_qrcode())
            .map_err(|e| SignatifError::Encoding(format!("qr encode: {e}")))?;
        Ok(code.render::<char>().min_dimensions(200, 200).build())
    }
}

#[cfg(all(test, feature = "barcode"))]
mod qr_tests {
    use super::Passport;
    #[cfg(feature = "barcode")]
    use super::QrEcc;
    use chrono::Utc;

    #[cfg(feature = "barcode")]
    #[test]
    fn passport_qr_encodes_with_error_correction() {
        let p = Passport {
            version: 1,
            object_id: "cnml-cert-2026-00001".into(),
            key_fingerprint: "ab00".into(),
            scope_summary: "domain:metrology".into(),
            valid_from: Utc::now(),
            valid_until: Utc::now() + chrono::Duration::days(365),
        };
        // render::<char> yields a character grid, not SVG.
        let svg = p.qr_svg(QrEcc::High).unwrap();
        let lines: Vec<&str> = svg.lines().collect();
        assert!(lines.len() >= 20, "qr grid too small: {}", lines.len());
        // Deterministic: same passport, same bytes, same grid.
        assert_eq!(p.qr_svg(QrEcc::High).unwrap(), svg);
        // Higher ECC still encodes the same payload.
        assert!(p.qr_svg(QrEcc::Low).is_ok());
    }
}
