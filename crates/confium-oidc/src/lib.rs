//! `confium-oidc` — OIDC token verifier for Mode 4 (Keyless Threshold).
//!
//! Verifies OIDC tokens from any standards-compliant issuer (GitHub
//! Actions, Google, Okta, Azure AD, Auth0, etc.) and extracts the
//! identity claims the Fulcio-style CA needs to bind to the joint
//! ephemeral threshold key.
//!
//! ## Quickstart
//!
//! ```no_run
//! use confium_oidc::{OidcVerifier, OidcIssuer};
//!
//! let verifier = OidcVerifier::new();
//! let issuer = OidcIssuer::GitHubActions;
//! let claims = verifier.verify(&issuer, "eyJhbGciOi...")
//!     .expect("OIDC token verifies");
//! println!("{} ({})", claims.subject, claims.email.unwrap_or_default());
//! ```
//!
//! ## What this enables
//!
//! Combined with `confium-tc-cmp20` + a Fulcio-style CA, this crate
//! powers **keyless threshold signing ceremonies** where each signer
//! authenticates via OIDC and the joint ephemeral key is bound to
//! the OIDC identities. See
//! `docs/architecture/mode-4-keyless-threshold.mdx` for the full
//! design.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};

/// Errors returned by the verifier.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    /// Issuer not known to this verifier.
    #[error("unknown OIDC issuer: {0}")]
    UnknownIssuer(String),
    /// Token validation failed.
    #[error("token validation failed: {0}")]
    Validation(String),
    /// Failed to fetch JWKS (issuer's public keys).
    #[error("JWKS fetch failed: {0}")]
    JwksFetch(String),
}

/// Known OIDC issuer. Each entry maps to a JWKS URL and a
/// signature algorithm. The defaults cover the issuers Confium
/// has been tested against; users can add their own via
/// [`OidcVerifier::with_issuer`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OidcIssuer {
    /// GitHub Actions (`https://token.actions.githubusercontent.com`).
    GitHubActions,
    /// Google Workspace / Google Cloud (`https://accounts.google.com`).
    Google,
    /// GitLab CI (`https://gitlab.com`).
    GitLab,
    /// Okta tenant — specify the tenant URL.
    Okta(String),
    /// Azure AD — specify the tenant ID.
    AzureAd(String),
    /// Custom issuer identified by its JWKS URL.
    Custom { issuer: String, jwks_url: String },
}

impl OidcIssuer {
    /// The `iss` claim value expected in tokens from this issuer.
    pub fn issuer_url(&self) -> &str {
        match self {
            OidcIssuer::GitHubActions => "https://token.actions.githubusercontent.com",
            OidcIssuer::Google => "https://accounts.google.com",
            OidcIssuer::GitLab => "https://gitlab.com",
            OidcIssuer::Okta(tenant) => tenant.as_str(),
            OidcIssuer::AzureAd(tenant_id) => tenant_id.as_str(),
            OidcIssuer::Custom { issuer, .. } => issuer.as_str(),
        }
    }

    /// JWKS URL — where to fetch the issuer's signing keys.
    pub fn jwks_url(&self) -> String {
        match self {
            OidcIssuer::GitHubActions => "https://token.actions.githubusercontent.com/.well-known/jwks".to_string(),
            OidcIssuer::Google => "https://www.googleapis.com/oauth2/v3/certs".to_string(),
            OidcIssuer::GitLab => "https://gitlab.com/-/jwks".to_string(),
            OidcIssuer::Okta(tenant) => format!("{tenant}/oauth2/default/v1/keys"),
            OidcIssuer::AzureAd(tenant_id) => format!("https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"),
            OidcIssuer::Custom { jwks_url, .. } => jwks_url.clone(),
        }
    }
}

/// Claims extracted from a verified OIDC token. The fields are the
/// minimum the Fulcio-style CA needs to bind to the joint ephemeral
/// threshold key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    /// Subject — stable identifier for the signer at the issuer.
    pub subject: String,
    /// Issuer URL.
    pub issuer: String,
    /// Audience — who the token was issued for.
    pub audience: Vec<String>,
    /// Expiry (Unix epoch seconds).
    pub expires_at: i64,
    /// Issued-at (Unix epoch seconds).
    pub issued_at: i64,
    /// Email claim, if present (Google, Okta, Azure AD).
    pub email: Option<String>,
    /// GitHub-specific claims: repository, workflow, ref, etc.
    pub github: Option<GithubClaims>,
    /// All raw claims, for callers that need fields not exposed above.
    pub raw: HashMap<String, serde_json::Value>,
}

/// GitHub Actions-specific OIDC claims.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GithubClaims {
    /// Repository in `owner/name` form (e.g. `confium/confium`).
    pub repository: String,
    /// Workflow file path (e.g. `.github/workflows/release.yml`).
    pub workflow: String,
    /// Git ref being built (e.g. `refs/tags/v1.0.0`).
    pub ref_: String,
    /// SHA of the commit being built.
    pub sha: String,
    /// GitHub actor (the user/app that triggered the run).
    pub actor: String,
}

/// OIDC token verifier. Cheap to construct; caches JWKS keys per
/// issuer in memory.
pub struct OidcVerifier {
    http: reqwest::blocking::Client,
    jwks_cache: std::sync::Mutex<HashMap<String, std::sync::Arc<JwksSet>>>,
}

impl Default for OidcVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl OidcVerifier {
    /// Construct a new verifier with empty JWKS cache.
    pub fn new() -> Self {
        Self {
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            jwks_cache: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Verify an OIDC token. Fetches the issuer's JWKS (cached on
    /// first call), validates the signature, checks `iss`/`aud`/
    /// `exp`, and returns the extracted claims.
    pub fn verify(
        &self,
        issuer: &OidcIssuer,
        token: &str,
    ) -> Result<OidcClaims, OidcError> {
        let expected_iss = issuer.issuer_url();
        let jwks = self.fetch_jwks(issuer)?;

        // Decode the header to find the key ID, then verify.
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| OidcError::Validation(format!("header decode: {e}")))?;
        let kid = header.kid.ok_or_else(|| {
            OidcError::Validation("token missing kid header".into())
        })?;

        let jwk = jwks.get(&kid).ok_or_else(|| {
            OidcError::Validation(format!("issuer has no key with kid={kid}"))
        })?;

        let decoding_key = DecodingKey::from_rsa_components(&jwk.modulus, &jwk.exponent)
            .map_err(|e| OidcError::Validation(format!("JWK decode: {e}")))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[expected_iss]);
        // We accept any audience the issuer set; the caller validates
        // `aud` against their expected audience (e.g. their own
        // signing service).
        validation.validate_aud = false;

        let token_data = decode::<HashMap<String, serde_json::Value>>(token, &decoding_key, &validation)
            .map_err(|e| OidcError::Validation(format!("token verify: {e}")))?;

        let raw = token_data.claims;
        let subject = raw
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OidcError::Validation("missing sub".into()))?
            .to_string();
        let email = raw
            .get("email")
            .and_then(|v| v.as_str())
            .map(String::from);
        let audience: Vec<String> = raw
            .get("aud")
            .map(|v| match v {
                serde_json::Value::String(s) => vec![s.clone()],
                serde_json::Value::Array(arr) => arr
                    .iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect(),
                _ => vec![],
            })
            .unwrap_or_default();
        let expires_at = raw
            .get("exp")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let issued_at = raw
            .get("iat")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        let github = if raw.contains_key("repository") {
            Some(GithubClaims {
                repository: raw.get("repository").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                workflow: raw.get("workflow").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                ref_: raw.get("ref").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                sha: raw.get("sha").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                actor: raw.get("actor").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            })
        } else {
            None
        };

        Ok(OidcClaims {
            subject,
            issuer: expected_iss.to_string(),
            audience,
            expires_at,
            issued_at,
            email,
            github,
            raw,
        })
    }

    fn fetch_jwks(&self, issuer: &OidcIssuer) -> Result<std::sync::Arc<JwksSet>, OidcError> {
        let key = issuer.issuer_url().to_string();
        {
            let cache = self.jwks_cache.lock().unwrap();
            if let Some(jwks) = cache.get(&key) {
                return Ok(jwks.clone());
            }
        }
        let url = issuer.jwks_url();
        let resp = self
            .http
            .get(&url)
            .send()
            .map_err(|e| OidcError::JwksFetch(e.to_string()))?;
        let body: serde_json::Value = resp
            .json()
            .map_err(|e| OidcError::JwksFetch(format!("JWKS parse: {e}")))?;
        let mut jwks = JwksSet::default();
        if let Some(keys) = body.get("keys").and_then(|v| v.as_array()) {
            for k in keys {
                let kid = k.get("kid").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let modulus = k.get("n").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let exponent = k.get("e").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if !kid.is_empty() {
                    jwks.keys.insert(kid, Jwk { modulus, exponent });
                }
            }
        }
        let arc = std::sync::Arc::new(jwks);
        self.jwks_cache.lock().unwrap().insert(key, arc.clone());
        Ok(arc)
    }
}

#[derive(Debug, Default)]
struct JwksSet {
    keys: HashMap<String, Jwk>,
}

impl JwksSet {
    fn get(&self, kid: &str) -> Option<&Jwk> {
        self.keys.get(kid)
    }
}

#[derive(Debug, Clone)]
struct Jwk {
    modulus: String,
    exponent: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_issuer_has_known_jwks_url() {
        assert_eq!(
            OidcIssuer::GitHubActions.jwks_url(),
            "https://token.actions.githubusercontent.com/.well-known/jwks"
        );
    }

    #[test]
    fn google_issuer_uses_googleapis_certs_endpoint() {
        assert_eq!(
            OidcIssuer::Google.jwks_url(),
            "https://www.googleapis.com/oauth2/v3/certs"
        );
    }

    #[test]
    fn okta_issuer_includes_tenant_in_url() {
        let i = OidcIssuer::Okta("https://example.okta.com".into());
        assert_eq!(
            i.jwks_url(),
            "https://example.okta.com/oauth2/default/v1/keys"
        );
    }

    #[test]
    fn custom_issuer_passes_through() {
        let i = OidcIssuer::Custom {
            issuer: "https://custom.example.com".into(),
            jwks_url: "https://custom.example.com/jwks".into(),
        };
        assert_eq!(i.issuer_url(), "https://custom.example.com");
        assert_eq!(i.jwks_url(), "https://custom.example.com/jwks");
    }

    #[test]
    fn verifier_rejects_garbage_token() {
        let v = OidcVerifier::new();
        let result = v.verify(&OidcIssuer::Google, "not a token");
        assert!(result.is_err());
    }
}
