//! Google Cloud Key Management Service backend.
//!
//! Talks to Cloud KMS via the [`google_cloud_kms::client::Client`]
//! async client. Construction goes through
//! [`google_cloud_kms::client::ClientConfig`] with auth resolved from
//! `GOOGLE_APPLICATION_CREDENTIALS` /
//! `GOOGLE_APPLICATION_CREDENTIALS_JSON` / the GCE metadata server —
//! exactly the same chain every other google-cloud-rust crate uses.
//!
//! # Wire name
//!
//! Registered as `"gcp-kms"`.
//!
//! # Options
//!
//! | key               | meaning                                              |
//! |-------------------|------------------------------------------------------|
//! | `credentials`     | Path to a service-account JSON key file.             |
//! | `credentials_json`| Inline service-account JSON (useful for sealed secrets).|
//! | `project`         | GCP project ID (used as the default key ring scope). |
//! | `location`        | KMS location (e.g. `global`, `us-central1`).         |
//! | `key_ring`        | Default key ring for `put_secret`.                   |
//!
//! # KMS API status
//!
//! Construction is wired; the [`StoreInstance`] methods return
//! [`NotImplemented`](confium_store::error::Error::NotImplemented)
//! pending the `cfmp_sign_with_handle` plugin contract (TODO #03).
//! Cloud KMS, like AWS KMS, never exports raw key material; it returns
//! opaque resource names (`projects/.../keyRings/.../cryptoKeys/...`)
//! that a signature plugin must use to invoke `AsymmetricSign`.

use std::ffi::c_void;

use confium_store::backend::{Compartment, Options, StoreBackend, StoreInstance};
use confium_store::error::{Error, Result};
use confium_store::register_backend;

/// Options key naming the path to a service-account JSON credentials
/// file. Falls back to `GOOGLE_APPLICATION_CREDENTIALS`.
pub const OPT_CREDENTIALS: &str = "credentials";

/// Options key naming inline service-account JSON. Useful when the
/// credentials are provisioned via a sealed secret rather than a file.
pub const OPT_CREDENTIALS_JSON: &str = "credentials_json";

/// Options key naming the GCP project ID.
pub const OPT_PROJECT: &str = "project";

/// Options key naming the KMS location (e.g. `global`).
pub const OPT_LOCATION: &str = "location";

/// Options key naming the default key ring.
pub const OPT_KEY_RING: &str = "key_ring";

/// Factory for the Google Cloud KMS backend.
pub struct GcpKmsBackend;

impl StoreBackend for GcpKmsBackend {
    fn name(&self) -> &'static str {
        "gcp-kms"
    }

    fn open(&self, opts: &Options) -> Result<Box<dyn StoreInstance>> {
        // Capture the resolved configuration now. The actual
        // `ClientConfig::default().with_auth().await` call is async and
        // the trait is synchronous, so we stash the inputs and defer
        // client construction to the first call that needs it.
        Ok(Box::new(GcpKmsInstance {
            config: GcpKmsConfig {
                credentials: opts.get(OPT_CREDENTIALS).cloned(),
                credentials_json: opts.get(OPT_CREDENTIALS_JSON).cloned(),
                project: opts.get(OPT_PROJECT).cloned(),
                location: opts.get(OPT_LOCATION).cloned(),
                key_ring: opts.get(OPT_KEY_RING).cloned(),
            },
            client: None,
        }))
    }
}

register_backend!(GcpKmsBackend);

/// Resolved GCP-side configuration captured at `open` time. Read once
/// `ensure_client` is un-stubbed (TODO #03).
#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
struct GcpKmsConfig {
    credentials: Option<String>,
    credentials_json: Option<String>,
    project: Option<String>,
    location: Option<String>,
    key_ring: Option<String>,
}

/// One open Cloud KMS connection.
///
/// The [`google_cloud_kms::client::Client`] is built lazily on first
/// use — the SDK's auth chain is async and the trait is not. A
/// per-instance tokio runtime drives the deferred load.
///
/// `config` is read once `ensure_client` is un-stubbed (TODO #03).
#[allow(dead_code)]
pub struct GcpKmsInstance {
    config: GcpKmsConfig,
    client: Option<google_cloud_kms::client::Client>,
}

impl GcpKmsInstance {
    /// Lazily build the Cloud KMS client. Returns
    /// [`Error::NotImplemented`] for now — the actual
    /// `AsymmetricSign` / `GetPublicKey` calls depend on the
    /// `cfmp_sign_with_handle` plugin contract (TODO #03).
    fn ensure_client(&mut self) -> Result<&google_cloud_kms::client::Client> {
        if self.client.is_none() {
            // The real construction goes here once the plugin contract
            // is finalised. Kept as a comment so the wiring is visible:
            //
            // let rt = tokio::runtime::Runtime::new()?;
            // let mut cfg = google_cloud_kms::client::ClientConfig::default();
            // if let Some(path) = &self.config.credentials {
            //     let cred = google_cloud_auth::credentials::CredentialsFile::new(path).await?;
            //     cfg = cfg.with_credentials(cred).await?;
            // } else {
            //     cfg = cfg.with_auth().await?;
            // }
            // self.client = Some(google_cloud_kms::client::Client::new(cfg));
            return Err(Error::NotImplemented {
                what: "gcp-kms client construction",
            });
        }
        Ok(self.client.as_ref().expect("client just constructed"))
    }
}

impl StoreInstance for GcpKmsInstance {
    fn put_secret(
        &mut self,
        _module: &str,
        _app: &str,
        _key_id: &str,
        _key: *mut c_void,
    ) -> Result<()> {
        let _ = self.ensure_client()?;
        // Cloud KMS key rings / crypto keys are created via
        // `CreateKeyRing` / `CreateCryptoKey`. Deferred to the
        // post-TODO-#03 revision.
        Err(Error::NotImplemented {
            what: "gcp-kms put_secret",
        })
    }

    fn get_secret(&self, _module: &str, _app: &str, _key_id: &str) -> Result<*mut c_void> {
        Err(Error::NotImplemented {
            what: "gcp-kms get_secret",
        })
    }

    fn put_public(
        &mut self,
        _module: &str,
        _app: &str,
        _identity: &str,
        _key: *mut c_void,
        _sig: &[u8],
    ) -> Result<()> {
        let _ = self.ensure_client()?;
        Err(Error::NotImplemented {
            what: "gcp-kms put_public",
        })
    }

    fn get_public(
        &self,
        _module: &str,
        _app: &str,
        _identity: &str,
    ) -> Result<(*mut c_void, Vec<u8>)> {
        Err(Error::NotImplemented {
            what: "gcp-kms get_public",
        })
    }

    fn enumerate(
        &self,
        _module: &str,
        _app: &str,
        _compartment: Compartment,
    ) -> Result<Vec<(*mut c_void, String)>> {
        // `client.list_key_rings(...)` / `list_crypto_keys(...)` is the
        // eventual backing call.
        Err(Error::NotImplemented {
            what: "gcp-kms enumerate",
        })
    }
}

// SAFETY: `google_cloud_kms::client::Client` wraps an Arc'd gRPC
// channel and is `Send + Sync`. The config is plain owned strings.
unsafe impl Send for GcpKmsInstance {}
unsafe impl Sync for GcpKmsInstance {}

#[cfg(test)]
mod tests {
    use super::*;

    // Distinct non-null sentinel pointer so the tests can pass a handle
    // into `put_secret` without allocating real key material. The
    // backend treats it as an opaque token. Mirrors the same helper in
    // `confium_store::backends::memory`.
    fn sentinel(n: usize) -> *mut c_void {
        n as *mut c_void
    }

    #[test]
    fn name_is_stable_wire_name() {
        assert_eq!(GcpKmsBackend.name(), "gcp-kms");
    }

    #[test]
    fn open_returns_instance_without_calling_gcp() {
        let opts = Options::new();
        let mut instance = GcpKmsBackend.open(&opts).expect("open");
        assert!(instance.put_secret("m", "a", "k", sentinel(1)).is_err());
    }

    #[test]
    fn put_secret_is_not_implemented() {
        let mut instance = GcpKmsBackend.open(&Options::new()).expect("open");
        let err = instance.put_secret("m", "a", "k", sentinel(1)).unwrap_err();
        assert!(matches!(err, Error::NotImplemented { .. }));
    }

    #[test]
    fn backend_is_registered() {
        let backend = confium_store::backend::find("gcp-kms").expect("gcp-kms backend registered");
        assert_eq!(backend.name(), "gcp-kms");
    }
}
