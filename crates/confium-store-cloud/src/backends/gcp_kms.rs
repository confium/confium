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
            rt: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| Error::Wrapped {
                    message: format!("gcp-kms tokio runtime: {e}"),
                })?,
            client: std::sync::OnceLock::new(),
        }))
    }
}

register_backend!(GcpKmsBackend);

/// Resolved GCP-side configuration captured at `open` time. Read once
/// Held by the instance for the lazy client construction.
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
pub struct GcpKmsInstance {
    config: GcpKmsConfig,
    rt: tokio::runtime::Runtime,
    client: std::sync::OnceLock<google_cloud_kms::client::Client>,
}

impl GcpKmsInstance {
    /// Build the Cloud KMS client on first use: an explicit
    /// service-account file (`credentials`), or the default ADC chain
    /// (GOOGLE_APPLICATION_CREDENTIALS / _JSON env vars, metadata
    /// server). `OnceLock` lets read-side calls construct it too.
    fn ensure_client(&self) -> Result<&google_cloud_kms::client::Client> {
        if let Some(client) = self.client.get() {
            return Ok(client);
        }
        let cfg = google_cloud_kms::client::ClientConfig::default();
        let cfg = if let Some(path) = &self.config.credentials {
            let cred = self
                .rt
                .block_on(
                    google_cloud_auth::credentials::CredentialsFile::new_from_file(path.clone()),
                )
                .map_err(|e| Error::Wrapped {
                    message: format!("gcp-kms credentials file: {e}"),
                })?;
            self.rt
                .block_on(cfg.with_credentials(cred))
                .map_err(|e| Error::Wrapped {
                    message: format!("gcp-kms credentials: {e}"),
                })?
        } else if let Some(json) = &self.config.credentials_json {
            let cred = self
                .rt
                .block_on(google_cloud_auth::credentials::CredentialsFile::new_from_str(json))
                .map_err(|e| Error::Wrapped {
                    message: format!("gcp-kms credentials json: {e}"),
                })?;
            self.rt
                .block_on(cfg.with_credentials(cred))
                .map_err(|e| Error::Wrapped {
                    message: format!("gcp-kms credentials: {e}"),
                })?
        } else {
            self.rt
                .block_on(cfg.with_auth())
                .map_err(|e| Error::Wrapped {
                    message: format!("gcp-kms application default credentials: {e}"),
                })?
        };
        let built = self
            .rt
            .block_on(google_cloud_kms::client::Client::new(cfg))
            .map_err(|e| Error::Wrapped {
                message: format!("gcp-kms client: {e}"),
            })?;
        Ok(self.client.get_or_init(|| built))
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
        self.ensure_client()?;
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
    // Credential chain reads process env; pin it off for hermetic tests.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvVarGuard(&'static str, Option<String>);

    impl EnvVarGuard {
        fn remove(name: &'static str) -> Self {
            let prev = std::env::var(name).ok();
            // SAFETY: every env-touching GCP test holds ENV_LOCK.
            unsafe { std::env::remove_var(name) };
            Self(name, prev)
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(v) = &self.1 {
                // SAFETY: as above.
                unsafe { std::env::set_var(self.0, v) };
            }
        }
    }

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

    // Client construction is real: with no credentials configured
    // (and no ADC on the machine) the auth failure surfaces as a
    // Wrapped error instead of the old NotImplemented stub.
    #[test]
    fn put_secret_without_credentials_surfaces_the_auth_error() {
        let _env = ENV_LOCK.lock().unwrap();
        let _g1 = EnvVarGuard::remove("GOOGLE_APPLICATION_CREDENTIALS");
        let _g2 = EnvVarGuard::remove("GOOGLE_APPLICATION_CREDENTIALS_JSON");
        let mut instance = GcpKmsBackend.open(&Options::new()).expect("open");
        let err = instance.put_secret("m", "a", "k", sentinel(1)).unwrap_err();
        match err {
            Error::Wrapped { message } => {
                assert!(message.contains("gcp-kms"), "message: {message}");
            }
            other => panic!("expected Wrapped, got {other:?}"),
        }
    }

    #[test]
    fn put_secret_with_malformed_credentials_reports_the_parse_error() {
        let _env = ENV_LOCK.lock().unwrap();
        let _g1 = EnvVarGuard::remove("GOOGLE_APPLICATION_CREDENTIALS");
        let _g2 = EnvVarGuard::remove("GOOGLE_APPLICATION_CREDENTIALS_JSON");
        let mut opts = Options::new();
        opts.insert(OPT_CREDENTIALS_JSON.to_string(), "not json".to_string());
        let mut instance = GcpKmsBackend.open(&opts).expect("open");
        let err = instance.put_secret("m", "a", "k", sentinel(1)).unwrap_err();
        match err {
            Error::Wrapped { message } => {
                assert!(message.contains("credentials json"), "message: {message}");
            }
            other => panic!("expected Wrapped, got {other:?}"),
        }
    }

    #[test]
    fn backend_is_registered() {
        let backend = confium_store::backend::find("gcp-kms").expect("gcp-kms backend registered");
        assert_eq!(backend.name(), "gcp-kms");
    }
}
