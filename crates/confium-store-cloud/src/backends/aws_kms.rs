//! AWS Key Management Service backend.
//!
//! Talks to AWS KMS via [`aws_sdk_kms::Client`]. Construction goes
//! through the standard [`aws_config`] loader so credentials, region,
//! and retry policy are resolved from the environment (env vars, shared
//! config, IMDS, SSO, …) exactly as any other AWS SDK consumer would
//! expect.
//!
//! # Wire name
//!
//! Registered as `"aws-kms"`.
//!
//! # Options
//!
//! The Confium Store's [`Options`](confium_store::backend::Options) map
//! is a flat `String → String`. The backend reads:
//!
//! | key          | meaning                                              |
//! |--------------|------------------------------------------------------|
//! | `region`     | AWS region override (e.g. `us-east-1`).              |
//! | `key_id`     | Default KMS key ID or ARN for `put_secret` targets.  |
//! | `endpoint`   | Custom endpoint URL (LocalStack, alternate partition).|
//!
//! Any option not understood is ignored.
//!
//! # KMS API status
//!
//! Construction builds a real [`aws_sdk_kms::Client`] on first use
//! (credentials/region/endpoint resolved from the environment plus
//! the `region` / `endpoint` options). Secret and public put/get stay
//! [`NotImplemented`](confium_store::error::Error::NotImplemented)
//! until the `cfmp_sign_with_handle` plugin contract (TODO #03)
//! lands: AWS KMS never exports raw key bytes — it returns opaque
//! key ARNs that the signature plugin must invoke via `Sign` /
//! `Verify`. `enumerate` of the private compartment lists real KMS
//! key IDs via `ListKeys` (remote keys have no local handle, so the
//! handle slot is null and the index string is the key ID).

use std::ffi::c_void;

use aws_sdk_kms::Client as KmsClient;
use confium_store::backend::{Compartment, Options, StoreBackend, StoreInstance};
use confium_store::error::{Error, Result};
use confium_store::register_backend;

/// Options key naming the AWS region.
pub const OPT_REGION: &str = "region";

/// Options key naming the default KMS key ID / ARN.
pub const OPT_KEY_ID: &str = "key_id";

/// Options key naming a custom KMS endpoint (LocalStack, alternate
/// partition, VPC endpoint).
pub const OPT_ENDPOINT: &str = "endpoint";

/// Factory for the AWS KMS backend. Stateless — all per-keystore state
/// lives in [`AwsKmsInstance`].
pub struct AwsKmsBackend;

impl StoreBackend for AwsKmsBackend {
    fn name(&self) -> &'static str {
        "aws-kms"
    }

    fn open(&self, opts: &Options) -> Result<Box<dyn StoreInstance>> {
        // `open` must not touch the network (see the tests): the client
        // is built lazily on first use from the captured config, so
        // credentials/region resolution — which may consult IMDS —
        // happens on the first StoreInstance call, not here.
        Ok(Box::new(AwsKmsInstance {
            config: AwsKmsConfig {
                region: opts.get(OPT_REGION).cloned(),
                key_id: opts.get(OPT_KEY_ID).cloned(),
                endpoint: opts.get(OPT_ENDPOINT).cloned(),
            },
            rt: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| Error::Wrapped {
                    message: format!("aws-kms tokio runtime: {e}"),
                })?,
            client: std::sync::OnceLock::new(),
        }))
    }
}

register_backend!(AwsKmsBackend);

/// Resolved AWS-side configuration captured at `open` time. Held by
/// [`AwsKmsInstance`] so the deferred client construction can use it.
/// Read once `ensure_client` is un-stubbed (TODO #03).
#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
struct AwsKmsConfig {
    region: Option<String>,
    key_id: Option<String>,
    endpoint: Option<String>,
}

/// One open AWS KMS connection.
///
/// The [`aws_sdk_kms::Client`] is constructed lazily on the first call
/// that needs it because building it requires an async config load
/// (`aws_config::defaults(...).load().await`), and the
/// [`StoreInstance`] trait is synchronous. A per-instance tokio runtime
/// drives that load.
///
/// `config` is read once `ensure_client` is un-stubbed (TODO #03).
#[allow(dead_code)]
pub struct AwsKmsInstance {
    config: AwsKmsConfig,
    rt: tokio::runtime::Runtime,
    client: std::sync::OnceLock<KmsClient>,
}

impl AwsKmsInstance {
    /// Build the KMS client on first use: credentials, region, and
    /// retry policy from the environment (env vars, shared config,
    /// IMDS, SSO, ...), then the `region` / `endpoint` option
    /// overrides. `OnceLock` lets read-side calls (`&self`)
    /// construct it too.
    fn ensure_client(&self) -> Result<&KmsClient> {
        if let Some(client) = self.client.get() {
            return Ok(client);
        }
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = &self.config.region {
            loader = loader.region(aws_config::Region::new(region.clone()));
        }
        let sdk_cfg = self.rt.block_on(loader.load());
        let mut builder = aws_sdk_kms::config::Builder::from(&sdk_cfg);
        if let Some(endpoint) = &self.config.endpoint {
            builder = builder.endpoint_url(endpoint);
        }
        let built = KmsClient::from_conf(builder.build());
        Ok(self.client.get_or_init(|| built))
    }
}

impl StoreInstance for AwsKmsInstance {
    fn put_secret(
        &mut self,
        _module: &str,
        _app: &str,
        _key_id: &str,
        _key: *mut c_void,
    ) -> Result<()> {
        // Force client construction so misconfiguration surfaces here
        // rather than at the first read.
        self.ensure_client()?;
        // AWS KMS keys are created out-of-band (CloudFormation, CLI,
        // console). `put_secret` will translate to either `CreateKey`
        // (when no `key_id` is configured) or `PutKeyPolicy` /
        // `EnableKey`. Deferred to the post-TODO-#03 revision.
        Err(Error::NotImplemented {
            what: "aws-kms put_secret",
        })
    }

    fn get_secret(&self, _module: &str, _app: &str, _key_id: &str) -> Result<*mut c_void> {
        // Reads can't construct the client (no `&mut self`); the
        // `NotImplemented` path covers the absent-client case.
        Err(Error::NotImplemented {
            what: "aws-kms get_secret",
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
            what: "aws-kms put_public",
        })
    }

    fn get_public(
        &self,
        _module: &str,
        _app: &str,
        _identity: &str,
    ) -> Result<(*mut c_void, Vec<u8>)> {
        Err(Error::NotImplemented {
            what: "aws-kms get_public",
        })
    }

    fn enumerate(
        &self,
        _module: &str,
        _app: &str,
        compartment: Compartment,
    ) -> Result<Vec<(*mut c_void, String)>> {
        if matches!(compartment, Compartment::Public) {
            return Err(Error::NotImplemented {
                what: "aws-kms enumerate (public compartment)",
            });
        }
        let client = self.ensure_client()?;
        let mut out = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut req = client.list_keys().limit(100);
            if let Some(m) = marker.as_deref() {
                req = req.marker(m);
            }
            let page = self.rt.block_on(req.send()).map_err(|e| Error::Wrapped {
                message: format!("aws-kms ListKeys: {e}"),
            })?;
            for key in page.keys() {
                if let Some(id) = key.key_id() {
                    // Remote KMS keys have no local handle; the index
                    // string (the KMS key ID) is the resource identity.
                    out.push((std::ptr::null_mut(), id.to_string()));
                }
            }
            marker = page.next_marker().map(|m| m.to_string());
            if marker.is_none() {
                break;
            }
        }
        Ok(out)
    }
}

// SAFETY: `aws_sdk_kms::Client` is `Send + Sync` (it wraps an Arc'd
// config + HTTP connector). The `AwsKmsConfig` is plain owned strings.
// Storing the client behind `Option<KmsClient>` is sound to share
// across threads.
unsafe impl Send for AwsKmsInstance {}
unsafe impl Sync for AwsKmsInstance {}

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

    // The credential chain reads process env; tests that trigger client
    // construction must pin it to a hermetic, offline configuration.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvVarGuard(&'static str, Option<String>);

    impl EnvVarGuard {
        fn set(name: &'static str, value: &str) -> Self {
            // SAFETY: every env-touching test holds ENV_LOCK, and no
            // other test in this binary reads the environment.
            unsafe { std::env::set_var(name, value) };
            Self(name, None)
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            // SAFETY: as above.
            match &self.1 {
                Some(v) => unsafe { std::env::set_var(self.0, v) },
                None => unsafe { std::env::remove_var(self.0) },
            }
        }
    }

    #[test]
    fn name_is_stable_wire_name() {
        assert_eq!(AwsKmsBackend.name(), "aws-kms");
    }

    #[test]
    fn open_returns_instance_without_calling_aws() {
        // Construction must not hit the network — the client is built
        // lazily on first use.
        let opts = Options::new();
        let mut instance = AwsKmsBackend.open(&opts).expect("open");
        assert!(instance.put_secret("m", "a", "k", sentinel(1)).is_err());
    }

    #[test]
    fn enumerate_private_lists_kms_keys_over_the_wire() {
        let _env = ENV_LOCK.lock().unwrap();
        let _creds = EnvVarGuard::set("AWS_ACCESS_KEY_ID", "test");
        let _secret = EnvVarGuard::set("AWS_SECRET_ACCESS_KEY", "test");
        let _no_imds = EnvVarGuard::set("AWS_EC2_METADATA_DISABLED", "true");
        let _region = EnvVarGuard::set("AWS_REGION", "us-east-1");
        // rustls-native-certs reads SSL_CERT_FILE on unix; macOS CI and
        // dev machines otherwise hit the keychain from the test process.
        let _certs = EnvVarGuard::set("SSL_CERT_FILE", "/etc/ssl/cert.pem");

        // wiremock's server setup is async; give the test a one-shot
        // runtime for it. The instance under test drives its own.
        let server = tokio::runtime::Runtime::new()
            .expect("test runtime")
            .block_on(async {
                let server = wiremock::MockServer::start().await;
                wiremock::Mock::given(wiremock::matchers::method("POST"))
                    .and(wiremock::matchers::path("/"))
                    .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(
                        r#"{"Keys":[{"KeyId":"1234abcd-12ab-34cd-56ef-1234567890ab"},
                             {"KeyId":"abcd1234-ab12-cd34-ef56-ab1234567890ab"}]}"#,
                    ))
                    .mount(&server)
                    .await;
                server
            });

        let mut opts = Options::new();
        opts.insert(OPT_ENDPOINT.to_string(), server.uri());
        let instance = AwsKmsBackend.open(&opts).expect("open");
        let entries = instance
            .enumerate("m", "a", Compartment::Private)
            .expect("enumerate");
        let ids: Vec<String> = entries.into_iter().map(|(_, id)| id).collect();
        assert_eq!(ids.len(), 2, "ids: {ids:?}");
        assert!(ids.contains(&"1234abcd-12ab-34cd-56ef-1234567890ab".to_string()));
        assert!(ids.contains(&"abcd1234-ab12-cd34-ef56-ab1234567890ab".to_string()));
    }

    #[test]
    fn enumerate_public_compartment_is_not_implemented() {
        let instance = AwsKmsBackend.open(&Options::new()).expect("open");
        let err = instance
            .enumerate("m", "a", Compartment::Public)
            .unwrap_err();
        assert!(matches!(err, Error::NotImplemented { .. }));
    }

    #[test]
    fn put_secret_still_not_implemented_but_client_builds() {
        let _env = ENV_LOCK.lock().unwrap();
        let _creds = EnvVarGuard::set("AWS_ACCESS_KEY_ID", "test");
        let _secret = EnvVarGuard::set("AWS_SECRET_ACCESS_KEY", "test");
        let _no_imds = EnvVarGuard::set("AWS_EC2_METADATA_DISABLED", "true");
        let _region = EnvVarGuard::set("AWS_REGION", "us-east-1");
        let _certs = EnvVarGuard::set("SSL_CERT_FILE", "/etc/ssl/cert.pem");

        let mut instance = AwsKmsBackend.open(&Options::new()).expect("open");
        let err = instance.put_secret("m", "a", "k", sentinel(1)).unwrap_err();
        assert!(matches!(err, Error::NotImplemented { .. }));
    }

    #[test]
    fn backend_is_registered() {
        let backend = confium_store::backend::find("aws-kms").expect("aws-kms backend registered");
        assert_eq!(backend.name(), "aws-kms");
    }
}
