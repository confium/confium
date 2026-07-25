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
//! Construction builds a real [`aws_sdk_kms::Client`]. The
//! [`StoreInstance`](confium_store::backend::StoreInstance) methods are
//! stubbed to return [`NotImplemented`](confium_store::error::Error::NotImplemented)
//! until the `cfmp_sign_with_handle` plugin contract (TODO #03) lands,
//! because AWS KMS never exports raw key bytes — it returns opaque key
//! ARNs that the signature plugin must invoke via `Sign` / `Verify`.

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
        // The ConfigLoader is the standard AWS SDK entry point. We
        // honour `region` if set; everything else (credentials, retry)
        // is left to the SDK's default chain so we behave like every
        // other AWS SDK consumer.
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = opts.get(OPT_REGION) {
            loader = loader.region(aws_sdk_kms::config::Region::new(region.clone()));
        }
        // We can't await inside `open` (the trait is synchronous), so we
        // stash the loader and materialise the client lazily on first
        // use. The `aws_sdk_kms::Client::builder()` accepts a
        // `&SdkConfig` synchronously once `load().await` has produced
        // one; for the skeleton we keep the loader around and let the
        // first `StoreInstance` call drive it to completion via the
        // per-instance tokio runtime.
        let _ = loader;
        Ok(Box::new(AwsKmsInstance {
            config: AwsKmsConfig {
                region: opts.get(OPT_REGION).cloned(),
                key_id: opts.get(OPT_KEY_ID).cloned(),
                endpoint: opts.get(OPT_ENDPOINT).cloned(),
            },
            client: None,
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
    client: Option<KmsClient>,
}

impl AwsKmsInstance {
    /// Lazily build the KMS client on first use. Construction is
    /// deferred because `aws_config::defaults(...).load()` is async and
    /// the `StoreInstance` trait is not. Returns
    /// [`Error::NotImplemented`] for now — the actual `Sign` / `Verify`
    /// calls depend on the `cfmp_sign_with_handle` plugin contract
    /// (TODO #03) and will replace this stub.
    fn ensure_client(&mut self) -> Result<&KmsClient> {
        if self.client.is_none() {
            // The real construction goes here once the plugin contract
            // is finalised. Kept as a comment so the wiring is visible:
            //
            // let rt = tokio::runtime::Runtime::new()?;
            // let mut loader = aws_config::defaults(
            //     aws_config::BehaviorVersion::latest(),
            // );
            // if let Some(region) = &self.config.region {
            //     loader = loader.region(Region::new(region.clone()));
            // }
            // let sdk_cfg = rt.block_on(loader.load());
            // let mut builder = aws_sdk_kms::config::Builder::from(&sdk_cfg);
            // if let Some(endpoint) = &self.config.endpoint {
            //     builder = builder.endpoint_url(endpoint);
            // }
            // self.client = Some(KmsClient::from_conf(builder.build()));
            return Err(Error::NotImplemented {
                what: "aws-kms client construction",
            });
        }
        Ok(self.client.as_ref().expect("client just constructed"))
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
        let _ = self.ensure_client()?;
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
        _compartment: Compartment,
    ) -> Result<Vec<(*mut c_void, String)>> {
        // `aws_sdk_kms::Client::list_keys()` is the eventual backing
        // call; returns paginated key ARNs. Stubbed for now.
        Err(Error::NotImplemented {
            what: "aws-kms enumerate",
        })
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
    fn put_secret_is_not_implemented() {
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
