//! Azure Key Vault backend.
//!
//! Talks to Key Vault via
//! [`azure_security_keyvault::KeyvaultClient`]. Auth goes through the
//! standard `azure_identity` chain (env vars, managed identity, shared
//! token cache); the credentials are surfaced to the client at
//! construction time.
//!
//! # Wire name
//!
//! Registered as `"azure-keyvault"`.
//!
//! # Options
//!
//! | key            | meaning                                              |
//! |----------------|------------------------------------------------------|
//! | `vault_url`    | Key Vault DNS name, e.g. `https://my-vault.vault.azure.net`. |
//! | `tenant_id`    | Azure AD tenant for service-principal auth.         |
//! | `client_id`    | Service-principal app ID.                            |
//! | `client_secret`| Service-principal secret.                            |
//!
//! # KMS API status
//!
//! Construction is wired; the [`StoreInstance`] methods return
//! [`NotImplemented`](confium_store::error::Error::NotImplemented)
//! pending the `cfmp_sign_with_handle` plugin contract (TODO #03).
//! Key Vault, like the other two cloud providers, returns opaque key
//! identifiers (`https://<vault>/keys/<name>/<version>`) rather than
//! raw key bytes; a signature plugin invokes `Sign` against the
//! identifier returned by `get_secret`.

use std::ffi::c_void;

use confium_store::backend::{Compartment, Options, StoreBackend, StoreInstance};
use confium_store::error::{Error, Result};
use confium_store::register_backend;

/// Options key naming the Key Vault DNS URL.
pub const OPT_VAULT_URL: &str = "vault_url";

/// Options key naming the Azure AD tenant.
pub const OPT_TENANT_ID: &str = "tenant_id";

/// Options key naming the service-principal app ID.
pub const OPT_CLIENT_ID: &str = "client_id";

/// Options key naming the service-principal secret.
pub const OPT_CLIENT_SECRET: &str = "client_secret";

/// Factory for the Azure Key Vault backend.
pub struct AzureKeyVaultBackend;

impl StoreBackend for AzureKeyVaultBackend {
    fn name(&self) -> &'static str {
        "azure-keyvault"
    }

    fn open(&self, opts: &Options) -> Result<Box<dyn StoreInstance>> {
        // Capture the resolved configuration now. The actual
        // `KeyvaultClient::new(...)` call needs a token credential that
        // is built from these inputs; the SDK's auth is async-capable
        // and the trait is not, so we defer client construction to the
        // first call that needs it.
        Ok(Box::new(AzureKeyVaultInstance {
            config: AzureKeyVaultConfig {
                vault_url: opts.get(OPT_VAULT_URL).cloned(),
                tenant_id: opts.get(OPT_TENANT_ID).cloned(),
                client_id: opts.get(OPT_CLIENT_ID).cloned(),
                client_secret: opts.get(OPT_CLIENT_SECRET).cloned(),
            },
            client: None,
        }))
    }
}

register_backend!(AzureKeyVaultBackend);

/// Resolved Azure-side configuration captured at `open` time. Read once
/// `ensure_client` is un-stubbed (TODO #03).
#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
struct AzureKeyVaultConfig {
    vault_url: Option<String>,
    tenant_id: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// One open Key Vault connection.
///
/// The [`azure_security_keyvault::KeyvaultClient`] is built lazily on
/// first use. The token credential construction in `azure_identity` is
/// async-capable; this stub defers it so the synchronous trait stays
/// honoured.
///
/// `config` is read once `ensure_client` is un-stubbed (TODO #03).
#[allow(dead_code)]
pub struct AzureKeyVaultInstance {
    config: AzureKeyVaultConfig,
    client: Option<azure_security_keyvault::KeyvaultClient>,
}

impl AzureKeyVaultInstance {
    /// Lazily build the Key Vault client. Returns
    /// [`Error::NotImplemented`] for now — the actual `Sign` /
    /// `GetKey` calls depend on the `cfmp_sign_with_handle` plugin
    /// contract (TODO #03).
    fn ensure_client(&mut self) -> Result<&azure_security_keyvault::KeyvaultClient> {
        if self.client.is_none() {
            // The real construction goes here once the plugin contract
            // is finalised. Kept as a comment so the wiring is visible:
            //
            // let cred = azure_identity::token_credential::
            //     ClientSecretCredential::new(
            //         self.config.tenant_id.clone()?,
            //         self.config.client_id.clone()?,
            //         self.config.client_secret.clone()?,
            //         *DEFAULT_TENANT_ID,
            //     );
            // let vault_url = self.config.vault_url.clone()?;
            // self.client = Some(
            //     azure_security_keyvault::KeyvaultClient::new(
            //         &vault_url, std::sync::Arc::new(cred),
            //     ),
            // );
            return Err(Error::NotImplemented {
                what: "azure-keyvault client construction",
            });
        }
        Ok(self.client.as_ref().expect("client just constructed"))
    }
}

impl StoreInstance for AzureKeyVaultInstance {
    fn put_secret(
        &mut self,
        _module: &str,
        _app: &str,
        _key_id: &str,
        _key: *mut c_void,
    ) -> Result<()> {
        let _ = self.ensure_client()?;
        // Key Vault keys are created via `CreateKey`. Deferred to the
        // post-TODO-#03 revision.
        Err(Error::NotImplemented {
            what: "azure-keyvault put_secret",
        })
    }

    fn get_secret(&self, _module: &str, _app: &str, _key_id: &str) -> Result<*mut c_void> {
        Err(Error::NotImplemented {
            what: "azure-keyvault get_secret",
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
            what: "azure-keyvault put_public",
        })
    }

    fn get_public(
        &self,
        _module: &str,
        _app: &str,
        _identity: &str,
    ) -> Result<(*mut c_void, Vec<u8>)> {
        Err(Error::NotImplemented {
            what: "azure-keyvault get_public",
        })
    }

    fn enumerate(
        &self,
        _module: &str,
        _app: &str,
        _compartment: Compartment,
    ) -> Result<Vec<(*mut c_void, String)>> {
        // `KeyvaultClient::get_keys(...)` is the eventual backing call.
        Err(Error::NotImplemented {
            what: "azure-keyvault enumerate",
        })
    }
}

// SAFETY: `azure_security_keyvault::KeyvaultClient` wraps a `Pipeline`
// (a vec of policies sharing an Arc'd HTTP transport) and is `Send +
// Sync`. The config is plain owned strings.
unsafe impl Send for AzureKeyVaultInstance {}
unsafe impl Sync for AzureKeyVaultInstance {}

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
        assert_eq!(AzureKeyVaultBackend.name(), "azure-keyvault");
    }

    #[test]
    fn open_returns_instance_without_calling_azure() {
        let opts = Options::new();
        let mut instance = AzureKeyVaultBackend.open(&opts).expect("open");
        assert!(instance.put_secret("m", "a", "k", sentinel(1)).is_err());
    }

    #[test]
    fn put_secret_is_not_implemented() {
        let mut instance = AzureKeyVaultBackend.open(&Options::new()).expect("open");
        let err = instance.put_secret("m", "a", "k", sentinel(1)).unwrap_err();
        assert!(matches!(err, Error::NotImplemented { .. }));
    }

    #[test]
    fn backend_is_registered() {
        let backend = confium_store::backend::find("azure-keyvault")
            .expect("azure-keyvault backend registered");
        assert_eq!(backend.name(), "azure-keyvault");
    }
}
