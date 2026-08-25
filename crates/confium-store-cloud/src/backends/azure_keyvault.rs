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
            client: std::sync::OnceLock::new(),
        }))
    }
}

register_backend!(AzureKeyVaultBackend);

/// Resolved Azure-side configuration captured at `open` time. Read once
/// Held by the instance for the lazy client construction.
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
/// Read by the lazy client construction on first use.
pub struct AzureKeyVaultInstance {
    config: AzureKeyVaultConfig,
    client: std::sync::OnceLock<azure_security_keyvault::KeyvaultClient>,
}

impl AzureKeyVaultInstance {
    /// Build the Key Vault client on first use: a client-secret
    /// credential (tenant_id + client_id + client_secret options,
    /// or the AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
    /// env vars via the config layer) against the vault_url option.
    fn ensure_client(&self) -> Result<&azure_security_keyvault::KeyvaultClient> {
        if let Some(client) = self.client.get() {
            return Ok(client);
        }
        let required = |v: &Option<String>, opt: &str| -> Result<String> {
            v.clone().ok_or_else(|| Error::Wrapped {
                message: format!("azure-keyvault: option '{opt}' is required"),
            })
        };
        let tenant_id = required(&self.config.tenant_id, "tenant_id")?;
        let client_id = required(&self.config.client_id, "client_id")?;
        let client_secret = required(&self.config.client_secret, "client_secret")?;
        let vault_url = required(&self.config.vault_url, "vault_url")?;

        let authority =
            azure_core::Url::parse("https://login.microsoftonline.com").map_err(|e| {
                Error::Wrapped {
                    message: format!("azure-keyvault authority host: {e}"),
                }
            })?;
        let cred = azure_identity::ClientSecretCredential::new(
            azure_core::new_http_client(),
            authority,
            tenant_id,
            client_id,
            client_secret,
        );
        let built =
            azure_security_keyvault::KeyvaultClient::new(&vault_url, std::sync::Arc::new(cred))
                .map_err(|e| Error::Wrapped {
                    message: format!("azure-keyvault client: {e}"),
                })?;
        Ok(self.client.get_or_init(|| built))
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
        self.ensure_client()?;
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
        self.ensure_client()?;
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

    // Construction is real: missing required options surface as
    // Wrapped errors naming the option; with all four provided the
    // NotImplemented contract (pending the sign plugin contract) is
    // what surfaces.
    #[test]
    fn put_secret_without_options_names_the_missing_option() {
        let mut instance = AzureKeyVaultBackend.open(&Options::new()).expect("open");
        let err = instance.put_secret("m", "a", "k", sentinel(1)).unwrap_err();
        match err {
            Error::Wrapped { message } => {
                assert!(message.contains("tenant_id"), "message: {message}");
            }
            other => panic!("expected Wrapped, got {other:?}"),
        }
    }

    #[test]
    fn put_secret_with_full_config_is_not_implemented() {
        let mut opts = Options::new();
        opts.insert(OPT_TENANT_ID.to_string(), "tenant".to_string());
        opts.insert(OPT_CLIENT_ID.to_string(), "client".to_string());
        opts.insert(OPT_CLIENT_SECRET.to_string(), "secret".to_string());
        opts.insert(
            OPT_VAULT_URL.to_string(),
            "https://vault.vault.azure.net".to_string(),
        );
        let mut instance = AzureKeyVaultBackend.open(&opts).expect("open");
        let err = instance.put_secret("m", "a", "k", sentinel(1)).unwrap_err();
        assert!(
            matches!(err, Error::NotImplemented { .. }),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn backend_is_registered() {
        let backend = confium_store::backend::find("azure-keyvault")
            .expect("azure-keyvault backend registered");
        assert_eq!(backend.name(), "azure-keyvault");
    }
}
