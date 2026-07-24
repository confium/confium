//! High-level install flow.
//!
//! `install(plugin, version)` resolves the plugin's manifest via the
//! master catalog and per-plugin index, checks the claimed signers
//! against the local trust store, downloads the artifact bytes, and
//! writes them to a local plugin directory under `dest`.
//!
//! For v1 the signer list on the manifest is taken at face value (see
//! `verify.rs`). Real PGP verification will replace how `signers` is
//! derived.

use crate::client::Client;
use crate::error::{Error, Result};
use crate::manifest::Manifest;
use crate::trust::{TrustStore, validate_plugin_name};
use crate::verify::{self, Verification};
use std::path::{Path, PathBuf};

/// Options for an install operation.
#[derive(Clone, Default)]
pub struct InstallOptions {
    /// Allow installing artifacts that fail the trust check (development).
    pub allow_untrusted: bool,
    /// Where to write the downloaded artifact. Defaults to
    /// `~/.config/confium/plugins/`.
    pub dest: Option<PathBuf>,
}

/// The result of a successful install: where the artifact landed, plus
/// the parsed manifest and the verification outcome.
#[derive(Debug, Clone)]
pub struct InstalledPlugin {
    pub path: PathBuf,
    pub manifest: Manifest,
    pub verification: Verification,
}

/// Resolve a registry-relative path (e.g. `/plugins/botan/index.toml`)
/// against the registry base URL.
pub(crate) fn resolve_url(base_url: &str, path: &str) -> Result<String> {
    // Registry paths are absolute on the registry host. Strip a leading
    // slash and join; tolerate trailing slash on the base URL.
    let trimmed_base = base_url.trim_end_matches('/');
    let trimmed_path = path.trim_start_matches('/');
    Ok(format!("{}/{}", trimmed_base, trimmed_path))
}

/// Run the install flow.
///
/// 1. Validate the plugin name.
/// 2. Fetch the master catalog, find the plugin entry.
/// 3. Fetch the per-plugin index, resolve `version` to a manifest URL.
/// 4. Fetch and parse the manifest.
/// 5. Check the manifest's claimed publishers against `trust`.
/// 6. Download the artifact bytes and write to `dest`.
pub fn install(
    client: &Client,
    registry_base: &str,
    trust: &TrustStore,
    plugin: &str,
    version: &str,
    opts: &InstallOptions,
) -> Result<InstalledPlugin> {
    // validate_plugin_name already produces an InvalidPublisherName error
    // (the name-validation variant is shared between plugin and publisher
    // identifiers — see trust.rs).
    validate_plugin_name(plugin)?;

    // Master catalog.
    let master_url = resolve_url(registry_base, "/index.toml")?;
    let master_text = client.get_text(&master_url)?;
    let catalog = crate::index::MasterCatalog::parse(&master_text)?;
    let entry = catalog.find(plugin).ok_or_else(|| Error::NotFound {
        what: "plugin".to_string(),
        detail: format!("plugin '{}' is not in the master catalog", plugin),
    })?;

    // Per-plugin index.
    let plugin_index_url = resolve_url(registry_base, &entry.versions_url)?;
    let plugin_index_text = client.get_text(&plugin_index_url)?;
    let plugin_index = crate::index::PluginIndex::parse(&plugin_index_text)?;
    let manifest_path = plugin_index.manifest_url_for(version)?;
    let manifest_url = resolve_url(registry_base, manifest_path)?;

    // Manifest.
    let manifest_text = client.get_text(&manifest_url)?;
    let manifest = Manifest::parse(&manifest_text)?;

    // Verification. The manifest's `[plugin].publisher` is the only
    // claimed signer we have today; real PGP verification will expand
    // this to the contents of `sigs/`.
    let signers = vec![manifest.plugin.publisher.clone()];
    let verification = verify::check(plugin, &signers, trust, opts.allow_untrusted)?;

    // Download.
    let artifact = manifest.require_artifact()?;
    let bytes = client.get_bytes(&artifact.url)?;
    if artifact.size != 0 && bytes.len() as u64 != artifact.size {
        return Err(Error::Fetch {
            url: artifact.url.clone(),
            message: format!(
                "artifact size mismatch: manifest says {}, got {}",
                artifact.size,
                bytes.len()
            ),
        });
    }

    // Write.
    let dest = opts.dest.clone().unwrap_or_else(default_plugin_dir);
    std::fs::create_dir_all(&dest).map_err(|e| Error::Io {
        path: dest.display().to_string(),
        message: Error::stringify(e),
    })?;
    let out_path = dest.join(format!("{}.bin", plugin));
    std::fs::write(&out_path, &bytes).map_err(|e| Error::Io {
        path: out_path.display().to_string(),
        message: Error::stringify(e),
    })?;

    Ok(InstalledPlugin {
        path: out_path,
        manifest,
        verification,
    })
}

fn default_plugin_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| Path::new(".").to_path_buf())
        .join("confium")
        .join("plugins")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::TrustRoot;
    use mockito::Server;

    fn root(name: &str) -> TrustRoot {
        TrustRoot {
            name: name.to_string(),
            key_id: "0x1".to_string(),
            fingerprint: "AAAA".to_string(),
            key_url: format!("/publishers/{}.asc", name),
        }
    }

    const MASTER: &str = include_str!("../../../sites/registry/index.toml");
    const PLUGIN_INDEX: &str = include_str!("../../../sites/registry/plugins/botan/index.toml");
    const MANIFEST: &str =
        include_str!("../../../sites/registry/plugins/botan/3.2.0/manifest.toml");

    #[test]
    fn resolves_registry_relative_url() {
        let url = resolve_url("https://registry.confium.org", "/plugins/botan/index.toml").unwrap();
        assert_eq!(url, "https://registry.confium.org/plugins/botan/index.toml");
    }

    #[test]
    fn tolerates_trailing_slash() {
        let url = resolve_url("https://registry.confium.org/", "/index.toml").unwrap();
        assert_eq!(url, "https://registry.confium.org/index.toml");
    }

    #[test]
    fn install_trusted_publisher() {
        let mut server = Server::new();
        let base = server.url();

        // The example manifest points at GitHub with a placeholder size;
        // rewrite the artifact URL and size so the download step hits the
        // test server and the size check passes.
        let art_bytes = b"fake-artifact-bytes";
        let manifest_with_local_artifact = MANIFEST
            .replace(
                "https://github.com/confium/confium-botan/releases/download/v3.2.0/libcfm-botan-3.2.0.dylib",
                &format!("{}/artifact", base),
            )
            .replace(
                "size = 1234567",
                &format!("size = {}", art_bytes.len()),
            );

        server
            .mock("GET", "/index.toml")
            .with_status(200)
            .with_body(MASTER)
            .create();
        server
            .mock("GET", "/plugins/botan/index.toml")
            .with_status(200)
            .with_body(PLUGIN_INDEX)
            .create();
        server
            .mock("GET", "/plugins/botan/3.2.0/manifest.toml")
            .with_status(200)
            .with_body(&manifest_with_local_artifact)
            .create();
        server
            .mock("GET", "/artifact")
            .with_status(200)
            .with_body(art_bytes)
            .create();

        let tmp = tempfile::tempdir().unwrap();
        let trust = TrustStore::open(tmp.path().join("trust")).unwrap();
        trust.put(&root("ribose")).unwrap();

        let client = Client::new();
        let dest = tmp.path().join("plugins");
        let opts = InstallOptions {
            allow_untrusted: false,
            dest: Some(dest.clone()),
        };
        let installed =
            install(&client, &base, &trust, "botan", "3.2.0", &opts).expect("install succeeds");
        assert!(installed.verification.is_verified());
        assert!(installed.path.exists());
        let written = std::fs::read(&installed.path).unwrap();
        assert_eq!(written, art_bytes);
    }

    #[test]
    fn install_refuses_untrusted_without_override() {
        let mut server = Server::new();
        let base = server.url();
        server
            .mock("GET", "/index.toml")
            .with_status(200)
            .with_body(MASTER)
            .create();
        server
            .mock("GET", "/plugins/botan/index.toml")
            .with_status(200)
            .with_body(PLUGIN_INDEX)
            .create();
        server
            .mock("GET", "/plugins/botan/3.2.0/manifest.toml")
            .with_status(200)
            .with_body(MANIFEST)
            .create();

        let tmp = tempfile::tempdir().unwrap();
        let trust = TrustStore::open(tmp.path().join("trust")).unwrap();
        // No publishers trusted.
        let client = Client::new();
        let dest = tmp.path().join("plugins");
        let opts = InstallOptions {
            allow_untrusted: false,
            dest: Some(dest),
        };
        let err = install(&client, &base, &trust, "botan", "3.2.0", &opts).unwrap_err();
        assert!(matches!(err, Error::UntrustedPlugin { .. }));
    }
}
