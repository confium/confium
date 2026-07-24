//! `confium info <plugin>[@version]`.
//!
//! Prints manifest details for a plugin. When a version is pinned, the
//! manifest is fetched from the registry. When no version is given, the
//! locally-cached manifest is read (falling back to the registry if the
//! plugin isn't installed).

use std::path::PathBuf;

use confium_registry::install::{list_installed, read_installed};

use crate::cli::InfoArgs;
use crate::commands::common::{fail, override_home, registry_client};
use crate::commands::install::split_plugin_spec;

pub fn run(args: InfoArgs) {
    let home = override_home();
    let home_ref: Option<&PathBuf> = home.as_ref();
    let (name, version) = split_plugin_spec(&args.plugin);

    let manifest = match version {
        Some(v) => {
            // Explicit version: always ask the registry.
            let client = match registry_client() {
                Ok(c) => c,
                Err(e) => fail(e),
            };
            match client.resolve(name, Some(v)) {
                Ok(m) => m,
                Err(e) => fail(e),
            }
        }
        None => {
            // No version: prefer the local cache, fall back to the
            // registry if the plugin isn't installed.
            let local = local_manifest_for(home_ref, name);
            match local {
                Ok(m) => m,
                Err(_) => {
                    let client = match registry_client() {
                        Ok(c) => c,
                        Err(e) => fail(e),
                    };
                    match client.resolve(name, None) {
                        Ok(m) => m,
                        Err(e) => fail(e),
                    }
                }
            }
        }
    };

    print_manifest(&manifest);
}

/// Read the cached manifest for `name` from the local plugin dir. If
/// multiple versions are installed, the highest is returned.
fn local_manifest_for(
    override_home: Option<&PathBuf>,
    name: &str,
) -> Result<confium_registry::Manifest, confium_registry::Error> {
    let installed = list_installed(override_home)?;
    if let Some(latest) = installed
        .into_iter()
        .filter(|r| r.name == name)
        .max_by_key(|r| r.version.clone())
    {
        return Ok(latest.manifest);
    }
    // Fall through to read_installed for the typed NotInstalled error.
    read_installed(override_home, name, "").map(|r| r.manifest)
}

fn print_manifest(manifest: &confium_registry::Manifest) {
    println!("name:      {}", manifest.plugin.name);
    println!("version:   {}", manifest.plugin.version);
    println!("publisher: {}", manifest.plugin.publisher);
    if !manifest.plugin.license.is_empty() {
        println!("license:   {}", manifest.plugin.license);
    }
    if !manifest.plugin.homepage.is_empty() {
        println!("homepage:  {}", manifest.plugin.homepage);
    }
    if !manifest.plugin.source.is_empty() {
        println!("source:    {}", manifest.plugin.source);
    }
    if !manifest.interfaces.is_empty() {
        let ifaces: Vec<String> = manifest
            .interfaces
            .iter()
            .map(|(k, v)| format!("{k} (v{v})"))
            .collect();
        println!("interfaces: {}", ifaces.join(", "));
    }
    for (iface, algos) in &manifest.algorithms {
        println!("algorithms[{iface}]: {}", algos.join(", "));
    }
    if !manifest.dependencies.is_empty() {
        let deps: Vec<String> = manifest
            .dependencies
            .iter()
            .map(|(k, v)| format!("{k} = {v}"))
            .collect();
        println!("dependencies: {}", deps.join(", "));
    }
    println!(
        "artifact:  {} ({} bytes, sha256 {})",
        manifest.artifact.url, manifest.artifact.size, manifest.artifact.sha256
    );
}
