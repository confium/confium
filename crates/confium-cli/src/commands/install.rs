//! `confium install <plugin>[@version]`.
//!
//! Splits the `name@version` argument, resolves the plugin against the
//! registry, downloads the artifact via HTTP (`ureq`), verifies the
//! SHA-256, and stages it under the local plugin directory. Prints a
//! one-line summary on success.

use std::path::PathBuf;

use confium_registry::install::{HttpDownloader, install};

use crate::cli::InstallArgs;
use crate::commands::common::{fail, override_home, registry_client};

pub fn run(args: InstallArgs) {
    let (name, version) = split_plugin_spec(&args.plugin);
    let home = override_home();
    let home_ref: Option<&PathBuf> = home.as_ref();

    let client = match registry_client() {
        Ok(c) => c,
        Err(e) => fail(e),
    };

    let downloader = HttpDownloader::new();

    match install(&client, &downloader, home_ref, name, version) {
        Ok(record) => {
            println!(
                "installed {} {} -> {}",
                record.name,
                record.version,
                record.artifact_path.display()
            );
        }
        Err(e) => fail(e),
    }
}

/// Split `name@version` into `(name, Some(version))`, or `(name, None)`
/// when no `@` is present. The name is the substring before the first
/// `@`; the version is everything after. Empty names are an error and
/// surface as a usage failure.
pub fn split_plugin_spec(spec: &str) -> (&str, Option<&str>) {
    match spec.split_once('@') {
        Some((name, version)) if !name.is_empty() => (name, Some(version)),
        _ => (spec, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_name_only() {
        assert_eq!(split_plugin_spec("botan"), ("botan", None));
    }

    #[test]
    fn split_name_version() {
        assert_eq!(split_plugin_spec("botan@3.2.0"), ("botan", Some("3.2.0")));
    }

    #[test]
    fn split_preserves_version_dots() {
        assert_eq!(
            split_plugin_spec("frost-ed25519@0.4.1"),
            ("frost-ed25519", Some("0.4.1"))
        );
    }
}
