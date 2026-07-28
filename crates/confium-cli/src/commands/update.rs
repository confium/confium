//! `confium update [<plugin>]`.
//!
//! For each installed plugin (or just the named one), check the latest
//! version from the registry and re-install if newer. Reports per-plugin
//! results. Plugins that are already at the latest version are skipped
//! silently; plugins that fail to update are reported but do not abort
//! the whole run.
//!
//! Version comparison is a simple SemVer-style ordering: equal-length
//! dotted numeric components compare numerically; differing lengths pad
//! with zeros. This is deliberately permissive — the registry is the
//! source of truth for what "latest" means, and we only need to decide
//! whether the installed version differs from it.

use std::path::PathBuf;

use confium_registry::install::{install_manifest, list_installed};

use crate::cli::UpdateArgs;
use crate::commands::common::{fail, override_home, registry_client};
use crate::commands::install::split_plugin_spec;

pub fn run(args: UpdateArgs) {
    let home = override_home();
    let home_ref: Option<&PathBuf> = home.as_ref();

    let installed = match list_installed(home_ref) {
        Ok(records) => records,
        Err(e) => fail(e),
    };

    let target = args.plugin.as_deref();
    let filtered: Vec<_> = installed
        .into_iter()
        .filter(|r| target.is_none_or(|t| r.name == t))
        .collect();

    if filtered.is_empty() {
        if let Some(name) = target {
            // Mirror the install.rs spec parser so `update botan@3.2.0`
            // is accepted even though only the name matters here.
            let (name_only, _) = split_plugin_spec(name);
            eprintln!("confium: plugin '{name_only}' is not installed");
            std::process::exit(64);
        }
        println!("no plugins installed");
        return;
    }

    let client = match registry_client() {
        Ok(c) => c,
        Err(e) => fail(e),
    };

    let mut updated = 0usize;
    let mut errored = 0usize;
    for record in &filtered {
        let latest = match client.resolve(&record.name, None) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("confium: {}: could not resolve latest: {e}", record.name);
                errored += 1;
                continue;
            }
        };
        if is_newer(&latest.plugin.version, &record.version) {
            let downloader = confium_registry::install::HttpDownloader::new();
            match install_manifest(&downloader, home_ref, latest.clone()) {
                Ok(new_record) => {
                    println!(
                        "updated {} {} -> {}",
                        record.name, record.version, new_record.version
                    );
                    updated += 1;
                }
                Err(e) => {
                    eprintln!("confium: {}: update failed: {e}", record.name);
                    errored += 1;
                }
            }
        }
    }

    if updated == 0 && errored == 0 {
        println!("all plugins up to date");
    }
    if errored > 0 {
        std::process::exit(70);
    }
}

/// Return true if `candidate` is strictly newer than `current`.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    cmp_version(candidate, current) == std::cmp::Ordering::Greater
}

/// Compare two dotted version strings component-by-component, padding
/// the shorter with zeros. Non-numeric components fall back to lexical
/// comparison so e.g. pre-release suffixes don't crash.
pub fn cmp_version(a: &str, b: &str) -> std::cmp::Ordering {
    let av: Vec<&str> = a.split('.').collect();
    let bv: Vec<&str> = b.split('.').collect();
    let len = av.len().max(bv.len());
    for i in 0..len {
        let ax = av.get(i).copied().unwrap_or("0");
        let bx = bv.get(i).copied().unwrap_or("0");
        let ord = match (ax.parse::<u64>(), bx.parse::<u64>()) {
            (Ok(an), Ok(bn)) => an.cmp(&bn),
            _ => ax.cmp(bx),
        };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    std::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_version_detected() {
        assert!(is_newer("3.3.0", "3.2.0"));
        assert!(is_newer("4.0.0", "3.99.99"));
    }

    #[test]
    fn equal_version_not_newer() {
        assert!(!is_newer("3.2.0", "3.2.0"));
    }

    #[test]
    fn older_version_not_newer() {
        assert!(!is_newer("3.1.0", "3.2.0"));
    }

    #[test]
    fn differing_length_versions() {
        assert!(is_newer("3.2", "3.1.9"));
        assert!(!is_newer("3.2", "3.2.0"));
    }
}
