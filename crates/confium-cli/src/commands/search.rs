//! `confium search [<interface>] [<algorithm>]`.
//!
//! Fetches the registry master index and, for each entry, the per-plugin
//! version index + latest manifest. Filters by the requested interface
//! and/or algorithm. Prints a table of matches.
//!
//! Filtering is case-insensitive on the interface name (so `AEAD` and
//! `aead` match). Algorithm filtering is case-sensitive (algorithm names
//! are canonical: `SHA-256`, `AES-256-GCM`).

use std::io::stdout;

use confium_registry::manifest::RegistryIndex;

use crate::cli::SearchArgs;
use crate::commands::common::{fail, registry_client};
use crate::commands::table::print_table;

pub fn run(args: SearchArgs) {
    let client = match registry_client() {
        Ok(c) => c,
        Err(e) => fail(e),
    };

    let index: RegistryIndex = match client.index() {
        Ok(i) => i,
        Err(e) => fail(e),
    };

    let interface = args.interface.as_deref().map(str::to_ascii_lowercase);
    let algorithm = args.algorithm.as_deref();

    let mut rows: Vec<Vec<String>> = Vec::new();
    for entry in &index.plugins {
        // Resolve the latest manifest to inspect interfaces + algorithms.
        let manifest = match client.resolve(&entry.name, None) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if let Some(ref iface) = interface {
            let has_iface = manifest
                .interfaces
                .keys()
                .any(|k| k.to_ascii_lowercase() == *iface);
            if !has_iface {
                continue;
            }
        }

        if let Some(algo) = algorithm {
            let has_algo = manifest.algorithms.values().flatten().any(|a| a == algo);
            if !has_algo {
                continue;
            }
        }

        let interfaces = manifest
            .interfaces
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        let algorithms = manifest
            .algorithms
            .values()
            .flatten()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        rows.push(vec![
            entry.name.clone(),
            entry.latest.clone(),
            entry.description.clone(),
            interfaces,
            algorithms,
        ]);
    }

    if rows.is_empty() {
        println!("no plugins match");
        return;
    }

    let mut out = stdout();
    let _ = print_table(
        &mut out,
        &["NAME", "VERSION", "DESCRIPTION", "INTERFACES", "ALGORITHMS"],
        &rows,
    );
}
