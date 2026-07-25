//! `confium list`.
//!
//! Reads the local plugin directory and prints a column-aligned table.
//! On an empty directory prints the canonical "no plugins installed"
//! line so shell scripts can grep for it.

use std::io::stdout;
use std::path::PathBuf;

use confium_registry::install::list_installed;

use crate::cli::ListArgs;
use crate::commands::common::{fail, override_home};
use crate::commands::table::print_table;

pub fn run(_args: ListArgs) {
    let home = override_home();
    let home_ref: Option<&PathBuf> = home.as_ref();

    let records = match list_installed(home_ref) {
        Ok(r) => r,
        Err(e) => fail(e),
    };

    if records.is_empty() {
        println!("no plugins installed");
        return;
    }

    let rows: Vec<Vec<String>> = records
        .iter()
        .map(|r| {
            let interfaces = r
                .manifest
                .interfaces
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(",");
            let algorithms = r
                .manifest
                .algorithms
                .values()
                .flatten()
                .cloned()
                .collect::<Vec<_>>()
                .join(",");
            vec![
                r.name.clone(),
                r.version.clone(),
                r.manifest.plugin.publisher.clone(),
                interfaces,
                algorithms,
            ]
        })
        .collect();

    let mut out = stdout();
    let _ = print_table(
        &mut out,
        &["NAME", "VERSION", "VENDOR", "INTERFACES", "ALGORITHMS"],
        &rows,
    );
}
