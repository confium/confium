//! `confium remove <plugin>`.
//!
//! Deletes the named plugin from the local plugin directory. Errors
//! with a clear message if the plugin is not installed.

use std::path::PathBuf;

use confium_registry::install::remove;

use crate::cli::RemoveArgs;
use crate::commands::common::{fail, override_home};

pub fn run(args: RemoveArgs) {
    let home = override_home();
    let home_ref: Option<&PathBuf> = home.as_ref();

    match remove(home_ref, &args.plugin) {
        Ok(()) => {
            println!("removed {}", args.plugin);
        }
        Err(e) => fail(e),
    }
}
