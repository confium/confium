// Subcommand dispatch modules.
//
// Each module exposes a `run` entry point that consumes the matching
// `*Args` struct from `crate::cli`. Commands that error print a
// human-readable message to stderr and exit with a non-zero status.
//
// Shared helpers live in `common` (env-var overrides, registry client
// construction, exit-code mapping), `config_store` (the local
// `config.toml` read/write), and `table` (column-aligned printing).
//
// Adding a new subcommand:
//   1. Add a variant to `Commands` in `crate::cli`.
//   2. Create `commands/<name>.rs` exposing `pub fn run(args: ...)`.
//   3. Declare the module here.

pub mod common;
pub mod config;
pub mod config_store;
pub mod info;
pub mod install;
pub mod list;
pub mod remove;
pub mod search;
pub mod table;
pub mod trust;
pub mod update;
pub mod version;
