// Subcommand dispatch modules.
//
// Each module exposes a `run` entry point that consumes the matching
// `*Args` struct from `crate::cli`. Commands that are not yet implemented
// print a clear "not yet implemented" notice and exit with status 2 so
// callers can distinguish scaffolding from real behavior.
//
// Adding a new subcommand:
//   1. Add a variant to `Commands` in `crate::cli`.
//   2. Create `commands/<name>.rs` exposing `pub fn run(args: ...) -> !`.
//   3. Declare the module here.

pub mod config;
pub mod info;
pub mod install;
pub mod list;
pub mod remove;
pub mod search;
pub mod trust;
pub mod update;
pub mod version;
