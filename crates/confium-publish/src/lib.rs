//! Library facade for the `confium-publish` tool.
//!
//! The binary (`src/main.rs`) is a thin wrapper over these modules so
//! that integration tests (`tests/`) can exercise the publishing flow
//! without spawning a subprocess. Each module is `pub` so tests can
//! reach the helpers directly.

pub mod cli;
pub mod load;
pub mod manifest;
pub mod output;
pub mod sign;

// Convenience re-exports for the common types tests and `main` reach for.
pub use cli::{PublishArgs, parse_algorithm_overrides, parse_interface_overrides};
pub use load::{
    CFMPluginMetadata, InterfaceEntry, LoadError, PluginMetadata, open_library, query_interfaces,
    query_metadata, resolve_algorithms, resolve_interfaces,
};
pub use manifest::{
    ArtifactSection, ConfiumSection, Manifest, ManifestInput, PluginSection, build, to_toml,
};
pub use output::{OutputError, OutputPaths, paths_for, sha256_of_file, write_tree};
pub use sign::{SignError, sign_manifest};
