// Clap-derived argument definitions for the `confium-publish` command.
//
// The single `PublishArgs` struct holds every flag the publishing flow
// needs. There are no subcommands — `confium-publish` is one-shot: load
// artifact, query FFI, emit a manifest tree. New flags are added by
// appending a field here (Open/Closed Principle — no dispatch table to
// touch).
//
// CLI shape: `TODO.roadmap/07-cli-tools.md`.

use std::path::PathBuf;

use clap::Parser;

/// Author a registry-ready plugin release.
///
/// Loads the built artifact, queries it via the FFI contract, computes
/// its SHA-256, generates `manifest.toml`, signs it with the publisher's
/// PGP key, and writes a directory tree ready to drop into
/// `github.com/confium/registry/plugins/`.
#[derive(Parser, Debug)]
#[command(
    name = "confium-publish",
    about = "Author a signed registry release for a Confium plugin",
    long_about = "Confium plugin publishing tool — load, manifest, sign, output.",
    // The spec's `--version <semver>` is the *plugin* version, which would
    // collide with clap's auto-generated tool `--version`. Disable the
    // auto flag so the plugin-version arg owns the name unambiguously.
    disable_version_flag = true,
)]
pub struct PublishArgs {
    /// Path to the built plugin artifact (`.so` / `.dylib` / `.dll`).
    pub artifact: PathBuf,

    /// Plugin name (e.g. `botan`). Overrides FFI metadata when present.
    #[arg(long)]
    pub name: Option<String>,

    /// Plugin version as SemVer (e.g. `3.2.0`). Overrides FFI metadata.
    #[arg(long)]
    pub version: Option<String>,

    /// Publisher identity whose key will sign the release.
    #[arg(long)]
    pub publisher: String,

    /// Path to the publisher's PGP secret-key file (`.asc`).
    #[arg(long)]
    pub signing_key: PathBuf,

    /// Registry git URL the output is destined for.
    #[arg(long, default_value = "git@github.com:confium/registry.git")]
    pub registry: String,

    /// URL prefix where the artifact will be hosted. The artifact
    /// basename is appended to form `[artifact].url`.
    #[arg(long)]
    pub artifact_base: Option<String>,

    /// Override the `[interfaces]` map (e.g. `hash:0,rng:0`). Skips the
    /// FFI query when present.
    #[arg(long, value_delimiter = ',')]
    pub interfaces: Option<Vec<String>>,

    /// Override the `[algorithms]` map (e.g. `hash:SHA-256;SHA-512`).
    #[arg(long, value_delimiter = ',')]
    pub algorithms: Option<Vec<String>>,

    /// Print the planned actions and output tree without writing to disk
    /// or invoking `gpg`.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

/// Parse `--interfaces name:ver,name:ver` into an ordered list of
/// `(name, version)` pairs. Used by `load` when the FFI query is
/// bypassed.
pub fn parse_interface_overrides(raw: &[String]) -> Result<Vec<(String, u8)>, String> {
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let (name, ver) = entry
            .split_once(':')
            .ok_or_else(|| format!("interface '{entry}' missing ':version'"))?;
        let version: u8 = ver
            .parse()
            .map_err(|_| format!("interface '{name}' version '{ver}' not a u8"))?;
        out.push((name.to_string(), version));
    }
    Ok(out)
}

/// Parse `--algorithms iface:a1;a2,iface:b1` into an ordered list of
/// `(interface, [algorithm, ...])` pairs.
pub fn parse_algorithm_overrides(raw: &[String]) -> Result<Vec<(String, Vec<String>)>, String> {
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let (iface, algos) = entry
            .split_once(':')
            .ok_or_else(|| format!("algorithm '{entry}' missing ':list'"))?;
        let list: Vec<String> = algos.split(';').map(str::to_string).collect();
        out.push((iface.to_string(), list));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_interface_overrides_splits_name_version() {
        let raw = vec!["hash:0".to_string(), "aead:1".to_string()];
        let got = parse_interface_overrides(&raw).unwrap();
        assert_eq!(got, vec![("hash".into(), 0), ("aead".into(), 1)]);
    }

    #[test]
    fn parse_interface_overrides_rejects_missing_colon() {
        let raw = vec!["hash".to_string()];
        assert!(parse_interface_overrides(&raw).is_err());
    }

    #[test]
    fn parse_algorithm_overrides_splits_semicolons() {
        let raw = vec!["hash:SHA-256;SHA-512".to_string()];
        let got = parse_algorithm_overrides(&raw).unwrap();
        assert_eq!(
            got,
            vec![("hash".into(), vec!["SHA-256".into(), "SHA-512".into()])]
        );
    }
}
