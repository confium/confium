// Clap-derived argument definitions for the `confium` command-line tool.
//
// The top-level `Cli` struct holds the parsed subcommand enum `Commands`.
// Each variant maps to a `*Args` struct in this file. Command
// implementations live in `commands::*` and are dispatched from `main`.
//

use clap::{Args, Parser, Subcommand};

/// Entry point for argument parsing.
///
/// `clap` derives `--help` and `--version` from the `Parser` derive. The
/// `name`, `version`, and `about` attributes shape the generated help text.
#[derive(Parser, Debug)]
#[command(
    name = "confium",
    version,
    about = "Confium trust store framework",
    long_about = "Confium trust store framework — install and manage cryptographic plugins.",
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level subcommands of `confium`.
///
/// Variants map one-to-one onto the command files under `commands/`. New
/// subcommands are added by appending a variant here, adding a matching
/// `*Args` struct, and a `commands/<name>.rs` module — no existing command
/// needs to change (Open/Closed Principle).
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Install a plugin from the registry.
    Install(InstallArgs),
    /// Uninstall a plugin.
    Remove(RemoveArgs),
    /// Update plugin(s) to the latest version.
    Update(UpdateArgs),
    /// List installed plugins.
    List(ListArgs),
    /// Show plugin manifest details.
    Info(InfoArgs),
    /// Search the registry index.
    Search(SearchArgs),
    /// Manage publisher trust roots.
    Trust(TrustArgs),
    /// Edit local configuration.
    Config(ConfigArgs),
    /// Show version and crate info.
    Version,
}

/// `confium install <plugin>[@version]`
#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Plugin to install, optionally pinned with `@<version>`.
    pub plugin: String,
}

/// `confium remove <plugin>`
#[derive(Args, Debug)]
pub struct RemoveArgs {
    /// Plugin to uninstall.
    pub plugin: String,
}

/// `confium update [<plugin>]`
#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// Plugin to update. Omit to update all installed plugins.
    pub plugin: Option<String>,
}

/// `confium list`
#[derive(Args, Debug)]
pub struct ListArgs {}

/// `confium info <plugin>[@version]`
#[derive(Args, Debug)]
pub struct InfoArgs {
    /// Plugin (optionally version-pinned) to inspect.
    pub plugin: String,
}

/// `confium search [<interface>] [<algorithm>]`
#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Crypto interface to filter on (e.g. `aead`, `hash`, `cipher`).
    pub interface: Option<String>,
    /// Algorithm to filter on (e.g. `SHA-256`, `AES-256`).
    pub algorithm: Option<String>,
}

/// `confium trust <subcommand>`
///
/// `trust` is itself a subcommand group. The inner enum selects the
/// action; each variant carries the arguments it needs.
#[derive(Args, Debug)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub action: TrustAction,
}

/// Sub-actions of `confium trust`.
#[derive(Subcommand, Debug)]
pub enum TrustAction {
    /// List trusted publishers.
    List,
    /// Trust a publisher (adds their pubkey to the local store).
    Add(TrustAddArgs),
    /// Remove trust for a publisher.
    Remove(TrustRemoveArgs),
}

/// `confium trust add <publisher> [--key <key>]`
#[derive(Args, Debug)]
pub struct TrustAddArgs {
    /// Publisher name to trust.
    pub publisher: String,
    /// Publisher's public key (hex fingerprint or path to key file).
    #[arg(long)]
    pub key: Option<String>,
}

/// `confium trust remove <publisher>`
#[derive(Args, Debug)]
pub struct TrustRemoveArgs {
    /// Publisher name to stop trusting.
    pub publisher: String,
}

/// `confium config <subcommand>`
///
/// `config` is a subcommand group mirroring `trust`.
#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

/// Sub-actions of `confium config`.
#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Open the config file in `$EDITOR`.
    Edit,
    /// Print the effective configuration.
    Show,
    /// Set a configuration value.
    Set(ConfigSetArgs),
    /// Get a configuration value.
    Get(ConfigGetArgs),
}

/// `confium config set <key> <value>`
#[derive(Args, Debug)]
pub struct ConfigSetArgs {
    /// Dotted config key (e.g. `registry.default`).
    pub key: String,
    /// Value to assign.
    pub value: String,
}

/// `confium config get <key>`
#[derive(Args, Debug)]
pub struct ConfigGetArgs {
    /// Dotted config key to read.
    pub key: String,
}
