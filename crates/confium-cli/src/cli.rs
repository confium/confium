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

    // Product-umbrella subcommands. Each routes to the product's own
    // subcommand enum and dispatch module. Adding a new product = adding
    // a variant here + a new module in commands/ + a Subcommand enum.
    /// Threshold signing operations (DKG, sign, refresh, recover).
    #[command(name = "threshold", subcommand)]
    Threshold(ThresholdCommand),

    /// Transparency log operations (append, prove, verify, serve).
    #[command(name = "transparency", subcommand)]
    Transparency(TransparencyCommand),

    /// PKI operations (issue, verify, composite sign).
    #[command(name = "pki", subcommand)]
    Pki(PkiCommand),

    /// Keyless signing operations (sign, verify, configure).
    #[command(name = "keyless", subcommand)]
    Keyless(KeylessCommand),

    /// Privacy primitives (psi, mpc, dp, ring-sig).
    #[command(name = "privacy", subcommand)]
    Privacy(PrivacyCommand),

    /// Verification operations (composite, inclusion, cert-chain).
    #[command(name = "verify", subcommand)]
    Verify(VerifyCommand),
}

/// Subcommands under `confium threshold`.
#[derive(Subcommand, Debug)]
pub enum ThresholdCommand {
    /// Show version and component crate info.
    Version,
    /// Threshold DKG. Generates N shares for a T-of-N key. Output is a
    /// JSON envelope written to --out (default: stdout).
    Dkg(ThresholdDkgArgs),
    /// Threshold sign. Reads shares from --shares and signs --message;
    /// writes the signature to --out (default: stdout, hex).
    Sign(ThresholdSignArgs),
}

/// `confium threshold dkg`
#[derive(Args, Debug)]
pub struct ThresholdDkgArgs {
    /// Threshold scheme: cmp20, gg18.
    #[arg(long, default_value = "cmp20")]
    pub scheme: String,
    /// Quorum size (T in T-of-N).
    #[arg(long)]
    pub threshold: u32,
    /// Total number of parties (N in T-of-N).
    #[arg(long)]
    pub parties: u32,
    /// Write output here instead of stdout.
    #[arg(long)]
    pub out: Option<std::path::PathBuf>,
}

/// `confium threshold sign`
#[derive(Args, Debug)]
pub struct ThresholdSignArgs {
    /// Path to the share envelope (JSON written by `threshold dkg`).
    #[arg(long)]
    pub shares: std::path::PathBuf,
    /// Message to sign. Use @file to read from a file; otherwise the
    /// literal string is signed.
    #[arg(long)]
    pub message: String,
    /// Write signature here (DER-encoded hex) instead of stdout.
    #[arg(long)]
    pub out: Option<std::path::PathBuf>,
}

/// Subcommands under `confium transparency`.
#[derive(Subcommand, Debug)]
pub enum TransparencyCommand {
    /// Show version and component crate info.
    Version,
    /// Append an artifact hash to the log. Returns the sequence number.
    Append(TransparencyAppendArgs),
    /// Generate an inclusion proof for a sequence number.
    Prove(TransparencyProveArgs),
    /// Verify an inclusion proof against a tree head.
    Verify(TransparencyVerifyArgs),
}

#[derive(Args, Debug)]
pub struct TransparencyAppendArgs {
    /// Path to the log database file.
    #[arg(long, default_value = "./transparency.db")]
    pub db: std::path::PathBuf,
    /// Artifact hash to append (e.g. "sha256:abc...").
    #[arg(long)]
    pub artifact_hash: String,
}

#[derive(Args, Debug)]
pub struct TransparencyProveArgs {
    #[arg(long, default_value = "./transparency.db")]
    pub db: std::path::PathBuf,
    /// Sequence number to prove inclusion for.
    #[arg(long)]
    pub seq: usize,
    /// Write proof JSON here.
    #[arg(long)]
    pub out: Option<std::path::PathBuf>,
}

#[derive(Args, Debug)]
pub struct TransparencyVerifyArgs {
    /// Proof JSON file.
    #[arg(long)]
    pub proof: std::path::PathBuf,
    /// Tree head JSON file.
    #[arg(long)]
    pub head: std::path::PathBuf,
}

/// Subcommands under `confium pki`.
#[derive(Subcommand, Debug)]
pub enum PkiCommand {
    /// Show version and component crate info.
    Version,
    /// Parse an X.509 cert (DER or PEM).
    ParseCert(PkiParseCertArgs),
    /// Composite sign (placeholder; full impl with composite crate TBD).
    CompositeSign,
    /// Verify a cert chain (placeholder; full impl TBD).
    Verify,
}

#[derive(Args, Debug)]
pub struct PkiParseCertArgs {
    /// Cert file path.
    #[arg(long)]
    pub cert: std::path::PathBuf,
    /// Format: der or pem.
    #[arg(long, default_value = "der")]
    pub format: String,
}

/// Subcommands under `confium keyless`.
#[derive(Subcommand, Debug)]
pub enum KeylessCommand {
    /// Show version and component crate info.
    Version,
    /// Keyless sign (placeholder; requires OIDC + threshold CA infra).
    Sign,
    /// Verify a keyless signature (placeholder).
    Verify,
}

/// Subcommands under `confium privacy`.
#[derive(Subcommand, Debug)]
pub enum PrivacyCommand {
    /// Show version and component crate info.
    Version,
    /// Run a two-party PSI (placeholder; full impl TBD).
    Psi,
    /// Run a MPC computation (placeholder).
    Mpc,
    /// Apply differential privacy to a query (placeholder).
    Dp,
}

/// Subcommands under `confium verify`.
#[derive(Subcommand, Debug)]
pub enum VerifyCommand {
    /// Show version and component crate info.
    Version,
    /// Verify a composite signature (placeholder).
    Composite,
    /// Verify a transparency inclusion proof (placeholder).
    Inclusion,
    /// Verify a certificate chain (placeholder).
    CertChain,
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
