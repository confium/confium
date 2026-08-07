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
    /// Verify a certificate chain (leaf + intermediates + anchor).
    Verify(PkiVerifyArgs),
    /// Composite sign — sign a message with classical + PQ keys (demo
    /// uses Ed25519 + ECDSA-P256; full PQ composite lands with ML-DSA).
    CompositeSign(PkiCompositeSignArgs),
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

#[derive(Args, Debug)]
pub struct PkiVerifyArgs {
    /// Leaf cert (end-entity).
    #[arg(long)]
    pub leaf: std::path::PathBuf,
    /// Anchor cert (root CA).
    #[arg(long)]
    pub anchor: std::path::PathBuf,
    /// Intermediate certs, leaf-adjacent first. Repeat the flag for
    /// multiple intermediates.
    #[arg(long = "intermediate")]
    pub intermediates: Vec<std::path::PathBuf>,
    /// Format for all certs: der or pem.
    #[arg(long, default_value = "der")]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct PkiCompositeSignArgs {
    /// Message to sign. Use @file to read from a file.
    #[arg(long)]
    pub message: String,
    /// Ed25519 signing key (32 bytes raw, hex-encoded in file).
    #[arg(long)]
    pub ed25519_key: std::path::PathBuf,
    /// ECDSA-P256 signing key (DER-encoded, PEM or raw bytes).
    #[arg(long)]
    pub p256_key: std::path::PathBuf,
    /// Write composite signature bytes here (hex).
    #[arg(long)]
    pub out: Option<std::path::PathBuf>,
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
    /// Compute the intersection of two sets (ECDH-PSI variant:
    /// hash-based, demo only — uses a salt instead of true ECDH).
    Psi(PrivacyPsiArgs),
    /// Apply Laplace DP noise to a query result.
    Dp(PrivacyDpArgs),
    /// Run a MPC computation (placeholder; needs multi-process setup).
    Mpc,
}

#[derive(Args, Debug)]
pub struct PrivacyPsiArgs {
    /// First set file (one entry per line).
    #[arg(long)]
    pub set_a: std::path::PathBuf,
    /// Second set file (one entry per line).
    #[arg(long)]
    pub set_b: std::path::PathBuf,
    /// Salt file (raw bytes) for hash blinding.
    #[arg(long, default_value = "/dev/urandom")]
    pub salt: std::path::PathBuf,
    /// Report only the cardinality of the intersection, not the elements.
    #[arg(long)]
    pub cardinality_only: bool,
}

#[derive(Args, Debug)]
pub struct PrivacyDpArgs {
    /// True query result to perturb.
    #[arg(long)]
    pub value: f64,
    /// Sensitivity of the query (how much one record can move the result).
    #[arg(long)]
    pub sensitivity: f64,
    /// Privacy budget ε. Smaller = more private, more noise.
    #[arg(long)]
    pub epsilon: f64,
    /// Noise distribution: laplace or gaussian.
    #[arg(long, default_value = "laplace")]
    pub distribution: String,
    /// δ for gaussian distribution. Ignored for laplace.
    #[arg(long, default_value = "0.00001")]
    pub delta: f64,
}

/// Subcommands under `confium verify`.
#[derive(Subcommand, Debug)]
pub enum VerifyCommand {
    /// Show version and component crate info.
    Version,
    /// Verify a composite signature (COSE-encoded bytes).
    Composite(VerifyCompositeArgs),
    /// Verify a transparency inclusion proof.
    Inclusion(VerifyInclusionArgs),
    /// Verify a certificate chain (leaf + intermediates + anchor).
    CertChain(VerifyCertChainArgs),
}

#[derive(Args, Debug)]
pub struct VerifyCompositeArgs {
    /// Message that was signed (use @file for file contents).
    #[arg(long)]
    pub message: String,
    /// Composite signature file (raw COSE bytes).
    #[arg(long)]
    pub signature: std::path::PathBuf,
    /// Algorithm name (ed25519 or ecdsa-p256).
    #[arg(long)]
    pub algorithm: String,
    /// Public key file (raw bytes).
    #[arg(long)]
    pub public_key: std::path::PathBuf,
}

#[derive(Args, Debug)]
pub struct VerifyInclusionArgs {
    /// Proof JSON file (from `transparency prove`).
    #[arg(long)]
    pub proof: std::path::PathBuf,
    /// Entry JSON file (the leaf being proven).
    #[arg(long)]
    pub entry: std::path::PathBuf,
}

#[derive(Args, Debug)]
pub struct VerifyCertChainArgs {
    /// Leaf cert (end-entity).
    #[arg(long)]
    pub leaf: std::path::PathBuf,
    /// Anchor cert (root CA).
    #[arg(long)]
    pub anchor: std::path::PathBuf,
    /// Intermediate certs, leaf-adjacent first. Repeat for multiple.
    #[arg(long = "intermediate")]
    pub intermediates: Vec<std::path::PathBuf>,
    /// Format for all certs: der or pem.
    #[arg(long, default_value = "der")]
    pub format: String,
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
