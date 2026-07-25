// Integration tests for the `confium` CLI sub-commands.
//
// These spawn the compiled binary (via `cargo run --quiet`) so the
// `CONFium_HOME` / `CONFium_REGISTRY_DIR` env vars take effect in the
// child process. Each test owns a fresh tempdir so there's no shared
// state.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

/// Run the CLI binary with the given home + (optional) registry dir,
/// returning (status, stdout, stderr).
fn run(
    home: &PathBuf,
    registry_dir: Option<&PathBuf>,
    args: &[&str],
) -> (std::process::ExitStatus, String, String) {
    let mut cmd = Command::new("cargo");
    cmd.arg("run").arg("--quiet").arg("--");
    // SAFETY: we set env vars on the child Command only, not the
    // process environment. This is sound.
    cmd.env("CONFium_HOME", home);
    if let Some(dir) = registry_dir {
        cmd.env("CONFium_REGISTRY_DIR", dir);
    }
    for a in args {
        cmd.arg(a);
    }
    let output = cmd.output().expect("failed to spawn `cargo run`");
    (
        output.status,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Materialise a minimal registry site (index.toml, per-plugin index,
/// one manifest) into `dir`. Mirrors the layout in `sites/registry/`.
fn write_registry_site(dir: &Path) {
    use std::fs;
    fs::create_dir_all(dir.join("plugins/botan/3.2.0")).unwrap();
    fs::write(
        dir.join("index.toml"),
        r#"
[[plugin]]
name = "botan"
latest = "3.2.0"
description = "Botan crypto provider plugin"
publishers = ["ribose"]
versions-url = "/plugins/botan/index.toml"
"#,
    )
    .unwrap();
    fs::write(
        dir.join("plugins/botan/index.toml"),
        r#"
name = "botan"
latest = "3.2.0"
description = "Botan crypto provider plugin"

[[version]]
version = "3.2.0"
manifest-url = "/plugins/botan/3.2.0/manifest.toml"
"#,
    )
    .unwrap();
    fs::write(
        dir.join("plugins/botan/3.2.0/manifest.toml"),
        r#"
[plugin]
name = "botan"
version = "3.2.0"
publisher = "ribose"
license = "BSD-2-Clause"
homepage = "https://botan.randombit.net"

[interfaces]
hash = 0
aead = 0

[algorithms]
hash = ["SHA-256", "SHA-512"]
aead = ["AES-256-GCM"]

[artifact]
url = "https://example.test/botan.so"
size = 0
sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
"#,
    )
    .unwrap();
}

#[test]
fn list_on_empty_plugin_dir_says_no_plugins() {
    let home = TempDir::new().unwrap();
    let (status, stdout, _stderr) = run(&home.path().to_path_buf(), None, &["list"]);
    assert!(
        status.success(),
        "`confium list` should succeed on empty dir"
    );
    assert!(
        stdout.contains("no plugins installed"),
        "expected empty-state message, got: {stdout:?}"
    );
}

#[test]
fn trust_list_on_empty_store_says_no_trusted() {
    let home = TempDir::new().unwrap();
    let (status, stdout, _stderr) = run(&home.path().to_path_buf(), None, &["trust", "list"]);
    assert!(
        status.success(),
        "`confium trust list` should succeed on empty store"
    );
    assert!(
        stdout.contains("no trusted publishers"),
        "expected empty trust-store message, got: {stdout:?}"
    );
}

#[test]
fn trust_add_then_list_shows_publisher() {
    let home = TempDir::new().unwrap();
    let home = home.path().to_path_buf();
    let (status, _, stderr) = run(
        &home,
        None,
        &["trust", "add", "ribose", "--key", "E73B0000B13F"],
    );
    assert!(
        status.success(),
        "`confium trust add` should succeed: {stderr}"
    );
    let (status, stdout, _stderr) = run(&home, None, &["trust", "list"]);
    assert!(status.success(), "`confium trust list` should succeed");
    assert!(
        stdout.contains("ribose"),
        "trusted publisher list should include ribose: {stdout:?}"
    );
}

#[test]
fn trust_remove_unknown_exits_nonzero() {
    let home = TempDir::new().unwrap();
    let (status, _stdout, stderr) = run(
        &home.path().to_path_buf(),
        None,
        &["trust", "remove", "ghost"],
    );
    assert!(
        !status.success(),
        "removing an unknown publisher should fail"
    );
    assert!(
        stderr.contains("not trusted"),
        "expected a not-trusted message, got: {stderr:?}"
    );
}

#[test]
fn remove_unknown_plugin_exits_nonzero() {
    let home = TempDir::new().unwrap();
    let (status, _stdout, stderr) = run(&home.path().to_path_buf(), None, &["remove", "ghost"]);
    assert!(!status.success(), "removing an unknown plugin should fail");
    assert!(
        stderr.contains("not installed"),
        "expected a not-installed message, got: {stderr:?}"
    );
}

#[test]
fn config_set_get_round_trip() {
    let home = TempDir::new().unwrap();
    let home = home.path().to_path_buf();
    let (status, _, stderr) = run(
        &home,
        None,
        &["config", "set", "registry.default", "https://x.test"],
    );
    assert!(status.success(), "`config set` should succeed: {stderr}");
    let (status, stdout, _stderr) = run(&home, None, &["config", "get", "registry.default"]);
    assert!(status.success(), "`config get` should succeed");
    assert!(
        stdout.contains("https://x.test"),
        "expected the value back, got: {stdout:?}"
    );
}

#[test]
fn config_get_unset_key_exits_nonzero() {
    let home = TempDir::new().unwrap();
    let (status, _stdout, stderr) = run(
        &home.path().to_path_buf(),
        None,
        &["config", "get", "registry.default"],
    );
    assert!(!status.success(), "getting an unset key should fail");
    assert!(
        stderr.contains("not set"),
        "expected a not-set message, got: {stderr:?}"
    );
}

#[test]
fn config_show_on_empty_dir_shows_placeholder() {
    let home = TempDir::new().unwrap();
    let (status, stdout, _stderr) = run(&home.path().to_path_buf(), None, &["config", "show"]);
    assert!(status.success(), "`config show` should succeed on empty");
    assert!(
        stdout.contains("no configuration"),
        "expected empty-config placeholder, got: {stdout:?}"
    );
}

#[test]
fn search_with_registry_dir_lists_matching_plugins() {
    let registry = TempDir::new().unwrap();
    let registry = registry.path().to_path_buf();
    write_registry_site(&registry);

    let home = TempDir::new().unwrap();
    let (status, stdout, _stderr) = run(
        &home.path().to_path_buf(),
        Some(&registry),
        &["search", "hash"],
    );
    assert!(status.success(), "`confium search hash` should succeed");
    assert!(
        stdout.contains("botan"),
        "search should list botan: {stdout:?}"
    );
}

#[test]
fn search_filters_by_algorithm() {
    let registry = TempDir::new().unwrap();
    let registry = registry.path().to_path_buf();
    write_registry_site(&registry);

    let home = TempDir::new().unwrap();
    let (status, stdout, _stderr) = run(
        &home.path().to_path_buf(),
        Some(&registry),
        &["search", "hash", "SHA-256"],
    );
    assert!(
        status.success(),
        "`confium search hash SHA-256` should succeed"
    );
    assert!(
        stdout.contains("botan"),
        "search by algo should list botan: {stdout:?}"
    );

    // An algorithm nobody implements -> no matches.
    let (status, stdout, _stderr) = run(
        &home.path().to_path_buf(),
        Some(&registry),
        &["search", "hash", "DEFINITELY-NOT-AN-ALGO"],
    );
    assert!(status.success());
    assert!(
        stdout.contains("no plugins match"),
        "expected no-match message, got: {stdout:?}"
    );
}

#[test]
fn info_reads_from_registry_when_version_pinned() {
    let registry = TempDir::new().unwrap();
    let registry = registry.path().to_path_buf();
    write_registry_site(&registry);

    let home = TempDir::new().unwrap();
    let (status, stdout, stderr) = run(
        &home.path().to_path_buf(),
        Some(&registry),
        &["info", "botan@3.2.0"],
    );
    assert!(
        status.success(),
        "`confium info botan@3.2.0` should succeed: {stderr}"
    );
    assert!(
        stdout.contains("botan"),
        "info output should mention botan: {stdout:?}"
    );
    assert!(
        stdout.contains("3.2.0"),
        "info output should mention version: {stdout:?}"
    );
    assert!(
        stdout.contains("ribose"),
        "info output should mention publisher: {stdout:?}"
    );
}

#[test]
fn update_with_no_plugins_says_so() {
    let home = TempDir::new().unwrap();
    let (status, stdout, _stderr) = run(&home.path().to_path_buf(), None, &["update"]);
    assert!(status.success(), "`confium update` on empty should succeed");
    assert!(
        stdout.contains("no plugins installed"),
        "expected empty message, got: {stdout:?}"
    );
}

#[test]
fn version_subcommand_still_works() {
    let home = TempDir::new().unwrap();
    let (status, stdout, _stderr) = run(&home.path().to_path_buf(), None, &["version"]);
    assert!(status.success(), "`confium version` should succeed");
    let expected = env!("CARGO_PKG_VERSION");
    assert!(
        stdout.contains(&format!("confium {expected}")),
        "expected version line, got: {stdout:?}"
    );
}

#[test]
fn unknown_subcommand_exits_nonzero() {
    // clap rejects unknown subcommands with exit code 2 and a usage
    // error. Kept from the original scaffold test.
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--", "definitely-not-a-subcommand"])
        .output()
        .expect("failed to spawn `cargo run`");
    assert!(
        !output.status.success(),
        "unknown subcommand should fail, but exited successfully",
    );
}
