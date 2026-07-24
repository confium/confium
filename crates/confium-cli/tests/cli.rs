// Integration test: `confium version` produces version output.
//
// Spawns `cargo run -- version` (the standard way to exercise a workspace
// binary from a test). Asserts the process succeeds and that stdout
// contains the CLI's version, derived from `CARGO_PKG_VERSION` of the
// `confium-cli` package.

use std::process::Command;

#[test]
fn version_subcommand_prints_version_string() {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--", "version"])
        .output()
        .expect("failed to spawn `cargo run -- version`");

    assert!(
        output.status.success(),
        "`confium version` did not exit successfully: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected_version = env!("CARGO_PKG_VERSION");
    let expected_line = format!("confium {expected_version}");
    assert!(
        stdout.contains(&expected_line),
        "expected stdout to contain {expected_line:?}, got: {stdout:?}",
    );
}

#[test]
fn unknown_subcommand_exits_nonzero() {
    // clap rejects unknown subcommands with exit code 2 and a usage error.
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--", "definitely-not-a-subcommand"])
        .output()
        .expect("failed to spawn `cargo run`");

    assert!(
        !output.status.success(),
        "unknown subcommand should fail, but exited successfully",
    );
}
