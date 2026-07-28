// PGP signing of the generated manifest.
//
// detached ASCII-armored PGP signatures stored under `sigs/<publisher>.asc`.
// We shell out to the system `gpg` rather than embedding a crypto
// library: the publish ceremony already trusts the author's local GPG
// keyring, and shelling avoids pulling PGP into the Confium binary
// dependency surface.

use std::path::Path;
use std::process::Command;

use snafu::{ResultExt, Snafu};

#[derive(Snafu, Debug)]
pub enum SignError {
    #[snafu(display("gpg not found on PATH; install GnuPG to sign releases"))]
    GpgMissing { source: std::io::Error },

    #[snafu(display(
        "gpg exited with status {exit_code} while signing {}\nstderr: {stderr}",
        manifest_path.display()
    ))]
    GpgFailed {
        exit_code: i32,
        stderr: String,
        manifest_path: Box<Path>,
    },
}

pub type Result<T> = std::result::Result<T, SignError>;

/// Sign the manifest at `manifest_path` with the publisher's key,
/// returning the detached ASCII-armored signature bytes.
///
/// `signing_key` is passed to `gpg --local-user`. It may be a key-id,
/// fingerprint, or path to a key file that gpg knows how to resolve.
/// When `dry_run` is true, returns a placeholder signature string
/// without invoking gpg or touching disk.
pub fn sign_manifest(manifest_path: &Path, signing_key: &str, dry_run: bool) -> Result<Vec<u8>> {
    if dry_run {
        return Ok(
            b"-----BEGIN PGP SIGNATURE-----\n[dry-run placeholder]\n-----END PGP SIGNATURE-----\n"
                .to_vec(),
        );
    }

    let output = Command::new("gpg")
        .args([
            "--detach-sign",
            "--armor",
            "--batch",
            "--yes",
            "--local-user",
            signing_key,
            "--output",
            "-", // stream signature to stdout
        ])
        .arg(manifest_path)
        .output()
        .context(GpgMissingSnafu)?;

    if !output.status.success() {
        let manifest_path_boxed: Box<Path> = Box::from(manifest_path);
        return GpgFailedSnafu {
            exit_code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            manifest_path: manifest_path_boxed,
        }
        .fail();
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_returns_placeholder_without_gpg() {
        let got = sign_manifest(std::path::Path::new("/nonexistent"), "key", true).unwrap();
        let s = String::from_utf8(got).unwrap();
        assert!(s.contains("BEGIN PGP SIGNATURE"));
        assert!(s.contains("dry-run placeholder"));
    }
}
