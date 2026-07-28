// Write the registry-ready directory tree for a published version.
//
//
//     <plugin>/<version>/
//       manifest.toml          # serialized manifest
//       artifact.sha256        # "<hex>  <basename>"
//       sigs/
//         <publisher>.asc      # detached PGP signature
//
// This module also computes the artifact SHA-256, which both the
// `artifact.sha256` file and the `[artifact].sha256` manifest field
// reference. Hashing lives here (next to the file that consumes it)
// rather than in `manifest.rs` so the manifest builder stays a pure
// function of resolved inputs.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use snafu::{ResultExt, Snafu};

#[derive(Snafu, Debug)]
pub enum OutputError {
    #[snafu(display("failed to read artifact at '{}'", path.display()))]
    ReadArtifact { path: Box<Path>, source: io::Error },

    #[snafu(display("failed to create output directory '{}'", path.display()))]
    Mkdir { path: Box<Path>, source: io::Error },

    #[snafu(display("failed to write '{}'", path.display()))]
    WriteFile { path: Box<Path>, source: io::Error },
}

pub type Result<T> = std::result::Result<T, OutputError>;

/// Compute the lowercase-hex SHA-256 of a file, reading in chunks so
/// large artifacts don't need to fit in memory.
pub fn sha256_of_file(path: &Path) -> Result<String> {
    let path_boxed: Box<Path> = Box::from(path);
    let mut file = fs::File::open(path_boxed.as_ref()).context(ReadArtifactSnafu {
        path: path_boxed.clone(),
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).context(ReadArtifactSnafu {
            path: path_boxed.clone(),
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Where each emitted file lives under the output root.
pub struct OutputPaths {
    pub dir: PathBuf,
    pub manifest: PathBuf,
    pub artifact_sha256: PathBuf,
    pub sigs_dir: PathBuf,
    pub signature: PathBuf,
}

/// Resolve the paths for `<root>/<plugin>/<version>/...`.
pub fn paths_for(root: &Path, plugin: &str, version: &str, publisher: &str) -> OutputPaths {
    let dir = root.join(plugin).join(version);
    let sigs_dir = dir.join("sigs");
    OutputPaths {
        manifest: dir.join("manifest.toml"),
        artifact_sha256: dir.join("artifact.sha256"),
        signature: sigs_dir.join(format!("{publisher}.asc")),
        dir,
        sigs_dir,
    }
}

/// Write the full tree atomically-ish: create dirs, then write each file.
/// Returns the manifest bytes written (for signing). When `dry_run` is
/// true, no filesystem writes occur and an empty `Vec` is returned.
pub fn write_tree(
    paths: &OutputPaths,
    manifest_toml: &str,
    artifact_path: &Path,
    sha256_hex: &str,
    signature: &[u8],
    dry_run: bool,
) -> Result<Vec<u8>> {
    let manifest_bytes = manifest_toml.as_bytes();

    if dry_run {
        return Ok(Vec::new());
    }

    let dir_boxed: Box<Path> = Box::from(paths.dir.as_path());
    fs::create_dir_all(dir_boxed.as_ref()).context(MkdirSnafu {
        path: dir_boxed.clone(),
    })?;
    let sigs_boxed: Box<Path> = Box::from(paths.sigs_dir.as_path());
    fs::create_dir_all(sigs_boxed.as_ref()).context(MkdirSnafu {
        path: sigs_boxed.clone(),
    })?;

    let manifest_boxed: Box<Path> = Box::from(paths.manifest.as_path());
    fs::write(manifest_boxed.as_ref(), manifest_bytes).context(WriteFileSnafu {
        path: manifest_boxed.clone(),
    })?;

    let basename = artifact_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "artifact".to_string());
    let sha_line = format!("{sha256_hex}  {basename}\n");
    let sha_boxed: Box<Path> = Box::from(paths.artifact_sha256.as_path());
    fs::write(sha_boxed.as_ref(), sha_line).context(WriteFileSnafu {
        path: sha_boxed.clone(),
    })?;

    let sig_boxed: Box<Path> = Box::from(paths.signature.as_path());
    fs::write(sig_boxed.as_ref(), signature).context(WriteFileSnafu {
        path: sig_boxed.clone(),
    })?;

    Ok(manifest_bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_file_matches_known_digest() {
        let tmp = std::env::temp_dir().join("cfm_publish_test_empty");
        fs::write(&tmp, b"").unwrap();
        let got = sha256_of_file(&tmp).unwrap();
        let _ = fs::remove_file(&tmp);
        // SHA-256 of the empty string.
        assert_eq!(
            got,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_of_known_bytes_matches_shasum() {
        // "abc" -> SHA-256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let tmp = std::env::temp_dir().join("cfm_publish_test_abc");
        fs::write(&tmp, b"abc").unwrap();
        let got = sha256_of_file(&tmp).unwrap();
        let _ = fs::remove_file(&tmp);
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn write_tree_creates_all_files() {
        let root = std::env::temp_dir().join("cfm_publish_tree_test");
        let _ = fs::remove_dir_all(&root);
        let paths = paths_for(&root, "plug", "1.0.0", "pub");
        let artifact = std::env::temp_dir().join("cfm_publish_tree_artifact");
        fs::write(&artifact, b"payload").unwrap();
        write_tree(
            &paths,
            "[plugin]\nname=\"x\"\n",
            &artifact,
            "deadbeef",
            b"SIG",
            false,
        )
        .unwrap();
        assert!(paths.dir.is_dir());
        assert!(paths.manifest.is_file());
        assert!(paths.artifact_sha256.is_file());
        assert!(paths.signature.is_file());
        let sha_content = fs::read_to_string(&paths.artifact_sha256).unwrap();
        assert!(sha_content.contains("deadbeef"));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&artifact);
    }

    #[test]
    fn dry_run_writes_nothing() {
        let root = std::env::temp_dir().join("cfm_publish_dryrun_test");
        let _ = fs::remove_dir_all(&root);
        let paths = paths_for(&root, "plug", "1.0.0", "pub");
        let artifact = std::env::temp_dir().join("cfm_publish_dryrun_art");
        fs::write(&artifact, b"x").unwrap();
        let bytes = write_tree(&paths, "[plugin]\n", &artifact, "aa", b"s", true).unwrap();
        assert!(bytes.is_empty());
        assert!(!paths.dir.exists());
        let _ = fs::remove_file(&artifact);
    }
}
