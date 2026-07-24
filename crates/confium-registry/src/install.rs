//! Install + local-plugin management.
//!
//! [`install`] resolves a plugin against a [`crate::Client`], downloads
//! the artifact through a pluggable [`Downloader`] (so tests can inject
//! bytes), verifies the SHA-256, and writes the result to
//! [`crate::paths::plugin_install_dir`]. A copy of the manifest is
//! stashed alongside (`.manifest`) so `list`/`info`/`update` can read
//! metadata without re-hitting the registry.
//!
//! Local enumeration helpers ([`list_installed`], [`read_installed`],
//! [`remove`]) keep the file-layout knowledge in one place.

use std::path::{Path, PathBuf};

use crate::client::Client;
use crate::error::{Error, Result};
use crate::manifest::Manifest;
use crate::paths::{plugin_install_dir, plugins_dir};

/// Pluggable artifact transport, mirroring [`crate::client::Fetcher`]
/// but for the binary blob referenced by a manifest's `[artifact]` url.
///
/// The default implementation is a no-op stub: real HTTP downloads are
/// waiting on a network crate being wired through the workspace
/// (`confium-net`). Tests inject a [`MemoryDownloader`].
pub trait Downloader {
    fn download(&self, url: &str) -> Result<Vec<u8>>;
}

/// In-memory downloader keyed by URL.
#[derive(Default, Clone)]
pub struct MemoryDownloader {
    artifacts: std::collections::HashMap<String, Vec<u8>>,
}

impl MemoryDownloader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, url: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        self.artifacts.insert(url.into(), body.into());
        self
    }
}

impl Downloader for MemoryDownloader {
    fn download(&self, url: &str) -> Result<Vec<u8>> {
        self.artifacts
            .get(url)
            .cloned()
            .ok_or_else(|| Error::Download {
                message: format!("no artifact registered for {url}"),
            })
    }
}

/// A stub downloader that surfaces a typed "not yet implemented" for any
/// URL. Used by the CLI when no real transport is wired in yet.
pub struct NoopDownloader;

impl Downloader for NoopDownloader {
    fn download(&self, url: &str) -> Result<Vec<u8>> {
        Err(Error::Download {
            message: format!("network download not yet wired (confium-net pending); URL: {url}"),
        })
    }
}

/// The on-disk record for an installed plugin: the artifact path plus
/// the cached manifest.
#[derive(Debug, Clone)]
pub struct InstalledRecord {
    pub name: String,
    pub version: String,
    pub artifact_path: PathBuf,
    pub manifest: Manifest,
}

/// Install `name` at `version` (or latest when `None`).
///
/// `override_home` redirects the install location for tests; pass `None`
/// for real use. Returns the [`InstalledRecord`] for the newly installed
/// plugin.
pub fn install<F: crate::client::Fetcher, D: Downloader>(
    client: &Client<F>,
    downloader: &D,
    override_home: Option<&PathBuf>,
    name: &str,
    version: Option<&str>,
) -> Result<InstalledRecord> {
    let manifest = client.resolve(name, version)?;
    install_manifest(downloader, override_home, manifest)
}

/// Install a resolved manifest. Split out so `update` can reuse the path
/// after re-resolving.
pub fn install_manifest<D: Downloader>(
    downloader: &D,
    override_home: Option<&PathBuf>,
    manifest: Manifest,
) -> Result<InstalledRecord> {
    let name = manifest.plugin.name.clone();
    let version = manifest.plugin.version.clone();

    let bytes = downloader.download(&manifest.artifact.url)?;
    verify_sha256(&name, &version, &bytes, &manifest.artifact.sha256)?;

    let target = plugin_install_dir(override_home, &name, &version)?;
    ensure_parent(&target)?;

    write_bytes(&target, &bytes, "artifact")?;

    // Stash the manifest next to the artifact so `list`/`info`/`update`
    // can read metadata offline.
    let manifest_path = manifest_path(&target);
    let manifest_toml =
        toml::to_string_pretty(&manifest).map_err(|e| Error::TomlSerialize { source: e })?;
    write_str(&manifest_path, &manifest_toml, "manifest")?;

    Ok(InstalledRecord {
        name,
        version,
        artifact_path: target,
        manifest,
    })
}

/// Enumerate installed plugins by scanning the plugins directory for
/// `<name>-<version>.so` files with a sibling `.manifest`.
pub fn list_installed(override_home: Option<&PathBuf>) -> Result<Vec<InstalledRecord>> {
    let dir = plugins_dir(override_home)?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| Error::io(e, format!("failed to read {}", dir.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(e, "directory iteration error"))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("so") {
            continue;
        }
        let manifest_path = manifest_path(&path);
        if !manifest_path.exists() {
            continue;
        }
        if let Ok(record) = read_record(&path) {
            records.push(record);
        }
    }
    records.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
    Ok(records)
}

/// Read a previously installed plugin's record from its artifact path.
pub fn read_installed(
    override_home: Option<&PathBuf>,
    name: &str,
    version: &str,
) -> Result<InstalledRecord> {
    let path = plugin_install_dir(override_home, name, version)?;
    if !path.exists() {
        return Err(Error::NotInstalled {
            name: name.to_string(),
        });
    }
    read_record(&path)
}

/// Remove a plugin by name. Removes every installed version whose name
/// matches (there should only be one under the single-version-per-name
/// model, but this is forgiving).
pub fn remove(override_home: Option<&PathBuf>, name: &str) -> Result<()> {
    let installed = list_installed(override_home)?;
    let mut removed = 0;
    for record in installed {
        if record.name != name {
            continue;
        }
        let manifest_path = manifest_path(&record.artifact_path);
        let _ = std::fs::remove_file(&manifest_path);
        std::fs::remove_file(&record.artifact_path).map_err(|e| {
            Error::io(
                e,
                format!("failed to remove {}", record.artifact_path.display()),
            )
        })?;
        removed += 1;
    }
    if removed == 0 {
        return Err(Error::NotInstalled {
            name: name.to_string(),
        });
    }
    Ok(())
}

fn read_record(artifact_path: &Path) -> Result<InstalledRecord> {
    let manifest_path = manifest_path(artifact_path);
    let body = std::fs::read_to_string(&manifest_path)
        .map_err(|e| Error::io(e, format!("failed to read {}", manifest_path.display())))?;
    let manifest: Manifest = toml::from_str(&body).map_err(|e| Error::TomlParse {
        path: manifest_path.display().to_string(),
        source: e,
    })?;
    let (name, version) = parse_artifact_name(artifact_path).ok_or_else(|| {
        Error::io(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "bad artifact filename"),
            format!(
                "artifact filename {} is not <name>-<version>.so",
                artifact_path.display()
            ),
        )
    })?;
    Ok(InstalledRecord {
        name,
        version,
        artifact_path: artifact_path.to_path_buf(),
        manifest,
    })
}

fn parse_artifact_name(path: &Path) -> Option<(String, String)> {
    let stem = path.file_stem()?.to_str()?;
    let idx = stem.rfind('-')?;
    let name = stem[..idx].to_string();
    let version = stem[idx + 1..].to_string();
    Some((name, version))
}

fn manifest_path(artifact: &Path) -> PathBuf {
    let mut p = artifact.to_path_buf();
    p.set_extension("manifest");
    p
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::io(e, format!("failed to create {}", parent.display())))?;
    }
    Ok(())
}

fn write_bytes(path: &Path, bytes: &[u8], what: &str) -> Result<()> {
    std::fs::write(path, bytes)
        .map_err(|e| Error::io(e, format!("failed to write {what} to {}", path.display())))
}

fn write_str(path: &Path, body: &str, what: &str) -> Result<()> {
    std::fs::write(path, body)
        .map_err(|e| Error::io(e, format!("failed to write {what} to {}", path.display())))
}

fn verify_sha256(name: &str, version: &str, bytes: &[u8], expected: &str) -> Result<()> {
    use std::fmt::Write;
    let digest = sha256(bytes);
    let mut got = String::with_capacity(64);
    for b in digest {
        let _ = write!(&mut got, "{:02x}", b);
    }
    if got.eq_ignore_ascii_case(expected.trim()) {
        return Ok(());
    }
    Err(Error::HashMismatch {
        name: name.to_string(),
        version: version.to_string(),
        expected: expected.to_string(),
        actual: got,
    })
}

/// Minimal SHA-256 implementation.
///
/// We avoid pulling a crypto crate into `confium-registry` to keep the
/// dependency surface minimal; SHA-256 is a few hundred lines of pure
/// arithmetic and the implementation here is the public-domain
/// reference algorithm (FIPS 180-4). It is only used for artifact
/// integrity checking against a published digest — never for security
/// primitives, which live in `confium-core`'s plugins.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn empty_body_hash() -> String {
        // SHA-256 of b""
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()
    }

    fn manifest_for(name: &str, version: &str, sha: &str) -> Manifest {
        let manifest_toml = format!(
            r#"
[plugin]
name = "{name}"
version = "{version}"
publisher = "ribose"

[artifact]
url = "https://example.test/{name}.so"
size = 0
sha256 = "{sha}"
"#
        );
        toml::from_str(&manifest_toml).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        use std::fmt::Write;
        for b in bytes {
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }

    #[test]
    fn sha256_of_empty_matches_known_digest() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_of_abc() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn install_writes_artifact_and_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let home = PathBuf::from(tmp.path());
        let manifest = manifest_for("botan", "3.2.0", &empty_body_hash());
        let downloader = MemoryDownloader::new().with("https://example.test/botan.so", Vec::new());

        let record = install_manifest(&downloader, Some(&home), manifest).unwrap();
        assert!(record.artifact_path.exists());
        assert!(manifest_path(&record.artifact_path).exists());

        let installed = list_installed(Some(&home)).unwrap();
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].name, "botan");
        assert_eq!(installed[0].version, "3.2.0");
    }

    #[test]
    fn install_rejects_hash_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let home = PathBuf::from(tmp.path());
        let manifest = manifest_for("botan", "3.2.0", "deadbeef");
        let downloader =
            MemoryDownloader::new().with("https://example.test/botan.so", vec![1, 2, 3]);
        let err = install_manifest(&downloader, Some(&home), manifest).unwrap_err();
        assert!(matches!(err, Error::HashMismatch { .. }));
    }

    #[test]
    fn remove_deletes_artifact_and_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let home = PathBuf::from(tmp.path());
        let manifest = manifest_for("botan", "3.2.0", &empty_body_hash());
        let downloader = MemoryDownloader::new().with("https://example.test/botan.so", Vec::new());
        install_manifest(&downloader, Some(&home), manifest).unwrap();

        remove(Some(&home), "botan").unwrap();
        assert!(list_installed(Some(&home)).unwrap().is_empty());
    }

    #[test]
    fn remove_unknown_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let home = PathBuf::from(tmp.path());
        let err = remove(Some(&home), "ghost").unwrap_err();
        assert!(matches!(err, Error::NotInstalled { .. }));
    }

    #[test]
    fn list_on_missing_dir_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let home = PathBuf::from(tmp.path());
        let installed = list_installed(Some(&home)).unwrap();
        assert!(installed.is_empty());
    }

    #[test]
    fn noop_downloader_errors() {
        let err = NoopDownloader
            .download("https://example.test/x.so")
            .unwrap_err();
        assert!(matches!(err, Error::Download { .. }));
    }
}
