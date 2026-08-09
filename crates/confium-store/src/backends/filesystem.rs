//! Filesystem backend.
//!
//! Persists key material as opaque byte blobs in a compartmentalised
//! directory tree rooted at `<root>` (configured via the
//! [`Options`](crate::backend::Options) key `"root"`, default
//! `~/.local/share/confium/store/`).
//!
//! ```text
//! <root>/
//!   <module_id>/
//!     <app_id>/
//!       private/
//!         <key_id>           # raw key bytes (opaque to Confium)
//!       public/
//!         <identity>         # raw key bytes
//!         <identity>.sig     # detached identity signature
//! ```
//!
//! Key handles (`*mut c_void`) are treated as opaque byte containers. On
//! `put_*`, the backend dereferences the caller's `*mut Box<Vec<u8>>` and
//! writes the inner bytes. On `get_*`/`enumerate`, it reads bytes from
//! disk and returns a freshly `Box::into_raw`-ed `Box<Vec<u8>>`. This
//! keeps the opaque-pointer contract from
//! [`crate::backend::StoreInstance`] intact while giving the filesystem
//! backend concrete bytes to persist. When the `keyfmt` interface (TODO
//! #11) lands, the translation between its `FFIKey` and these byte blobs
//! will move into a codec layer; the directory layout is stable.

use std::ffi::c_void;
use std::fs;
use std::path::{Path, PathBuf};

use snafu::ResultExt;

use crate::backend::{Compartment, Options, StoreBackend, StoreInstance};
use crate::error::{InvalidPathSnafu, IoSnafu, Result, ValueNotFoundSnafu};
use crate::register_backend;

/// Options key naming the store root directory.
pub const OPT_ROOT: &str = "root";

/// Default store root if `OPT_ROOT` is absent from [`Options`].
const DEFAULT_ROOT: &str = "~/.local/share/confium/store/";

/// Extension appended to an identity's public-key file to store its
/// detached signature. Listed in [`forbidden_chars`] so identities cannot
/// smuggle a `.sig` suffix that would collide with the signature file.
const SIG_EXT: &str = "sig";

/// Characters that must never appear in a caller-supplied path component.
const fn forbidden_char(c: char) -> bool {
    matches!(c, '/' | '\\' | '\0')
}

/// Replace characters that are illegal in filenames on the host platform
/// (notably `:` on Windows, which `email:alice@example.com` contains).
/// Returns a string that's safe to use as a path leaf on this OS. Only
/// the on-disk filename is rewritten; the identity in the API stays as
/// the caller supplied it.
#[cfg(target_os = "windows")]
fn sanitize_for_filename(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            ':' | '<' | '>' | '"' | '|' | '?' | '*' | '/' | '\\' => '_',
            other => other,
        })
        .collect()
}

#[cfg(not(target_os = "windows"))]
fn sanitize_for_filename(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '/' | '\\' | '\0' => '_',
            other => other,
        })
        .collect()
}

// --- path sanitisation ---------------------------------------------------

/// Reject path components that could escape the store root or otherwise
/// corrupt the on-disk layout. Accepts any single path component that is
/// non-empty, contains no path separators, no NUL, and is not `.` or
/// `..`. This keeps the backend open/closed: a future backend that wants
/// a richer identity grammar relaxes its own validator, not this one.
fn validate_component(component: &str) -> Result<()> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains(forbidden_char)
    {
        return Err(InvalidPathSnafu {
            component: component.to_string(),
        }
        .build());
    }
    Ok(())
}

/// Build `<root>/<module>/<app>/<sub>/<leaf>`, validating every
/// caller-supplied segment.
fn join_path(root: &Path, module: &str, app: &str, sub: &str, leaf: &str) -> Result<PathBuf> {
    validate_component(module)?;
    validate_component(app)?;
    validate_component(sub)?;
    validate_component(leaf)?;
    Ok(root.join(module).join(app).join(sub).join(leaf))
}

// --- key handle <-> bytes codec -----------------------------------------

/// Treat the opaque `key` handle as `*mut Box<Vec<u8>>` and borrow the
/// inner bytes for writing.
///
/// # Safety
///
/// The caller must honour the [`StoreInstance`] contract: `key` is either
/// null or a valid, non-aliased pointer to a `Box<Vec<u8>>` produced by
/// the Engine's keyfmt codec (or by [`encode_key`] on a prior read).
///
/// [`StoreInstance`]: crate::backend::StoreInstance
unsafe fn key_bytes(key: *mut c_void) -> Result<&'static [u8]> {
    if key.is_null() {
        return Ok(&[]);
    }
    // SAFETY: caller guarantees `key` points to a `Box<Vec<u8>>`.
    let boxed: &Vec<u8> = unsafe { &*(key as *mut Box<Vec<u8>>) };
    Ok(boxed.as_slice())
}

/// Wrap `bytes` in a `Box<Vec<u8>>` and return it as an opaque
/// `*mut c_void`. Ownership of the allocation transfers to the caller,
/// matching the `StoreInstance` contract for `get_*`.
fn encode_key(bytes: Vec<u8>) -> *mut c_void {
    Box::into_raw(Box::new(Box::new(bytes))) as *mut c_void
}

/// Reclaim a `*mut c_void` produced by [`encode_key`]. Used only in tests
/// to avoid leaking the handles we hand to `put_*`.
#[cfg(test)]
unsafe fn reclaim_key(key: *mut c_void) {
    if key.is_null() {
        return;
    }
    // SAFETY: `key` was produced by `encode_key` in this test process.
    unsafe {
        drop(Box::from_raw(key as *mut Box<Vec<u8>>));
    }
}

// --- atomic write --------------------------------------------------------

/// Write `bytes` to `path` atomically: stage into a sibling temp file,
/// then rename over the target. Creates parent directories as needed.
/// The temp file shares the target's directory so the rename is
/// guaranteed to be on the same filesystem (atomic on POSIX).
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context(IoSnafu {})?;
    }
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("confium")
    ));
    fs::write(&tmp, bytes).context(IoSnafu {})?;
    fs::rename(&tmp, path).context(IoSnafu)?;
    Ok(())
}

// --- backend -------------------------------------------------------------

/// Factory for the filesystem backend. Stateless; all mutable state lives
/// in [`FilesystemInstance`].
pub struct FilesystemBackend;

impl StoreBackend for FilesystemBackend {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    fn open(&self, opts: &Options) -> Result<Box<dyn StoreInstance>> {
        let raw = opts
            .get(OPT_ROOT)
            .map(String::as_str)
            .unwrap_or(DEFAULT_ROOT);
        let root = expand_tilde(raw);
        fs::create_dir_all(&root).context(IoSnafu {})?;
        Ok(Box::new(FilesystemInstance { root }))
    }
}

register_backend!(FilesystemBackend);

/// Expand a leading `~` to the user's home directory. Falls back to the
/// literal path if the home directory cannot be resolved — the subsequent
/// `create_dir_all` will then report the real error.
fn expand_tilde(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if raw == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(raw)
}

pub struct FilesystemInstance {
    root: PathBuf,
}

impl FilesystemInstance {
    fn private_path(&self, module: &str, app: &str, key_id: &str) -> Result<PathBuf> {
        join_path(&self.root, module, app, "private", key_id)
    }

    fn public_key_path(&self, module: &str, app: &str, identity: &str) -> Result<PathBuf> {
        validate_component(module)?;
        validate_component(app)?;
        let identity = sanitize_for_filename(identity);
        validate_component(&identity)?;
        Ok(self
            .root
            .join(module)
            .join(app)
            .join("public")
            .join(identity))
    }

    fn public_sig_path(&self, module: &str, app: &str, identity: &str) -> Result<PathBuf> {
        // Build `<identity>.sig` from the identity. We must not use
        // `PathBuf::set_extension` here: identities legitimately contain
        // dots (e.g. `email:alice@example.com`) and `set_extension` would
        // replace the trailing `.com` rather than append. Instead we form
        // the leaf as a single validated component — `validate_component`
        // rejects separators/NUL so the concatenated `<identity>.sig`
        // cannot escape the `public/` directory even if `identity` were
        // hostile.
        validate_component(module)?;
        validate_component(app)?;
        let identity = sanitize_for_filename(identity);
        let leaf = format!("{identity}.{SIG_EXT}");
        validate_component(&leaf)?;
        Ok(self.root.join(module).join(app).join("public").join(leaf))
    }

    /// Directory whose immediate children are the entries for one
    /// compartment. Validates `module`/`app` so a caller cannot probe
    /// outside the root.
    fn compartment_dir(
        &self,
        module: &str,
        app: &str,
        compartment: Compartment,
    ) -> Result<PathBuf> {
        let sub = match compartment {
            Compartment::Private => "private",
            Compartment::Public => "public",
        };
        validate_component(module)?;
        validate_component(app)?;
        Ok(self.root.join(module).join(app).join(sub))
    }
}

impl StoreInstance for FilesystemInstance {
    fn put_secret(
        &mut self,
        module: &str,
        app: &str,
        key_id: &str,
        key: *mut c_void,
    ) -> Result<()> {
        let path = self.private_path(module, app, key_id)?;
        // SAFETY: the caller honours the StoreInstance contract; `key` is
        // a valid `*mut Box<Vec<u8>>` or null.
        let bytes = unsafe { key_bytes(key) }?;
        atomic_write(&path, bytes)
    }

    fn get_secret(&self, module: &str, app: &str, key_id: &str) -> Result<*mut c_void> {
        read_or_not_found(&self.private_path(module, app, key_id)?).map(encode_key)
    }

    fn put_public(
        &mut self,
        module: &str,
        app: &str,
        identity: &str,
        key: *mut c_void,
        sig: &[u8],
    ) -> Result<()> {
        let key_path = self.public_key_path(module, app, identity)?;
        let sig_path = self.public_sig_path(module, app, identity)?;
        // SAFETY: caller honours StoreInstance contract.
        let bytes = unsafe { key_bytes(key) }?;
        atomic_write(&key_path, bytes)?;
        atomic_write(&sig_path, sig)
    }

    fn get_public(
        &self,
        module: &str,
        app: &str,
        identity: &str,
    ) -> Result<(*mut c_void, Vec<u8>)> {
        let key_path = self.public_key_path(module, app, identity)?;
        let sig_path = self.public_sig_path(module, app, identity)?;
        let key_bytes = read_or_not_found(&key_path)?;
        let sig = read_or_not_found(&sig_path)?;
        Ok((encode_key(key_bytes), sig))
    }

    fn enumerate(
        &self,
        module: &str,
        app: &str,
        compartment: Compartment,
    ) -> Result<Vec<(*mut c_void, String)>> {
        let dir = self.compartment_dir(module, app, compartment)?;
        let read = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(e) => return Err(e).context(IoSnafu {}),
        };

        let mut entries: Vec<(PathBuf, String)> = Vec::new();
        for entry in read {
            let entry = entry.context(IoSnafu {})?;
            let path = entry.path();
            let Some(name) = path
                .file_name()
                .and_then(|s| s.to_str())
                .map(str::to_string)
            else {
                continue;
            };
            match compartment {
                Compartment::Private => {
                    entries.push((path, name));
                }
                Compartment::Public => {
                    // Each public entry is stored as `<identity>` plus a
                    // sibling `<identity>.sig`. Yield the identity once,
                    // keyed on the key file (the one without the `.sig`
                    // extension).
                    if path.extension().and_then(|s| s.to_str()) == Some(SIG_EXT) {
                        continue;
                    }
                    entries.push((path, name));
                }
            }
        }

        entries.sort_by(|a, b| a.1.cmp(&b.1));

        let mut out = Vec::with_capacity(entries.len());
        for (path, index) in entries {
            let bytes = fs::read(&path).context(IoSnafu {})?;
            out.push((encode_key(bytes), index));
        }
        Ok(out)
    }
}

/// Read a file, mapping `NotFound` to [`Error::ValueNotFound`] and every
/// other I/O error to [`Error::Io`].
///
/// [`Error::ValueNotFound`]: crate::error::Error::ValueNotFound
/// [`Error::Io`]: crate::error::Error::Io
fn read_or_not_found(path: &Path) -> Result<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ValueNotFoundSnafu.build()),
        Err(e) => Err(e).context(IoSnafu {}),
    }
}

// SAFETY: the backend stores only a `PathBuf` root; no per-thread state.
// Key handles are opaque `*mut c_void` tokens that the backend never
// dereferences outside the brief `unsafe` blocks above, each of which
// borrows a caller-owned `Box<Vec<u8>>` for the duration of a single call.
unsafe impl Send for FilesystemInstance {}
unsafe impl Sync for FilesystemInstance {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{Options, StoreBackend, StoreInstance};
    use std::collections::HashMap;
    use tempfile::TempDir;

    /// Open a filesystem backend rooted at a fresh temp dir.
    fn open() -> (TempDir, Box<dyn StoreInstance>) {
        let dir = TempDir::new().expect("tempdir");
        let mut opts: Options = HashMap::new();
        opts.insert(
            OPT_ROOT.to_string(),
            dir.path().to_str().expect("utf8 tmpdir").to_string(),
        );
        let ks = FilesystemBackend
            .open(&opts)
            .expect("filesystem backend opens");
        (dir, ks)
    }

    /// Wrap `bytes` in the opaque handle shape the codec expects.
    fn key_handle(bytes: &[u8]) -> *mut c_void {
        encode_key(bytes.to_vec())
    }

    #[test]
    fn put_get_secret_round_trip() {
        let (_dir, mut ks) = open();
        let secret = b"\x01\x02\x03\x04 secret key bytes";
        let handle = key_handle(secret);
        ks.put_secret("mod", "app", "key-1", handle)
            .expect("put_secret");
        unsafe { reclaim_key(handle) };

        let got = ks.get_secret("mod", "app", "key-1").expect("get_secret");
        let bytes = unsafe { key_bytes(got) }.expect("decode");
        assert_eq!(bytes, secret);
        unsafe { reclaim_key(got) };
    }

    #[test]
    fn put_get_public_round_trip() {
        let (_dir, mut ks) = open();
        let pubkey = b"PUBKEY-BYTES";
        let sig = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let handle = key_handle(pubkey);
        ks.put_public("mod", "app", "email:alice@example.com", handle, &sig)
            .expect("put_public");
        unsafe { reclaim_key(handle) };

        let (got_key, got_sig) = ks
            .get_public("mod", "app", "email:alice@example.com")
            .expect("get_public");
        let bytes = unsafe { key_bytes(got_key) }.expect("decode");
        assert_eq!(bytes, pubkey);
        assert_eq!(got_sig, sig);
        unsafe { reclaim_key(got_key) };
    }

    #[test]
    fn get_secret_missing_returns_value_not_found() {
        let (_dir, ks) = open();
        let err = ks.get_secret("mod", "app", "missing").unwrap_err();
        assert!(matches!(err, crate::error::Error::ValueNotFound));
    }

    #[test]
    fn get_public_missing_returns_value_not_found() {
        let (_dir, ks) = open();
        let err = ks
            .get_public("mod", "app", "email:nobody@example.com")
            .unwrap_err();
        assert!(matches!(err, crate::error::Error::ValueNotFound));
    }

    #[test]
    fn public_files_distinct_for_dotted_identity() {
        // Identities may contain dots (e.g. email addresses). The public
        // key file and the detached signature file must be siblings
        // distinguished by an appended `.sig`, not by `set_extension`
        // (which would overwrite the trailing `.com`).
        let (dir, mut ks) = open();
        let identity = "email:alice@example.com";
        let h = key_handle(b"pk-bytes");
        ks.put_public("mod", "app", identity, h, b"sig-bytes")
            .expect("put_public");
        unsafe { reclaim_key(h) };

        let key_path = dir
            .path()
            .join("mod")
            .join("app")
            .join("public")
            .join(identity);
        let sig_path = dir
            .path()
            .join("mod")
            .join("app")
            .join("public")
            .join(format!("{identity}.sig"));
        assert!(key_path.exists(), "key file at leaf identity");
        assert!(sig_path.exists(), "sig file at leaf identity + .sig");
        assert_ne!(key_path, sig_path, "key and sig paths must differ");
        assert_eq!(std::fs::read(&key_path).expect("read key"), b"pk-bytes");
        assert_eq!(std::fs::read(&sig_path).expect("read sig"), b"sig-bytes");

        let (got_key, got_sig) = ks.get_public("mod", "app", identity).expect("get_public");
        let bytes = unsafe { key_bytes(got_key) }.expect("decode");
        assert_eq!(bytes, b"pk-bytes");
        assert_eq!(got_sig, b"sig-bytes");
        unsafe { reclaim_key(got_key) };
    }

    #[test]
    fn enumerate_private_lists_key_ids() {
        let (_dir, mut ks) = open();
        for (kid, bytes) in [
            ("key-a", b"a".as_slice()),
            ("key-b", b"bb".as_slice()),
            ("key-c", b"ccc".as_slice()),
        ] {
            let h = key_handle(bytes);
            ks.put_secret("mod", "app", kid, h).expect("put_secret");
            unsafe { reclaim_key(h) };
        }

        let entries = ks
            .enumerate("mod", "app", Compartment::Private)
            .expect("enumerate private");
        let ids: Vec<String> = entries.iter().map(|(_, id)| id.clone()).collect();
        assert_eq!(ids, vec!["key-a", "key-b", "key-c"]);
        for (key, _) in &entries {
            unsafe { reclaim_key(*key) };
        }
    }

    #[test]
    fn enumerate_public_lists_identities_not_sigs() {
        let (_dir, mut ks) = open();
        for (id, bytes) in [
            ("email:alice@example.com", b"pk-a"),
            ("email:bob@example.com", b"pk-b"),
        ] {
            let h = key_handle(bytes);
            ks.put_public("mod", "app", id, h, &[0u8])
                .expect("put_public");
            unsafe { reclaim_key(h) };
        }

        let entries = ks
            .enumerate("mod", "app", Compartment::Public)
            .expect("enumerate public");
        let ids: Vec<&str> = entries.iter().map(|(_, id)| id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["email:alice@example.com", "email:bob@example.com"]
        );
        for (key, _) in &entries {
            unsafe { reclaim_key(*key) };
        }
    }

    #[test]
    fn enumerate_missing_scope_returns_empty() {
        let (_dir, ks) = open();
        let entries = ks
            .enumerate("nope", "nope", Compartment::Private)
            .expect("enumerate should not error on absent scope");
        assert!(entries.is_empty());
    }

    #[test]
    fn put_secret_overwrites() {
        let (_dir, mut ks) = open();
        let h1 = key_handle(b"old");
        ks.put_secret("mod", "app", "key-1", h1).expect("put old");
        unsafe { reclaim_key(h1) };
        let h2 = key_handle(b"new");
        ks.put_secret("mod", "app", "key-1", h2).expect("put new");
        unsafe { reclaim_key(h2) };

        let got = ks.get_secret("mod", "app", "key-1").expect("get");
        let bytes = unsafe { key_bytes(got) }.expect("decode");
        assert_eq!(bytes, b"new");
        unsafe { reclaim_key(got) };
    }

    #[test]
    fn path_traversal_module_rejected() {
        let (_dir, mut ks) = open();
        let h = key_handle(b"x");
        let err = ks.put_secret("..", "app", "key", h).unwrap_err();
        assert!(matches!(err, crate::error::Error::InvalidPath { .. }));
        unsafe { reclaim_key(h) };
    }

    #[test]
    fn path_traversal_app_rejected() {
        let (_dir, mut ks) = open();
        let h = key_handle(b"x");
        let err = ks.put_secret("mod", "../../etc", "key", h).unwrap_err();
        assert!(matches!(err, crate::error::Error::InvalidPath { .. }));
        unsafe { reclaim_key(h) };
    }

    #[test]
    fn path_traversal_key_id_rejected() {
        let (_dir, mut ks) = open();
        let h = key_handle(b"x");
        let err = ks.put_secret("mod", "app", "../escape", h).unwrap_err();
        assert!(matches!(err, crate::error::Error::InvalidPath { .. }));
        unsafe { reclaim_key(h) };
    }

    #[test]
    fn path_traversal_absolute_rejected() {
        let (_dir, mut ks) = open();
        let h = key_handle(b"x");
        // Absolute-looking component — contains a separator, so rejected.
        let err = ks.put_secret("/etc", "app", "key", h).unwrap_err();
        assert!(matches!(err, crate::error::Error::InvalidPath { .. }));
        unsafe { reclaim_key(h) };
    }

    #[test]
    fn nul_in_component_rejected() {
        let (_dir, mut ks) = open();
        let h = key_handle(b"x");
        let err = ks.put_secret("mo\0d", "app", "key", h).unwrap_err();
        assert!(matches!(err, crate::error::Error::InvalidPath { .. }));
        unsafe { reclaim_key(h) };
    }

    #[test]
    fn backend_is_registered() {
        let backend = crate::backend::find("filesystem").expect("filesystem backend registered");
        assert_eq!(backend.name(), "filesystem");
    }

    #[test]
    fn open_creates_root_if_missing() {
        let dir = TempDir::new().expect("tempdir");
        let nested = dir.path().join("a/b/c/store");
        let mut opts: Options = HashMap::new();
        opts.insert(
            OPT_ROOT.to_string(),
            nested.to_str().expect("utf8").to_string(),
        );
        let _ks = FilesystemBackend.open(&opts).expect("open");
        assert!(nested.exists(), "open should create the root directory");
    }

    #[test]
    fn on_disk_layout_matches_spec() {
        let (dir, mut ks) = open();
        let h = key_handle(b"secret");
        ks.put_secret("mod", "app", "key-1", h).expect("put_secret");
        unsafe { reclaim_key(h) };

        // Verify the exact path: <root>/<module>/<app>/private/<key_id>.
        let expected = dir
            .path()
            .join("mod")
            .join("app")
            .join("private")
            .join("key-1");
        assert!(expected.exists(), "private key file at spec path");
        let on_disk = std::fs::read(&expected).expect("read");
        assert_eq!(on_disk, b"secret");
    }
}
