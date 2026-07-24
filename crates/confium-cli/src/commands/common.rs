//! Shared helpers for command implementations.
//!
//! Centralises the few bits of glue every command needs:
//!
//! - resolving the home directory (real or overridden via the
//!   `CONFium_HOME` env var for integration tests),
//! - constructing a registry [`Client`] bound to a [`FileFetcher`] that
//!   reads the registry static-site from a local directory (set
//!   `CONFium_REGISTRY_DIR`), otherwise an empty fetcher that surfaces
//!   typed `NotFound` errors,
//! - and a tiny error-to-exit-code helper.
//!
//! Keeping this here means each `commands/<name>.rs` stays focused on
//! its own logic.

use std::path::PathBuf;

use confium_registry::{Client, DEFAULT_REGISTRY_URL, Error, Fetcher};

/// Environment variable consulted by every command to redirect both
/// config and data dirs to a temp root. Integration tests set this so
/// they never touch the real `~/.config/confium`.
pub const HOME_ENV: &str = "CONFium_HOME";

/// Environment variable naming a directory whose contents mirror the
/// registry static site. When set, commands load documents from disk
/// via a file-backed [`Fetcher`] instead of the network. This is what
/// the CLI tests use to exercise install/search/info without HTTP.
pub const REGISTRY_DIR_ENV: &str = "CONFium_REGISTRY_DIR";

/// Environment variable overriding the registry base URL.
pub const REGISTRY_URL_ENV: &str = "CONFium_REGISTRY_URL";

/// Resolve the home override, if any.
pub fn override_home() -> Option<PathBuf> {
    std::env::var_os(HOME_ENV).map(PathBuf::from)
}

/// Build a registry client honouring the env-var overrides.
///
/// When [`REGISTRY_DIR_ENV`] is set, the client reads from a local
/// checkout of the registry static site (file-backed fetcher). Otherwise
/// it uses an empty [`FileFetcher`] so commands surface a typed
/// `NotFound` rather than panicking. Production wiring replaces the
/// empty branch with an HTTP-backed fetcher once `confium-net` lands.
pub fn registry_client() -> Result<Client<FileFetcher>, Error> {
    let base_url =
        std::env::var(REGISTRY_URL_ENV).unwrap_or_else(|_| DEFAULT_REGISTRY_URL.to_string());
    let root = std::env::var_os(REGISTRY_DIR_ENV).map(PathBuf::from);
    let fetcher = FileFetcher::new(root);
    Ok(Client::with_fetcher(base_url, fetcher))
}

/// A [`Fetcher`] backed by a local directory mirroring the static-site
/// layout. Registry-relative paths (`/index.toml`,
/// `/plugins/botan/index.toml`) map to files under the root. When `root`
/// is `None`, every fetch returns `NotFound` — the typed signal that no
/// registry source is configured.
pub struct FileFetcher {
    root: Option<PathBuf>,
}

impl FileFetcher {
    pub fn new(root: Option<PathBuf>) -> Self {
        FileFetcher { root }
    }
}

impl Fetcher for FileFetcher {
    fn fetch(&self, path: &str) -> Result<Vec<u8>, Error> {
        let Some(ref root) = self.root else {
            return Err(Error::NotFound {
                path: path.to_string(),
            });
        };
        // Strip leading slash so `join` doesn't discard `root`.
        let relative = path.trim_start_matches('/');
        let full = root.join(relative);
        std::fs::read(&full).map_err(|e| Error::io(e, format!("failed to read {}", full.display())))
    }
}

/// Translate a registry [`Error`] into a printable message + exit code.
pub fn fail(err: Error) -> ! {
    eprintln!("confium: {err}");
    let code = match err {
        Error::PluginNotFound { .. }
        | Error::VersionNotFound { .. }
        | Error::NotInstalled { .. }
        | Error::NotFound { .. } => 64,
        Error::UntrustedPlugin { .. } => 78,
        Error::HashMismatch { .. } => 65,
        _ => 70,
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_home_reads_env() {
        // SAFETY: this test mutates the process environment. Cargo runs
        // each crate's tests in a single process, so we isolate by
        // setting/unsetting only our own var. Edition 2024 made
        // env mutation unsafe because reads in other threads could
        // race; these tests are single-threaded.
        unsafe {
            std::env::remove_var(HOME_ENV);
        }
        assert!(override_home().is_none());
        unsafe {
            std::env::set_var(HOME_ENV, "/tmp/example");
        }
        assert_eq!(override_home(), Some(PathBuf::from("/tmp/example")));
        unsafe {
            std::env::remove_var(HOME_ENV);
        }
    }

    #[test]
    fn empty_fetcher_returns_not_found() {
        let fetcher = FileFetcher::new(None);
        let err = fetcher.fetch("/index.toml").unwrap_err();
        assert!(matches!(err, Error::NotFound { .. }));
    }
}
