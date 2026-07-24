//! Filesystem locations used by the CLI and the registry client.
//!
//! All paths are derived from the `XDG_*` / `HOME` environment so the
//! behaviour matches `TODO.roadmap/07-cli-tools.md` (Configuration
//! section) on POSIX systems:
//!
//! - config: `~/.config/confium/`
//! - plugins: `~/.local/share/confium/plugins/`
//!
//! Each helper accepts an optional override root so tests can point the
//! CLI at a temp directory without touching the real home. When the
//! override is `None` the function falls back to the environment-derived
//! path.

use std::path::PathBuf;

use crate::error::{Error, Result};

/// The base config directory, honouring `XDG_CONFIG_HOME` then `$HOME`.
///
/// When `override_home` is supplied, the returned path is
/// `<override_home>/.config/confium` — useful for tests.
pub fn config_dir(override_home: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(home) = override_home {
        return Ok(home.join(".config").join("confium"));
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("confium"));
        }
    }
    Ok(home_dir()?.join(".config").join("confium"))
}

/// The base data directory for installed plugins.
pub fn plugins_dir(override_home: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(home) = override_home {
        return Ok(home
            .join(".local")
            .join("share")
            .join("confium")
            .join("plugins"));
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("confium").join("plugins"));
        }
    }
    Ok(home_dir()?
        .join(".local")
        .join("share")
        .join("confium")
        .join("plugins"))
}

/// Where a single installed plugin artifact lives:
/// `<plugins>/<name>-<version>.so`.
pub fn plugin_install_dir(
    override_home: Option<&PathBuf>,
    name: &str,
    version: &str,
) -> Result<PathBuf> {
    let file = format!("{name}-{version}.so");
    Ok(plugins_dir(override_home)?.join(file))
}

/// The trust-store directory (`<config>/trust`).
pub fn trust_dir(override_home: Option<&PathBuf>) -> Result<PathBuf> {
    Ok(config_dir(override_home)?.join("trust"))
}

/// The main config file (`<config>/config.toml`).
pub fn config_file(override_home: Option<&PathBuf>) -> Result<PathBuf> {
    Ok(config_dir(override_home)?.join("config.toml"))
}

fn home_dir() -> Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| Error::InvalidPath {
            path: "HOME is not set".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_dir_honours_override() {
        let home = PathBuf::from("/tmp/fake-home");
        let got = config_dir(Some(&home)).unwrap();
        assert_eq!(got, PathBuf::from("/tmp/fake-home/.config/confium"));
    }

    #[test]
    fn plugins_dir_honours_override() {
        let home = PathBuf::from("/tmp/fake-home");
        let got = plugins_dir(Some(&home)).unwrap();
        assert_eq!(
            got,
            PathBuf::from("/tmp/fake-home/.local/share/confium/plugins")
        );
    }

    #[test]
    fn plugin_install_dir_combines_name_version() {
        let home = PathBuf::from("/tmp/fake-home");
        let got = plugin_install_dir(Some(&home), "botan", "3.2.0").unwrap();
        assert_eq!(
            got,
            PathBuf::from("/tmp/fake-home/.local/share/confium/plugins/botan-3.2.0.so")
        );
    }

    #[test]
    fn trust_dir_under_config() {
        let home = PathBuf::from("/tmp/fake-home");
        let got = trust_dir(Some(&home)).unwrap();
        assert_eq!(got, PathBuf::from("/tmp/fake-home/.config/confium/trust"));
    }
}
