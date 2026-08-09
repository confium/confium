// FFI entry points accept raw pointers and null-check them before
// dereferencing; they are not `unsafe` from the C caller's perspective.
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::redundant_explicit_links)]
#![allow(rustdoc::private_intra_doc_links)]
#![allow(rustdoc::invalid_html_tags)]

#[macro_use]
pub mod utils;
pub mod aead;
pub mod audit;
pub mod cipher;
pub mod error;
#[macro_use]
pub mod ffi;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod keyfmt;
pub mod mlock;
pub mod options;
pub mod rng;
pub mod secret;
pub mod sensitive;
pub mod signature;

use std::any::Any;
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

use libloading::Library;

use audit::AuditLogger;
use error::Error;
use snafu::ResultExt;

use ffi::plugin::{CFMPluginMetadata, METADATA_FN_NAME, MetadataFn, PluginVTable};

type StringOptions = HashMap<String, String>;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub type Result<T> = std::result::Result<T, Error>;

pub struct Provider {
    pub name: String,
    pub plugin: Plugin,
}

pub struct Plugin {
    pub library: Rc<Library>,
    pub vtable: PluginVTable,
    /// Each interface advertised by the plugin, type-erased so the core
    /// doesn't need a closed enum of interface variants. Concrete
    /// interface types live in their respective modules (`ffi::hash`,
    /// `ffi::cipher`, etc.).
    pub interfaces: Vec<PluginInterface>,
}

impl Plugin {
    /// Look up the plugin's optional `cfmp_metadata` symbol and return a
    /// Rust-friendly copy of the data if the plugin exports it, or `None`
    /// if the plugin doesn't export the symbol or the symbol returns a
    /// NULL pointer. The returned [`PluginMetadata`] owns its strings,
    /// so the caller can drop the plugin and still use the data.
    pub fn metadata(&self) -> Result<Option<PluginMetadata>> {
        // The symbol is optional: a missing export is a normal "no
        // metadata" answer, not an error. `Library::get` returns a
        // `DlSym` error when the platform lookup fails, which we treat
        // as `None`. A returned NULL pointer also means "no metadata".
        let symbol: std::result::Result<libloading::Symbol<MetadataFn>, libloading::Error> =
            unsafe { self.library.get::<MetadataFn>(METADATA_FN_NAME) };
        let metadata_fn = match symbol {
            Ok(f) => *f,
            Err(libloading::Error::DlSym { .. }) => return Ok(None),
            Err(source) => {
                return Err(Error::PluginSymbolError {
                    name: String::new(),
                    symbol: METADATA_FN_NAME,
                    source,
                });
            }
        };
        let raw = metadata_fn();
        if raw.is_null() {
            return Ok(None);
        }
        // SAFETY: the plugin contract guarantees the pointer returned by
        // `cfmp_metadata` is valid for the lifetime of the loaded plugin
        // (the plugin is kept alive by `self.library`). We copy the
        // strings out immediately so the borrow ends before this
        // function returns.
        let raw = unsafe { &*raw };
        Ok(Some(PluginMetadata::from_raw(raw)?))
    }
}

/// Rust-friendly mirror of `ffi::plugin::CFMPluginMetadata`. Owns each
/// string so the caller doesn't need to keep the plugin loaded for the
/// data to remain valid. Fields not provided by the plugin (NULL pointers
/// in the C struct) become `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PluginMetadata {
    pub name: Option<String>,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub license: Option<String>,
    pub homepage_url: Option<String>,
    pub source_url: Option<String>,
    pub issue_tracker_url: Option<String>,
    pub description: Option<String>,
}

impl PluginMetadata {
    /// Copy the strings out of a plugin-owned `CFMPluginMetadata`. NULL
    /// fields become `None`. After this returns the borrowed raw struct
    /// may be invalidated — all data is owned by the returned value.
    fn from_raw(raw: &CFMPluginMetadata) -> Result<Self> {
        fn copy(ptr: *const std::os::raw::c_char) -> Result<Option<String>> {
            if ptr.is_null() {
                return Ok(None);
            }
            // SAFETY: the plugin contract promises each non-NULL field is
            // a NUL-terminated UTF-8 string valid for the plugin's
            // lifetime. We only read it here.
            let s = unsafe { std::ffi::CStr::from_ptr(ptr) };
            Ok(Some(
                s.to_str()
                    .context(crate::error::InvalidUTF8Snafu {})?
                    .to_string(),
            ))
        }
        Ok(PluginMetadata {
            name: copy(raw.name)?,
            version: copy(raw.version)?,
            vendor: copy(raw.vendor)?,
            license: copy(raw.license)?,
            homepage_url: copy(raw.homepage_url)?,
            source_url: copy(raw.source_url)?,
            issue_tracker_url: copy(raw.issue_tracker_url)?,
            description: copy(raw.description)?,
        })
    }
}

/// A type-erased plugin interface with its negotiated name and version.
///
/// Concrete interface types are recovered via downcast by the consumer
/// module that owns the type (e.g. `hash::interface_for(plugin)`).
pub struct PluginInterface {
    pub name: &'static str,
    pub version: u8,
    pub inner: Rc<dyn Any>,
}

impl PluginInterface {
    /// Borrow the underlying concrete interface if it matches `T`.
    pub fn downcast<T: Any>(&self) -> Option<&T> {
        self.inner.downcast_ref::<T>()
    }

    /// Clone a shared handle to the underlying concrete interface if it
    /// matches `T`.
    pub fn clone_inner<T: Any>(&self) -> Option<Rc<T>> {
        Rc::clone(&self.inner).downcast::<T>().ok()
    }
}

pub struct Confium {
    providers: Vec<Provider>,
    preferred_providers: HashMap<String, Vec<String>>,
    /// Structured audit log sink. Logs plugin loads, key accesses, and
    /// TC session boundaries as JSON Lines. See [`audit::AuditLogger`].
    pub audit: AuditLogger,
}

impl Confium {
    /// Construct a `Confium` whose audit logger resolves its sink from
    /// the environment (`CONFIUM_AUDIT_LOG` or the default path under
    /// `~/.local/share/confium/log/`, falling back to stderr).
    pub fn new() -> Self {
        Self::new_with_audit(AuditLogger::default_logger())
    }

    /// Construct a `Confium` with a caller-supplied audit logger. Use
    /// this to pass [`audit::AuditLogger::disabled`] for tests or
    /// opt-out, or a logger configured for a specific file.
    pub fn new_with_audit(logger: AuditLogger) -> Self {
        Confium {
            providers: Vec::new(),
            preferred_providers: HashMap::new(),
            audit: logger,
        }
    }

    pub fn load_plugin(&mut self, path: &Path, options: &StringOptions) -> Result<()> {
        use std::ffi::CString;
        let path_str = path.to_string_lossy();
        let c_path = CString::new(path_str.as_ref()).unwrap();
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("plugin");
        let c_name = CString::new(name).unwrap();
        let mut opts = options::Options::new();
        for (k, v) in options {
            opts.insert(k.clone(), options::OptionValue::String(v.clone()));
        }
        crate::ffi::plugin::cfm_plugin_load_(
            self as *mut Confium,
            c_name.as_ptr(),
            c_path.as_ptr(),
            &mut opts,
        )
    }
}

impl Default for Confium {
    fn default() -> Self {
        Self::new()
    }
}

impl Confium {
    /// Find a loaded provider by name. Shared by all interface modules
    /// (DRY — eliminates 16 copies of this function across 8 files).
    /// Not yet called by all modules; pending incremental refactoring.
    #[allow(dead_code)]
    pub(crate) fn find_provider(&self, name: &str) -> Option<&Provider> {
        self.providers.iter().find(|p| p.name == name)
    }

    /// Get a loaded provider by name, or return `UnknownProvider`.
    #[allow(dead_code)]
    pub(crate) fn get_provider(&self, name: &str) -> Result<&Provider> {
        self.find_provider(name)
            .ok_or_else(|| error::UnknownProviderSnafu { name }.build())
    }

    /// Resolve the candidate provider list for a given interface name.
    /// Precedence: explicit provider → preferred_providers → all loaded
    /// providers offering the interface (in load order).
    #[allow(dead_code)]
    pub(crate) fn resolve_providers(
        &self,
        interface_name: &str,
        preferred: Option<&str>,
        has_interface: impl Fn(&Plugin) -> bool,
    ) -> Result<Vec<&Provider>> {
        let mut providers: Vec<&Provider> = Vec::new();
        if let Some(name) = preferred {
            providers.push(self.get_provider(name)?);
        } else if let Some(list) = self.preferred_providers.get(interface_name) {
            for name in list {
                providers.push(self.get_provider(name)?);
            }
        } else {
            for provider in &self.providers {
                if has_interface(&provider.plugin) {
                    providers.push(provider);
                }
            }
        }
        Ok(providers)
    }
}

#[cfg(test)]
mod metadata_tests {
    use super::*;
    use std::ffi::CString;
    use std::os::raw::c_char;

    /// Build a `CFMPluginMetadata` whose string fields point at the
    /// provided `CString`s, simulating what a real plugin's
    /// `cfmp_metadata` would return. The `CString`s own the backing
    /// storage, mirroring plugin-owned statics.
    #[allow(clippy::too_many_arguments)]
    fn raw_metadata(
        name: &str,
        version: &str,
        vendor: &str,
        license: &str,
        homepage_url: &str,
        source_url: &str,
        issue_tracker_url: &str,
        description: &str,
    ) -> (ffi::plugin::CFMPluginMetadata, Vec<CString>) {
        let cstrings = vec![
            CString::new(name).unwrap(),
            CString::new(version).unwrap(),
            CString::new(vendor).unwrap(),
            CString::new(license).unwrap(),
            CString::new(homepage_url).unwrap(),
            CString::new(source_url).unwrap(),
            CString::new(issue_tracker_url).unwrap(),
            CString::new(description).unwrap(),
        ];
        let raw = ffi::plugin::CFMPluginMetadata {
            name: cstrings[0].as_ptr(),
            version: cstrings[1].as_ptr(),
            vendor: cstrings[2].as_ptr(),
            license: cstrings[3].as_ptr(),
            homepage_url: cstrings[4].as_ptr(),
            source_url: cstrings[5].as_ptr(),
            issue_tracker_url: cstrings[6].as_ptr(),
            description: cstrings[7].as_ptr(),
        };
        (raw, cstrings)
    }

    #[test]
    fn from_raw_copies_all_fields_correctly() {
        let (raw, _owners) = raw_metadata(
            "botan",
            "3.2.0",
            "Ribose",
            "BSD-2-Clause",
            "https://botan.randombit.net",
            "https://github.com/confium/confium-botan",
            "https://github.com/confium/confium-botan/issues",
            "Botan 3.x crypto provider plugin",
        );
        let md = PluginMetadata::from_raw(&raw).expect("from_raw succeeds on valid input");
        assert_eq!(md.name.as_deref(), Some("botan"));
        assert_eq!(md.version.as_deref(), Some("3.2.0"));
        assert_eq!(md.vendor.as_deref(), Some("Ribose"));
        assert_eq!(md.license.as_deref(), Some("BSD-2-Clause"));
        assert_eq!(
            md.homepage_url.as_deref(),
            Some("https://botan.randombit.net")
        );
        assert_eq!(
            md.source_url.as_deref(),
            Some("https://github.com/confium/confium-botan")
        );
        assert_eq!(
            md.issue_tracker_url.as_deref(),
            Some("https://github.com/confium/confium-botan/issues")
        );
        assert_eq!(
            md.description.as_deref(),
            Some("Botan 3.x crypto provider plugin")
        );
    }

    #[test]
    fn from_raw_clones_strings_so_data_outlives_plugin() {
        let (raw, owners) = raw_metadata(
            "frost-ed25519",
            "0.4.1",
            "cfrg-frost-implementers",
            "Apache-2.0",
            "https://example.com/frost",
            "https://example.com/frost/src",
            "https://example.com/frost/issues",
            "FROST threshold signature for ed25519",
        );
        let md = PluginMetadata::from_raw(&raw).expect("from_raw succeeds");
        // Zero the simulated plugin storage through the raw pointers to
        // prove that PluginMetadata owns its strings (the borrow ended
        // at the previous line).
        for c in &owners {
            let p = c.as_ptr() as *mut c_char;
            let len = c.as_bytes_with_nul().len();
            for i in 0..len {
                unsafe {
                    *p.add(i) = 0;
                }
            }
        }
        let _ = owners;
        assert_eq!(md.name.as_deref(), Some("frost-ed25519"));
        assert_eq!(md.version.as_deref(), Some("0.4.1"));
        assert_eq!(md.vendor.as_deref(), Some("cfrg-frost-implementers"));
        assert_eq!(md.license.as_deref(), Some("Apache-2.0"));
    }

    #[test]
    fn from_raw_treats_null_fields_as_none() {
        let name = CString::new("minimal").unwrap();
        let version = CString::new("1.0.0").unwrap();
        let raw = ffi::plugin::CFMPluginMetadata {
            name: name.as_ptr(),
            version: version.as_ptr(),
            vendor: std::ptr::null(),
            license: std::ptr::null(),
            homepage_url: std::ptr::null(),
            source_url: std::ptr::null(),
            issue_tracker_url: std::ptr::null(),
            description: std::ptr::null(),
        };
        let md = PluginMetadata::from_raw(&raw).expect("from_raw handles NULLs");
        assert_eq!(md.name.as_deref(), Some("minimal"));
        assert_eq!(md.version.as_deref(), Some("1.0.0"));
        assert!(md.vendor.is_none());
        assert!(md.license.is_none());
        assert!(md.homepage_url.is_none());
        assert!(md.source_url.is_none());
        assert!(md.issue_tracker_url.is_none());
        assert!(md.description.is_none());
    }

    #[test]
    fn from_raw_rejects_invalid_utf8() {
        let bad = CString::new(b"\xFF\xFF".to_vec()).unwrap();
        let raw = ffi::plugin::CFMPluginMetadata {
            name: bad.as_ptr(),
            version: std::ptr::null(),
            vendor: std::ptr::null(),
            license: std::ptr::null(),
            homepage_url: std::ptr::null(),
            source_url: std::ptr::null(),
            issue_tracker_url: std::ptr::null(),
            description: std::ptr::null(),
        };
        let err = PluginMetadata::from_raw(&raw).unwrap_err();
        assert_eq!(err.code(), error::ErrorCode::INVALID_UTF8.into());
    }
}
