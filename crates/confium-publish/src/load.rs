// Load a built plugin artifact and query it via the FFI contract.
//
// `confium-publish` is a standalone tool: it does NOT spin up a full
// `Confium` runtime (that would require a configured trust store, loaded
// providers, etc.). Instead it opens the artifact as a plain dynamic
// library with `libloading` and calls the C-ABI entry points directly.
//
// Two symbols are consulted, both optional per the plugin contract
//
//   * `cfmp_metadata`           -> `*const CFMPluginMetadata` (or NULL)
//   * `cfmp_query_interfaces`   -> packed `name\0ver\0...` byte stream
//
// When a symbol is absent the caller falls back to the matching CLI
// override (`--name`, `--version`, `--interfaces`, ...).

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;

use libloading::Library;
use snafu::{ResultExt, Snafu};

use crate::cli::{parse_algorithm_overrides, parse_interface_overrides};

/// C-ABI mirror of the plugin metadata struct declared in
/// a plugin may leave any of them NULL.
#[repr(C)]
pub struct CFMPluginMetadata {
    pub name: *const c_char,
    pub version: *const c_char,
    pub vendor: *const c_char,
    pub license: *const c_char,
    pub homepage: *const c_char,
    pub description: *const c_char,
    pub homepage_url: *const c_char,
    pub source_url: *const c_char,
    pub issue_tracker_url: *const c_char,
}

/// Rust-friendly, owned copy of the metadata. Every field is `Option`
/// because the plugin may omit any of them; the caller fills gaps from
/// CLI args.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PluginMetadata {
    pub name: Option<String>,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub license: Option<String>,
    pub homepage: Option<String>,
    pub description: Option<String>,
    pub source_url: Option<String>,
}

/// A single advertised interface: its wire name and the version byte
/// the plugin speaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    pub name: String,
    pub version: u8,
}

#[derive(Snafu, Debug)]
pub enum LoadError {
    #[snafu(display("failed to open artifact at '{}'", path.display()))]
    OpenLibrary {
        path: Box<Path>,
        source: libloading::Error,
    },

    #[snafu(display("invalid UTF-8 in FFI payload"))]
    InvalidUtf8 { source: std::str::Utf8Error },

    #[snafu(display("invalid CLI override: {}", message))]
    InvalidOverride { message: String },
}

impl LoadError {
    fn from_override(message: String) -> Self {
        Self::InvalidOverride { message }
    }
}

pub type Result<T> = std::result::Result<T, LoadError>;

/// Open the artifact as a dynamic library. The `Library` handle owns the
/// mapping; keep it alive for as long as any borrowed FFI data is in use.
pub fn open_library(path: &Path) -> Result<Library> {
    let path_boxed: Box<Path> = Box::from(path);
    unsafe { Library::new(path_boxed.as_ref()) }.context(OpenLibrarySnafu { path: path_boxed })
}

/// Call `cfmp_metadata()` if exported, returning an owned copy. Returns
/// `Ok(None)` when the symbol is absent (the plugin is still loadable by
/// Confium but ineligible for registry publishing per the contract).
pub fn query_metadata(lib: &Library) -> Result<Option<PluginMetadata>> {
    let Ok(sym) =
        (unsafe { lib.get::<extern "C" fn() -> *const CFMPluginMetadata>(b"cfmp_metadata\0") })
    else {
        return Ok(None);
    };
    let raw_ptr = sym();
    if raw_ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: the plugin vouched for the pointer by returning non-NULL.
    // We copy every string out immediately and never hold the raw struct
    // across an FFI boundary.
    let raw = unsafe { &*raw_ptr };
    Ok(Some(PluginMetadata {
        name: cstr_to_string(raw.name),
        version: cstr_to_string(raw.version),
        vendor: cstr_to_string(raw.vendor),
        license: cstr_to_string(raw.license),
        homepage: cstr_to_string(raw.homepage),
        description: cstr_to_string(raw.description),
        source_url: cstr_to_string(raw.source_url),
    }))
}

/// Call `cfmp_query_interfaces()` if exported, parsing the packed
/// `name\0ver\0` stream. Returns `Ok(None)` when the symbol is absent.
///
/// The v0 contract signature takes a `*mut Confium`, which we do not
/// have in the standalone publish tool. Plugins that need the handle to
/// answer should be queried at runtime instead; for publishing we pass a
/// null pointer and rely on well-behaved plugins that can enumerate
/// without a handle. When that is not possible the caller supplies
/// `--interfaces` on the command line.
pub fn query_interfaces(lib: &Library) -> Result<Option<Vec<InterfaceEntry>>> {
    let Ok(sym) = (unsafe {
        lib.get::<extern "C" fn(*mut std::ffi::c_void) -> *const u8>(b"cfmp_query_interfaces\0")
    }) else {
        return Ok(None);
    };
    let ptr = sym(std::ptr::null_mut());
    if ptr.is_null() {
        return Ok(Some(Vec::new()));
    }
    Ok(Some(parse_interface_stream(ptr)?))
}

/// Parse the packed `name\0version_byte\0` stream terminated by an empty
/// name, mirroring `confium-core`'s `enumerate_plugin_interfaces`.
fn parse_interface_stream(start: *const u8) -> Result<Vec<InterfaceEntry>> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    loop {
        let name_start = idx;
        let mut name_end = name_start;
        // SAFETY: we read bytes one at a time, stopping at the NUL that
        // terminates each name. The stream is guaranteed NUL-terminated
        // by the contract; a missing terminator is UB on the plugin's
        // side, not ours.
        while unsafe { *start.add(name_end) } != 0 {
            name_end += 1;
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(start.add(name_start), name_end - name_start) };
        let name = std::str::from_utf8(bytes).context(InvalidUtf8Snafu)?;
        if name.is_empty() {
            break;
        }
        let version = unsafe { *start.add(name_end + 1) };
        out.push(InterfaceEntry {
            name: name.to_string(),
            version,
        });
        idx = name_end + 2;
    }
    Ok(out)
}

fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the plugin promises a NUL-terminated UTF-8 string when the
    // pointer is non-NULL.
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
    std::str::from_utf8(bytes).ok().map(str::to_string)
}

/// Resolve the effective `[interfaces]` map: CLI override wins, else the
/// FFI query, else empty. Returns a `BTreeMap` so the serialized TOML is
/// deterministic.
pub fn resolve_interfaces(
    ffi: Option<&[InterfaceEntry]>,
    cli_override: Option<&[String]>,
) -> Result<BTreeMap<String, u8>> {
    if let Some(raw) = cli_override {
        let parsed = parse_interface_overrides(raw).map_err(LoadError::from_override)?;
        let mut map = BTreeMap::new();
        for (name, ver) in parsed {
            map.insert(name, ver);
        }
        return Ok(map);
    }
    let mut map: BTreeMap<String, u8> = BTreeMap::new();
    if let Some(entries) = ffi {
        for entry in entries {
            map.entry(entry.name.clone())
                .and_modify(|v: &mut u8| *v = (*v).max(entry.version))
                .or_insert(entry.version);
        }
    }
    Ok(map)
}

/// Resolve the effective `[algorithms]` map: CLI override wins, else
/// empty (FFI does not advertise algorithms today).
pub fn resolve_algorithms(
    cli_override: Option<&[String]>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut map = BTreeMap::new();
    if let Some(raw) = cli_override {
        let parsed = parse_algorithm_overrides(raw).map_err(LoadError::from_override)?;
        for (iface, algos) in parsed {
            map.insert(iface, algos);
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_interfaces_prefers_cli_override() {
        let ffi = vec![
            InterfaceEntry {
                name: "hash".into(),
                version: 0,
            },
            InterfaceEntry {
                name: "rng".into(),
                version: 0,
            },
        ];
        let cli = vec!["aead:1".to_string()];
        let got = resolve_interfaces(Some(&ffi), Some(&cli)).unwrap();
        // Only the CLI entry survives.
        assert_eq!(got.len(), 1);
        assert_eq!(got["aead"], 1);
    }

    #[test]
    fn resolve_interfaces_falls_back_to_ffi() {
        let ffi = vec![InterfaceEntry {
            name: "hash".into(),
            version: 0,
        }];
        let got = resolve_interfaces(Some(&ffi), None).unwrap();
        assert_eq!(got["hash"], 0);
    }

    #[test]
    fn resolve_interfaces_empty_when_no_source() {
        let got = resolve_interfaces(None, None).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn resolve_algorithms_parses_cli() {
        let cli = vec!["hash:SHA-256;SHA-512".to_string()];
        let got = resolve_algorithms(Some(&cli)).unwrap();
        assert_eq!(
            got["hash"],
            vec!["SHA-256".to_string(), "SHA-512".to_string()]
        );
    }
}
