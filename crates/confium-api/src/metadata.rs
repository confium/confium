//! Plugin metadata exposed via the optional `cfmp_metadata` symbol.
//!
//! The wire shape mirrors `confium_core::ffi::plugin::CFMPluginMetadata`
//! — a `#[repr(C)]` struct of `*const c_char` fields. Plugin authors use
//! [`PluginMetadataBuilder`] to construct the value at static-storage
//! time, and the `export!` macro generates the `cfmp_metadata` entry
//! point that returns a pointer to it.
//!
//! Field strings are owned by the plugin (stored as `'static` so they
//! outlive the loader's borrow). The returned pointer is valid for the
//! lifetime of the loaded plugin.

use std::ffi::CString;
use std::os::raw::c_char;

/// `#[repr(C)]` metadata struct returned by `cfmp_metadata`. Layout
/// matches `confium_core::ffi::plugin::CFMPluginMetadata` so the loader
/// can reinterpret the pointer.
///
/// Wire-stable: never reorder, repurpose, or remove existing fields.
#[repr(C)]
pub struct PluginMetadata {
    pub name: *const c_char,
    pub version: *const c_char,
    pub vendor: *const c_char,
    pub license: *const c_char,
    pub homepage_url: *const c_char,
    pub source_url: *const c_char,
    pub issue_tracker_url: *const c_char,
    pub description: *const c_char,
}

// SAFETY: `PluginMetadata` is logically immutable after construction.
// The raw `*const c_char` fields point at `'static` storage owned by
// the plugin (leaked `CString`s in the `PluginMetadataBuilder::build`
// path). The struct is only read by the loader's `cfmp_metadata` call,
// never mutated. Sharing it across threads is sound.
unsafe impl Sync for PluginMetadata {}
unsafe impl Send for PluginMetadata {}

/// Builder for [`PluginMetadata`]. Each call leaks a `CString` so the
/// returned pointer is `'static` (the value lives for the lifetime of
/// the plugin, matching the contract).
///
/// Use via the `#[plugin_metadata]` proc-macro attribute on the
/// `export!`-annotated module — the macro constructs the builder for
/// you from attribute arguments.
#[derive(Default)]
pub struct PluginMetadataBuilder {
    name: Option<CString>,
    version: Option<CString>,
    vendor: Option<CString>,
    license: Option<CString>,
    homepage_url: Option<CString>,
    source_url: Option<CString>,
    issue_tracker_url: Option<CString>,
    description: Option<CString>,
}

impl PluginMetadataBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn name(mut self, s: impl Into<String>) -> Self {
        self.name = CString::new(s.into()).ok();
        self
    }
    pub fn version(mut self, s: impl Into<String>) -> Self {
        self.version = CString::new(s.into()).ok();
        self
    }
    pub fn vendor(mut self, s: impl Into<String>) -> Self {
        self.vendor = CString::new(s.into()).ok();
        self
    }
    pub fn license(mut self, s: impl Into<String>) -> Self {
        self.license = CString::new(s.into()).ok();
        self
    }
    pub fn homepage_url(mut self, s: impl Into<String>) -> Self {
        self.homepage_url = CString::new(s.into()).ok();
        self
    }
    pub fn source_url(mut self, s: impl Into<String>) -> Self {
        self.source_url = CString::new(s.into()).ok();
        self
    }
    pub fn issue_tracker_url(mut self, s: impl Into<String>) -> Self {
        self.issue_tracker_url = CString::new(s.into()).ok();
        self
    }
    pub fn description(mut self, s: impl Into<String>) -> Self {
        self.description = CString::new(s.into()).ok();
        self
    }

    /// Materialize the metadata. The returned struct holds raw pointers
    /// to `'static`-lifetime strings (the `CString`s are leaked to match
    /// the plugin contract that the pointer is valid for the plugin's
    /// lifetime).
    pub fn build(self) -> PluginMetadata {
        PluginMetadata {
            name: self.name.map(leak_cstring).unwrap_or(std::ptr::null()),
            version: self.version.map(leak_cstring).unwrap_or(std::ptr::null()),
            vendor: self.vendor.map(leak_cstring).unwrap_or(std::ptr::null()),
            license: self.license.map(leak_cstring).unwrap_or(std::ptr::null()),
            homepage_url: self
                .homepage_url
                .map(leak_cstring)
                .unwrap_or(std::ptr::null()),
            source_url: self
                .source_url
                .map(leak_cstring)
                .unwrap_or(std::ptr::null()),
            issue_tracker_url: self
                .issue_tracker_url
                .map(leak_cstring)
                .unwrap_or(std::ptr::null()),
            description: self
                .description
                .map(leak_cstring)
                .unwrap_or(std::ptr::null()),
        }
    }
}

/// Leak a `CString` into `'static` storage. Matches the plugin contract
/// that `cfmp_metadata` returns a pointer valid for the plugin's lifetime.
fn leak_cstring(s: CString) -> *const c_char {
    let ptr = s.as_ptr();
    std::mem::forget(s);
    ptr
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn builder_yields_nul_terminated_strings() {
        let md = PluginMetadataBuilder::new()
            .name("mock-hash")
            .version("0.1.0")
            .vendor("confium")
            .license("BSD-2-Clause")
            .description("deterministic mock hash for tests")
            .build();

        unsafe {
            assert_eq!(CStr::from_ptr(md.name).to_str().unwrap(), "mock-hash");
            assert_eq!(CStr::from_ptr(md.version).to_str().unwrap(), "0.1.0");
            assert_eq!(CStr::from_ptr(md.vendor).to_str().unwrap(), "confium");
            assert_eq!(CStr::from_ptr(md.license).to_str().unwrap(), "BSD-2-Clause");
            assert_eq!(
                CStr::from_ptr(md.description).to_str().unwrap(),
                "deterministic mock hash for tests"
            );
        }
        assert!(md.homepage_url.is_null());
        assert!(md.source_url.is_null());
        assert!(md.issue_tracker_url.is_null());
    }

    #[test]
    fn empty_builder_yields_all_null() {
        let md = PluginMetadataBuilder::new().build();
        assert!(md.name.is_null());
        assert!(md.version.is_null());
        assert!(md.vendor.is_null());
        assert!(md.license.is_null());
        assert!(md.homepage_url.is_null());
        assert!(md.source_url.is_null());
        assert!(md.issue_tracker_url.is_null());
        assert!(md.description.is_null());
    }
}
