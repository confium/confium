//! Option map types passed from Confium into a plugin's `create` entry
//! point.
//!
//! The wire shape mirrors `confium_core::options::Options` exactly so a
//! pointer of one can be reinterpreted as the other across the FFI
//! boundary. Plugin authors get typed accessors
//! ([`OptionView::get_str`], [`OptionView::get_u32`],
//! [`OptionView::get_map`]) without depending on `confium-core`.
//!
//! The proc-macro generated `cfmp_<iface>_create` reinterprets the
//! `*const Options` argument as `&OptionMap` (they share a layout) and
//! hands the borrow to the trait method.

use std::collections::HashMap;
use std::ffi::c_void;

/// Discriminated union of the option values that may flow across the
/// FFI option map. Layout-compatible with
/// `confium_core::options::OptionValue`.
#[derive(Debug, Clone, PartialEq)]
pub enum OptionValue {
    String(String),
    U32(u32),
    /// A nested option map (used for subkeys like `keyfmt = { encoding = "pem" }`).
    Map(Box<OptionMap>),
}

/// A string-keyed map of [`OptionValue`]s, layout-compatible with
/// `confium_core::options::Options` (`HashMap<String, OptionValue>`).
pub type OptionMap = HashMap<String, OptionValue>;

/// Read-only view over an [`OptionMap`] borrowed across the FFI.
///
/// The plugin contract hands the loader-owned `&OptionMap` to the plugin
/// for the duration of `create`; this wrapper gives plugin authors a
/// typed accessor surface without forcing them to construct a
/// `HashMap<String, String>` themselves.
pub struct OptionView<'a> {
    inner: &'a OptionMap,
}

impl<'a> OptionView<'a> {
    /// Wrap a borrow over an option map. The macro-generated entry point
    /// typically reinterprets the incoming `*const Options` as
    /// `&OptionMap` and hands it here.
    pub fn new(inner: &'a OptionMap) -> Self {
        Self { inner }
    }

    /// Wrap a raw pointer that the loader produced. The pointer must
    /// point at a value layout-compatible with [`OptionMap`] and remain
    /// valid for the borrow. A NULL pointer yields `None`.
    ///
    /// # Safety
    ///
    /// `ptr` must either be NULL or point at a value that is
    /// layout-compatible with `OptionMap` and valid for `'a`.
    pub unsafe fn from_raw_ptr(ptr: *const c_void) -> Option<Self> {
        if ptr.is_null() {
            return None;
        }
        // SAFETY: caller guarantees the pointer is a valid, properly
        // aligned `&OptionMap` borrow for `'a`.
        let inner: &'a OptionMap = unsafe { &*(ptr as *const OptionMap) };
        Some(Self { inner })
    }

    /// Read a string option. Returns `None` if the key is absent or the
    /// value isn't a [`OptionValue::String`].
    pub fn get_str(&self, key: &str) -> Option<&str> {
        match self.inner.get(key)? {
            OptionValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Read a u32 option. Returns `None` if the key is absent or the
    /// value isn't a [`OptionValue::U32`].
    pub fn get_u32(&self, key: &str) -> Option<u32> {
        match self.inner.get(key)? {
            OptionValue::U32(n) => Some(*n),
            _ => None,
        }
    }

    /// Read a nested map option. Returns `None` if the key is absent or
    /// the value isn't a [`OptionValue::Map`].
    pub fn get_map(&self, key: &str) -> Option<OptionView<'_>> {
        match self.inner.get(key)? {
            OptionValue::Map(m) => Some(OptionView::new(m.as_ref())),
            _ => None,
        }
    }

    /// True if the map contains no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> OptionMap {
        let mut m = OptionMap::new();
        m.insert(
            "algorithm".to_string(),
            OptionValue::String("sha-256".to_string()),
        );
        m.insert("output_size".to_string(), OptionValue::U32(32));
        let mut nested = OptionMap::new();
        nested.insert(
            "encoding".to_string(),
            OptionValue::String("pem".to_string()),
        );
        m.insert("keyfmt".to_string(), OptionValue::Map(Box::new(nested)));
        m
    }

    #[test]
    fn reads_string_value() {
        let m = sample();
        let view = OptionView::new(&m);
        assert_eq!(view.get_str("algorithm"), Some("sha-256"));
    }

    #[test]
    fn reads_u32_value() {
        let m = sample();
        let view = OptionView::new(&m);
        assert_eq!(view.get_u32("output_size"), Some(32));
    }

    #[test]
    fn reads_nested_map() {
        let m = sample();
        let view = OptionView::new(&m);
        let nested = view.get_map("keyfmt").expect("nested map present");
        assert_eq!(nested.get_str("encoding"), Some("pem"));
    }

    #[test]
    fn missing_key_returns_none() {
        let m = sample();
        let view = OptionView::new(&m);
        assert_eq!(view.get_str("missing"), None);
        assert_eq!(view.get_u32("missing"), None);
        assert!(view.get_map("missing").is_none());
    }

    #[test]
    fn wrong_type_returns_none() {
        let m = sample();
        let view = OptionView::new(&m);
        // algorithm is a string — asking for it as u32/map is a type mismatch.
        assert_eq!(view.get_u32("algorithm"), None);
        assert!(view.get_map("algorithm").is_none());
    }

    #[test]
    fn null_pointer_yields_none() {
        let view = unsafe { OptionView::from_raw_ptr(std::ptr::null()) };
        assert!(view.is_none());
    }
}
