//! Key serialization (keyfmt) interface.
//!
//! Plugin contract — the plugin exports these C symbols with the
//! `cfmp_keyfmt_` prefix:
//!
//! ```c
//! uint32_t cfmp_keyfmt_parse(const Confium*, FFIKey**,
//!                            const char* format, const char* algorithm_hint,
//!                            const uint8_t* bytes, uint32_t len,
//!                            const Option*);
//! uint32_t cfmp_keyfmt_serialize(const FFIKey*, const char* format,
//!                                uint8_t* out, uint32_t out_max, uint32_t* out_len);
//! uint32_t cfmp_keyfmt_kind(const FFIKey*, uint32_t* out);   // 0=secret,1=public,2=both
//! uint32_t cfmp_keyfmt_algorithm(const FFIKey*, char** algorithm_out);
//! uint32_t cfmp_keyfmt_public(const FFIKey*, FFIKey** public_only_out);
//! void     cfmp_keyfmt_destroy(FFIKey*);
//! ```
//!
//! Formats the plugin may advertise (case-sensitive ASCII). Confium does
//! not enforce the set — the plugin declares which it supports:
//! - `OpenPGP` — RFC 9580 packet format
//! - `PKCS#8-PEM`, `PKCS#8-DER` — RFC 5208 / 5958
//! - `PKCS#1-PEM`, `PKCS#1-DER` — RSA-specific legacy
//! - `SPKI-PEM`, `SPKI-DER` — SubjectPublicKeyInfo
//! - `JWK` — RFC 7517
//! - `Raw` — algorithm-specific byte string
//! - `OpenSSH` — RFC 4253 + extensions
//!
//! The plugin is responsible for parsing AND serializing; it owns the
//! format ↔ algorithm mapping. `cfmp_keyfmt_public` strips secret
//! material — required for keystore public/private compartmentalization.
//!
//! This module owns the [`KeyfmtInterface`] type and the registry kind;
//! the user-facing [`crate::keyfmt::Key`] wrapper lives in `src/keyfmt.rs`.

use std::any::Any;
use std::ffi::c_void;
use std::fmt;
use std::os::raw::c_char;
use std::rc::Rc;

use libloading::Library;

use crate::Confium;
use crate::Result;
use crate::error::Error;
use crate::ffi::plugin::get_plugin_symbol;
use crate::ffi::registry::PluginInterfaceKind;
use crate::ffi::utils::cstring;
use crate::keyfmt::Key;
use crate::options::Options;
use crate::register_interface;

pub enum FFIKey {}

pub type KeyfmtParseFnV0 = extern "C" fn(
    *const Confium,
    *mut *mut FFIKey,
    *const c_char,
    *const c_char,
    *const u8,
    u32,
    Option<&Options>,
) -> u32;
const KEYFMT_PARSE_FN_V0_NAME: &[u8] = b"cfmp_keyfmt_parse\0";

pub type KeyfmtSerializeFnV0 =
    extern "C" fn(*const FFIKey, *const c_char, *mut u8, u32, *mut u32) -> u32;
const KEYFMT_SERIALIZE_FN_V0_NAME: &[u8] = b"cfmp_keyfmt_serialize\0";

pub type KeyfmtKindFnV0 = extern "C" fn(*const FFIKey, *mut u32) -> u32;
const KEYFMT_KIND_FN_V0_NAME: &[u8] = b"cfmp_keyfmt_kind\0";

pub type KeyfmtAlgorithmFnV0 = extern "C" fn(*const FFIKey, *mut *mut c_char) -> u32;
const KEYFMT_ALGORITHM_FN_V0_NAME: &[u8] = b"cfmp_keyfmt_algorithm\0";

pub type KeyfmtPublicFnV0 = extern "C" fn(*const FFIKey, *mut *mut FFIKey) -> u32;
const KEYFMT_PUBLIC_FN_V0_NAME: &[u8] = b"cfmp_keyfmt_public\0";

pub type KeyfmtDestroyFnV0 = extern "C" fn(*mut FFIKey) -> c_void;
const KEYFMT_DESTROY_FN_V0_NAME: &[u8] = b"cfmp_keyfmt_destroy\0";

pub struct KeyfmtInterfaceV0 {
    pub parse: Box<KeyfmtParseFnV0>,
    pub serialize: Box<KeyfmtSerializeFnV0>,
    pub kind: Box<KeyfmtKindFnV0>,
    pub algorithm: Box<KeyfmtAlgorithmFnV0>,
    pub public: Box<KeyfmtPublicFnV0>,
    pub destroy: Box<KeyfmtDestroyFnV0>,
}

impl fmt::Debug for KeyfmtInterfaceV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyfmtInterfaceV0")
            .field("parse", &((*self.parse) as *const u8))
            .field("serialize", &((*self.serialize) as *const u8))
            .field("kind", &((*self.kind) as *const u8))
            .field("algorithm", &((*self.algorithm) as *const u8))
            .field("public", &((*self.public) as *const u8))
            .field("destroy", &((*self.destroy) as *const u8))
            .finish()
    }
}

#[derive(Debug)]
pub enum KeyfmtInterface {
    V0(KeyfmtInterfaceV0),
}

/// Registry kind for the key serialization interface. Lives next to the
/// interface it describes so registration stays co-located with the
/// implementation (open/closed-compliant).
pub struct KeyfmtKind;

impl PluginInterfaceKind for KeyfmtKind {
    fn name(&self) -> &'static str {
        "keyfmt"
    }

    fn max_version(&self) -> u8 {
        0
    }

    fn build(&self, lib: &Library, version: u8) -> Result<Option<Rc<dyn Any>>> {
        match version {
            0 => Ok(create_keyfmt_interface_v0(lib)?.map(|iface| Rc::new(iface) as Rc<dyn Any>)),
            _ => Ok(None),
        }
    }
}

register_interface!(KeyfmtKind);

fn create_keyfmt_interface_v0(lib: &Library) -> Result<Option<KeyfmtInterface>> {
    let iface = KeyfmtInterfaceV0 {
        parse: get_plugin_symbol::<KeyfmtParseFnV0>(lib, "keyfmt", KEYFMT_PARSE_FN_V0_NAME)?,
        serialize: get_plugin_symbol::<KeyfmtSerializeFnV0>(
            lib,
            "keyfmt",
            KEYFMT_SERIALIZE_FN_V0_NAME,
        )?,
        kind: get_plugin_symbol::<KeyfmtKindFnV0>(lib, "keyfmt", KEYFMT_KIND_FN_V0_NAME)?,
        algorithm: get_plugin_symbol::<KeyfmtAlgorithmFnV0>(
            lib,
            "keyfmt",
            KEYFMT_ALGORITHM_FN_V0_NAME,
        )?,
        public: get_plugin_symbol::<KeyfmtPublicFnV0>(lib, "keyfmt", KEYFMT_PUBLIC_FN_V0_NAME)?,
        destroy: get_plugin_symbol::<KeyfmtDestroyFnV0>(lib, "keyfmt", KEYFMT_DESTROY_FN_V0_NAME)?,
    };
    Ok(Some(KeyfmtInterface::V0(iface)))
}

/// Downcast a plugin's type-erased interface to a shared
/// [`KeyfmtInterface`]. Owned by this module so consumers of the keyfmt
/// interface don't need to know about the registry.
pub fn interface_of(plugin: &crate::Plugin) -> Option<Rc<KeyfmtInterface>> {
    plugin
        .interfaces
        .iter()
        .find_map(|i| i.clone_inner::<KeyfmtInterface>())
}

// Parameter count is fixed by the FFI wire contract (cfm, out, format,
// hint, bytes+len, provider, opts, errptr); cannot be reduced without
// changing the C ABI.
#[allow(clippy::too_many_arguments)]
fn cfm_keyfmt_parse_(
    cfm: *const Confium,
    key: *mut *mut Key,
    format: *const c_char,
    algorithm_hint: *const c_char,
    bytes: *const u8,
    len: u32,
    provider: *const c_char,
    opts: *const Options,
    _errptr: *mut *mut Error,
) -> Result<()> {
    check_not_null!(cfm);
    check_not_null!(key);
    check_not_null!(format);
    let cfm = unsafe { &*cfm };
    let format = cstring(format)?;
    let algorithm_hint = match algorithm_hint.is_null() {
        true => None,
        false => Some(cstring(algorithm_hint)?),
    };
    let algorithm_hint = algorithm_hint.as_deref();
    let provider = match provider.is_null() {
        true => None,
        false => Some(cstring(provider)?),
    };
    let provider = provider.as_deref();
    let opts = match opts.is_null() {
        true => None,
        false => Some(unsafe { &*opts }),
    };
    let data = slice_or_empty(bytes, len);
    unsafe {
        *key = Box::into_raw(Box::new(Key::parse(
            cfm,
            &format,
            algorithm_hint,
            data,
            provider,
            opts,
        )?));
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_keyfmt_parse(
    cfm: *const Confium,
    key: *mut *mut Key,
    format: *const c_char,
    algorithm_hint: *const c_char,
    bytes: *const u8,
    len: u32,
    provider: *const c_char,
    opts: *const Options,
    errptr: *mut *mut Error,
) -> u32 {
    cfm_keyfmt_parse_(
        cfm,
        key,
        format,
        algorithm_hint,
        bytes,
        len,
        provider,
        opts,
        errptr,
    )
    .map_or_else(|e| ffi_return_err!(e, errptr), |_| 0)
}

fn cfm_keyfmt_serialize_(
    key: *const Key,
    format: *const c_char,
    out: *mut u8,
    out_max: u32,
    out_len: *mut u32,
) -> Result<()> {
    check_not_null!(format);
    let format = cstring(format)?;
    let written = unsafe { (*key).serialize(&format)? };
    let bytes: &[u8] = written.as_ref();
    let n = bytes.len();
    if (out_max as usize) < n {
        return crate::error::InsufficientBufferSnafu {}.fail();
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, n);
        *out_len = n as u32;
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_keyfmt_serialize(
    key: *const Key,
    format: *const c_char,
    out: *mut u8,
    out_max: u32,
    out_len: *mut u32,
) -> u32 {
    cfm_keyfmt_serialize_(key, format, out, out_max, out_len).map_or_else(|e| e.code(), |_| 0)
}

fn cfm_keyfmt_kind_(key: *const Key, out_kind: *mut u32) -> Result<()> {
    let kind = unsafe { (*key).kind()? };
    unsafe {
        *out_kind = kind as u32;
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_keyfmt_kind(key: *const Key, out_kind: *mut u32) -> u32 {
    cfm_keyfmt_kind_(key, out_kind).map_or_else(|e| e.code(), |_| 0)
}

fn cfm_keyfmt_algorithm_(key: *const Key, algorithm_out: *mut *mut c_char) -> Result<()> {
    let algorithm = unsafe { (*key).algorithm()? };
    // `algorithm` is a valid Rust `String` (UTF-8); the only way
    // `CString::new` fails is an interior NUL, which algorithm names
    // never contain. Treat that as an internal plugin contract breach.
    let cstr = std::ffi::CString::new(algorithm).map_err(|_| {
        crate::error::PluginInternalSnafu {
            name: "",
            code: 0u32,
        }
        .build()
    })?;
    unsafe {
        *algorithm_out = cstr.into_raw();
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_keyfmt_algorithm(key: *const Key, algorithm_out: *mut *mut c_char) -> u32 {
    cfm_keyfmt_algorithm_(key, algorithm_out).map_or_else(|e| e.code(), |_| 0)
}

fn cfm_keyfmt_public_(key: *const Key, public_only_out: *mut *mut Key) -> Result<()> {
    let public = unsafe { (*key).public()? };
    unsafe {
        *public_only_out = Box::into_raw(Box::new(public));
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_keyfmt_public(key: *const Key, public_only_out: *mut *mut Key) -> u32 {
    cfm_keyfmt_public_(key, public_only_out).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_keyfmt_destroy(key: *mut Key) -> u32 {
    unsafe {
        if !key.is_null() {
            std::mem::drop(Box::from_raw(key));
        }
    }
    0
}

/// Build a `&[u8]` view of `(ptr, len)`. A null pointer is treated as an
/// empty slice (only valid when `len == 0`); a non-null pointer yields a
/// slice of `len` bytes. Mirrors the precondition of
/// `slice::from_raw_parts` so callers can pass null for empty input
/// without each call site having to special-case it.
fn slice_or_empty<'a>(ptr: *const u8, len: u32) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len as usize) }
    }
}
