//! AEAD (authenticated encryption with associated data) interface.
//!
//! Plugin contract — the plugin exports these C symbols with the
//! `cfmp_aead_` prefix:
//!
//! ```c
//! uint32_t cfmp_aead_create(const Confium*, FFIAead**, const char* algorithm,
//!                           const void* key, uint32_t key_len, const Option*);
//! uint32_t cfmp_aead_set_nonce(FFIAead*, const uint8_t*, uint32_t);
//! uint32_t cfmp_aead_associated_data_update(FFIAead*, const uint8_t*, uint32_t);
//! uint32_t cfmp_aead_encrypt_update(FFIAead*, const uint8_t*, uint32_t,
//!                                   uint8_t*, uint32_t*);
//! uint32_t cfmp_aead_decrypt_update(FFIAead*, const uint8_t*, uint32_t,
//!                                   uint8_t*, uint32_t*);
//! uint32_t cfmp_aead_finalize(FFIAead*, uint8_t*, uint32_t, uint32_t*);
//! uint32_t cfmp_aead_verify_tag(FFIAead*, const uint8_t*, uint32_t);
//! void     cfmp_aead_destroy(FFIAead*);
//! ```
//!
//! Algorithms the plugin may advertise (case-sensitive ASCII):
//! - `AES-128-GCM`, `AES-192-GCM`, `AES-256-GCM`
//! - `AES-128-OCB`, `AES-192-OCB`, `AES-256-OCB` (RFC 9580 default)
//! - `AES-128-EAX`, `AES-192-EAX`, `AES-256-EAX`
//! - `ChaCha20-Poly1305`
//! - `SM4-GCM`, `SM4-OCB` (rare, optional)
//!
//! `encrypt_update` and `decrypt_update` are split because direction
//! matters for the internal state machine and for tag verification.
//! This module owns the [`AeadInterface`] type and the registry kind;
//! the user-facing [`crate::aead::Aead`] wrapper lives in `src/aead.rs`.

use std::any::Any;
use std::ffi::c_void;
use std::os::raw::c_char;
use std::rc::Rc;

use libloading::Library;

use crate::Confium;
use crate::Result;
use crate::error::Error;
use crate::ffi::plugin::get_plugin_symbol;
use crate::ffi::registry::PluginInterfaceKind;
use crate::options::Options;
use crate::register_interface;

use crate::aead::Aead;

pub enum FFIAead {}

pub type AeadCreateFnV0 = extern "C" fn(
    *const Confium,
    *mut *mut FFIAead,
    *const c_char,
    *const c_void,
    u32,
    Option<&Options>,
) -> u32;
const AEAD_CREATE_FN_V0_NAME: &[u8] = b"cfmp_aead_create\0";

pub type AeadSetNonceFnV0 = extern "C" fn(*mut FFIAead, *const u8, u32) -> u32;
const AEAD_SET_NONCE_FN_V0_NAME: &[u8] = b"cfmp_aead_set_nonce\0";

pub type AeadAssociatedDataUpdateFnV0 = extern "C" fn(*mut FFIAead, *const u8, u32) -> u32;
const AEAD_ASSOCIATED_DATA_UPDATE_FN_V0_NAME: &[u8] = b"cfmp_aead_associated_data_update\0";

pub type AeadEncryptUpdateFnV0 =
    extern "C" fn(*mut FFIAead, *const u8, u32, *mut u8, *mut u32) -> u32;
const AEAD_ENCRYPT_UPDATE_FN_V0_NAME: &[u8] = b"cfmp_aead_encrypt_update\0";

pub type AeadDecryptUpdateFnV0 =
    extern "C" fn(*mut FFIAead, *const u8, u32, *mut u8, *mut u32) -> u32;
const AEAD_DECRYPT_UPDATE_FN_V0_NAME: &[u8] = b"cfmp_aead_decrypt_update\0";

pub type AeadFinalizeFnV0 = extern "C" fn(*mut FFIAead, *mut u8, u32, *mut u32) -> u32;
const AEAD_FINALIZE_FN_V0_NAME: &[u8] = b"cfmp_aead_finalize\0";

pub type AeadVerifyTagFnV0 = extern "C" fn(*mut FFIAead, *const u8, u32) -> u32;
const AEAD_VERIFY_TAG_FN_V0_NAME: &[u8] = b"cfmp_aead_verify_tag\0";

pub type AeadDestroyFnV0 = extern "C" fn(*mut FFIAead) -> c_void;
const AEAD_DESTROY_FN_V0_NAME: &[u8] = b"cfmp_aead_destroy\0";

#[derive(Debug)]
pub struct AeadInterfaceV0 {
    pub create: Box<AeadCreateFnV0>,
    pub set_nonce: Box<AeadSetNonceFnV0>,
    pub associated_data_update: Box<AeadAssociatedDataUpdateFnV0>,
    pub encrypt_update: Box<AeadEncryptUpdateFnV0>,
    pub decrypt_update: Box<AeadDecryptUpdateFnV0>,
    pub finalize: Box<AeadFinalizeFnV0>,
    pub verify_tag: Box<AeadVerifyTagFnV0>,
    pub destroy: Box<AeadDestroyFnV0>,
}

#[derive(Debug)]
pub enum AeadInterface {
    V0(AeadInterfaceV0),
}

/// Registry kind for the AEAD interface. Lives next to the interface
/// it describes so registration stays co-located with the
/// implementation (open/closed-compliant).
pub struct AeadKind;

impl PluginInterfaceKind for AeadKind {
    fn name(&self) -> &'static str {
        "aead"
    }

    fn max_version(&self) -> u8 {
        0
    }

    fn build(&self, lib: &Library, version: u8) -> Result<Option<Rc<dyn Any>>> {
        match version {
            0 => Ok(create_aead_interface_v0(lib)?.map(|iface| Rc::new(iface) as Rc<dyn Any>)),
            _ => Ok(None),
        }
    }
}

register_interface!(AeadKind);

fn create_aead_interface_v0(lib: &Library) -> Result<Option<AeadInterface>> {
    let iface = AeadInterfaceV0 {
        create: get_plugin_symbol::<AeadCreateFnV0>(lib, "aead", AEAD_CREATE_FN_V0_NAME)?,
        set_nonce: get_plugin_symbol::<AeadSetNonceFnV0>(lib, "aead", AEAD_SET_NONCE_FN_V0_NAME)?,
        associated_data_update: get_plugin_symbol::<AeadAssociatedDataUpdateFnV0>(
            lib,
            "aead",
            AEAD_ASSOCIATED_DATA_UPDATE_FN_V0_NAME,
        )?,
        encrypt_update: get_plugin_symbol::<AeadEncryptUpdateFnV0>(
            lib,
            "aead",
            AEAD_ENCRYPT_UPDATE_FN_V0_NAME,
        )?,
        decrypt_update: get_plugin_symbol::<AeadDecryptUpdateFnV0>(
            lib,
            "aead",
            AEAD_DECRYPT_UPDATE_FN_V0_NAME,
        )?,
        finalize: get_plugin_symbol::<AeadFinalizeFnV0>(lib, "aead", AEAD_FINALIZE_FN_V0_NAME)?,
        verify_tag: get_plugin_symbol::<AeadVerifyTagFnV0>(
            lib,
            "aead",
            AEAD_VERIFY_TAG_FN_V0_NAME,
        )?,
        destroy: get_plugin_symbol::<AeadDestroyFnV0>(lib, "aead", AEAD_DESTROY_FN_V0_NAME)?,
    };
    Ok(Some(AeadInterface::V0(iface)))
}

/// Downcast a plugin's type-erased interface to a shared
/// [`AeadInterface`]. Owned by this module so consumers of the AEAD
/// interface don't need to know about the registry.
pub fn interface_of(plugin: &crate::Plugin) -> Option<Rc<AeadInterface>> {
    plugin
        .interfaces
        .iter()
        .find_map(|i| i.clone_inner::<AeadInterface>())
}

#[allow(clippy::too_many_arguments)]
fn cfm_aead_create_(
    cfm: *const Confium,
    aead: *mut *mut Aead,
    algorithm: *const c_char,
    key: *const c_void,
    key_len: u32,
    provider: *const c_char,
    opts: *const Options,
    _errptr: *mut *mut Error,
) -> Result<()> {
    check_not_null!(cfm);
    check_not_null!(aead);
    check_not_null!(algorithm);
    check_not_null!(key);
    let cfm = unsafe { &*cfm };
    let algorithm = crate::ffi::utils::cstring(algorithm)?;
    let provider = match provider.is_null() {
        true => None,
        false => Some(crate::ffi::utils::cstring(provider)?),
    };
    let provider = provider.as_deref();
    let opts = match opts.is_null() {
        true => None,
        false => Some(unsafe { &*opts }),
    };
    let key = unsafe { std::slice::from_raw_parts(key as *const u8, key_len as usize) };
    unsafe {
        *aead = Box::into_raw(Box::new(Aead::new(cfm, &algorithm, key, provider, opts)?));
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_aead_create(
    cfm: *const Confium,
    aead: *mut *mut Aead,
    algorithm: *const c_char,
    key: *const c_void,
    key_len: u32,
    provider: *const c_char,
    opts: *const Options,
    errptr: *mut *mut Error,
) -> u32 {
    cfm_aead_create_(cfm, aead, algorithm, key, key_len, provider, opts, errptr)
        .map_or_else(|e| ffi_return_err!(e, errptr), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_aead_set_nonce(aead: *mut Aead, nonce: *const u8, len: u32) -> u32 {
    if aead.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if nonce.is_null() && len != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let a = unsafe { &mut *aead };
    let nonce = if nonce.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(nonce, len as usize) }
    };
    a.set_nonce(nonce).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_aead_associated_data_update(
    aead: *mut Aead,
    data: *const u8,
    len: u32,
) -> u32 {
    if aead.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if data.is_null() && len != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let a = unsafe { &mut *aead };
    let data = if data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len as usize) }
    };
    a.associated_data_update(data)
        .map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_aead_encrypt_update(
    aead: *mut Aead,
    input: *const u8,
    in_len: u32,
    output: *mut u8,
    out_len: *mut u32,
) -> u32 {
    if aead.is_null() || out_len.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if input.is_null() && in_len != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if output.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let a = unsafe { &mut *aead };
    let input = if input.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(input, in_len as usize) }
    };
    let avail = unsafe { *out_len } as usize;
    let output = unsafe { std::slice::from_raw_parts_mut(output, avail) };
    match a.encrypt_update(input, output) {
        Ok(written) => {
            unsafe {
                *out_len = written as u32;
            }
            0
        }
        Err(e) => e.code(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_aead_decrypt_update(
    aead: *mut Aead,
    input: *const u8,
    in_len: u32,
    output: *mut u8,
    out_len: *mut u32,
) -> u32 {
    if aead.is_null() || out_len.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if input.is_null() && in_len != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if output.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let a = unsafe { &mut *aead };
    let input = if input.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(input, in_len as usize) }
    };
    let avail = unsafe { *out_len } as usize;
    let output = unsafe { std::slice::from_raw_parts_mut(output, avail) };
    match a.decrypt_update(input, output) {
        Ok(written) => {
            unsafe {
                *out_len = written as u32;
            }
            0
        }
        Err(e) => e.code(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_aead_finalize(
    aead: *mut Aead,
    tag: *mut u8,
    tag_max: u32,
    tag_len: *mut u32,
) -> u32 {
    if aead.is_null() || tag_len.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if tag.is_null() && tag_max != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let a = unsafe { &mut *aead };
    let tag = if tag.is_null() {
        &mut [][..]
    } else {
        unsafe { std::slice::from_raw_parts_mut(tag, tag_max as usize) }
    };
    match a.finalize(tag) {
        Ok(written) => {
            unsafe {
                *tag_len = written as u32;
            }
            0
        }
        Err(e) => e.code(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_aead_verify_tag(aead: *mut Aead, tag: *const u8, len: u32) -> u32 {
    if aead.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if tag.is_null() && len != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let a = unsafe { &mut *aead };
    let tag = if tag.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(tag, len as usize) }
    };
    a.verify_tag(tag).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_aead_destroy(aead: *mut Aead) -> u32 {
    if !aead.is_null() {
        unsafe {
            std::mem::drop(Box::from_raw(aead));
        }
    }
    0
}
