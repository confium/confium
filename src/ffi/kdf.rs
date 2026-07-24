//! KDF (key derivation function) interface.
//!
//! Plugin contract — the plugin exports these C symbols with the
//! `cfmp_kdf_` prefix:
//!
//! ```c
//! uint32_t cfmp_kdf_create(const Confium*, FFIKdf**, const char* algorithm, const Option*);
//! uint32_t cfmp_kdf_set_salt(FFIKdf*, const uint8_t*, uint32_t);
//! uint32_t cfmp_kdf_set_iterations(FFIKdf*, uint32_t);
//! uint32_t cfmp_kdf_set_memory_cost(FFIKdf*, uint64_t);
//! uint32_t cfmp_kdf_set_parallelism(FFIKdf*, uint32_t);
//! uint32_t cfmp_kdf_set_hash(FFIKdf*, const char*);
//! uint32_t cfmp_kdf_derive(FFIKdf*, const uint8_t*, uint32_t, uint8_t*, uint32_t);
//! void     cfmp_kdf_destroy(FFIKdf*);
//! ```
//!
//! Algorithms the plugin may advertise (case-sensitive ASCII):
//! - `HKDF-SHA256`, `HKDF-SHA512`, `HKDF-SHA3-256`, `HKDF-SHA3-512`
//! - `PBKDF2-HMAC-SHA256`, `PBKDF2-HMAC-SHA512`
//! - `Argon2id`, `Argon2i`, `Argon2d` (RFC 9106)
//! - `Scrypt` (RFC 7914)
//! - `S2K-Simple`, `S2K-Salted`, `S2K-Iterated`, `S2K-Argon2` (OpenPGP / RFC 9580)
//!
//! The setters are KDF-family-specific: a plugin returns a non-zero
//! code from a setter that does not apply to its algorithm, and the
//! wrapper propagates that as `Error::PluginInternalError`. This module
//! owns the [`KdfInterface`] type and the registry kind; the
//! user-facing [`crate::kdf::Kdf`] wrapper lives in `src/kdf.rs`.

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

use crate::kdf::Kdf;

pub enum FFIKdf {}

pub type KdfCreateFnV0 =
    extern "C" fn(*const Confium, *mut *mut FFIKdf, *const c_char, Option<&Options>) -> u32;
const KDF_CREATE_FN_V0_NAME: &[u8] = b"cfmp_kdf_create\0";

pub type KdfSetSaltFnV0 = extern "C" fn(*mut FFIKdf, *const u8, u32) -> u32;
const KDF_SET_SALT_FN_V0_NAME: &[u8] = b"cfmp_kdf_set_salt\0";

pub type KdfSetIterationsFnV0 = extern "C" fn(*mut FFIKdf, u32) -> u32;
const KDF_SET_ITERATIONS_FN_V0_NAME: &[u8] = b"cfmp_kdf_set_iterations\0";

pub type KdfSetMemoryCostFnV0 = extern "C" fn(*mut FFIKdf, u64) -> u32;
const KDF_SET_MEMORY_COST_FN_V0_NAME: &[u8] = b"cfmp_kdf_set_memory_cost\0";

pub type KdfSetParallelismFnV0 = extern "C" fn(*mut FFIKdf, u32) -> u32;
const KDF_SET_PARALLELISM_FN_V0_NAME: &[u8] = b"cfmp_kdf_set_parallelism\0";

pub type KdfSetHashFnV0 = extern "C" fn(*mut FFIKdf, *const c_char) -> u32;
const KDF_SET_HASH_FN_V0_NAME: &[u8] = b"cfmp_kdf_set_hash\0";

pub type KdfDeriveFnV0 = extern "C" fn(*mut FFIKdf, *const u8, u32, *mut u8, u32) -> u32;
const KDF_DERIVE_FN_V0_NAME: &[u8] = b"cfmp_kdf_derive\0";

pub type KdfDestroyFnV0 = extern "C" fn(*mut FFIKdf) -> c_void;
const KDF_DESTROY_FN_V0_NAME: &[u8] = b"cfmp_kdf_destroy\0";

#[derive(Debug)]
pub struct KdfInterfaceV0 {
    pub create: Box<KdfCreateFnV0>,
    pub set_salt: Box<KdfSetSaltFnV0>,
    pub set_iterations: Box<KdfSetIterationsFnV0>,
    pub set_memory_cost: Box<KdfSetMemoryCostFnV0>,
    pub set_parallelism: Box<KdfSetParallelismFnV0>,
    pub set_hash: Box<KdfSetHashFnV0>,
    pub derive: Box<KdfDeriveFnV0>,
    pub destroy: Box<KdfDestroyFnV0>,
}

#[derive(Debug)]
pub enum KdfInterface {
    V0(KdfInterfaceV0),
}

/// Registry kind for the KDF interface. Lives next to the interface
/// it describes so registration stays co-located with the
/// implementation (open/closed-compliant).
pub struct KdfKind;

impl PluginInterfaceKind for KdfKind {
    fn name(&self) -> &'static str {
        "kdf"
    }

    fn max_version(&self) -> u8 {
        0
    }

    fn build(&self, lib: &Library, version: u8) -> Result<Option<Rc<dyn Any>>> {
        match version {
            0 => Ok(create_kdf_interface_v0(lib)?.map(|iface| Rc::new(iface) as Rc<dyn Any>)),
            _ => Ok(None),
        }
    }
}

register_interface!(KdfKind);

fn create_kdf_interface_v0(lib: &Library) -> Result<Option<KdfInterface>> {
    let iface = KdfInterfaceV0 {
        create: get_plugin_symbol::<KdfCreateFnV0>(lib, "kdf", KDF_CREATE_FN_V0_NAME)?,
        set_salt: get_plugin_symbol::<KdfSetSaltFnV0>(lib, "kdf", KDF_SET_SALT_FN_V0_NAME)?,
        set_iterations: get_plugin_symbol::<KdfSetIterationsFnV0>(
            lib,
            "kdf",
            KDF_SET_ITERATIONS_FN_V0_NAME,
        )?,
        set_memory_cost: get_plugin_symbol::<KdfSetMemoryCostFnV0>(
            lib,
            "kdf",
            KDF_SET_MEMORY_COST_FN_V0_NAME,
        )?,
        set_parallelism: get_plugin_symbol::<KdfSetParallelismFnV0>(
            lib,
            "kdf",
            KDF_SET_PARALLELISM_FN_V0_NAME,
        )?,
        set_hash: get_plugin_symbol::<KdfSetHashFnV0>(lib, "kdf", KDF_SET_HASH_FN_V0_NAME)?,
        derive: get_plugin_symbol::<KdfDeriveFnV0>(lib, "kdf", KDF_DERIVE_FN_V0_NAME)?,
        destroy: get_plugin_symbol::<KdfDestroyFnV0>(lib, "kdf", KDF_DESTROY_FN_V0_NAME)?,
    };
    Ok(Some(KdfInterface::V0(iface)))
}

/// Downcast a plugin's type-erased interface to a shared
/// [`KdfInterface`]. Owned by this module so consumers of the KDF
/// interface don't need to know about the registry.
pub fn interface_of(plugin: &crate::Plugin) -> Option<Rc<KdfInterface>> {
    plugin
        .interfaces
        .iter()
        .find_map(|i| i.clone_inner::<KdfInterface>())
}

fn cfm_kdf_create_(
    cfm: *const Confium,
    kdf: *mut *mut Kdf,
    algorithm: *const c_char,
    provider: *const c_char,
    opts: *const Options,
    _errptr: *mut *mut Error,
) -> Result<()> {
    check_not_null!(cfm);
    check_not_null!(kdf);
    check_not_null!(algorithm);
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
    unsafe {
        *kdf = Box::into_raw(Box::new(Kdf::new(cfm, &algorithm, provider, opts)?));
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kdf_create(
    cfm: *const Confium,
    kdf: *mut *mut Kdf,
    algorithm: *const c_char,
    provider: *const c_char,
    opts: *const Options,
    errptr: *mut *mut Error,
) -> u32 {
    cfm_kdf_create_(cfm, kdf, algorithm, provider, opts, errptr)
        .map_or_else(|e| ffi_return_err!(e, errptr), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kdf_set_salt(kdf: *mut Kdf, salt: *const u8, len: u32) -> u32 {
    if kdf.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let k = unsafe { &mut *kdf };
    let salt = unsafe { std::slice::from_raw_parts(salt, len as usize) };
    k.set_salt(salt).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kdf_set_iterations(kdf: *mut Kdf, n: u32) -> u32 {
    if kdf.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let k = unsafe { &mut *kdf };
    k.set_iterations(n).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kdf_set_memory_cost(kdf: *mut Kdf, bytes: u64) -> u32 {
    if kdf.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let k = unsafe { &mut *kdf };
    k.set_memory_cost(bytes).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kdf_set_parallelism(kdf: *mut Kdf, lanes: u32) -> u32 {
    if kdf.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let k = unsafe { &mut *kdf };
    k.set_parallelism(lanes).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kdf_set_hash(kdf: *mut Kdf, hash_name: *const c_char) -> u32 {
    if kdf.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let k = unsafe { &mut *kdf };
    match crate::ffi::utils::cstring(hash_name) {
        Ok(name) => k.set_hash(&name).map_or_else(|e| e.code(), |_| 0),
        Err(e) => e.code(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kdf_derive(
    kdf: *mut Kdf,
    input: *const u8,
    input_len: u32,
    out: *mut u8,
    out_len: u32,
) -> u32 {
    if kdf.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let k = unsafe { &mut *kdf };
    let input = unsafe { std::slice::from_raw_parts(input, input_len as usize) };
    let out = unsafe { std::slice::from_raw_parts_mut(out, out_len as usize) };
    k.derive(input, out).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kdf_destroy(kdf: *mut Kdf) -> u32 {
    if !kdf.is_null() {
        unsafe {
            std::mem::drop(Box::from_raw(kdf));
        }
    }
    0
}
