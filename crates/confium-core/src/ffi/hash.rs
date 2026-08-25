use std::any::Any;
use std::fmt;
use std::os::raw::c_char;
use std::rc::Rc;

use libloading::Library;

use crate::Confium;
use crate::Result;
use crate::error;
use crate::error::Error;
use crate::ffi::plugin::get_plugin_symbol;
use crate::ffi::registry::PluginInterfaceKind;
use crate::ffi::utils::cstring;
use crate::hash::Hash;
use crate::options::Options;
use crate::register_interface;

pub enum FFIHash {}

pub type HashCreateFnV0 =
    extern "C" fn(*const Confium, *mut *mut FFIHash, *const c_char, Option<&Options>) -> u32;
const HASH_CREATE_FN_V0_NAME: &[u8] = b"cfmp_hash_create\0";

pub type HashOutputSizeFnV0 = extern "C" fn(*const FFIHash, *mut u32) -> u32;
const HASH_OUTPUT_SIZE_FN_V0_NAME: &[u8] = b"cfmp_hash_output_size\0";

pub type HashBlockSizeFnV0 = extern "C" fn(*const FFIHash, *mut u32) -> u32;
const HASH_BLOCK_SIZE_FN_V0_NAME: &[u8] = b"cfmp_hash_block_size\0";

pub type HashUpdateFnV0 = extern "C" fn(*mut FFIHash, *const u8, u32) -> u32;
const HASH_UPDATE_FN_V0_NAME: &[u8] = b"cfmp_hash_update\0";

pub type HashResetFnV0 = extern "C" fn(*mut FFIHash) -> u32;
const HASH_RESET_FN_V0_NAME: &[u8] = b"cfmp_hash_reset\0";

pub type HashCloneFnV0 = extern "C" fn(*mut FFIHash, *mut *mut FFIHash) -> u32;
const HASH_CLONE_FN_V0_NAME: &[u8] = b"cfmp_hash_clone\0";

pub type HashFinalizeFnV0 = extern "C" fn(*mut FFIHash, *mut u8, u32) -> u32;
const HASH_FINALIZE_FN_V0_NAME: &[u8] = b"cfmp_hash_finalize\0";

pub type HashDestroyFnV0 = extern "C" fn(*mut FFIHash);
const HASH_DESTROY_FN_V0_NAME: &[u8] = b"cfmp_hash_destroy\0";

pub struct HashInterfaceV0 {
    pub create: Box<HashCreateFnV0>,
    pub output_size: Box<HashOutputSizeFnV0>,
    pub block_size: Box<HashBlockSizeFnV0>,
    pub update: Box<HashUpdateFnV0>,
    pub reset: Box<HashResetFnV0>,
    pub clone: Box<HashCloneFnV0>,
    pub finalize: Box<HashFinalizeFnV0>,
    pub destroy: Box<HashDestroyFnV0>,
}

impl fmt::Debug for HashInterfaceV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashInterfaceV0")
            .field("create", &((*self.create) as *const u8))
            .field("output_size", &((*self.output_size) as *const u8))
            .field("block_size", &((*self.block_size) as *const u8))
            .field("update", &((*self.update) as *const u8))
            .field("reset", &((*self.reset) as *const u8))
            .field("clone", &((*self.clone) as *const u8))
            .field("finalize", &((*self.finalize) as *const u8))
            .field("destroy", &((*self.destroy) as *const u8))
            .finish()
    }
}

#[derive(Debug)]
pub enum HashInterface {
    V0(HashInterfaceV0),
}

/// Registry kind for the hash interface. Lives next to the interface
/// it describes so the registration stays co-located with the
/// implementation (open/closed-compliant).
pub struct HashKind;

impl PluginInterfaceKind for HashKind {
    fn name(&self) -> &'static str {
        "hash"
    }

    fn max_version(&self) -> u8 {
        0
    }

    fn build(&self, lib: &Library, version: u8) -> Result<Option<Rc<dyn Any>>> {
        match version {
            0 => Ok(create_hash_interface_v0(lib)?.map(|iface| Rc::new(iface) as Rc<dyn Any>)),
            _ => Ok(None),
        }
    }
}

register_interface!(HashKind);

fn create_hash_interface_v0(lib: &Library) -> Result<Option<HashInterface>> {
    let iface = HashInterfaceV0 {
        create: get_plugin_symbol::<HashCreateFnV0>(lib, "hash", HASH_CREATE_FN_V0_NAME)?,
        output_size: get_plugin_symbol::<HashOutputSizeFnV0>(
            lib,
            "hash",
            HASH_OUTPUT_SIZE_FN_V0_NAME,
        )?,
        block_size: get_plugin_symbol::<HashBlockSizeFnV0>(
            lib,
            "hash",
            HASH_BLOCK_SIZE_FN_V0_NAME,
        )?,
        update: get_plugin_symbol::<HashUpdateFnV0>(lib, "hash", HASH_UPDATE_FN_V0_NAME)?,
        reset: get_plugin_symbol::<HashResetFnV0>(lib, "hash", HASH_RESET_FN_V0_NAME)?,
        clone: get_plugin_symbol::<HashCloneFnV0>(lib, "hash", HASH_CLONE_FN_V0_NAME)?,
        finalize: get_plugin_symbol::<HashFinalizeFnV0>(lib, "hash", HASH_FINALIZE_FN_V0_NAME)?,
        destroy: get_plugin_symbol::<HashDestroyFnV0>(lib, "hash", HASH_DESTROY_FN_V0_NAME)?,
    };
    Ok(Some(HashInterface::V0(iface)))
}

/// Downcast a plugin's type-erased interface back to a shared
/// [`HashInterface`]. Owned by this module so consumers of the hash
/// interface don't need to know about the registry.
pub fn interface_of(plugin: &crate::Plugin) -> Option<Rc<HashInterface>> {
    plugin
        .interfaces
        .iter()
        .find_map(|i| i.clone_inner::<HashInterface>())
}

fn cfm_hash_create_(
    cfm: *const Confium,
    hash: *mut *mut Hash,
    name: *const c_char,
    provider: *const c_char,
    opts: *const Options,
    _errptr: *mut *mut Error,
) -> Result<()> {
    check_not_null!(cfm);
    check_not_null!(hash);
    check_not_null!(name);
    let cfm = unsafe { &*cfm };
    let name = cstring(name)?;
    let provider = match provider.is_null() {
        true => None,
        false => Some(cstring(provider)?),
    };
    let provider = provider.as_deref();
    let opts = match opts.is_null() {
        true => None,
        false => Some(unsafe { &*opts }),
    };
    unsafe {
        *hash = Box::into_raw(Box::new(Hash::new(cfm, &name, provider, opts)?));
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_hash_create(
    cfm: *const Confium,
    hash: *mut *mut Hash,
    name: *const c_char,
    provider: *const c_char,
    opts: *const Options,
    errptr: *mut *mut Error,
) -> u32 {
    cfm_hash_create_(cfm, hash, name, provider, opts, errptr)
        .map_or_else(|e| ffi_return_err!(e, errptr), |_| 0)
}

fn cfm_hash_output_size_(hash: *mut Hash, size: *mut u32) -> Result<()> {
    unsafe {
        *size = (*hash).output_size()?;
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_hash_output_size(hash: *mut Hash, size: *mut u32) -> u32 {
    cfm_hash_output_size_(hash, size).map_or_else(|e| e.code(), |_| 0)
}

fn cfm_hash_block_size_(hash: *mut Hash, size: *mut u32) -> Result<()> {
    unsafe {
        *size = (*hash).block_size()?;
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_hash_block_size(hash: *mut Hash, size: *mut u32) -> u32 {
    cfm_hash_block_size_(hash, size).map_or_else(|e| e.code(), |_| 0)
}

fn cfm_hash_update_(hash: *mut Hash, data: *const u8, size: u32) -> Result<()> {
    unsafe {
        (*hash).update(std::slice::from_raw_parts(data, size as usize))?;
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_hash_update(hash: *mut Hash, data: *const u8, size: u32) -> u32 {
    cfm_hash_update_(hash, data, size).map_or_else(|e| e.code(), |_| 0)
}

fn cfm_hash_reset_(hash: *mut Hash) -> Result<()> {
    unsafe { (*hash).reset() }
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_hash_reset(hash: *mut Hash) -> u32 {
    cfm_hash_reset_(hash).map_or_else(|e| e.code(), |_| 0)
}

fn cfm_hash_clone_(src: *mut Hash, dst: *mut *mut Hash) -> Result<()> {
    unsafe { *dst = Box::into_raw(Box::new((*src).try_clone()?)) }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_hash_clone(src: *mut Hash, dst: *mut *mut Hash) -> u32 {
    cfm_hash_clone_(src, dst).map_or_else(|e| e.code(), |_| 0)
}

fn cfm_hash_finalize_(hash: *mut Hash, result: *mut u8, size: u32) -> Result<()> {
    unsafe {
        let vec = (*hash).finalize()?;
        if (size as usize) < vec.len() {
            return error::InsufficientBufferSnafu {}.fail();
        }
        std::ptr::copy(vec.as_ptr(), result, vec.len());
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_hash_finalize(hash: *mut Hash, result: *mut u8, size: u32) -> u32 {
    cfm_hash_finalize_(hash, result, size).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_hash_destroy(hash: *mut Hash) -> u32 {
    unsafe {
        if !hash.is_null() {
            std::mem::drop(Box::from_raw(hash));
        }
    }
    0
}
