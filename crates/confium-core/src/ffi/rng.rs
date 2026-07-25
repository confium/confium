//! RNG (cryptographically-secure random number generator) interface.
//!
//! Plugin contract — the plugin exports these C symbols with the
//! `cfmp_rng_` prefix:
//!
//! ```c
//! uint32_t cfmp_rng_create(const Confium*, FFIRng**, const char* algorithm, const Option*);
//! uint32_t cfmp_rng_reseed(FFIRng*, const uint8_t*, uint32_t);
//! uint32_t cfmp_rng_add_entropy(FFIRng*, const uint8_t*, uint32_t);
//! uint32_t cfmp_rng_generate(FFIRng*, uint8_t*, uint32_t);
//! void     cfmp_rng_destroy(FFIRng*);
//! ```
//!
//! Algorithms the plugin may advertise (case-sensitive ASCII):
//! - `System` — OS CSPRNG (getrandom / BCryptGenRandom / SecRandomCopyBytes)
//! - `ChaCha20DRBG` — NIST SP 800-90A
//! - `HMAC-DRBG-SHA256`, `HMAC-DRBG-SHA512`
//!
//! This module owns the [`RngInterface`] type and the registry kind;
//! the user-facing [`crate::rng::Rng`] wrapper lives in `src/rng.rs`.

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

use crate::rng::Rng;

pub enum FFIRng {}

pub type RngCreateFnV0 =
    extern "C" fn(*const Confium, *mut *mut FFIRng, *const c_char, Option<&Options>) -> u32;
const RNG_CREATE_FN_V0_NAME: &[u8] = b"cfmp_rng_create\0";

pub type RngReseedFnV0 = extern "C" fn(*mut FFIRng, *const u8, u32) -> u32;
const RNG_RESEED_FN_V0_NAME: &[u8] = b"cfmp_rng_reseed\0";

pub type RngAddEntropyFnV0 = extern "C" fn(*mut FFIRng, *const u8, u32) -> u32;
const RNG_ADD_ENTROPY_FN_V0_NAME: &[u8] = b"cfmp_rng_add_entropy\0";

pub type RngGenerateFnV0 = extern "C" fn(*mut FFIRng, *mut u8, u32) -> u32;
const RNG_GENERATE_FN_V0_NAME: &[u8] = b"cfmp_rng_generate\0";

pub type RngDestroyFnV0 = extern "C" fn(*mut FFIRng) -> c_void;
const RNG_DESTROY_FN_V0_NAME: &[u8] = b"cfmp_rng_destroy\0";

#[derive(Debug)]
pub struct RngInterfaceV0 {
    pub create: Box<RngCreateFnV0>,
    pub reseed: Box<RngReseedFnV0>,
    pub add_entropy: Box<RngAddEntropyFnV0>,
    pub generate: Box<RngGenerateFnV0>,
    pub destroy: Box<RngDestroyFnV0>,
}

#[derive(Debug)]
pub enum RngInterface {
    V0(RngInterfaceV0),
}

/// Registry kind for the RNG interface. Lives next to the interface
/// it describes so registration stays co-located with the
/// implementation (open/closed-compliant).
pub struct RngKind;

impl PluginInterfaceKind for RngKind {
    fn name(&self) -> &'static str {
        "rng"
    }

    fn max_version(&self) -> u8 {
        0
    }

    fn build(&self, lib: &Library, version: u8) -> Result<Option<Rc<dyn Any>>> {
        match version {
            0 => Ok(create_rng_interface_v0(lib)?.map(|iface| Rc::new(iface) as Rc<dyn Any>)),
            _ => Ok(None),
        }
    }
}

register_interface!(RngKind);

fn create_rng_interface_v0(lib: &Library) -> Result<Option<RngInterface>> {
    let iface = RngInterfaceV0 {
        create: get_plugin_symbol::<RngCreateFnV0>(lib, "rng", RNG_CREATE_FN_V0_NAME)?,
        reseed: get_plugin_symbol::<RngReseedFnV0>(lib, "rng", RNG_RESEED_FN_V0_NAME)?,
        add_entropy: get_plugin_symbol::<RngAddEntropyFnV0>(
            lib,
            "rng",
            RNG_ADD_ENTROPY_FN_V0_NAME,
        )?,
        generate: get_plugin_symbol::<RngGenerateFnV0>(lib, "rng", RNG_GENERATE_FN_V0_NAME)?,
        destroy: get_plugin_symbol::<RngDestroyFnV0>(lib, "rng", RNG_DESTROY_FN_V0_NAME)?,
    };
    Ok(Some(RngInterface::V0(iface)))
}

/// Downcast a plugin's type-erased interface to a shared
/// [`RngInterface`]. Owned by this module so consumers of the RNG
/// interface don't need to know about the registry.
pub fn interface_of(plugin: &crate::Plugin) -> Option<Rc<RngInterface>> {
    plugin
        .interfaces
        .iter()
        .find_map(|i| i.clone_inner::<RngInterface>())
}

fn cfm_rng_create_(
    cfm: *const Confium,
    rng: *mut *mut Rng,
    algorithm: *const c_char,
    provider: *const c_char,
    opts: *const Options,
    _errptr: *mut *mut Error,
) -> Result<()> {
    check_not_null!(cfm);
    check_not_null!(rng);
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
        *rng = Box::into_raw(Box::new(Rng::new(cfm, &algorithm, provider, opts)?));
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_rng_create(
    cfm: *const Confium,
    rng: *mut *mut Rng,
    algorithm: *const c_char,
    provider: *const c_char,
    opts: *const Options,
    errptr: *mut *mut Error,
) -> u32 {
    cfm_rng_create_(cfm, rng, algorithm, provider, opts, errptr)
        .map_or_else(|e| ffi_return_err!(e, errptr), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_rng_reseed(rng: *mut Rng, data: *const u8, len: u32) -> u32 {
    if rng.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let r = unsafe { &mut *rng };
    let data = unsafe { std::slice::from_raw_parts(data, len as usize) };
    r.reseed(data).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_rng_add_entropy(rng: *mut Rng, data: *const u8, len: u32) -> u32 {
    if rng.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let r = unsafe { &mut *rng };
    let data = unsafe { std::slice::from_raw_parts(data, len as usize) };
    r.add_entropy(data).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_rng_generate(rng: *mut Rng, out: *mut u8, len: u32) -> u32 {
    if rng.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let r = unsafe { &mut *rng };
    let out = unsafe { std::slice::from_raw_parts_mut(out, len as usize) };
    r.generate(out).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_rng_destroy(rng: *mut Rng) -> u32 {
    if !rng.is_null() {
        unsafe {
            std::mem::drop(Box::from_raw(rng));
        }
    }
    0
}
