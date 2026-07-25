//! KEM (key encapsulation mechanism) interface.
//!
//! Plugin contract — the plugin exports these C symbols with the
//! `cfmp_kem_` prefix. KEM has two distinct object types: an
//! encapsulator (sender side, holds the recipient's public key) and a
//! decapsulator (recipient side, holds the recipient's secret key).
//! A keypair-generation entry point and a shared-secret size query
//! round out the interface.
//!
//! ```c
//! uint32_t cfmp_kem_encapsulator_create(const Confium*, FFIKemEncapsulator**,
//!                                       const char* algorithm,
//!                                       const void* recipient_pubkey, uint32_t pk_len,
//!                                       const Option* opts);
//! uint32_t cfmp_kem_encapsulate(FFIKemEncapsulator*,
//!                               uint8_t* ct_out, uint32_t ct_max, uint32_t* ct_len,
//!                               uint8_t* ss_out, uint32_t ss_max, uint32_t* ss_len);
//! void     cfmp_kem_encapsulator_destroy(FFIKemEncapsulator*);
//!
//! uint32_t cfmp_kem_decapsulator_create(const Confium*, FFIKemDecapsulator**,
//!                                       const char* algorithm,
//!                                       const void* recipient_seckey, uint32_t sk_len,
//!                                       const Option* opts);
//! uint32_t cfmp_kem_decapsulate(FFIKemDecapsulator*,
//!                               const uint8_t* ciphertext, uint32_t ct_len,
//!                               uint8_t* ss_out, uint32_t ss_max, uint32_t* ss_len);
//! void     cfmp_kem_decapsulator_destroy(FFIKemDecapsulator*);
//!
//! uint32_t cfmp_kem_shared_secret_size(const Confium*, const char* algorithm, uint32_t* out_size);
//! uint32_t cfmp_kem_keypair_generate(const Confium*, const char* algorithm,
//!                                    const uint8_t* seed_optional, uint32_t seed_len,
//!                                    uint8_t* pk_out, uint32_t pk_max, uint32_t* pk_len,
//!                                    uint8_t* sk_out, uint32_t sk_max, uint32_t* sk_len);
//! ```
//!
//! Algorithms the plugin may advertise (case-sensitive ASCII):
//! - Classical KEMs: `RSAES-PKCS1-v1_5`, `RSAES-OAEP-SHA256`,
//!   `ECDH-P256`/`P384`/`P521`, `ECDH-X25519`, `ECDH-X448`,
//!   `ECDH-BrainpoolP256r1`/`P384r1`/`P512r1`, `SM2-Encryption`.
//! - PQC composite: `Kyber768-X25519`, `Kyber1024-X448`,
//!   `Kyber768-P384`, `Kyber1024-P521`, `Kyber768-BrainpoolP384r1`,
//!   `Kyber1024-BrainpoolP512r1`.
//! - Pure PQC: `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`.
//!
//! The split into encapsulator/decapsulator (rather than
//! encrypter/decrypter) matches the NIST PQC API and the standard
//! ML-KEM shape. This module owns the [`KemInterface`] type and the
//! registry kind; the user-facing [`crate::kem::KemEncapsulator`] and
//! [`crate::kem::KemDecapsulator`] wrappers live in `src/kem.rs`.

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

use crate::kem::{KemDecapsulator, KemEncapsulator};

/// Opaque plugin handle for the sender side of a KEM.
pub enum FFIKemEncapsulator {}

/// Opaque plugin handle for the recipient side of a KEM.
pub enum FFIKemDecapsulator {}

pub type KemEncapsulatorCreateFnV0 = extern "C" fn(
    *const Confium,
    *mut *mut FFIKemEncapsulator,
    *const c_char,
    *const c_void,
    u32,
    Option<&Options>,
) -> u32;
const KEM_ENCAPSULATOR_CREATE_FN_V0_NAME: &[u8] = b"cfmp_kem_encapsulator_create\0";

pub type KemEncapsulateFnV0 =
    extern "C" fn(*mut FFIKemEncapsulator, *mut u8, u32, *mut u32, *mut u8, u32, *mut u32) -> u32;
const KEM_ENCAPSULATE_FN_V0_NAME: &[u8] = b"cfmp_kem_encapsulate\0";

pub type KemEncapsulatorDestroyFnV0 = extern "C" fn(*mut FFIKemEncapsulator) -> c_void;
const KEM_ENCAPSULATOR_DESTROY_FN_V0_NAME: &[u8] = b"cfmp_kem_encapsulator_destroy\0";

pub type KemDecapsulatorCreateFnV0 = extern "C" fn(
    *const Confium,
    *mut *mut FFIKemDecapsulator,
    *const c_char,
    *const c_void,
    u32,
    Option<&Options>,
) -> u32;
const KEM_DECAPSULATOR_CREATE_FN_V0_NAME: &[u8] = b"cfmp_kem_decapsulator_create\0";

pub type KemDecapsulateFnV0 =
    extern "C" fn(*mut FFIKemDecapsulator, *const u8, u32, *mut u8, u32, *mut u32) -> u32;
const KEM_DECAPSULATE_FN_V0_NAME: &[u8] = b"cfmp_kem_decapsulate\0";

pub type KemDecapsulatorDestroyFnV0 = extern "C" fn(*mut FFIKemDecapsulator) -> c_void;
const KEM_DECAPSULATOR_DESTROY_FN_V0_NAME: &[u8] = b"cfmp_kem_decapsulator_destroy\0";

pub type KemSharedSecretSizeFnV0 = extern "C" fn(*const Confium, *const c_char, *mut u32) -> u32;
const KEM_SHARED_SECRET_SIZE_FN_V0_NAME: &[u8] = b"cfmp_kem_shared_secret_size\0";

pub type KemKeypairGenerateFnV0 = extern "C" fn(
    *const Confium,
    *const c_char,
    *const u8,
    u32,
    *mut u8,
    u32,
    *mut u32,
    *mut u8,
    u32,
    *mut u32,
) -> u32;
const KEM_KEYPAIR_GENERATE_FN_V0_NAME: &[u8] = b"cfmp_kem_keypair_generate\0";

#[derive(Debug)]
pub struct KemInterfaceV0 {
    pub encapsulator_create: Box<KemEncapsulatorCreateFnV0>,
    pub encapsulate: Box<KemEncapsulateFnV0>,
    pub encapsulator_destroy: Box<KemEncapsulatorDestroyFnV0>,
    pub decapsulator_create: Box<KemDecapsulatorCreateFnV0>,
    pub decapsulate: Box<KemDecapsulateFnV0>,
    pub decapsulator_destroy: Box<KemDecapsulatorDestroyFnV0>,
    pub shared_secret_size: Box<KemSharedSecretSizeFnV0>,
    pub keypair_generate: Box<KemKeypairGenerateFnV0>,
}

#[derive(Debug)]
pub enum KemInterface {
    V0(KemInterfaceV0),
}

/// Registry kind for the KEM interface. Lives next to the interface
/// it describes so registration stays co-located with the
/// implementation (open/closed-compliant).
pub struct KemKind;

impl PluginInterfaceKind for KemKind {
    fn name(&self) -> &'static str {
        "kem"
    }

    fn max_version(&self) -> u8 {
        0
    }

    fn build(&self, lib: &Library, version: u8) -> Result<Option<Rc<dyn Any>>> {
        match version {
            0 => Ok(create_kem_interface_v0(lib)?.map(|iface| Rc::new(iface) as Rc<dyn Any>)),
            _ => Ok(None),
        }
    }
}

register_interface!(KemKind);

fn create_kem_interface_v0(lib: &Library) -> Result<Option<KemInterface>> {
    let iface = KemInterfaceV0 {
        encapsulator_create: get_plugin_symbol::<KemEncapsulatorCreateFnV0>(
            lib,
            "kem",
            KEM_ENCAPSULATOR_CREATE_FN_V0_NAME,
        )?,
        encapsulate: get_plugin_symbol::<KemEncapsulateFnV0>(
            lib,
            "kem",
            KEM_ENCAPSULATE_FN_V0_NAME,
        )?,
        encapsulator_destroy: get_plugin_symbol::<KemEncapsulatorDestroyFnV0>(
            lib,
            "kem",
            KEM_ENCAPSULATOR_DESTROY_FN_V0_NAME,
        )?,
        decapsulator_create: get_plugin_symbol::<KemDecapsulatorCreateFnV0>(
            lib,
            "kem",
            KEM_DECAPSULATOR_CREATE_FN_V0_NAME,
        )?,
        decapsulate: get_plugin_symbol::<KemDecapsulateFnV0>(
            lib,
            "kem",
            KEM_DECAPSULATE_FN_V0_NAME,
        )?,
        decapsulator_destroy: get_plugin_symbol::<KemDecapsulatorDestroyFnV0>(
            lib,
            "kem",
            KEM_DECAPSULATOR_DESTROY_FN_V0_NAME,
        )?,
        shared_secret_size: get_plugin_symbol::<KemSharedSecretSizeFnV0>(
            lib,
            "kem",
            KEM_SHARED_SECRET_SIZE_FN_V0_NAME,
        )?,
        keypair_generate: get_plugin_symbol::<KemKeypairGenerateFnV0>(
            lib,
            "kem",
            KEM_KEYPAIR_GENERATE_FN_V0_NAME,
        )?,
    };
    Ok(Some(KemInterface::V0(iface)))
}

/// Downcast a plugin's type-erased interface to a shared
/// [`KemInterface`]. Owned by this module so consumers of the KEM
/// interface don't need to know about the registry.
pub fn interface_of(plugin: &crate::Plugin) -> Option<Rc<KemInterface>> {
    plugin
        .interfaces
        .iter()
        .find_map(|i| i.clone_inner::<KemInterface>())
}

// Parameter count is fixed by the FFI wire contract; cannot be reduced
// without changing the C ABI.
#[allow(clippy::too_many_arguments)]
fn cfm_kem_encapsulator_create_(
    cfm: *const Confium,
    enc: *mut *mut KemEncapsulator,
    algorithm: *const c_char,
    recipient_pubkey: *const c_void,
    pk_len: u32,
    provider: *const c_char,
    opts: *const Options,
    _errptr: *mut *mut Error,
) -> Result<()> {
    check_not_null!(cfm);
    check_not_null!(enc);
    check_not_null!(algorithm);
    check_not_null!(recipient_pubkey);
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
    let recipient_pubkey =
        unsafe { std::slice::from_raw_parts(recipient_pubkey as *const u8, pk_len as usize) };
    unsafe {
        *enc = Box::into_raw(Box::new(KemEncapsulator::new(
            cfm,
            &algorithm,
            recipient_pubkey,
            provider,
            opts,
        )?));
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kem_encapsulator_create(
    cfm: *const Confium,
    enc: *mut *mut KemEncapsulator,
    algorithm: *const c_char,
    recipient_pubkey: *const c_void,
    pk_len: u32,
    provider: *const c_char,
    opts: *const Options,
    errptr: *mut *mut Error,
) -> u32 {
    cfm_kem_encapsulator_create_(
        cfm,
        enc,
        algorithm,
        recipient_pubkey,
        pk_len,
        provider,
        opts,
        errptr,
    )
    .map_or_else(|e| ffi_return_err!(e, errptr), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kem_encapsulate(
    enc: *mut KemEncapsulator,
    ct_out: *mut u8,
    ct_max: u32,
    ct_len: *mut u32,
    ss_out: *mut u8,
    ss_max: u32,
    ss_len: *mut u32,
) -> u32 {
    if enc.is_null() || ct_len.is_null() || ss_len.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if ct_out.is_null() && ct_max != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if ss_out.is_null() && ss_max != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let e = unsafe { &mut *enc };
    let ct_out = if ct_out.is_null() {
        &mut [][..]
    } else {
        unsafe { std::slice::from_raw_parts_mut(ct_out, ct_max as usize) }
    };
    let ss_out = if ss_out.is_null() {
        &mut [][..]
    } else {
        unsafe { std::slice::from_raw_parts_mut(ss_out, ss_max as usize) }
    };
    match e.encapsulate(ct_out, ss_out) {
        Ok((ct_written, ss_written)) => {
            unsafe {
                *ct_len = ct_written as u32;
                *ss_len = ss_written as u32;
            }
            0
        }
        Err(err) => err.code(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kem_encapsulator_destroy(enc: *mut KemEncapsulator) -> u32 {
    if !enc.is_null() {
        unsafe {
            std::mem::drop(Box::from_raw(enc));
        }
    }
    0
}

// Parameter count is fixed by the FFI wire contract; cannot be reduced
// without changing the C ABI.
#[allow(clippy::too_many_arguments)]
fn cfm_kem_decapsulator_create_(
    cfm: *const Confium,
    dec: *mut *mut KemDecapsulator,
    algorithm: *const c_char,
    recipient_seckey: *const c_void,
    sk_len: u32,
    provider: *const c_char,
    opts: *const Options,
    _errptr: *mut *mut Error,
) -> Result<()> {
    check_not_null!(cfm);
    check_not_null!(dec);
    check_not_null!(algorithm);
    check_not_null!(recipient_seckey);
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
    let recipient_seckey =
        unsafe { std::slice::from_raw_parts(recipient_seckey as *const u8, sk_len as usize) };
    unsafe {
        *dec = Box::into_raw(Box::new(KemDecapsulator::new(
            cfm,
            &algorithm,
            recipient_seckey,
            provider,
            opts,
        )?));
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kem_decapsulator_create(
    cfm: *const Confium,
    dec: *mut *mut KemDecapsulator,
    algorithm: *const c_char,
    recipient_seckey: *const c_void,
    sk_len: u32,
    provider: *const c_char,
    opts: *const Options,
    errptr: *mut *mut Error,
) -> u32 {
    cfm_kem_decapsulator_create_(
        cfm,
        dec,
        algorithm,
        recipient_seckey,
        sk_len,
        provider,
        opts,
        errptr,
    )
    .map_or_else(|e| ffi_return_err!(e, errptr), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kem_decapsulate(
    dec: *mut KemDecapsulator,
    ciphertext: *const u8,
    ct_len: u32,
    ss_out: *mut u8,
    ss_max: u32,
    ss_len: *mut u32,
) -> u32 {
    if dec.is_null() || ss_len.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if ciphertext.is_null() && ct_len != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if ss_out.is_null() && ss_max != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let d = unsafe { &mut *dec };
    let ciphertext = if ciphertext.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ciphertext, ct_len as usize) }
    };
    let ss_out = if ss_out.is_null() {
        &mut [][..]
    } else {
        unsafe { std::slice::from_raw_parts_mut(ss_out, ss_max as usize) }
    };
    match d.decapsulate(ciphertext, ss_out) {
        Ok(ss_written) => {
            unsafe {
                *ss_len = ss_written as u32;
            }
            0
        }
        Err(err) => err.code(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kem_decapsulator_destroy(dec: *mut KemDecapsulator) -> u32 {
    if !dec.is_null() {
        unsafe {
            std::mem::drop(Box::from_raw(dec));
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_kem_shared_secret_size(
    cfm: *const Confium,
    algorithm: *const c_char,
    out_size: *mut u32,
) -> u32 {
    if cfm.is_null() || algorithm.is_null() || out_size.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let cfm = unsafe { &*cfm };
    let algorithm = match crate::ffi::utils::cstring(algorithm) {
        Ok(s) => s,
        Err(e) => return e.code(),
    };
    match KemEncapsulator::shared_secret_size(cfm, &algorithm) {
        Ok(size) => {
            unsafe {
                *out_size = size;
            }
            0
        }
        Err(e) => e.code(),
    }
}

// Parameter count is fixed by the FFI wire contract; cannot be reduced
// without changing the C ABI.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub extern "C" fn cfm_kem_keypair_generate(
    cfm: *const Confium,
    algorithm: *const c_char,
    seed: *const u8,
    seed_len: u32,
    pk_out: *mut u8,
    pk_max: u32,
    pk_len: *mut u32,
    sk_out: *mut u8,
    sk_max: u32,
    sk_len: *mut u32,
) -> u32 {
    if cfm.is_null() || algorithm.is_null() || pk_len.is_null() || sk_len.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if pk_out.is_null() && pk_max != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if sk_out.is_null() && sk_max != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if seed.is_null() && seed_len != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let cfm = unsafe { &*cfm };
    let algorithm = match crate::ffi::utils::cstring(algorithm) {
        Ok(s) => s,
        Err(e) => return e.code(),
    };
    let seed = if seed.is_null() {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(seed, seed_len as usize) })
    };
    let pk_out = if pk_out.is_null() {
        &mut [][..]
    } else {
        unsafe { std::slice::from_raw_parts_mut(pk_out, pk_max as usize) }
    };
    let sk_out = if sk_out.is_null() {
        &mut [][..]
    } else {
        unsafe { std::slice::from_raw_parts_mut(sk_out, sk_max as usize) }
    };
    match KemEncapsulator::keypair_generate(cfm, &algorithm, seed, pk_out, sk_out) {
        Ok((pk_written, sk_written)) => {
            unsafe {
                *pk_len = pk_written as u32;
                *sk_len = sk_written as u32;
            }
            0
        }
        Err(e) => e.code(),
    }
}
