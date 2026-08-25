//! Asymmetric signature interface.
//!
//! Plugin contract — the plugin exports these C symbols with the
//! `cfmp_sig_` prefix:
//!
//! ```c
//! uint32_t cfmp_sig_signer_create(
//!     const Confium*, FFISigner**, const char* algorithm,
//!     const void* secret_key, uint32_t sk_len, const Option*);
//! uint32_t cfmp_sig_signer_set_hash(FFISigner*, const char* hash_name);
//! uint32_t cfmp_sig_signer_update(FFISigner*, const uint8_t*, uint32_t);
//! uint32_t cfmp_sig_signer_finalize(FFISigner*, uint8_t* sig, uint32_t sig_max, uint32_t* sig_len);
//! void      cfmp_sig_signer_destroy(FFISigner*);
//!
//! uint32_t cfmp_sig_verifier_create(
//!     const Confium*, FFIVerifier**, const char* algorithm,
//!     const void* public_key, uint32_t pk_len, const Option*);
//! uint32_t cfmp_sig_verifier_set_hash(FFIVerifier*, const char* hash_name);
//! uint32_t cfmp_sig_verifier_update(FFIVerifier*, const uint8_t*, uint32_t);
//! uint32_t cfmp_sig_verifier_finalize(FFIVerifier*, const uint8_t* sig, uint32_t sig_len);
//! void      cfmp_sig_verifier_destroy(FFIVerifier*);
//!
//! uint32_t cfmp_sig_keypair_generate(
//!     const Confium*, const char* algorithm,
//!     const uint8_t* seed_optional, uint32_t seed_len,
//!     uint8_t* pk_out, uint32_t pk_max, uint32_t* pk_len,
//!     uint8_t* sk_out, uint32_t sk_max, uint32_t* sk_len);
//! ```
//!
//! Algorithms the plugin may advertise (case-sensitive ASCII):
//!
//! Classical:
//! - `RSA-1024`, `RSA-2048`, `RSA-3072`, `RSA-4096`
//! - `DSA`
//! - `ECDSA-P256`, `ECDSA-P384`, `ECDSA-P521`, `ECDSA-secp256k1`,
//!   `ECDSA-brainpool256r1`, `ECDSA-brainpool384r1`, `ECDSA-brainpool512r1`
//! - `EdDSA`, `Ed25519`, `Ed448`
//! - `SM2`
//!
//! PQC composite:
//! - `Dilithium3-Ed25519`, `Dilithium5-Ed448`, `Dilithium3-P384`,
//!   `Dilithium5-P521`, `Dilithium3-BrainpoolP384r1`,
//!   `Dilithium5-BrainpoolP512r1`
//!
//! PQC standalone:
//! - `SLH-DSA-SHAKE-128f`, `SLH-DSA-SHAKE-128s`, `SLH-DSA-SHAKE-256s`
//!
//! Composite signatures (e.g. `Dilithium3-Ed25519`) are atomic from
//! Confium's perspective: one key, one signature, one verify call. The
//! plugin internally produces the classical and PQC signatures and
//! concatenates them per RFC draft-ietf-openpgp-pqc.
//!
//! This module owns the [`SignerInterface`] and [`VerifierInterface`]
//! types and the registry kind; the user-facing [`crate::signature`]
//! wrappers (`Signer`, `Verifier`, `Keypair`) live in
//! `src/signature.rs`.

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

use crate::signature::{Keypair, Signer, Verifier};

pub enum FFISigner {}
pub enum FFIVerifier {}

// ---------------------------------------------------------------------
// Signer interface
// ---------------------------------------------------------------------

pub type SigSignerCreateFnV0 = extern "C" fn(
    *const Confium,
    *mut *mut FFISigner,
    *const c_char,
    *const c_void,
    u32,
    Option<&Options>,
) -> u32;
const SIG_SIGNER_CREATE_FN_V0_NAME: &[u8] = b"cfmp_sig_signer_create\0";

pub type SigSignerSetHashFnV0 = extern "C" fn(*mut FFISigner, *const c_char) -> u32;
const SIG_SIGNER_SET_HASH_FN_V0_NAME: &[u8] = b"cfmp_sig_signer_set_hash\0";

pub type SigSignerUpdateFnV0 = extern "C" fn(*mut FFISigner, *const u8, u32) -> u32;
const SIG_SIGNER_UPDATE_FN_V0_NAME: &[u8] = b"cfmp_sig_signer_update\0";

pub type SigSignerFinalizeFnV0 = extern "C" fn(*mut FFISigner, *mut u8, u32, *mut u32) -> u32;
const SIG_SIGNER_FINALIZE_FN_V0_NAME: &[u8] = b"cfmp_sig_signer_finalize\0";

pub type SigSignerDestroyFnV0 = extern "C" fn(*mut FFISigner);
const SIG_SIGNER_DESTROY_FN_V0_NAME: &[u8] = b"cfmp_sig_signer_destroy\0";

#[derive(Debug)]
pub struct SignerInterfaceV0 {
    pub create: Box<SigSignerCreateFnV0>,
    pub set_hash: Box<SigSignerSetHashFnV0>,
    pub update: Box<SigSignerUpdateFnV0>,
    pub finalize: Box<SigSignerFinalizeFnV0>,
    pub destroy: Box<SigSignerDestroyFnV0>,
}

#[derive(Debug)]
pub enum SignerInterface {
    V0(SignerInterfaceV0),
}

// ---------------------------------------------------------------------
// Verifier interface
// ---------------------------------------------------------------------

pub type SigVerifierCreateFnV0 = extern "C" fn(
    *const Confium,
    *mut *mut FFIVerifier,
    *const c_char,
    *const c_void,
    u32,
    Option<&Options>,
) -> u32;
const SIG_VERIFIER_CREATE_FN_V0_NAME: &[u8] = b"cfmp_sig_verifier_create\0";

pub type SigVerifierSetHashFnV0 = extern "C" fn(*mut FFIVerifier, *const c_char) -> u32;
const SIG_VERIFIER_SET_HASH_FN_V0_NAME: &[u8] = b"cfmp_sig_verifier_set_hash\0";

pub type SigVerifierUpdateFnV0 = extern "C" fn(*mut FFIVerifier, *const u8, u32) -> u32;
const SIG_VERIFIER_UPDATE_FN_V0_NAME: &[u8] = b"cfmp_sig_verifier_update\0";

/// Returns 0 if the signature is valid, non-zero if invalid (or any
/// other plugin error). The wrapper distinguishes a verification
/// failure from a plugin internal error via the wire convention: the
/// plugin returns the well-known verification-failed code for an
/// invalid signature and any other non-zero code for an internal fault.
pub type SigVerifierFinalizeFnV0 = extern "C" fn(*mut FFIVerifier, *const u8, u32) -> u32;
const SIG_VERIFIER_FINALIZE_FN_V0_NAME: &[u8] = b"cfmp_sig_verifier_finalize\0";

pub type SigVerifierDestroyFnV0 = extern "C" fn(*mut FFIVerifier);
const SIG_VERIFIER_DESTROY_FN_V0_NAME: &[u8] = b"cfmp_sig_verifier_destroy\0";

#[derive(Debug)]
pub struct VerifierInterfaceV0 {
    pub create: Box<SigVerifierCreateFnV0>,
    pub set_hash: Box<SigVerifierSetHashFnV0>,
    pub update: Box<SigVerifierUpdateFnV0>,
    pub finalize: Box<SigVerifierFinalizeFnV0>,
    pub destroy: Box<SigVerifierDestroyFnV0>,
}

#[derive(Debug)]
pub enum VerifierInterface {
    V0(VerifierInterfaceV0),
}

// ---------------------------------------------------------------------
// Keypair generation interface
// ---------------------------------------------------------------------

pub type SigKeypairGenerateFnV0 = extern "C" fn(
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
const SIG_KEYPAIR_GENERATE_FN_V0_NAME: &[u8] = b"cfmp_sig_keypair_generate\0";

#[derive(Debug)]
pub struct KeypairInterfaceV0 {
    pub generate: Box<SigKeypairGenerateFnV0>,
}

#[derive(Debug)]
pub enum KeypairInterface {
    V0(KeypairInterfaceV0),
}

// ---------------------------------------------------------------------
// Registry kind
// ---------------------------------------------------------------------

/// Registry kind for the signature interface. Lives next to the
/// interface it describes so registration stays co-located with the
/// implementation (open/closed-compliant). A single plugin interface
/// advertises signer, verifier, and keypair-generation capability
/// together; the plugin dispatches internally based on which
/// `cfmp_sig_*` symbols are called.
pub struct SignatureKind;

impl PluginInterfaceKind for SignatureKind {
    fn name(&self) -> &'static str {
        "signature"
    }

    fn max_version(&self) -> u8 {
        0
    }

    fn build(&self, lib: &Library, version: u8) -> Result<Option<Rc<dyn Any>>> {
        match version {
            0 => Ok(Some(
                Rc::new(SignatureInterface::build_v0(lib)?) as Rc<dyn Any>
            )),
            _ => Ok(None),
        }
    }
}

register_interface!(SignatureKind);

/// The full signature interface a plugin offers at version 0: a signer
/// half, a verifier half, and a keypair-generation entry point. All
/// three are present for a v0 plugin; individual algorithms may not be
/// supported, which the plugin signals by returning a non-zero code
/// from the relevant call.
#[derive(Debug)]
pub struct SignatureInterface {
    pub signer: SignerInterface,
    pub verifier: VerifierInterface,
    pub keypair: KeypairInterface,
}

impl SignatureInterface {
    fn build_v0(lib: &Library) -> Result<SignatureInterface> {
        let signer = SignerInterfaceV0 {
            create: get_plugin_symbol::<SigSignerCreateFnV0>(
                lib,
                "signature",
                SIG_SIGNER_CREATE_FN_V0_NAME,
            )?,
            set_hash: get_plugin_symbol::<SigSignerSetHashFnV0>(
                lib,
                "signature",
                SIG_SIGNER_SET_HASH_FN_V0_NAME,
            )?,
            update: get_plugin_symbol::<SigSignerUpdateFnV0>(
                lib,
                "signature",
                SIG_SIGNER_UPDATE_FN_V0_NAME,
            )?,
            finalize: get_plugin_symbol::<SigSignerFinalizeFnV0>(
                lib,
                "signature",
                SIG_SIGNER_FINALIZE_FN_V0_NAME,
            )?,
            destroy: get_plugin_symbol::<SigSignerDestroyFnV0>(
                lib,
                "signature",
                SIG_SIGNER_DESTROY_FN_V0_NAME,
            )?,
        };
        let verifier = VerifierInterfaceV0 {
            create: get_plugin_symbol::<SigVerifierCreateFnV0>(
                lib,
                "signature",
                SIG_VERIFIER_CREATE_FN_V0_NAME,
            )?,
            set_hash: get_plugin_symbol::<SigVerifierSetHashFnV0>(
                lib,
                "signature",
                SIG_VERIFIER_SET_HASH_FN_V0_NAME,
            )?,
            update: get_plugin_symbol::<SigVerifierUpdateFnV0>(
                lib,
                "signature",
                SIG_VERIFIER_UPDATE_FN_V0_NAME,
            )?,
            finalize: get_plugin_symbol::<SigVerifierFinalizeFnV0>(
                lib,
                "signature",
                SIG_VERIFIER_FINALIZE_FN_V0_NAME,
            )?,
            destroy: get_plugin_symbol::<SigVerifierDestroyFnV0>(
                lib,
                "signature",
                SIG_VERIFIER_DESTROY_FN_V0_NAME,
            )?,
        };
        let keypair = KeypairInterfaceV0 {
            generate: get_plugin_symbol::<SigKeypairGenerateFnV0>(
                lib,
                "signature",
                SIG_KEYPAIR_GENERATE_FN_V0_NAME,
            )?,
        };
        Ok(SignatureInterface {
            signer: SignerInterface::V0(signer),
            verifier: VerifierInterface::V0(verifier),
            keypair: KeypairInterface::V0(keypair),
        })
    }
}

/// Downcast a plugin's type-erased interface to a shared
/// [`SignatureInterface`]. Owned by this module so consumers of the
/// signature interface don't need to know about the registry.
pub fn interface_of(plugin: &crate::Plugin) -> Option<Rc<SignatureInterface>> {
    plugin
        .interfaces
        .iter()
        .find_map(|i| i.clone_inner::<SignatureInterface>())
}

// ---------------------------------------------------------------------
// cfm_sig_signer_* entry points
// ---------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn cfm_sig_signer_create_(
    cfm: *const Confium,
    signer: *mut *mut Signer,
    algorithm: *const c_char,
    secret_key: *const c_void,
    sk_len: u32,
    provider: *const c_char,
    opts: *const Options,
    _errptr: *mut *mut Error,
) -> Result<()> {
    check_not_null!(cfm);
    check_not_null!(signer);
    check_not_null!(algorithm);
    check_not_null!(secret_key);
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
    let secret_key =
        unsafe { std::slice::from_raw_parts(secret_key as *const u8, sk_len as usize) };
    unsafe {
        *signer = Box::into_raw(Box::new(Signer::new(
            cfm, &algorithm, secret_key, provider, opts,
        )?));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub extern "C" fn cfm_sig_signer_create(
    cfm: *const Confium,
    signer: *mut *mut Signer,
    algorithm: *const c_char,
    secret_key: *const c_void,
    sk_len: u32,
    provider: *const c_char,
    opts: *const Options,
    errptr: *mut *mut Error,
) -> u32 {
    cfm_sig_signer_create_(
        cfm, signer, algorithm, secret_key, sk_len, provider, opts, errptr,
    )
    .map_or_else(|e| ffi_return_err!(e, errptr), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_sig_signer_set_hash(signer: *mut Signer, hash_name: *const c_char) -> u32 {
    if signer.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let s = unsafe { &mut *signer };
    match crate::ffi::utils::cstring(hash_name) {
        Ok(name) => s.set_hash(&name).map_or_else(|e| e.code(), |_| 0),
        Err(e) => e.code(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_sig_signer_update(signer: *mut Signer, data: *const u8, len: u32) -> u32 {
    if signer.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if data.is_null() && len != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let s = unsafe { &mut *signer };
    let data = if data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len as usize) }
    };
    s.update(data).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_sig_signer_finalize(
    signer: *mut Signer,
    sig_out: *mut u8,
    sig_max: u32,
    sig_len: *mut u32,
) -> u32 {
    if signer.is_null() || sig_len.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if sig_out.is_null() && sig_max != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let s = unsafe { &mut *signer };
    let sig_out = if sig_out.is_null() {
        &mut [][..]
    } else {
        unsafe { std::slice::from_raw_parts_mut(sig_out, sig_max as usize) }
    };
    match s.finalize(sig_out) {
        Ok(written) => {
            unsafe {
                *sig_len = written as u32;
            }
            0
        }
        Err(e) => e.code(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_sig_signer_destroy(signer: *mut Signer) -> u32 {
    if !signer.is_null() {
        unsafe {
            std::mem::drop(Box::from_raw(signer));
        }
    }
    0
}

// ---------------------------------------------------------------------
// cfm_sig_verifier_* entry points
// ---------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn cfm_sig_verifier_create_(
    cfm: *const Confium,
    verifier: *mut *mut Verifier,
    algorithm: *const c_char,
    public_key: *const c_void,
    pk_len: u32,
    provider: *const c_char,
    opts: *const Options,
    _errptr: *mut *mut Error,
) -> Result<()> {
    check_not_null!(cfm);
    check_not_null!(verifier);
    check_not_null!(algorithm);
    check_not_null!(public_key);
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
    let public_key =
        unsafe { std::slice::from_raw_parts(public_key as *const u8, pk_len as usize) };
    unsafe {
        *verifier = Box::into_raw(Box::new(Verifier::new(
            cfm, &algorithm, public_key, provider, opts,
        )?));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub extern "C" fn cfm_sig_verifier_create(
    cfm: *const Confium,
    verifier: *mut *mut Verifier,
    algorithm: *const c_char,
    public_key: *const c_void,
    pk_len: u32,
    provider: *const c_char,
    opts: *const Options,
    errptr: *mut *mut Error,
) -> u32 {
    cfm_sig_verifier_create_(
        cfm, verifier, algorithm, public_key, pk_len, provider, opts, errptr,
    )
    .map_or_else(|e| ffi_return_err!(e, errptr), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_sig_verifier_set_hash(
    verifier: *mut Verifier,
    hash_name: *const c_char,
) -> u32 {
    if verifier.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let v = unsafe { &mut *verifier };
    match crate::ffi::utils::cstring(hash_name) {
        Ok(name) => v.set_hash(&name).map_or_else(|e| e.code(), |_| 0),
        Err(e) => e.code(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_sig_verifier_update(
    verifier: *mut Verifier,
    data: *const u8,
    len: u32,
) -> u32 {
    if verifier.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if data.is_null() && len != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let v = unsafe { &mut *verifier };
    let data = if data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len as usize) }
    };
    v.update(data).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_sig_verifier_finalize(
    verifier: *mut Verifier,
    sig: *const u8,
    sig_len: u32,
) -> u32 {
    if verifier.is_null() {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    if sig.is_null() && sig_len != 0 {
        return crate::error::ErrorCode::NULL_POINTER as u32;
    }
    let v = unsafe { &mut *verifier };
    let sig = if sig.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(sig, sig_len as usize) }
    };
    v.finalize(sig).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_sig_verifier_destroy(verifier: *mut Verifier) -> u32 {
    if !verifier.is_null() {
        unsafe {
            std::mem::drop(Box::from_raw(verifier));
        }
    }
    0
}

// ---------------------------------------------------------------------
// cfm_sig_keypair_generate entry point
// ---------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub extern "C" fn cfm_sig_keypair_generate(
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
    errptr: *mut *mut Error,
) -> u32 {
    if let Err(e) = cfm_sig_keypair_generate_(
        cfm, algorithm, seed, seed_len, pk_out, pk_max, pk_len, sk_out, sk_max, sk_len,
    ) {
        ffi_return_err!(e, errptr);
    }
    0
}

#[allow(clippy::too_many_arguments)]
fn cfm_sig_keypair_generate_(
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
) -> Result<()> {
    check_not_null!(cfm);
    check_not_null!(algorithm);
    check_not_null!(pk_out);
    check_not_null!(pk_len);
    check_not_null!(sk_out);
    check_not_null!(sk_len);
    if seed.is_null() && seed_len != 0 {
        check_not_null!(seed);
    }
    let cfm = unsafe { &*cfm };
    let algorithm = crate::ffi::utils::cstring(algorithm)?;
    let seed = if seed.is_null() {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(seed, seed_len as usize) })
    };
    let keypair = Keypair::generate(cfm, &algorithm, seed, None)?;
    let pk = &keypair.public_key;
    let sk: &[u8] = keypair.secret_key.as_ref();
    if pk.len() > pk_max as usize || sk.len() > sk_max as usize {
        return crate::error::InsufficientBufferSnafu {}.fail();
    }
    unsafe {
        std::ptr::copy_nonoverlapping(pk.as_ptr(), pk_out, pk.len());
        std::ptr::copy_nonoverlapping(sk.as_ptr(), sk_out, sk.len());
        *pk_len = pk.len() as u32;
        *sk_len = sk.len() as u32;
    }
    Ok(())
}
