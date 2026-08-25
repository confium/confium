//! Symmetric cipher interface.
//!
//! Plugin contract — the plugin exports these C symbols with the
//! `cfmp_cipher_` prefix:
//!
//! ```c
//! uint32_t cfmp_cipher_create(const Confium*, FFICipher**, const char* algorithm,
//!                             const void* key, uint32_t key_len,
//!                             const void* iv,  uint32_t iv_len,
//!                             const Option* opts);
//! uint32_t cfmp_cipher_block_size(const FFICipher*, uint32_t* out);
//! uint32_t cfmp_cipher_key_size(const FFICipher*, uint32_t* out);
//! uint32_t cfmp_cipher_iv_size(const FFICipher*, uint32_t* out);
//! uint32_t cfmp_cipher_update(FFICipher*, const uint8_t* in, uint32_t in_len,
//!                             uint8_t* out, uint32_t* out_len);
//! uint32_t cfmp_cipher_finalize(FFICipher*, uint8_t* out, uint32_t out_max,
//!                               uint32_t* out_len);
//! uint32_t cfmp_cipher_reset(FFICipher*);
//! void     cfmp_cipher_destroy(FFICipher*);
//! ```
//!
//! Algorithms the plugin may advertise (case-insensitive,
//! hyphen-or-underscore-tolerant): `AES-128/192/256` (with `-CFB`/`-CTR`
//! mode suffixes), `ChaCha20`, `Camellia-128/192/256`, `Twofish`, `SM4`,
//! `3DES`, `CAST5`, `Blowfish`, `IDEA`. `ChaCha20-Poly1305` is forwarded
//! to the AEAD interface. Cipher mode selection is the plugin's concern,
//! not Confium's.
//!
//! This module owns the [`CipherInterface`] type and the registry kind;
//! the user-facing [`crate::cipher::Cipher`] wrapper lives in `src/cipher.rs`.

use std::any::Any;
use std::ffi::c_void;
use std::fmt;
use std::os::raw::c_char;
use std::rc::Rc;

use libloading::Library;

use crate::Confium;
use crate::Result;
use crate::cipher::Cipher;
use crate::error;
use crate::error::Error;
use crate::ffi::plugin::get_plugin_symbol;
use crate::ffi::registry::PluginInterfaceKind;
use crate::ffi::utils::cstring;
use crate::options::Options;
use crate::register_interface;

pub enum FFICipher {}

pub type CipherCreateFnV0 = extern "C" fn(
    *const Confium,
    *mut *mut FFICipher,
    *const c_char,
    *const c_void,
    u32,
    *const c_void,
    u32,
    Option<&Options>,
) -> u32;
const CIPHER_CREATE_FN_V0_NAME: &[u8] = b"cfmp_cipher_create\0";

pub type CipherBlockSizeFnV0 = extern "C" fn(*const FFICipher, *mut u32) -> u32;
const CIPHER_BLOCK_SIZE_FN_V0_NAME: &[u8] = b"cfmp_cipher_block_size\0";

pub type CipherKeySizeFnV0 = extern "C" fn(*const FFICipher, *mut u32) -> u32;
const CIPHER_KEY_SIZE_FN_V0_NAME: &[u8] = b"cfmp_cipher_key_size\0";

pub type CipherIvSizeFnV0 = extern "C" fn(*const FFICipher, *mut u32) -> u32;
const CIPHER_IV_SIZE_FN_V0_NAME: &[u8] = b"cfmp_cipher_iv_size\0";

pub type CipherUpdateFnV0 = extern "C" fn(*mut FFICipher, *const u8, u32, *mut u8, *mut u32) -> u32;
const CIPHER_UPDATE_FN_V0_NAME: &[u8] = b"cfmp_cipher_update\0";

pub type CipherFinalizeFnV0 = extern "C" fn(*mut FFICipher, *mut u8, u32, *mut u32) -> u32;
const CIPHER_FINALIZE_FN_V0_NAME: &[u8] = b"cfmp_cipher_finalize\0";

pub type CipherResetFnV0 = extern "C" fn(*mut FFICipher) -> u32;
const CIPHER_RESET_FN_V0_NAME: &[u8] = b"cfmp_cipher_reset\0";

pub type CipherDestroyFnV0 = extern "C" fn(*mut FFICipher);
const CIPHER_DESTROY_FN_V0_NAME: &[u8] = b"cfmp_cipher_destroy\0";

pub struct CipherInterfaceV0 {
    pub create: Box<CipherCreateFnV0>,
    pub block_size: Box<CipherBlockSizeFnV0>,
    pub key_size: Box<CipherKeySizeFnV0>,
    pub iv_size: Box<CipherIvSizeFnV0>,
    pub update: Box<CipherUpdateFnV0>,
    pub finalize: Box<CipherFinalizeFnV0>,
    pub reset: Box<CipherResetFnV0>,
    pub destroy: Box<CipherDestroyFnV0>,
}

impl fmt::Debug for CipherInterfaceV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherInterfaceV0")
            .field("create", &((*self.create) as *const u8))
            .field("block_size", &((*self.block_size) as *const u8))
            .field("key_size", &((*self.key_size) as *const u8))
            .field("iv_size", &((*self.iv_size) as *const u8))
            .field("update", &((*self.update) as *const u8))
            .field("finalize", &((*self.finalize) as *const u8))
            .field("reset", &((*self.reset) as *const u8))
            .field("destroy", &((*self.destroy) as *const u8))
            .finish()
    }
}

#[derive(Debug)]
pub enum CipherInterface {
    V0(CipherInterfaceV0),
}

/// Registry kind for the symmetric cipher interface. Lives next to the
/// interface it describes so the registration stays co-located with the
/// implementation (open/closed-compliant).
pub struct CipherKind;

impl PluginInterfaceKind for CipherKind {
    fn name(&self) -> &'static str {
        "symmetric"
    }

    fn max_version(&self) -> u8 {
        0
    }

    fn build(&self, lib: &Library, version: u8) -> Result<Option<Rc<dyn Any>>> {
        match version {
            0 => Ok(create_cipher_interface_v0(lib)?.map(|iface| Rc::new(iface) as Rc<dyn Any>)),
            _ => Ok(None),
        }
    }
}

register_interface!(CipherKind);

fn create_cipher_interface_v0(lib: &Library) -> Result<Option<CipherInterface>> {
    let iface = CipherInterfaceV0 {
        create: get_plugin_symbol::<CipherCreateFnV0>(lib, "symmetric", CIPHER_CREATE_FN_V0_NAME)?,
        block_size: get_plugin_symbol::<CipherBlockSizeFnV0>(
            lib,
            "symmetric",
            CIPHER_BLOCK_SIZE_FN_V0_NAME,
        )?,
        key_size: get_plugin_symbol::<CipherKeySizeFnV0>(
            lib,
            "symmetric",
            CIPHER_KEY_SIZE_FN_V0_NAME,
        )?,
        iv_size: get_plugin_symbol::<CipherIvSizeFnV0>(
            lib,
            "symmetric",
            CIPHER_IV_SIZE_FN_V0_NAME,
        )?,
        update: get_plugin_symbol::<CipherUpdateFnV0>(lib, "symmetric", CIPHER_UPDATE_FN_V0_NAME)?,
        finalize: get_plugin_symbol::<CipherFinalizeFnV0>(
            lib,
            "symmetric",
            CIPHER_FINALIZE_FN_V0_NAME,
        )?,
        reset: get_plugin_symbol::<CipherResetFnV0>(lib, "symmetric", CIPHER_RESET_FN_V0_NAME)?,
        destroy: get_plugin_symbol::<CipherDestroyFnV0>(
            lib,
            "symmetric",
            CIPHER_DESTROY_FN_V0_NAME,
        )?,
    };
    Ok(Some(CipherInterface::V0(iface)))
}

/// Downcast a plugin's type-erased interface back to a shared
/// [`CipherInterface`]. Owned by this module so consumers of the cipher
/// interface don't need to know about the registry.
pub fn interface_of(plugin: &crate::Plugin) -> Option<Rc<CipherInterface>> {
    plugin
        .interfaces
        .iter()
        .find_map(|i| i.clone_inner::<CipherInterface>())
}

// Parameter count is fixed by the FFI wire contract (cfm, out, algorithm,
// key+iv with their lengths, provider, opts, errptr); cannot be reduced
// without changing the C ABI.
#[allow(clippy::too_many_arguments)]
fn cfm_cipher_create_(
    cfm: *const Confium,
    cipher: *mut *mut Cipher,
    algorithm: *const c_char,
    key: *const c_void,
    key_len: u32,
    iv: *const c_void,
    iv_len: u32,
    provider: *const c_char,
    opts: *const Options,
    _errptr: *mut *mut Error,
) -> Result<()> {
    check_not_null!(cfm);
    check_not_null!(cipher);
    check_not_null!(algorithm);
    let cfm = unsafe { &*cfm };
    let algorithm = cstring(algorithm)?;
    let provider = match provider.is_null() {
        true => None,
        false => Some(cstring(provider)?),
    };
    let provider = provider.as_deref();
    let opts = match opts.is_null() {
        true => None,
        false => Some(unsafe { &*opts }),
    };
    // Null key/iv is permitted only when the corresponding length is 0;
    // mirror the slice-from-raw-parts precondition so plugins that accept
    // a null pointer for empty input still work, while non-zero lengths
    // require a valid pointer.
    let key = slice_or_empty(key, key_len);
    let iv = slice_or_empty(iv, iv_len);
    unsafe {
        *cipher = Box::into_raw(Box::new(Cipher::new(
            cfm, &algorithm, key, iv, provider, opts,
        )?));
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_cipher_create(
    cfm: *const Confium,
    cipher: *mut *mut Cipher,
    algorithm: *const c_char,
    key: *const c_void,
    key_len: u32,
    iv: *const c_void,
    iv_len: u32,
    provider: *const c_char,
    opts: *const Options,
    errptr: *mut *mut Error,
) -> u32 {
    cfm_cipher_create_(
        cfm, cipher, algorithm, key, key_len, iv, iv_len, provider, opts, errptr,
    )
    .map_or_else(|e| ffi_return_err!(e, errptr), |_| 0)
}

fn cfm_cipher_block_size_(cipher: *const Cipher, size: *mut u32) -> Result<()> {
    unsafe {
        *size = (*cipher).block_size()?;
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_cipher_block_size(cipher: *const Cipher, size: *mut u32) -> u32 {
    cfm_cipher_block_size_(cipher, size).map_or_else(|e| e.code(), |_| 0)
}

fn cfm_cipher_key_size_(cipher: *const Cipher, size: *mut u32) -> Result<()> {
    unsafe {
        *size = (*cipher).key_size()?;
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_cipher_key_size(cipher: *const Cipher, size: *mut u32) -> u32 {
    cfm_cipher_key_size_(cipher, size).map_or_else(|e| e.code(), |_| 0)
}

fn cfm_cipher_iv_size_(cipher: *const Cipher, size: *mut u32) -> Result<()> {
    unsafe {
        *size = (*cipher).iv_size()?;
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_cipher_iv_size(cipher: *const Cipher, size: *mut u32) -> u32 {
    cfm_cipher_iv_size_(cipher, size).map_or_else(|e| e.code(), |_| 0)
}

fn cfm_cipher_update_(
    cipher: *mut Cipher,
    input: *const u8,
    in_len: u32,
    output: *mut u8,
    out_len: *mut u32,
) -> Result<()> {
    unsafe {
        let input = slice_or_empty(input as *const c_void, in_len);
        let written = (*cipher).update(input)?;
        let n = written.len();
        if (out_len.read() as usize) < n {
            return error::InsufficientBufferSnafu {}.fail();
        }
        std::ptr::copy_nonoverlapping(written.as_ptr(), output, n);
        out_len.write(n as u32);
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_cipher_update(
    cipher: *mut Cipher,
    input: *const u8,
    in_len: u32,
    output: *mut u8,
    out_len: *mut u32,
) -> u32 {
    cfm_cipher_update_(cipher, input, in_len, output, out_len).map_or_else(|e| e.code(), |_| 0)
}

fn cfm_cipher_finalize_(
    cipher: *mut Cipher,
    output: *mut u8,
    out_max: u32,
    out_len: *mut u32,
) -> Result<()> {
    unsafe {
        let written = (*cipher).finalize()?;
        let n = written.len();
        if (out_max as usize) < n {
            return error::InsufficientBufferSnafu {}.fail();
        }
        std::ptr::copy_nonoverlapping(written.as_ptr(), output, n);
        out_len.write(n as u32);
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_cipher_finalize(
    cipher: *mut Cipher,
    output: *mut u8,
    out_max: u32,
    out_len: *mut u32,
) -> u32 {
    cfm_cipher_finalize_(cipher, output, out_max, out_len).map_or_else(|e| e.code(), |_| 0)
}

fn cfm_cipher_reset_(cipher: *mut Cipher) -> Result<()> {
    unsafe { (*cipher).reset() }
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_cipher_reset(cipher: *mut Cipher) -> u32 {
    cfm_cipher_reset_(cipher).map_or_else(|e| e.code(), |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfm_cipher_destroy(cipher: *mut Cipher) -> u32 {
    unsafe {
        if !cipher.is_null() {
            std::mem::drop(Box::from_raw(cipher));
        }
    }
    0
}

/// Build a `&[u8]` view of `(ptr, len)`. A null pointer is treated as an
/// empty slice (only valid when `len == 0`); a non-null pointer yields a
/// slice of `len` bytes. Mirrors the precondition of
/// `slice::from_raw_parts` so callers can pass null when the cipher's
/// key/iv is empty without us having to special-case it at each call site.
fn slice_or_empty<'a>(ptr: *const c_void, len: u32) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) }
    }
}
