//! User-facing symmetric cipher wrapper. Mirrors the structure of
//! [`crate::hash`] and [`crate::rng`]: resolves a provider offering the
//! `"symmetric"` interface, owns the opaque plugin handle, and dispatches
//! lifecycle + encryption/decryption calls through the negotiated vtable.
//!
//! Cipher modes (CFB, CBC, CTR, ECB, …) are selected by the plugin via the
//! algorithm name suffix or the `opts` bag; Confium is mode-agnostic.

use std::ffi::CString;
use std::rc::Rc;

use libloading::Library;

use crate::Confium;
use crate::Provider;
use crate::Result;
use crate::error;
use crate::ffi::cipher::{CipherInterface, CipherInterfaceV0, FFICipher, interface_of};
use crate::options::Options;

pub struct Cipher {
    obj: *mut FFICipher,
    #[allow(dead_code)]
    lib: Rc<Library>,
    interface: Rc<CipherInterface>,
}

fn find_provider<'a>(cfm: &'a Confium, name: &str) -> Option<&'a Provider> {
    cfm.providers.iter().find(|&plugin| plugin.name == name)
}

fn get_provider<'a>(cfm: &'a Confium, name: &str) -> Result<&'a Provider> {
    find_provider(cfm, name).ok_or(error::UnknownProviderSnafu { name }.build())
}

fn create_v0(
    cfm: &Confium,
    plugin_name: &str,
    v0: &CipherInterfaceV0,
    algorithm: &str,
    key: &[u8],
    iv: &[u8],
    opts: Option<&Options>,
) -> Result<Option<*mut FFICipher>> {
    let mut obj: *mut FFICipher = std::ptr::null_mut();
    let cname = CString::new(algorithm).unwrap();
    let code = (*v0.create)(
        cfm,
        &mut obj,
        cname.as_ptr(),
        key.as_ptr() as *const _,
        key.len() as u32,
        iv.as_ptr() as *const _,
        iv.len() as u32,
        opts,
    );
    if code != 0 {
        return error::PluginInternalSnafu {
            name: plugin_name,
            code,
        }
        .fail();
    }
    if obj.is_null() {
        return Ok(None);
    }
    Ok(Some(obj))
}

fn create(
    cfm: &Confium,
    plugin_name: &str,
    iface: &CipherInterface,
    algorithm: &str,
    key: &[u8],
    iv: &[u8],
    opts: Option<&Options>,
) -> Result<Option<*mut FFICipher>> {
    match iface {
        CipherInterface::V0(v0) => create_v0(cfm, plugin_name, v0, algorithm, key, iv, opts),
    }
}

impl Cipher {
    fn try_new(
        cfm: &Confium,
        providers: Vec<&Provider>,
        algorithm: &str,
        key: &[u8],
        iv: &[u8],
        opts: Option<&Options>,
    ) -> Result<Cipher> {
        for provider in providers {
            let Some(iface) = interface_of(&provider.plugin) else {
                continue;
            };
            let obj = create(cfm, &provider.name, &iface, algorithm, key, iv, opts)?;
            if let Some(obj) = obj {
                return Ok(Cipher {
                    obj,
                    lib: Rc::clone(&provider.plugin.library),
                    interface: iface,
                });
            }
        }
        error::UnsupportedAlgorithmSnafu { name: algorithm }.fail()
    }

    pub fn new(
        cfm: &Confium,
        algorithm: &str,
        key: &[u8],
        iv: &[u8],
        provider_name: Option<&str>,
        opts: Option<&Options>,
    ) -> Result<Cipher> {
        let mut providers: Vec<&Provider> = Vec::new();
        if let Some(provider_name) = provider_name {
            let provider = get_provider(cfm, provider_name)?;
            providers.push(provider);
        } else if let Some(preferred) = cfm.preferred_providers.get("symmetric") {
            for provider in preferred {
                providers.push(get_provider(cfm, provider)?);
            }
        } else {
            for provider in &cfm.providers {
                if interface_of(&provider.plugin).is_some() {
                    providers.push(provider);
                }
            }
        }
        Cipher::try_new(cfm, providers, algorithm, key, iv, opts)
    }

    pub fn block_size(&self) -> Result<u32> {
        let CipherInterface::V0(v0) = &*self.interface;
        let mut size: u32 = 0;
        let code = (*v0.block_size)(self.obj, &mut size);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(size)
    }

    pub fn key_size(&self) -> Result<u32> {
        let CipherInterface::V0(v0) = &*self.interface;
        let mut size: u32 = 0;
        let code = (*v0.key_size)(self.obj, &mut size);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(size)
    }

    pub fn iv_size(&self) -> Result<u32> {
        let CipherInterface::V0(v0) = &*self.interface;
        let mut size: u32 = 0;
        let code = (*v0.iv_size)(self.obj, &mut size);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(size)
    }

    /// Feed `input` through the cipher. The plugin decides how many output
    /// bytes to emit (a stream mode emits one byte per input byte; a
    /// buffered block mode may emit fewer, holding a partial block until
    /// the next call or [`Cipher::finalize`]). Returns exactly the bytes
    /// the plugin wrote.
    pub fn update(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let CipherInterface::V0(v0) = &*self.interface;
        // Upper bound on output: input length plus one block of slack to
        // absorb any leftover buffered bytes the plugin emits ahead of the
        // trailing partial block. A stream cipher returns input.len(); a
        // block cipher in a buffered mode returns at most this much.
        let block = self.block_size().unwrap_or(0) as usize;
        let cap = input.len().saturating_add(block.max(1));
        let mut out: Vec<u8> = vec![0u8; cap];
        let mut out_len: u32 = out.len() as u32;
        let code = (*v0.update)(
            self.obj,
            input.as_ptr(),
            input.len() as u32,
            out.as_mut_ptr(),
            &mut out_len,
        );
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        out.truncate(out_len as usize);
        Ok(out)
    }

    /// Flush any buffered trailing output. For unauthenticated stream
    /// modes this is typically empty; for padded block modes it carries
    /// the final block. The plugin reports the byte count via `out_len`.
    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        let CipherInterface::V0(v0) = &*self.interface;
        let block = self.block_size().unwrap_or(0) as usize;
        // One block is the most a finalize ever needs for an unauthenticated
        // symmetric cipher (padding). AEAD ciphertext trailers are a
        // separate interface.
        let cap = block.max(1);
        let mut out: Vec<u8> = vec![0u8; cap];
        let mut out_len: u32 = out.len() as u32;
        let code = (*v0.finalize)(self.obj, out.as_mut_ptr(), out.len() as u32, &mut out_len);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        out.truncate(out_len as usize);
        Ok(out)
    }

    /// Reset the cipher to its initial key/iv state without re-deriving
    /// the key schedule. Useful for reusing a cipher context for multiple
    /// messages under the same key.
    pub fn reset(&mut self) -> Result<()> {
        let CipherInterface::V0(v0) = &*self.interface;
        let code = (*v0.reset)(self.obj);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }
}

impl Drop for Cipher {
    fn drop(&mut self) {
        let CipherInterface::V0(v0) = &*self.interface;
        (*v0.destroy)(self.obj);
    }
}
