//! User-facing AEAD wrapper. Mirrors the structure of [`crate::rng`] and
//! [`crate::hash`]: resolves a provider offering the `"aead"` interface,
//! owns the opaque plugin handle, and dispatches lifecycle +
//! encryption/decryption calls through the negotiated vtable.
//!
//! AEAD instances are directional: the first call to
//! [`Aead::encrypt_update`] or [`Aead::decrypt_update`] fixes the
//! direction for the lifetime of the instance. Mixing the two on one
//! instance is rejected with [`Error::WrongType`] (the direction is the
//! "type" of operation). This mirrors the wire-protocol asymmetry: the
//! plugin's internal state machine and tag computation depend on
//! direction.

use std::rc::Rc;

use libloading::Library;

use crate::Confium;
use crate::Provider;
use crate::Result;
use crate::error;
use crate::ffi::aead::{AeadInterface, AeadInterfaceV0, FFIAead, interface_of};
use crate::options::Options;

/// Direction of an AEAD instance. Fixed on the first
/// [`Aead::encrypt_update`] or [`Aead::decrypt_update`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Encrypt,
    Decrypt,
}

pub struct Aead {
    obj: *mut FFIAead,
    #[allow(dead_code)]
    lib: Rc<Library>,
    interface: Rc<AeadInterface>,
    direction: Option<Direction>,
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
    v0: &AeadInterfaceV0,
    algorithm: &str,
    key: &[u8],
    opts: Option<&Options>,
) -> Result<Option<*mut FFIAead>> {
    let mut obj: *mut FFIAead = std::ptr::null_mut();
    let cname = std::ffi::CString::new(algorithm).unwrap();
    let code = (*v0.create)(
        cfm,
        &mut obj,
        cname.as_ptr(),
        key.as_ptr() as *const std::ffi::c_void,
        key.len() as u32,
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
    iface: &AeadInterface,
    algorithm: &str,
    key: &[u8],
    opts: Option<&Options>,
) -> Result<Option<*mut FFIAead>> {
    match iface {
        AeadInterface::V0(v0) => create_v0(cfm, plugin_name, v0, algorithm, key, opts),
    }
}

impl Aead {
    fn try_new(
        cfm: &Confium,
        providers: Vec<&Provider>,
        algorithm: &str,
        key: &[u8],
        opts: Option<&Options>,
    ) -> Result<Aead> {
        for provider in providers {
            let Some(iface) = interface_of(&provider.plugin) else {
                continue;
            };
            let obj = create(cfm, &provider.name, &iface, algorithm, key, opts)?;
            if let Some(obj) = obj {
                return Ok(Aead {
                    obj,
                    lib: Rc::clone(&provider.plugin.library),
                    interface: iface,
                    direction: None,
                });
            }
        }
        error::UnsupportedAlgorithmSnafu { name: algorithm }.fail()
    }

    pub fn new(
        cfm: &Confium,
        algorithm: &str,
        key: &[u8],
        provider_name: Option<&str>,
        opts: Option<&Options>,
    ) -> Result<Aead> {
        let mut providers: Vec<&Provider> = Vec::new();
        if let Some(provider_name) = provider_name {
            let provider = get_provider(cfm, provider_name)?;
            providers.push(provider);
        } else if let Some(preferred) = cfm.preferred_providers.get("aead") {
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
        Aead::try_new(cfm, providers, algorithm, key, opts)
    }

    pub fn set_nonce(&mut self, nonce: &[u8]) -> Result<()> {
        let AeadInterface::V0(v0) = &*self.interface;
        let code = (*v0.set_nonce)(self.obj, nonce.as_ptr(), nonce.len() as u32);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    pub fn associated_data_update(&mut self, data: &[u8]) -> Result<()> {
        let AeadInterface::V0(v0) = &*self.interface;
        let code = (*v0.associated_data_update)(self.obj, data.as_ptr(), data.len() as u32);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    /// Encrypt a chunk of plaintext. The first call to this or
    /// [`Aead::decrypt_update`] fixes the instance direction; calling
    /// the opposite direction afterward is rejected. Returns the number
    /// of bytes written into `out`. The caller must size `out` to at
    /// least `input.len()`; streaming modes that expand (e.g. padding)
    /// are responsible for documenting any surplus.
    pub fn encrypt_update(&mut self, input: &[u8], out: &mut [u8]) -> Result<usize> {
        self.fix_direction(Direction::Encrypt)?;
        let AeadInterface::V0(v0) = &*self.interface;
        let mut written: u32 = out.len() as u32;
        let code = (*v0.encrypt_update)(
            self.obj,
            input.as_ptr(),
            input.len() as u32,
            out.as_mut_ptr(),
            &mut written,
        );
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(written as usize)
    }

    /// Decrypt a chunk of ciphertext. The first call to this or
    /// [`Aead::encrypt_update`] fixes the instance direction; calling
    /// the opposite direction afterward is rejected. Returns the number
    /// of bytes written into `out`.
    pub fn decrypt_update(&mut self, input: &[u8], out: &mut [u8]) -> Result<usize> {
        self.fix_direction(Direction::Decrypt)?;
        let AeadInterface::V0(v0) = &*self.interface;
        let mut written: u32 = out.len() as u32;
        let code = (*v0.decrypt_update)(
            self.obj,
            input.as_ptr(),
            input.len() as u32,
            out.as_mut_ptr(),
            &mut written,
        );
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(written as usize)
    }

    /// Finalize the AEAD operation and write the authentication tag.
    /// Used on the encrypt side after all plaintext has been fed via
    /// [`Aead::encrypt_update`]. Returns the number of tag bytes
    /// written.
    pub fn finalize(&mut self, tag: &mut [u8]) -> Result<usize> {
        let AeadInterface::V0(v0) = &*self.interface;
        let mut written: u32 = tag.len() as u32;
        let code = (*v0.finalize)(self.obj, tag.as_mut_ptr(), tag.len() as u32, &mut written);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(written as usize)
    }

    /// Verify a candidate authentication tag against the internally
    /// computed tag. Used on the decrypt side after all ciphertext has
    /// been fed via [`Aead::decrypt_update`]. Returns `Ok(())` if the
    /// tag matches, an error otherwise.
    pub fn verify_tag(&mut self, tag: &[u8]) -> Result<()> {
        let AeadInterface::V0(v0) = &*self.interface;
        let code = (*v0.verify_tag)(self.obj, tag.as_ptr(), tag.len() as u32);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    /// Set the instance direction if not yet set, or assert it matches
    /// the existing direction. Mixing encrypt and decrypt on one
    /// instance is a programming error, not a transient failure.
    fn fix_direction(&mut self, want: Direction) -> Result<()> {
        match self.direction {
            None => {
                self.direction = Some(want);
                Ok(())
            }
            Some(have) if have == want => Ok(()),
            Some(_) => error::WrongTypeSnafu {
                expected: "consistent AEAD direction (encrypt or decrypt)",
            }
            .fail(),
        }
    }
}

impl Drop for Aead {
    fn drop(&mut self) {
        let AeadInterface::V0(v0) = &*self.interface;
        (*v0.destroy)(self.obj);
    }
}
