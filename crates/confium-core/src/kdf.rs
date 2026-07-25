//! User-facing KDF (key derivation function) wrapper. Mirrors the
//! structure of [`crate::rng`]: resolves a provider offering the
//! `"kdf"` interface, owns the opaque plugin handle, and dispatches
//! lifecycle + derivation calls through the negotiated vtable.
//!
//! The setters are KDF-family-specific. A plugin returns a non-zero
//! code from a setter that doesn't apply to its algorithm; the wrapper
//! propagates that as `Error::PluginInternalError`.

use std::ffi::CString;
use std::rc::Rc;

use libloading::Library;

use crate::Confium;
use crate::Provider;
use crate::Result;
use crate::error;
use crate::ffi::kdf::{FFIKdf, KdfInterface, KdfInterfaceV0, interface_of};
use crate::options::Options;

pub struct Kdf {
    obj: *mut FFIKdf,
    #[allow(dead_code)]
    lib: Rc<Library>,
    interface: Rc<KdfInterface>,
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
    v0: &KdfInterfaceV0,
    algorithm: &str,
    opts: Option<&Options>,
) -> Result<Option<*mut FFIKdf>> {
    let mut obj: *mut FFIKdf = std::ptr::null_mut();
    let cname = CString::new(algorithm).unwrap();
    let code = (*v0.create)(cfm, &mut obj, cname.as_ptr(), opts);
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
    iface: &KdfInterface,
    algorithm: &str,
    opts: Option<&Options>,
) -> Result<Option<*mut FFIKdf>> {
    match iface {
        KdfInterface::V0(v0) => create_v0(cfm, plugin_name, v0, algorithm, opts),
    }
}

impl Kdf {
    fn try_new(
        cfm: &Confium,
        providers: Vec<&Provider>,
        algorithm: &str,
        opts: Option<&Options>,
    ) -> Result<Kdf> {
        for provider in providers {
            let Some(iface) = interface_of(&provider.plugin) else {
                continue;
            };
            let obj = create(cfm, &provider.name, &iface, algorithm, opts)?;
            if let Some(obj) = obj {
                return Ok(Kdf {
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
        provider_name: Option<&str>,
        opts: Option<&Options>,
    ) -> Result<Kdf> {
        let mut providers: Vec<&Provider> = Vec::new();
        if let Some(provider_name) = provider_name {
            let provider = get_provider(cfm, provider_name)?;
            providers.push(provider);
        } else if let Some(preferred) = cfm.preferred_providers.get("kdf") {
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
        Kdf::try_new(cfm, providers, algorithm, opts)
    }

    pub fn set_salt(&mut self, salt: &[u8]) -> Result<()> {
        let KdfInterface::V0(v0) = &*self.interface;
        let code = (*v0.set_salt)(self.obj, salt.as_ptr(), salt.len() as u32);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    pub fn set_iterations(&mut self, n: u32) -> Result<()> {
        let KdfInterface::V0(v0) = &*self.interface;
        let code = (*v0.set_iterations)(self.obj, n);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    pub fn set_memory_cost(&mut self, bytes: u64) -> Result<()> {
        let KdfInterface::V0(v0) = &*self.interface;
        let code = (*v0.set_memory_cost)(self.obj, bytes);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    pub fn set_parallelism(&mut self, lanes: u32) -> Result<()> {
        let KdfInterface::V0(v0) = &*self.interface;
        let code = (*v0.set_parallelism)(self.obj, lanes);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    pub fn set_hash(&mut self, hash_name: &str) -> Result<()> {
        let KdfInterface::V0(v0) = &*self.interface;
        let cname = CString::new(hash_name).unwrap();
        let code = (*v0.set_hash)(self.obj, cname.as_ptr());
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    pub fn derive(&mut self, input: &[u8], out: &mut [u8]) -> Result<()> {
        let KdfInterface::V0(v0) = &*self.interface;
        let code = (*v0.derive)(
            self.obj,
            input.as_ptr(),
            input.len() as u32,
            out.as_mut_ptr(),
            out.len() as u32,
        );
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    /// Convenience: derive `out_len` bytes into a fresh `Sensitive`
    /// buffer so the key material is zeroized on drop.
    pub fn derive_sensitive(
        &mut self,
        input: &[u8],
        out_len: usize,
    ) -> Result<crate::sensitive::Sensitive<Vec<u8>>> {
        let mut buf = vec![0u8; out_len];
        self.derive(input, &mut buf)?;
        Ok(crate::sensitive::Sensitive::new(buf))
    }
}

impl Drop for Kdf {
    fn drop(&mut self) {
        let KdfInterface::V0(v0) = &*self.interface;
        (*v0.destroy)(self.obj);
    }
}
