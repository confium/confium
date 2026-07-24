//! User-facing RNG wrapper. Mirrors the structure of [`crate::hash`]:
//! resolves a provider offering the `"rng"` interface, owns the opaque
//! plugin handle, and dispatches lifecycle + generation calls through
//! the negotiated vtable.

use std::rc::Rc;

use libloading::Library;

use crate::Confium;
use crate::Provider;
use crate::Result;
use crate::error;
use crate::ffi::rng::{FFIRng, RngInterface, RngInterfaceV0, interface_of};
use crate::options::Options;

pub struct Rng {
    obj: *mut FFIRng,
    #[allow(dead_code)]
    lib: Rc<Library>,
    interface: Rc<RngInterface>,
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
    v0: &RngInterfaceV0,
    algorithm: &str,
    opts: Option<&Options>,
) -> Result<Option<*mut FFIRng>> {
    let mut obj: *mut FFIRng = std::ptr::null_mut();
    let cname = std::ffi::CString::new(algorithm).unwrap();
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
    iface: &RngInterface,
    algorithm: &str,
    opts: Option<&Options>,
) -> Result<Option<*mut FFIRng>> {
    match iface {
        RngInterface::V0(v0) => create_v0(cfm, plugin_name, v0, algorithm, opts),
    }
}

impl Rng {
    fn try_new(
        cfm: &Confium,
        providers: Vec<&Provider>,
        algorithm: &str,
        opts: Option<&Options>,
    ) -> Result<Rng> {
        for provider in providers {
            let Some(iface) = interface_of(&provider.plugin) else {
                continue;
            };
            let obj = create(cfm, &provider.name, &iface, algorithm, opts)?;
            if let Some(obj) = obj {
                return Ok(Rng {
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
    ) -> Result<Rng> {
        let mut providers: Vec<&Provider> = Vec::new();
        if let Some(provider_name) = provider_name {
            let provider = get_provider(cfm, provider_name)?;
            providers.push(provider);
        } else if let Some(preferred) = cfm.preferred_providers.get("rng") {
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
        Rng::try_new(cfm, providers, algorithm, opts)
    }

    pub fn reseed(&mut self, data: &[u8]) -> Result<()> {
        let RngInterface::V0(v0) = &*self.interface;
        let code = (*v0.reseed)(self.obj, data.as_ptr(), data.len() as u32);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    pub fn add_entropy(&mut self, data: &[u8]) -> Result<()> {
        let RngInterface::V0(v0) = &*self.interface;
        let code = (*v0.add_entropy)(self.obj, data.as_ptr(), data.len() as u32);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    pub fn generate(&mut self, out: &mut [u8]) -> Result<()> {
        let RngInterface::V0(v0) = &*self.interface;
        let code = (*v0.generate)(self.obj, out.as_mut_ptr(), out.len() as u32);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    /// Convenience: generate `n` bytes into a fresh `Sensitive` buffer.
    /// The caller doesn't see the raw bytes outside a zeroizing wrapper.
    pub fn generate_sensitive(&mut self, n: usize) -> Result<crate::sensitive::Sensitive<Vec<u8>>> {
        let mut buf = vec![0u8; n];
        self.generate(&mut buf)?;
        Ok(crate::sensitive::Sensitive::new(buf))
    }
}

impl Drop for Rng {
    fn drop(&mut self) {
        let RngInterface::V0(v0) = &*self.interface;
        (*v0.destroy)(self.obj);
    }
}
