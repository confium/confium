use std::ffi::CString;
use std::rc::Rc;

use libloading::Library;

use crate::Confium;
use crate::Provider;
use crate::Result;
use crate::error;
use crate::ffi::hash::{FFIHash, HashInterface, HashInterfaceV0, interface_of};
use crate::options::Options;

pub struct Hash {
    obj: *mut FFIHash,
    name: String,
    lib: Rc<Library>,
    interface: Rc<HashInterface>,
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
    v0: &HashInterfaceV0,
    name: &str,
    opts: Option<&Options>,
) -> Result<Option<*mut FFIHash>> {
    let mut obj: *mut FFIHash = std::ptr::null_mut();
    let cname = CString::new(name).unwrap();
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
    iface: &HashInterface,
    name: &str,
    opts: Option<&Options>,
) -> Result<Option<*mut FFIHash>> {
    match iface {
        HashInterface::V0(v0) => create_v0(cfm, plugin_name, v0, name, opts),
    }
}

impl Hash {
    fn try_new(
        cfm: &Confium,
        providers: Vec<&Provider>,
        name: &str,
        opts: Option<&Options>,
    ) -> Result<Hash> {
        for provider in providers {
            let Some(iface) = interface_of(&provider.plugin) else {
                continue;
            };
            let obj = create(cfm, &provider.name, &iface, name, opts)?;
            if let Some(obj) = obj {
                return Ok(Hash {
                    obj,
                    name: name.to_string(),
                    lib: Rc::clone(&provider.plugin.library),
                    interface: iface,
                });
            }
        }
        error::UnsupportedAlgorithmSnafu { name }.fail()
    }

    pub fn new(
        cfm: &Confium,
        name: &str,
        provider_name: Option<&str>,
        opts: Option<&Options>,
    ) -> Result<Hash> {
        let mut providers: Vec<&Provider> = Vec::new();
        if let Some(provider_name) = provider_name {
            // specific provider specified, try only that one, else fail
            // error if provider does not exist
            // error if provider is missing the interface
            let provider = get_provider(cfm, provider_name)?;
            providers.push(provider);
        } else if let Some(preferred) = cfm.preferred_providers.get("hash") {
            // try all in the preferred provider list
            for provider in preferred {
                providers.push(get_provider(cfm, provider)?);
            }
        } else {
            // try all providers, in the order they were loaded
            for provider in &cfm.providers {
                if interface_of(&provider.plugin).is_some() {
                    providers.push(provider);
                }
            }
        }
        Hash::try_new(cfm, providers, name, opts)
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) -> Result<()> {
        let HashInterface::V0(hashif) = &*self.interface;
        let data = data.as_ref();
        let code = (*hashif.update)(self.obj, data.as_ptr(), data.len() as u32);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    pub fn reset(&mut self) -> Result<()> {
        let HashInterface::V0(hashif) = &*self.interface;
        let code = (*hashif.reset)(self.obj);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    pub fn try_clone(&self) -> Result<Hash> {
        let HashInterface::V0(hashif) = &*self.interface;
        let mut dst: *mut FFIHash = std::ptr::null_mut();
        let code = (*hashif.clone)(self.obj, &mut dst);
        if code != 0 || dst.is_null() {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(Hash {
            obj: dst,
            name: self.name.clone(),
            lib: Rc::clone(&self.lib),
            interface: Rc::clone(&self.interface),
        })
    }

    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        let size = self.output_size()?;
        let mut result: Vec<u8> = vec![0; size as usize];
        let HashInterface::V0(hashif) = &*self.interface;
        let code = (*hashif.finalize)(self.obj, result.as_mut_ptr(), size);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(result)
    }

    pub fn block_size(&self) -> Result<u32> {
        let HashInterface::V0(hashif) = &*self.interface;
        let mut size: u32 = 0;
        let code = (*hashif.block_size)(self.obj, &mut size);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(size)
    }

    pub fn output_size(&self) -> Result<u32> {
        let HashInterface::V0(hashif) = &*self.interface;
        let mut size: u32 = 0;
        let code = (*hashif.output_size)(self.obj, &mut size);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(size)
    }

    pub fn digest(cfm: &Confium, name: &str, data: &[u8]) -> Result<Vec<u8>> {
        let mut hash = Hash::new(cfm, name, None, None)?;
        hash.update(data)?;
        hash.finalize()
    }
}

impl Drop for Hash {
    fn drop(&mut self) {
        let HashInterface::V0(hashif) = &*self.interface;
        (*hashif.destroy)(self.obj);
    }
}
