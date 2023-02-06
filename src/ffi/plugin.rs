use std::collections::HashMap;
use std::os::raw::c_char;
use std::rc::Rc;

use libloading::{Library, Symbol};
use snafu::ResultExt;

use crate::error::Error;
use crate::error::*;
use crate::ffi::hash::create_hash_interface;
use crate::ffi::hash::HashInterface;
use crate::ffi::utils::cstring;
use crate::options::Options;
use crate::Confium;
use crate::Plugin;
use crate::Provider;
use crate::Result;

#[derive(Debug)]
pub enum PluginInterface {
    Hash(HashInterface),
}

// plugin interface version
type InterfaceVersionFn = extern "C" fn(*mut Confium) -> u32;
const INTERFACE_VERSION_FN_NAME: &'static [u8] = b"cfmp_interface_version\0";

// plugin v0 interface
type InitializeFnV0 = extern "C" fn(*mut Confium, opts: *const Options) -> u32;
const INITIALIZE_FN_V0_NAME: &'static [u8] = b"cfmp_initialize\0";

type FinalizeFnV0 = extern "C" fn(*mut Confium) -> u32;
const FINALIZE_FN_V0_NAME: &'static [u8] = b"cfmp_finalize\0";

type QueryInterfacesFnV0 = extern "C" fn(*mut Confium) -> *const u8;
const QUERY_INTERFACES_FN_V0_NAME: &'static [u8] = b"cfmp_query_interfaces\0";

pub struct PluginV0 {
    initialize: Box<InitializeFnV0>,
    finalize: Box<FinalizeFnV0>,
    query_interfaces: Box<QueryInterfacesFnV0>,
}

pub enum PluginVTable {
    V0(PluginV0),
}

macro_rules! check_not_null {
    ($param:ident) => {{
        if $param.is_null() {
            return $crate::error::NullPointer {
                param: stringify!($param),
            }
            .fail();
        }
    }};
}

pub(crate) fn get_plugin_symbol<T>(
    lib: &Library,
    name: &str,
    symbol: &'static [u8],
) -> Result<Box<T>>
where
    T: Copy,
{
    let func: Symbol<T> = unsafe { lib.get::<T>(symbol) }.context(PluginSymbolError {
        name,
        symbol: symbol,
    })?;
    Ok(Box::new(*func))
}

fn load_plugin_v0(
    cfm: &mut Confium,
    name: &str,
    lib: Library,
    opts: &mut Options,
) -> Result<Plugin> {
    let initialize = get_plugin_symbol::<InitializeFnV0>(&lib, name, INITIALIZE_FN_V0_NAME)?;
    let finalize = get_plugin_symbol::<FinalizeFnV0>(&lib, name, FINALIZE_FN_V0_NAME)?;
    let query_interfaces =
        get_plugin_symbol::<QueryInterfacesFnV0>(&lib, name, QUERY_INTERFACES_FN_V0_NAME)?;
    let code = initialize(cfm, opts);
    if code != 0 {
        return PluginInternalError { name, code }.fail();
    }
    let vtable = PluginVTable::V0(PluginV0 {
        initialize: initialize,
        finalize: finalize,
        query_interfaces: query_interfaces,
    });
    Ok(Plugin {
        library: Rc::new(lib),
        vtable: vtable,
        interfaces: Vec::new(),
    })
}

type InterfaceList = HashMap<String, Vec<u8>>;
fn enumerate_plugin_interfaces(cfm: &mut Confium, vtable: &PluginVTable) -> Result<InterfaceList> {
    let mut list = InterfaceList::new();
    match vtable {
        PluginVTable::V0(v0) => {
            let ifs = (*v0.query_interfaces)(cfm);
            let mut idx: usize = 0;
            loop {
                let mut start = idx;
                let mut end = start;
                while unsafe { *(ifs.offset(end as isize)) } != 0 {
                    end += 1;
                }
                let name =
                    unsafe { std::slice::from_raw_parts(ifs.offset(start as isize), end - start) };
                let name = std::str::from_utf8(name).context(InvalidUTF8 {})?;
                if name == "" {
                    break;
                }
                let version = unsafe { *ifs.offset(end as isize + 1) };
                // add to the list of this plugin's advertised interfaces
                if !list.contains_key(name) {
                    list.insert(name.to_string(), Vec::<u8>::new());
                }
                let iflist = list.get_mut(name).unwrap();
                iflist.push(version);
                idx = end + 2;
            }
        }
    }
    for (_, versions) in list.iter_mut() {
        versions.sort();
    }
    Ok(list)
}

fn create_plugin_interface(
    _cfm: &mut Confium,
    lib: &Library,
    name: &str,
    versions: &Vec<u8>,
) -> Result<Option<PluginInterface>> {
    for version in versions.iter().rev() {
        match name {
            "hash" => {
                if let Some(iface) = create_hash_interface(lib, name, *version)? {
                    return Ok(Some(PluginInterface::Hash(iface)));
                }
            }
            _ => continue,
        }
    }
    Ok(None)
}

fn load_plugin_interfaces(
    cfm: &mut Confium,
    lib: &Library,
    vtable: &PluginVTable,
) -> Result<Vec<Rc<PluginInterface>>> {
    let mut interfaces = Vec::new();
    let advertised_ifs = enumerate_plugin_interfaces(cfm, vtable)?;
    for (name, versions) in advertised_ifs {
        if let Some(iface) = create_plugin_interface(cfm, lib, &name, &versions)? {
            interfaces.push(Rc::new(iface));
        }
    }
    Ok(interfaces)
}

fn finalize_plugin(cfm: &mut Confium, plugin: &Plugin) {
    match &plugin.vtable {
        PluginVTable::V0(v0) => {
            (*v0.finalize)(cfm);
        }
    }
}

fn cfm_plugin_load_(
    cfm: *mut Confium,
    c_name: *const c_char,
    c_path: *const c_char,
    opts: *mut Options,
) -> Result<()> {
    check_not_null!(cfm);
    check_not_null!(c_name);
    check_not_null!(c_path);
    let cfm = unsafe { &mut *cfm };
    let name = cstring(c_name)?;
    let path = std::path::PathBuf::from(cstring(c_path)?);
    for provider in &cfm.providers {
        if provider.name == name {
            return PluginNameCollision { name }.fail();
        }
    }
    let lib = unsafe { Library::new(&path).context(PluginLoadFailed { name: &name })? };
    let plugin_iface_ver =
        get_plugin_symbol::<InterfaceVersionFn>(&lib, &name, INTERFACE_VERSION_FN_NAME)?;
    let mut plugin;
    match plugin_iface_ver(cfm) {
        0 => {
            plugin = load_plugin_v0(cfm, &name, lib, unsafe { &mut *opts })?;
        }
        _ => return PluginInterfaceVersionUnsupported { name }.fail(),
    }
    plugin.interfaces =
        load_plugin_interfaces(cfm, &plugin.library, &plugin.vtable).or_else(|e| {
            finalize_plugin(cfm, &plugin);
            Err(e)
        })?;
    cfm.providers.push(Provider { name, plugin });
    Ok(())
}

#[no_mangle]
pub extern "C" fn cfm_plugin_load(
    cfm: *mut Confium,
    c_name: *const c_char,
    c_path: *const c_char,
    opts: *mut Options,
    errptr: *mut *mut Error,
) -> u32 {
    cfm_plugin_load_(cfm, c_name, c_path, opts).map_or_else(|e| ffi_return_err!(e, errptr), |_| 0)
}

#[no_mangle]
pub extern "C" fn cfm_plugin_unload(_cfm: *mut Confium, _c_name: *const c_char) -> u32 {
    unimplemented!();
}
