//! User-facing key serialization wrapper. Mirrors the structure of
//! [`crate::rng`]: resolves a provider offering the `"keyfmt"` interface,
//! owns the opaque plugin handle, and dispatches parse/serialize/kind/
//! algorithm/public calls through the negotiated vtable.
//!
//! The [`Key`] wraps a plugin-owned `FFIKey*` opaque handle. Signature
//! and KEM plugins accept and return these handles so keys can flow
//! between plugins and across language boundaries without Confium
//! needing to know any format-specific detail.

use std::ffi::CString;
use std::os::raw::c_char;
use std::rc::Rc;

use libloading::Library;
use snafu::ResultExt;

use crate::Confium;
use crate::Provider;
use crate::Result;
use crate::error;
use crate::ffi::keyfmt::{FFIKey, KeyfmtInterface, KeyfmtInterfaceV0, interface_of};
use crate::keyfmt::KeyKind::{Both, Public, Secret};
use crate::options::Options;

/// What a parsed [`Key`] carries.
///
/// Wire values (returned by `cfmp_keyfmt_kind`) are: `0` = secret, `1`
/// = public, `2` = both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyKind {
    Secret = 0,
    Public = 1,
    Both = 2,
}

impl KeyKind {
    /// Recover a [`KeyKind`] from the wire value returned by
    /// `cfmp_keyfmt_kind`. Returns `None` for any value outside the
    /// defined range rather than panicking, so a future plugin can
    /// advertise a new kind without crashing older Confium builds.
    pub fn from_wire(value: u32) -> Option<Self> {
        match value {
            0 => Some(Secret),
            1 => Some(Public),
            2 => Some(Both),
            _ => None,
        }
    }
}

/// ASCII names of key formats a plugin may advertise support for. These
/// are the canonical spellings Confium passes verbatim to the plugin;
/// the plugin decides which it accepts. Confium does not enforce the
/// set.
pub mod formats {
    pub const OPENPGP: &str = "OpenPGP";
    pub const PKCS8_PEM: &str = "PKCS#8-PEM";
    pub const PKCS8_DER: &str = "PKCS#8-DER";
    pub const PKCS1_PEM: &str = "PKCS#1-PEM";
    pub const PKCS1_DER: &str = "PKCS#1-DER";
    pub const SPKI_PEM: &str = "SPKI-PEM";
    pub const SPKI_DER: &str = "SPKI-DER";
    pub const JWK: &str = "JWK";
    pub const RAW: &str = "Raw";
    pub const OPENSSH: &str = "OpenSSH";
}

pub struct Key {
    obj: *mut FFIKey,
    #[allow(dead_code)]
    lib: Rc<Library>,
    interface: Rc<KeyfmtInterface>,
}

fn find_provider<'a>(cfm: &'a Confium, name: &str) -> Option<&'a Provider> {
    cfm.providers.iter().find(|&plugin| plugin.name == name)
}

fn get_provider<'a>(cfm: &'a Confium, name: &str) -> Result<&'a Provider> {
    find_provider(cfm, name).ok_or(error::UnknownProviderSnafu { name }.build())
}

fn parse_v0(
    cfm: &Confium,
    plugin_name: &str,
    v0: &KeyfmtInterfaceV0,
    format: &str,
    algorithm_hint: Option<&str>,
    bytes: &[u8],
    opts: Option<&Options>,
) -> Result<Option<*mut FFIKey>> {
    let mut obj: *mut FFIKey = std::ptr::null_mut();
    let cformat = CString::new(format).unwrap();
    // An absent hint is conveyed to the plugin as a null pointer; the
    // plugin decides how to disambiguate the format on its own.
    let chint = algorithm_hint.map(|h| CString::new(h).unwrap());
    let hint_ptr: *const c_char = chint.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    let code = (*v0.parse)(
        cfm,
        &mut obj,
        cformat.as_ptr(),
        hint_ptr,
        bytes.as_ptr(),
        bytes.len() as u32,
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

fn parse(
    cfm: &Confium,
    plugin_name: &str,
    iface: &KeyfmtInterface,
    format: &str,
    algorithm_hint: Option<&str>,
    bytes: &[u8],
    opts: Option<&Options>,
) -> Result<Option<*mut FFIKey>> {
    match iface {
        KeyfmtInterface::V0(v0) => {
            parse_v0(cfm, plugin_name, v0, format, algorithm_hint, bytes, opts)
        }
    }
}

impl Key {
    fn try_parse(
        cfm: &Confium,
        providers: Vec<&Provider>,
        format: &str,
        algorithm_hint: Option<&str>,
        bytes: &[u8],
        opts: Option<&Options>,
    ) -> Result<Key> {
        for provider in providers {
            let Some(iface) = interface_of(&provider.plugin) else {
                continue;
            };
            let obj = parse(
                cfm,
                &provider.name,
                &iface,
                format,
                algorithm_hint,
                bytes,
                opts,
            )?;
            if let Some(obj) = obj {
                return Ok(Key {
                    obj,
                    lib: Rc::clone(&provider.plugin.library),
                    interface: iface,
                });
            }
        }
        // No plugin accepted the bytes for this format. Surface as an
        // unsupported-algorithm error so the caller can distinguish
        // "wrong format/provider" from a generic plugin failure.
        error::UnsupportedAlgorithmSnafu {
            name: format.to_string(),
        }
        .fail()
    }

    /// Parse `bytes` in `format` using a provider offering the `"keyfmt"`
    /// interface. `algorithm_hint` is optional; some formats (e.g.
    /// `PKCS#8`) embed the algorithm, others (e.g. `Raw`) require it.
    /// `provider_name` selects a specific provider; when `None`, the
    /// preferred providers (or any offering the interface) are tried in
    /// order.
    pub fn parse(
        cfm: &Confium,
        format: &str,
        algorithm_hint: Option<&str>,
        bytes: &[u8],
        provider_name: Option<&str>,
        opts: Option<&Options>,
    ) -> Result<Key> {
        let mut providers: Vec<&Provider> = Vec::new();
        if let Some(provider_name) = provider_name {
            let provider = get_provider(cfm, provider_name)?;
            providers.push(provider);
        } else if let Some(preferred) = cfm.preferred_providers.get("keyfmt") {
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
        Key::try_parse(cfm, providers, format, algorithm_hint, bytes, opts)
    }

    /// Serialize this key into `format`. Returns the serialized bytes in
    /// a zeroizing wrapper so secret-key material does not linger in
    /// process memory after the caller drops the value.
    pub fn serialize(&self, format: &str) -> Result<crate::sensitive::Sensitive<Vec<u8>>> {
        let KeyfmtInterface::V0(v0) = &*self.interface;
        // Two-pass: probe the required size with a null/zero buffer, then
        // allocate exactly and fill. The plugin contract is that a call
        // with `out_max` too small writes the required length into
        // `out_len` and returns the insufficient-buffer code; we use that
        // to size the second pass.
        let cformat = CString::new(format).unwrap();
        let mut required: u32 = 0;
        let probe = (*v0.serialize)(
            self.obj,
            cformat.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut required,
        );
        if probe != 0 && probe != crate::error::ErrorCode::INSUFFICIENT_BUFFER as u32 {
            return error::PluginInternalSnafu {
                name: "",
                code: probe,
            }
            .fail();
        }
        let mut buf = vec![0u8; required as usize];
        let mut written: u32 = 0;
        let code = (*v0.serialize)(
            self.obj,
            cformat.as_ptr(),
            buf.as_mut_ptr(),
            required,
            &mut written,
        );
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        buf.truncate(written as usize);
        Ok(crate::sensitive::Sensitive::new(buf))
    }

    /// What this key carries: secret material, public material, or both.
    pub fn kind(&self) -> Result<KeyKind> {
        let KeyfmtInterface::V0(v0) = &*self.interface;
        let mut value: u32 = 0;
        let code = (*v0.kind)(self.obj, &mut value);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        KeyKind::from_wire(value).ok_or(
            error::WrongTypeSnafu {
                expected: "KeyKind",
            }
            .build(),
        )
    }

    /// Algorithm name the plugin associated with this key (e.g.
    /// `"Kyber768-X25519"`). The string is plugin-owned; Confium copies
    /// it into a fresh Rust `String` so the caller does not need to free
    /// anything.
    pub fn algorithm(&self) -> Result<String> {
        let KeyfmtInterface::V0(v0) = &*self.interface;
        let mut raw: *mut c_char = std::ptr::null_mut();
        let code = (*v0.algorithm)(self.obj, &mut raw);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        if raw.is_null() {
            return error::ValueNotFoundSnafu {}.fail();
        }
        // Reclaim the plugin-allocated buffer so it is freed regardless
        // of how the bytes are decoded.
        let _boxed = unsafe { Box::from_raw(raw) };
        // SAFETY: `raw` is a valid NUL-terminated C string produced by
        // the plugin. The Box above owns the memory for the duration of
        // this scope.
        let cstr = unsafe { std::ffi::CStr::from_ptr(raw) };
        let s = cstr
            .to_str()
            .context(crate::error::InvalidUTF8Snafu {})?
            .to_string();
        Ok(s)
    }

    /// Derive a public-only key, stripping any secret material. Required
    /// for keystore public/private compartmentalization (TODO #12).
    pub fn public(&self) -> Result<Key> {
        let KeyfmtInterface::V0(v0) = &*self.interface;
        let mut obj: *mut FFIKey = std::ptr::null_mut();
        let code = (*v0.public)(self.obj, &mut obj);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        if obj.is_null() {
            return error::ValueNotFoundSnafu {}.fail();
        }
        Ok(Key {
            obj,
            lib: Rc::clone(&self.lib),
            interface: Rc::clone(&self.interface),
        })
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        let KeyfmtInterface::V0(v0) = &*self.interface;
        (*v0.destroy)(self.obj);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_kind_wire_roundtrip() {
        assert_eq!(KeyKind::from_wire(0), Some(Secret));
        assert_eq!(KeyKind::from_wire(1), Some(Public));
        assert_eq!(KeyKind::from_wire(2), Some(Both));
    }

    #[test]
    fn key_kind_wire_unknown_is_none() {
        assert_eq!(KeyKind::from_wire(3), None);
        assert_eq!(KeyKind::from_wire(u32::MAX), None);
    }

    #[test]
    fn key_kind_wire_values_match_spec() {
        // The wire protocol pins 0=secret, 1=public, 2=both — these must
        // not drift without a version bump.
        assert_eq!(Secret as u32, 0);
        assert_eq!(Public as u32, 1);
        assert_eq!(Both as u32, 2);
    }

    #[test]
    fn formats_are_canonical_spellings() {
        // The plugin declares which formats it supports; these spellings
        // are the canonical ones Confium hands through.
        assert_eq!(formats::OPENPGP, "OpenPGP");
        assert_eq!(formats::PKCS8_PEM, "PKCS#8-PEM");
        assert_eq!(formats::PKCS8_DER, "PKCS#8-DER");
        assert_eq!(formats::PKCS1_PEM, "PKCS#1-PEM");
        assert_eq!(formats::PKCS1_DER, "PKCS#1-DER");
        assert_eq!(formats::SPKI_PEM, "SPKI-PEM");
        assert_eq!(formats::SPKI_DER, "SPKI-DER");
        assert_eq!(formats::JWK, "JWK");
        assert_eq!(formats::RAW, "Raw");
        assert_eq!(formats::OPENSSH, "OpenSSH");
    }
}
