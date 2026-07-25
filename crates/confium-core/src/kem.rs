//! User-facing KEM (key encapsulation mechanism) wrappers. Mirrors the
//! structure of [`crate::aead`] and [`crate::rng`]: resolves a provider
//! offering the `"kem"` interface, owns the opaque plugin handle, and
//! dispatches lifecycle + encapsulation/decapsulation calls through the
//! negotiated vtable.
//!
//! KEM splits cleanly into two objects: [`KemEncapsulator`] (sender
//! side, holds the recipient's public key) and [`KemDecapsulator`]
//! (recipient side, holds the recipient's secret key). Both resolve
//! the same provider for a given algorithm so an encapsulated
//! ciphertext produced by one is decapsulable by the other.
//!
//! The algorithm-only static helpers [`KemEncapsulator::shared_secret_size`]
//! and [`KemEncapsulator::keypair_generate`] are exposed on the
//! encapsulator type because they are invoked before any instance
//! exists (the caller sizes buffers or generates a keypair to feed
//! into `KemEncapsulator::new`). They live here rather than on the FFI
//! module so the C entry points can delegate to a single Rust
//! implementation.

use std::ffi::CString;
use std::rc::Rc;

use libloading::Library;

use crate::Confium;
use crate::Provider;
use crate::Result;
use crate::error;
use crate::ffi::kem::{
    FFIKemDecapsulator, FFIKemEncapsulator, KemInterface, KemInterfaceV0, interface_of,
};
use crate::options::Options;

fn find_provider<'a>(cfm: &'a Confium, name: &str) -> Option<&'a Provider> {
    cfm.providers.iter().find(|&plugin| plugin.name == name)
}

fn get_provider<'a>(cfm: &'a Confium, name: &str) -> Result<&'a Provider> {
    find_provider(cfm, name).ok_or(error::UnknownProviderSnafu { name }.build())
}

/// Collect the candidate providers for the `"kem"` interface given an
/// optional explicit provider name. Mirrors the precedence used by the
/// other wrappers: explicit name, then configured preferences, then
/// any provider offering the interface.
fn candidate_providers<'a>(
    cfm: &'a Confium,
    provider_name: Option<&str>,
) -> Result<Vec<&'a Provider>> {
    let mut providers: Vec<&Provider> = Vec::new();
    if let Some(provider_name) = provider_name {
        let provider = get_provider(cfm, provider_name)?;
        providers.push(provider);
    } else if let Some(preferred) = cfm.preferred_providers.get("kem") {
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
    Ok(providers)
}

fn encapsulator_create_v0(
    cfm: &Confium,
    plugin_name: &str,
    v0: &KemInterfaceV0,
    algorithm: &str,
    recipient_pubkey: &[u8],
    opts: Option<&Options>,
) -> Result<Option<*mut FFIKemEncapsulator>> {
    let mut obj: *mut FFIKemEncapsulator = std::ptr::null_mut();
    let cname = CString::new(algorithm).unwrap();
    let code = (*v0.encapsulator_create)(
        cfm,
        &mut obj,
        cname.as_ptr(),
        recipient_pubkey.as_ptr() as *const std::ffi::c_void,
        recipient_pubkey.len() as u32,
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

fn decapsulator_create_v0(
    cfm: &Confium,
    plugin_name: &str,
    v0: &KemInterfaceV0,
    algorithm: &str,
    recipient_seckey: &[u8],
    opts: Option<&Options>,
) -> Result<Option<*mut FFIKemDecapsulator>> {
    let mut obj: *mut FFIKemDecapsulator = std::ptr::null_mut();
    let cname = CString::new(algorithm).unwrap();
    let code = (*v0.decapsulator_create)(
        cfm,
        &mut obj,
        cname.as_ptr(),
        recipient_seckey.as_ptr() as *const std::ffi::c_void,
        recipient_seckey.len() as u32,
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

/// Sender-side KEM handle. Constructed with the recipient's public key;
/// produces a ciphertext plus a shared secret via [`KemEncapsulator::encapsulate`].
/// The recipient decapsulates the ciphertext with [`KemDecapsulator`] to
/// recover the same shared secret.
pub struct KemEncapsulator {
    obj: *mut FFIKemEncapsulator,
    #[allow(dead_code)]
    lib: Rc<Library>,
    interface: Rc<KemInterface>,
}

impl KemEncapsulator {
    fn try_new(
        cfm: &Confium,
        providers: Vec<&Provider>,
        algorithm: &str,
        recipient_pubkey: &[u8],
        opts: Option<&Options>,
    ) -> Result<KemEncapsulator> {
        for provider in providers {
            let Some(iface) = interface_of(&provider.plugin) else {
                continue;
            };
            let KemInterface::V0(v0) = &*iface;
            let obj =
                encapsulator_create_v0(cfm, &provider.name, v0, algorithm, recipient_pubkey, opts)?;
            if let Some(obj) = obj {
                return Ok(KemEncapsulator {
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
        recipient_pubkey: &[u8],
        provider_name: Option<&str>,
        opts: Option<&Options>,
    ) -> Result<KemEncapsulator> {
        let providers = candidate_providers(cfm, provider_name)?;
        KemEncapsulator::try_new(cfm, providers, algorithm, recipient_pubkey, opts)
    }

    /// Encapsulate: produce a ciphertext (to send to the recipient) and
    /// the matching shared secret (for the sender's own use, e.g. as an
    /// AEAD key). Writes into `ciphertext_out` and `shared_secret_out`
    /// and returns `(ct_written, ss_written)`. The caller is expected to
    /// size the buffers via [`KemEncapsulator::shared_secret_size`] (for
    /// the shared secret) and the algorithm's documented ciphertext size
    /// (for the ciphertext); a too-small buffer surfaces as an
    /// [`Error::InsufficientBuffer`] from the plugin.
    pub fn encapsulate(
        &mut self,
        ciphertext_out: &mut [u8],
        shared_secret_out: &mut [u8],
    ) -> Result<(usize, usize)> {
        let KemInterface::V0(v0) = &*self.interface;
        let mut ct_len: u32 = ciphertext_out.len() as u32;
        let mut ss_len: u32 = shared_secret_out.len() as u32;
        let code = (*v0.encapsulate)(
            self.obj,
            ciphertext_out.as_mut_ptr(),
            ciphertext_out.len() as u32,
            &mut ct_len,
            shared_secret_out.as_mut_ptr(),
            shared_secret_out.len() as u32,
            &mut ss_len,
        );
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok((ct_len as usize, ss_len as usize))
    }

    /// Query the shared-secret byte length for `algorithm` without
    /// constructing an instance. The caller uses this to size the
    /// `shared_secret_out` buffer before calling [`KemEncapsulator::encapsulate`]
    /// or [`KemDecapsulator::decapsulate`]. For composite KEMs the size
    /// is the sum of the component shared-secret sizes.
    pub fn shared_secret_size(cfm: &Confium, algorithm: &str) -> Result<u32> {
        for provider in candidate_providers(cfm, None)? {
            let Some(iface) = interface_of(&provider.plugin) else {
                continue;
            };
            let KemInterface::V0(v0) = &*iface;
            let cname = CString::new(algorithm).unwrap();
            let mut size: u32 = 0;
            let code = (*v0.shared_secret_size)(cfm, cname.as_ptr(), &mut size);
            if code == 0 {
                return Ok(size);
            }
        }
        error::UnsupportedAlgorithmSnafu { name: algorithm }.fail()
    }

    /// Generate a fresh keypair for `algorithm`. When `seed` is `Some`,
    /// the plugin uses it as a deterministic seed (test/determinism mode
    /// only — never use a seeded RNG in production). Writes the public
    /// and secret keys into `pk_out` and `sk_out` and returns
    /// `(pk_written, sk_written)`.
    pub fn keypair_generate(
        cfm: &Confium,
        algorithm: &str,
        seed: Option<&[u8]>,
        pk_out: &mut [u8],
        sk_out: &mut [u8],
    ) -> Result<(usize, usize)> {
        for provider in candidate_providers(cfm, None)? {
            let Some(iface) = interface_of(&provider.plugin) else {
                continue;
            };
            let KemInterface::V0(v0) = &*iface;
            let cname = CString::new(algorithm).unwrap();
            let mut pk_len: u32 = pk_out.len() as u32;
            let mut sk_len: u32 = sk_out.len() as u32;
            let (seed_ptr, seed_len) = match seed {
                Some(s) => (s.as_ptr(), s.len() as u32),
                None => (std::ptr::null(), 0),
            };
            let code = (*v0.keypair_generate)(
                cfm,
                cname.as_ptr(),
                seed_ptr,
                seed_len,
                pk_out.as_mut_ptr(),
                pk_out.len() as u32,
                &mut pk_len,
                sk_out.as_mut_ptr(),
                sk_out.len() as u32,
                &mut sk_len,
            );
            if code == 0 {
                return Ok((pk_len as usize, sk_len as usize));
            }
        }
        error::UnsupportedAlgorithmSnafu { name: algorithm }.fail()
    }
}

impl Drop for KemEncapsulator {
    fn drop(&mut self) {
        let KemInterface::V0(v0) = &*self.interface;
        (*v0.encapsulator_destroy)(self.obj);
    }
}

/// Recipient-side KEM handle. Constructed with the recipient's secret
/// key; recovers the shared secret from a ciphertext produced by the
/// sender's [`KemEncapsulator`]. The recovered shared secret matches
/// the sender's on a correct keypair; a wrong secret key (or a
/// tampered ciphertext) yields an error or a distinct (useless)
/// secret depending on the algorithm's decapsulation-failure semantics.
pub struct KemDecapsulator {
    obj: *mut FFIKemDecapsulator,
    #[allow(dead_code)]
    lib: Rc<Library>,
    interface: Rc<KemInterface>,
}

impl KemDecapsulator {
    fn try_new(
        cfm: &Confium,
        providers: Vec<&Provider>,
        algorithm: &str,
        recipient_seckey: &[u8],
        opts: Option<&Options>,
    ) -> Result<KemDecapsulator> {
        for provider in providers {
            let Some(iface) = interface_of(&provider.plugin) else {
                continue;
            };
            let KemInterface::V0(v0) = &*iface;
            let obj =
                decapsulator_create_v0(cfm, &provider.name, v0, algorithm, recipient_seckey, opts)?;
            if let Some(obj) = obj {
                return Ok(KemDecapsulator {
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
        recipient_seckey: &[u8],
        provider_name: Option<&str>,
        opts: Option<&Options>,
    ) -> Result<KemDecapsulator> {
        let providers = candidate_providers(cfm, provider_name)?;
        KemDecapsulator::try_new(cfm, providers, algorithm, recipient_seckey, opts)
    }

    /// Decapsulate `ciphertext` (produced by the matching
    /// [`KemEncapsulator`]) and write the recovered shared secret into
    /// `shared_secret_out`. Returns the number of shared-secret bytes
    /// written. The caller sizes the buffer via
    /// [`KemEncapsulator::shared_secret_size`].
    pub fn decapsulate(
        &mut self,
        ciphertext: &[u8],
        shared_secret_out: &mut [u8],
    ) -> Result<usize> {
        let KemInterface::V0(v0) = &*self.interface;
        let mut ss_len: u32 = shared_secret_out.len() as u32;
        let code = (*v0.decapsulate)(
            self.obj,
            ciphertext.as_ptr(),
            ciphertext.len() as u32,
            shared_secret_out.as_mut_ptr(),
            shared_secret_out.len() as u32,
            &mut ss_len,
        );
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(ss_len as usize)
    }
}

impl Drop for KemDecapsulator {
    fn drop(&mut self) {
        let KemInterface::V0(v0) = &*self.interface;
        (*v0.decapsulator_destroy)(self.obj);
    }
}
