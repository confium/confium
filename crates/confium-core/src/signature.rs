//! User-facing asymmetric signature wrapper. Mirrors the structure of
//! [`crate::aead`] and [`crate::hash`]: resolves a provider offering
//! the `"signature"` interface, owns the opaque plugin handles, and
//! dispatches lifecycle + signing/verification calls through the
//! negotiated vtable.
//!
//! Three objects live here:
//!
//! - [`Signer`] — accumulates the message and produces a signature on
//!   [`Signer::finalize`]. Created from a serialized secret key.
//! - [`Verifier`] — accumulates the message and verifies a candidate
//!   signature on [`Verifier::finalize`]. Created from a serialized
//!   public key.
//! - [`Keypair`] — generates fresh keypairs via
//!   [`Keypair::generate`]. The plugin reads the loaded RNG; an
//!   optional caller-supplied seed is forwarded for deterministic
//!   test-vector generation.
//!
//! Composite algorithms (e.g. `Dilithium3-Ed25519`) are atomic: one
//! key, one signature, one verify call. `set_hash` is meaningful for
//! RSA / DSA / ECDSA; Ed25519, Ed448, and PQC algorithms ignore it
//! (the plugin returns success without changing state).
//!
//! Key serialization is shared with the KEM interface; both depend on
//! the key-format interface. Until that lands, keys are passed as
//! opaque byte blobs whose interpretation is plugin-defined.

use std::ffi::CString;
use std::rc::Rc;

use libloading::Library;

use crate::Confium;
use crate::Provider;
use crate::Result;
use crate::error;
use crate::ffi::signature::{
    FFISigner, FFIVerifier, KeypairInterface, KeypairInterfaceV0, SignatureInterface,
    SignerInterface, SignerInterfaceV0, VerifierInterface, VerifierInterfaceV0, interface_of,
};
use crate::options::Options;
use crate::sensitive::Sensitive;

fn find_provider<'a>(cfm: &'a Confium, name: &str) -> Option<&'a Provider> {
    cfm.providers.iter().find(|&plugin| plugin.name == name)
}

fn get_provider<'a>(cfm: &'a Confium, name: &str) -> Result<&'a Provider> {
    find_provider(cfm, name).ok_or(error::UnknownProviderSnafu { name }.build())
}

/// The collected candidates for a `"signature"` provider lookup, in
/// preference order: an explicit provider, the configured preferred
/// list, or every loaded provider that advertises the interface.
fn candidates<'a>(cfm: &'a Confium, provider_name: Option<&str>) -> Result<Vec<&'a Provider>> {
    let mut providers: Vec<&Provider> = Vec::new();
    if let Some(provider_name) = provider_name {
        providers.push(get_provider(cfm, provider_name)?);
    } else if let Some(preferred) = cfm.preferred_providers.get("signature") {
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

// =====================================================================
// Signer
// =====================================================================

fn signer_create_v0(
    cfm: &Confium,
    plugin_name: &str,
    v0: &SignerInterfaceV0,
    algorithm: &str,
    secret_key: &[u8],
    opts: Option<&Options>,
) -> Result<Option<*mut FFISigner>> {
    let mut obj: *mut FFISigner = std::ptr::null_mut();
    let cname = CString::new(algorithm).unwrap();
    let code = (*v0.create)(
        cfm,
        &mut obj,
        cname.as_ptr(),
        secret_key.as_ptr() as *const std::ffi::c_void,
        secret_key.len() as u32,
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

fn signer_create(
    cfm: &Confium,
    plugin_name: &str,
    iface: &SignatureInterface,
    algorithm: &str,
    secret_key: &[u8],
    opts: Option<&Options>,
) -> Result<Option<*mut FFISigner>> {
    let SignerInterface::V0(v0) = &iface.signer;
    signer_create_v0(cfm, plugin_name, v0, algorithm, secret_key, opts)
}

pub struct Signer {
    obj: *mut FFISigner,
    #[allow(dead_code)]
    lib: Rc<Library>,
    interface: Rc<SignatureInterface>,
}

impl Signer {
    fn try_new(
        cfm: &Confium,
        providers: Vec<&Provider>,
        algorithm: &str,
        secret_key: &[u8],
        opts: Option<&Options>,
    ) -> Result<Signer> {
        for provider in providers {
            let Some(iface) = interface_of(&provider.plugin) else {
                continue;
            };
            let obj = signer_create(cfm, &provider.name, &iface, algorithm, secret_key, opts)?;
            if let Some(obj) = obj {
                return Ok(Signer {
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
        secret_key: &[u8],
        provider_name: Option<&str>,
        opts: Option<&Options>,
    ) -> Result<Signer> {
        let providers = candidates(cfm, provider_name)?;
        Signer::try_new(cfm, providers, algorithm, secret_key, opts)
    }

    /// Set the hash used by RSA / DSA / ECDSA signing. Ed25519, Ed448,
    /// and PQC algorithms ignore this; the plugin returns success
    /// without changing state.
    pub fn set_hash(&mut self, hash_name: &str) -> Result<()> {
        let SignerInterface::V0(v0) = &self.interface.signer;
        let cname = CString::new(hash_name).unwrap();
        let code = (*v0.set_hash)(self.obj, cname.as_ptr());
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        let SignerInterface::V0(v0) = &self.interface.signer;
        let code = (*v0.update)(self.obj, data.as_ptr(), data.len() as u32);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    /// Finalize the signature. Returns the number of bytes written into
    /// `sig_out`. The caller must size `sig_out` to at least the
    /// algorithm's maximum signature length; an undersized buffer is
    /// rejected with [`error::Error::InsufficientBuffer`].
    pub fn finalize(&mut self, sig_out: &mut [u8]) -> Result<usize> {
        let SignerInterface::V0(v0) = &self.interface.signer;
        let mut written: u32 = 0;
        let code = (*v0.finalize)(
            self.obj,
            sig_out.as_mut_ptr(),
            sig_out.len() as u32,
            &mut written,
        );
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(written as usize)
    }
}

impl Drop for Signer {
    fn drop(&mut self) {
        let SignerInterface::V0(v0) = &self.interface.signer;
        (*v0.destroy)(self.obj);
    }
}

// =====================================================================
// Verifier
// =====================================================================

fn verifier_create_v0(
    cfm: &Confium,
    plugin_name: &str,
    v0: &VerifierInterfaceV0,
    algorithm: &str,
    public_key: &[u8],
    opts: Option<&Options>,
) -> Result<Option<*mut FFIVerifier>> {
    let mut obj: *mut FFIVerifier = std::ptr::null_mut();
    let cname = CString::new(algorithm).unwrap();
    let code = (*v0.create)(
        cfm,
        &mut obj,
        cname.as_ptr(),
        public_key.as_ptr() as *const std::ffi::c_void,
        public_key.len() as u32,
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

fn verifier_create(
    cfm: &Confium,
    plugin_name: &str,
    iface: &SignatureInterface,
    algorithm: &str,
    public_key: &[u8],
    opts: Option<&Options>,
) -> Result<Option<*mut FFIVerifier>> {
    let VerifierInterface::V0(v0) = &iface.verifier;
    verifier_create_v0(cfm, plugin_name, v0, algorithm, public_key, opts)
}

pub struct Verifier {
    obj: *mut FFIVerifier,
    #[allow(dead_code)]
    lib: Rc<Library>,
    interface: Rc<SignatureInterface>,
}

impl Verifier {
    fn try_new(
        cfm: &Confium,
        providers: Vec<&Provider>,
        algorithm: &str,
        public_key: &[u8],
        opts: Option<&Options>,
    ) -> Result<Verifier> {
        for provider in providers {
            let Some(iface) = interface_of(&provider.plugin) else {
                continue;
            };
            let obj = verifier_create(cfm, &provider.name, &iface, algorithm, public_key, opts)?;
            if let Some(obj) = obj {
                return Ok(Verifier {
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
        public_key: &[u8],
        provider_name: Option<&str>,
        opts: Option<&Options>,
    ) -> Result<Verifier> {
        let providers = candidates(cfm, provider_name)?;
        Verifier::try_new(cfm, providers, algorithm, public_key, opts)
    }

    /// Set the hash used by RSA / DSA / ECDSA verification. Ed25519,
    /// Ed448, and PQC algorithms ignore this.
    pub fn set_hash(&mut self, hash_name: &str) -> Result<()> {
        let VerifierInterface::V0(v0) = &self.interface.verifier;
        let cname = CString::new(hash_name).unwrap();
        let code = (*v0.set_hash)(self.obj, cname.as_ptr());
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        let VerifierInterface::V0(v0) = &self.interface.verifier;
        let code = (*v0.update)(self.obj, data.as_ptr(), data.len() as u32);
        if code != 0 {
            return error::PluginInternalSnafu { name: "", code }.fail();
        }
        Ok(())
    }

    /// Finalize verification against `sig`. Returns `Ok(())` if the
    /// signature is valid, `Err(Error::WrongType)` if invalid (the
    /// signature does not verify), or any other error for a plugin
    /// internal fault.
    ///
    /// The wire convention is that the plugin returns a dedicated
    /// verification-failed code for an invalid signature and any other
    /// non-zero code for an internal error. The wrapper maps the
    /// verification-failed code to [`error::Error::WrongType`] so
    /// callers can distinguish "wrong signature" from "plugin broke".
    pub fn finalize(&mut self, sig: &[u8]) -> Result<()> {
        let VerifierInterface::V0(v0) = &self.interface.verifier;
        let code = (*v0.finalize)(self.obj, sig.as_ptr(), sig.len() as u32);
        if code == 0 {
            return Ok(());
        }
        if code == u32::from(crate::error::ErrorCode::WRONG_TYPE) {
            return error::WrongTypeSnafu {
                expected: "a valid signature",
            }
            .fail();
        }
        error::PluginInternalSnafu { name: "", code }.fail()
    }
}

impl Drop for Verifier {
    fn drop(&mut self) {
        let VerifierInterface::V0(v0) = &self.interface.verifier;
        (*v0.destroy)(self.obj);
    }
}

// =====================================================================
// Keypair
// =====================================================================

/// A freshly generated keypair. The secret half is wrapped in
/// [`Sensitive`] so it is zeroized on drop.
pub struct Keypair {
    pub public_key: Vec<u8>,
    pub secret_key: Sensitive<Vec<u8>>,
}

fn keypair_generate_v0(
    cfm: &Confium,
    plugin_name: &str,
    v0: &KeypairInterfaceV0,
    algorithm: &str,
    seed: Option<&[u8]>,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    // No upper bound is known a priori; size generously and let the
    // plugin fail if either buffer is too small. These buffers are
    // large enough for every algorithm in the supported set (the
    // largest is RSA-4096 at ~512 bytes per key, and PQC composite
    // keys at a few kilobytes).
    const MAX_KEY: usize = 8192;
    let mut pk = vec![0u8; MAX_KEY];
    let mut sk = vec![0u8; MAX_KEY];
    let mut pk_len: u32 = 0;
    let mut sk_len: u32 = 0;
    let cname = CString::new(algorithm).unwrap();
    let (seed_ptr, seed_len) = match seed {
        Some(s) => (s.as_ptr(), s.len() as u32),
        None => (std::ptr::null(), 0),
    };
    let code = (*v0.generate)(
        cfm,
        cname.as_ptr(),
        seed_ptr,
        seed_len,
        pk.as_mut_ptr(),
        MAX_KEY as u32,
        &mut pk_len,
        sk.as_mut_ptr(),
        MAX_KEY as u32,
        &mut sk_len,
    );
    if code != 0 {
        return error::PluginInternalSnafu {
            name: plugin_name,
            code,
        }
        .fail();
    }
    if pk_len == 0 && sk_len == 0 {
        // The plugin declined this algorithm; try the next provider.
        return Ok(None);
    }
    pk.truncate(pk_len as usize);
    sk.truncate(sk_len as usize);
    Ok(Some((pk, sk)))
}

impl Keypair {
    /// Generate a keypair for `algorithm`. Walks providers in
    /// preference order; the first provider that returns a keypair
    /// wins. If `seed` is supplied it is forwarded to the plugin for
    /// deterministic test-vector generation; production callers pass
    /// `None` so the plugin reads the loaded RNG.
    pub fn generate(
        cfm: &Confium,
        algorithm: &str,
        seed: Option<&[u8]>,
        provider_name: Option<&str>,
    ) -> Result<Keypair> {
        let providers = candidates(cfm, provider_name)?;
        for provider in providers {
            let Some(iface) = interface_of(&provider.plugin) else {
                continue;
            };
            let KeypairInterface::V0(v0) = &iface.keypair;
            let pair = keypair_generate_v0(cfm, &provider.name, v0, algorithm, seed)?;
            if let Some((public_key, secret_key)) = pair {
                return Ok(Keypair {
                    public_key,
                    secret_key: Sensitive::new(secret_key),
                });
            }
        }
        error::UnsupportedAlgorithmSnafu { name: algorithm }.fail()
    }
}
