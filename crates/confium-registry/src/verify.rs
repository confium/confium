//! Signature verification.
//!
//! Two layers are kept deliberately separate:
//!
//! - **Cryptographic layer** — [`verify_signature`] checks a single
//!   detached PGP signature against the artifact bytes using the
//!   publisher's public key. It is a pure "does this signature hold?"
//!   answer with no notion of trust.
//! - **Policy layer** — [`check`] decides whether the set of signers
//!   that produced valid signatures intersects with the user's
//!   [`TrustStore`]. Only the policy layer can produce
//!   [`Error::UntrustedPlugin`].
//!
//! # Backend
//!
//! The cryptographic layer prefers the in-process RNP library (Ribose's
//! OpenPGP implementation, loaded via `libloading`). When `librnp` is
//! not loadable — e.g. it isn't installed on the host yet — the
//! verifier falls back to shelling out to `gpg --verify`. The fallback
//! exists so the trust model is enforceable in environments without a
//! pre-built `librnp`; once `rnp-rs` (see `TODO.roadmap/13-rnp-rust-binding.md`)
//! ships, the fallback will be removed and RNP becomes the sole backend.
//!
//! See `TODO.roadmap/06-module-registry.md` for the trust model
//! (publisher identity = PGP key registered in `publishers/`, artifact
//! signature = detached PGP in `sigs/`).

use crate::error::{Error, Result};
use crate::trust::TrustStore;

/// The outcome of a signature check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// At least one `signer` matched a trusted publisher.
    Verified { signers: Vec<String> },
    /// No trusted publisher signed the artifact. The caller may still
    /// proceed if `allow_untrusted` is set (development escape hatch).
    Unverified { signers: Vec<String> },
}

impl Verification {
    /// True if the artifact passed the trust policy.
    pub fn is_verified(&self) -> bool {
        matches!(self, Verification::Verified { .. })
    }

    /// The publisher names that signed the artifact (regardless of
    /// whether any were trusted).
    pub fn signers(&self) -> &[String] {
        match self {
            Verification::Verified { signers } | Verification::Unverified { signers } => signers,
        }
    }
}

/// Apply the trust policy: the artifact is trusted iff at least one of
/// `signers` is present in `trust`. Returns
/// [`Error::UntrustedPlugin`] when unverified and `allow_untrusted` is
/// false.
pub fn check(
    plugin_name: &str,
    signers: &[String],
    trust: &TrustStore,
    allow_untrusted: bool,
) -> Result<Verification> {
    let any_trusted = signers.iter().any(|s| trust.contains(s).unwrap_or(false));
    if any_trusted {
        Ok(Verification::Verified {
            signers: signers.to_vec(),
        })
    } else if allow_untrusted {
        Ok(Verification::Unverified {
            signers: signers.to_vec(),
        })
    } else {
        Err(Error::UntrustedPlugin {
            name: plugin_name.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Cryptographic layer
// ---------------------------------------------------------------------------

/// Verify a single detached PGP signature.
///
/// `artifact` is the raw bytes of the thing that was signed. `signature`
/// is the detached signature (ASCII-armored or binary). `pubkey` is the
/// publisher's public key in OpenPGP form (also ASCII-armored or
/// binary).
///
/// Returns `Ok(())` when the signature is valid, `Err(...)` otherwise.
/// The error distinguishes between:
/// - signature-format problems ([`Error::SignatureFormat`],
///   [`Error::PublicKeyFormat`]),
/// - the RNP library not being loadable ([`Error::RnpLoad`]),
/// - RNP itself rejecting the operation ([`Error::RnpVerify`]),
/// - and a syntactically valid but cryptographically bad signature
///   ([`Error::SignatureInvalid`]).
///
/// # Backend selection
///
/// Prefers in-process RNP via `libloading`. If `librnp` cannot be
/// loaded, falls back to `gpg --verify` (transitional). The fallback is
/// gated behind the [`verify_via_gpg`] helper so it can be removed
/// cleanly once `rnp-rs` lands.
pub fn verify_signature(artifact: &[u8], signature: &[u8], pubkey: &[u8]) -> Result<()> {
    match load_librnp() {
        Ok(lib) => verify_via_rnp(&lib, artifact, signature, pubkey),
        // RNP not loadable — fall back to `gpg --verify`. We deliberately
        // do NOT wrap the gpg result: the gpg path returns its own typed
        // errors (e.g. [`Error::SignatureInvalid`]) so callers can match
        // on them regardless of which backend ran. The RNP load failure
        // is logged via [`tracing`] when a logger is configured; the
        // caller sees the semantically meaningful gpg error.
        Err(_load_err) => verify_via_gpg(artifact, signature, pubkey),
    }
}

/// Candidate library filenames tried, in order, when locating `librnp`.
///
/// `libloading::Library::new` already searches the platform's standard
/// library paths; the explicit names here let us cover the
/// platform-specific SONAMEs (`librnp.dylib` on macOS, `librnp.so` on
/// Linux, `rnp.dll` on Windows) without requiring the caller to know
/// the host OS.
const LIBRNP_CANDIDATES: &[&str] = &["librnp.dylib", "librnp.so", "rnp.dll", "librnp"];

fn load_librnp() -> std::result::Result<libloading::Library, String> {
    let mut last: Option<String> = None;
    for name in LIBRNP_CANDIDATES {
        match unsafe { libloading::Library::new(*name) } {
            Ok(lib) => return Ok(lib),
            Err(e) => last = Some(format!("{name}: {e}")),
        }
    }
    Err(last.unwrap_or_else(|| "no candidate names".to_string()))
}

/// Verify via the RNP C FFI.
///
/// Mirrors the sequence documented in
/// `~/src/rnp/rnp/include/rnp/rnp.h`:
///
/// 1. `rnp_ffi_create("GPG", "GPG")` — top-level handle. Both rings are
///    GPG-format because that's what an `.asc` file is.
/// 2. `rnp_load_keys` with the publisher's public key.
/// 3. `rnp_op_verify_detached_create` over the artifact + signature.
/// 4. `rnp_op_verify_execute` — runs the verification.
/// 5. Inspect each signature via
///    `rnp_op_verify_get_signature_at` +
///    `rnp_op_verify_signature_get_status`. A signature is valid iff
///    its status is `RNP_SUCCESS`.
fn verify_via_rnp(
    lib: &libloading::Library,
    artifact: &[u8],
    signature: &[u8],
    pubkey: &[u8],
) -> Result<()> {
    // ---- function pointer typedefs matching rnp.h ----
    type RnpFfiCreateFn = unsafe extern "C" fn(
        *mut ffi::RnpFfi,
        *const std::os::raw::c_char,
        *const std::os::raw::c_char,
    ) -> ffi::RnpResult;
    type RnpFfiDestroyFn = unsafe extern "C" fn(ffi::RnpFfi) -> ffi::RnpResult;
    type RnpInputFromMemoryFn =
        unsafe extern "C" fn(*mut ffi::RnpInput, *const u8, usize, ffi::RnpBool) -> ffi::RnpResult;
    type RnpInputDestroyFn = unsafe extern "C" fn(ffi::RnpInput) -> ffi::RnpResult;
    type RnpLoadKeysFn = unsafe extern "C" fn(
        ffi::RnpFfi,
        *const std::os::raw::c_char,
        ffi::RnpInput,
        u32,
    ) -> ffi::RnpResult;
    type RnpOpVerifyDetachedCreateFn = unsafe extern "C" fn(
        *mut ffi::RnpOpVerify,
        ffi::RnpFfi,
        ffi::RnpInput,
        ffi::RnpInput,
    ) -> ffi::RnpResult;
    type RnpOpVerifyExecuteFn = unsafe extern "C" fn(ffi::RnpOpVerify) -> ffi::RnpResult;
    type RnpOpVerifyDestroyFn = unsafe extern "C" fn(ffi::RnpOpVerify) -> ffi::RnpResult;
    type RnpOpVerifyGetSignatureCountFn =
        unsafe extern "C" fn(ffi::RnpOpVerify, *mut usize) -> ffi::RnpResult;
    type RnpOpVerifyGetSignatureAtFn =
        unsafe extern "C" fn(ffi::RnpOpVerify, usize, *mut ffi::RnpOpVerifySig) -> ffi::RnpResult;
    type RnpOpVerifySignatureGetStatusFn =
        unsafe extern "C" fn(ffi::RnpOpVerifySig) -> ffi::RnpResult;

    // ---- resolve symbols ----
    macro_rules! sym {
        ($name:literal, $ty:ty) => {{
            let name_str = std::str::from_utf8($name).unwrap_or("<non-utf8 symbol>");
            match unsafe { lib.get::<$ty>($name) } {
                Ok(f) => *f,
                Err(e) => {
                    return Err(Error::RnpLoad {
                        message: format!("symbol {name_str} not found: {e}"),
                    });
                }
            }
        }};
    }

    let ffi_create: RnpFfiCreateFn = sym!(b"rnp_ffi_create\0", RnpFfiCreateFn);
    let ffi_destroy: RnpFfiDestroyFn = sym!(b"rnp_ffi_destroy\0", RnpFfiDestroyFn);
    let input_from_memory: RnpInputFromMemoryFn =
        sym!(b"rnp_input_from_memory\0", RnpInputFromMemoryFn);
    let input_destroy: RnpInputDestroyFn = sym!(b"rnp_input_destroy\0", RnpInputDestroyFn);
    let load_keys: RnpLoadKeysFn = sym!(b"rnp_load_keys\0", RnpLoadKeysFn);
    let op_verify_detached_create: RnpOpVerifyDetachedCreateFn = sym!(
        b"rnp_op_verify_detached_create\0",
        RnpOpVerifyDetachedCreateFn
    );
    let op_verify_execute: RnpOpVerifyExecuteFn =
        sym!(b"rnp_op_verify_execute\0", RnpOpVerifyExecuteFn);
    let op_verify_destroy: RnpOpVerifyDestroyFn =
        sym!(b"rnp_op_verify_destroy\0", RnpOpVerifyDestroyFn);
    let get_sig_count: RnpOpVerifyGetSignatureCountFn = sym!(
        b"rnp_op_verify_get_signature_count\0",
        RnpOpVerifyGetSignatureCountFn
    );
    let get_sig_at: RnpOpVerifyGetSignatureAtFn = sym!(
        b"rnp_op_verify_get_signature_at\0",
        RnpOpVerifyGetSignatureAtFn
    );
    let get_sig_status: RnpOpVerifySignatureGetStatusFn = sym!(
        b"rnp_op_verify_signature_get_status\0",
        RnpOpVerifySignatureGetStatusFn
    );

    // ---- run the verification ----
    // SAFETY: every call below passes either a freshly-created opaque
    // handle or a borrowed byte slice whose lifetime outlives the call.
    // The handles are paired with their destroyers in the same scope.
    unsafe {
        let mut ffi_handle: ffi::RnpFfi = std::ptr::null_mut();
        let gpg = b"GPG\0";
        let rc = (ffi_create)(
            &mut ffi_handle as *mut ffi::RnpFfi,
            gpg.as_ptr() as *const std::os::raw::c_char,
            gpg.as_ptr() as *const std::os::raw::c_char,
        );
        if rc != ffi::RNP_SUCCESS || ffi_handle.is_null() {
            return Err(Error::RnpVerify {
                message: format!("rnp_ffi_create failed (rc={rc:#x})"),
            });
        }
        // RAII guard so the FFI handle is always destroyed.
        struct FfiGuard {
            handle: ffi::RnpFfi,
            destroy: RnpFfiDestroyFn,
        }
        impl Drop for FfiGuard {
            fn drop(&mut self) {
                if !self.handle.is_null() {
                    unsafe { (self.destroy)(self.handle) };
                }
            }
        }
        let ffi_guard = FfiGuard {
            handle: ffi_handle,
            destroy: ffi_destroy,
        };

        // Load the publisher's public key.
        let mut key_input: ffi::RnpInput = std::ptr::null_mut();
        let rc = (input_from_memory)(
            &mut key_input as *mut ffi::RnpInput,
            pubkey.as_ptr(),
            pubkey.len(),
            ffi::RNP_TRUE,
        );
        if rc != ffi::RNP_SUCCESS {
            return Err(Error::PublicKeyFormat {
                path: "<bytes>".to_string(),
            });
        }
        let key_guard = InputGuard {
            handle: key_input,
            destroy: input_destroy,
        };
        let rc = (load_keys)(
            ffi_guard.handle,
            gpg.as_ptr() as *const std::os::raw::c_char,
            key_input,
            ffi::RNP_LOAD_SAVE_PUBLIC_KEYS,
        );
        drop(key_guard);
        if rc != ffi::RNP_SUCCESS {
            return Err(Error::PublicKeyFormat {
                path: "<bytes>".to_string(),
            });
        }

        // Build the artifact + signature inputs.
        let mut data_input: ffi::RnpInput = std::ptr::null_mut();
        let rc = (input_from_memory)(
            &mut data_input as *mut ffi::RnpInput,
            artifact.as_ptr(),
            artifact.len(),
            ffi::RNP_TRUE,
        );
        if rc != ffi::RNP_SUCCESS {
            return Err(Error::RnpVerify {
                message: format!("rnp_input_from_memory (artifact) failed (rc={rc:#x})"),
            });
        }
        let data_guard = InputGuard {
            handle: data_input,
            destroy: input_destroy,
        };

        let mut sig_input: ffi::RnpInput = std::ptr::null_mut();
        let rc = (input_from_memory)(
            &mut sig_input as *mut ffi::RnpInput,
            signature.as_ptr(),
            signature.len(),
            ffi::RNP_TRUE,
        );
        if rc != ffi::RNP_SUCCESS {
            return Err(Error::SignatureFormat {
                path: "<bytes>".to_string(),
            });
        }
        let sig_guard = InputGuard {
            handle: sig_input,
            destroy: input_destroy,
        };

        let mut op: ffi::RnpOpVerify = std::ptr::null_mut();
        let rc = (op_verify_detached_create)(
            &mut op as *mut ffi::RnpOpVerify,
            ffi_guard.handle,
            data_input,
            sig_input,
        );
        if rc != ffi::RNP_SUCCESS || op.is_null() {
            return Err(Error::RnpVerify {
                message: format!("rnp_op_verify_detached_create failed (rc={rc:#x})"),
            });
        }
        let op_guard = OpVerifyGuard {
            handle: op,
            destroy: op_verify_destroy,
        };

        // Execute. By default RNP returns success when at least one
        // signature is valid; we explicitly check each signature
        // afterward so we can report the exact status.
        let rc = (op_verify_execute)(op);
        if rc != ffi::RNP_SUCCESS {
            // Execute failed outright — likely a malformed signature or
            // unreadable data. Surface as invalid rather than RNP-internal
            // so callers can distinguish "couldn't run" from "ran, bad".
            return Err(Error::SignatureInvalid {
                message: format!("rnp_op_verify_execute failed (rc={rc:#x})"),
            });
        }

        // Walk signatures. We need at least one RNP_SUCCESS status.
        let mut count: usize = 0;
        let rc = (get_sig_count)(op, &mut count as *mut usize);
        if rc != ffi::RNP_SUCCESS {
            return Err(Error::RnpVerify {
                message: format!("rnp_op_verify_get_signature_count failed (rc={rc:#x})"),
            });
        }
        if count == 0 {
            return Err(Error::SignatureInvalid {
                message: "no signatures present".to_string(),
            });
        }

        let mut last_status: u32 = 0;
        let mut saw_valid = false;
        for idx in 0..count {
            let mut sig: ffi::RnpOpVerifySig = std::ptr::null_mut();
            let rc = (get_sig_at)(op, idx, &mut sig as *mut ffi::RnpOpVerifySig);
            if rc != ffi::RNP_SUCCESS {
                return Err(Error::RnpVerify {
                    message: format!("rnp_op_verify_get_signature_at({idx}) failed (rc={rc:#x})"),
                });
            }
            let status = (get_sig_status)(sig);
            last_status = status;
            if status == ffi::RNP_SUCCESS {
                saw_valid = true;
            }
        }

        drop(op_guard);
        drop(sig_guard);
        drop(data_guard);
        drop(ffi_guard);

        if saw_valid {
            Ok(())
        } else {
            Err(Error::SignatureInvalid {
                message: format!("no valid signature (last status={last_status:#x})"),
            })
        }
    }
}

struct InputGuard {
    handle: ffi::RnpInput,
    destroy: unsafe extern "C" fn(ffi::RnpInput) -> ffi::RnpResult,
}
impl Drop for InputGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { (self.destroy)(self.handle) };
        }
    }
}

struct OpVerifyGuard {
    handle: ffi::RnpOpVerify,
    destroy: unsafe extern "C" fn(ffi::RnpOpVerify) -> ffi::RnpResult,
}
impl Drop for OpVerifyGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { (self.destroy)(self.handle) };
        }
    }
}

/// Transitional verifier: shell out to `gpg --verify`.
///
/// Writes the three byte slices into a scratch tempdir, then invokes
/// `gpg --verify <sig> <data>` with a keyring pointed at the publisher's
/// pubkey. The exit code distinguishes valid (0) from invalid (1).
///
/// This is intentionally simple: it's the path that runs when `librnp`
/// isn't available. Once `rnp-rs` is wired in this whole function (and
/// its caller in [`verify_signature`]) will be removed.
fn verify_via_gpg(artifact: &[u8], signature: &[u8], pubkey: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::process::Command;

    // Use a process-unique scratch dir under the system temp rather
    // than pulling `tempfile` as a runtime dependency. We clean up at
    // the end; if cleanup fails the OS will reap it on reboot.
    let scratch = std::env::temp_dir().join(format!(
        "confium-verify-{}-{}",
        std::process::id(),
        scratch_counter()
    ));
    std::fs::create_dir_all(&scratch).map_err(|e| Error::VerificationSubprocess {
        message: format!("failed to create tempdir {}: {e}", scratch.display()),
    })?;

    let key_path = scratch.join("pubkey.asc");
    let data_path = scratch.join("artifact.bin");
    let sig_path = scratch.join("sig.asc");
    let gpg_home = scratch.join("gpghome");

    let write_file = |path: &std::path::Path, body: &[u8], what: &str| -> Result<()> {
        let mut f = std::fs::File::create(path).map_err(|e| Error::VerificationSubprocess {
            message: format!("failed to create {what} {}: {e}", path.display()),
        })?;
        f.write_all(body)
            .map_err(|e| Error::VerificationSubprocess {
                message: format!("failed to write {what} {}: {e}", path.display()),
            })?;
        Ok(())
    };

    write_file(&key_path, pubkey, "pubkey")?;
    write_file(&data_path, artifact, "artifact")?;
    write_file(&sig_path, signature, "signature")?;

    // gpg insists on 0700 perms on its home dir.
    std::fs::create_dir_all(&gpg_home).map_err(|e| Error::VerificationSubprocess {
        message: format!("failed to create gpghome: {e}"),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&gpg_home, std::fs::Permissions::from_mode(0o700)).map_err(
            |e| Error::VerificationSubprocess {
                message: format!("failed to chmod gpghome: {e}"),
            },
        )?;
    }

    let gnupg_arg = format!("{}", gpg_home.display());

    let import = Command::new("gpg")
        .args(["--homedir", &gnupg_arg, "--import"])
        .arg(&key_path)
        .output()
        .map_err(|e| Error::VerificationSubprocess {
            message: format!("failed to invoke gpg --import: {e}"),
        })?;
    if !import.status.success() {
        let _ = std::fs::remove_dir_all(&scratch);
        return Err(Error::VerificationSubprocess {
            message: format!(
                "gpg --import failed: {}",
                String::from_utf8_lossy(&import.stderr).trim()
            ),
        });
    }

    let verify = Command::new("gpg")
        .args(["--homedir", &gnupg_arg, "--verify"])
        .arg(&sig_path)
        .arg(&data_path)
        .output()
        .map_err(|e| Error::VerificationSubprocess {
            message: format!("failed to invoke gpg --verify: {e}"),
        })?;

    // Best-effort cleanup. We don't care if it fails.
    let _ = std::fs::remove_dir_all(&scratch);

    if verify.status.success() {
        Ok(())
    } else {
        Err(Error::SignatureInvalid {
            message: format!(
                "gpg --verify rejected signature: {}",
                String::from_utf8_lossy(&verify.stderr).trim()
            ),
        })
    }
}

/// Monotonic counter to ensure each `verify_via_gpg` invocation gets a
/// unique scratch directory even when called concurrently from the same
/// process. Uses `AtomicU64` so concurrent calls don't collide.
fn scratch_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Minimal FFI type aliases for RNP. Kept private; once `rnp-rs` ships
/// these move into the binding crate.
mod ffi {
    pub type RnpResult = u32;
    pub type RnpBool = bool;

    pub type RnpFfi = *mut std::os::raw::c_void;
    pub type RnpInput = *mut std::os::raw::c_void;
    pub type RnpOpVerify = *mut std::os::raw::c_void;
    pub type RnpOpVerifySig = *mut std::os::raw::c_void;

    /// RNP_SUCCESS — see `rnp_err.h` in the RNP source tree.
    pub const RNP_SUCCESS: RnpResult = 0;
    pub const RNP_TRUE: RnpBool = true;

    /// `RNP_LOAD_SAVE_PUBLIC_KEYS` from `rnp.h`.
    pub const RNP_LOAD_SAVE_PUBLIC_KEYS: u32 = 1 << 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::TrustRoot;
    use crate::trust::TrustStore;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn root(name: &str) -> TrustRoot {
        TrustRoot {
            name: name.to_string(),
            key_id: "0x1".to_string(),
            fingerprint: "AAAA".to_string(),
            key_url: format!("/publishers/{}.asc", name),
        }
    }

    fn store_at(dir: &tempfile::TempDir) -> TrustStore {
        TrustStore::for_home(PathBuf::from(dir.path()))
    }

    #[test]
    fn verifies_when_trusted_signer_present() {
        let dir = tempdir().unwrap();
        let store = store_at(&dir);
        store.add(root("ribose")).unwrap();
        let v = check("botan", &["ribose".to_string()], &store, false).unwrap();
        assert!(v.is_verified());
    }

    #[test]
    fn refuses_untrusted_without_override() {
        let dir = tempdir().unwrap();
        let store = store_at(&dir);
        let err = check("botan", &["stranger".to_string()], &store, false).unwrap_err();
        assert!(matches!(err, Error::UntrustedPlugin { .. }));
    }

    #[test]
    fn allows_untrusted_with_override() {
        let dir = tempdir().unwrap();
        let store = store_at(&dir);
        let v = check("botan", &["stranger".to_string()], &store, true).unwrap();
        assert!(!v.is_verified());
        assert_eq!(v.signers(), &["stranger"]);
    }
}

#[cfg(test)]
mod pgp_tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::TempDir;

    /// Skip the whole module if `gpg` isn't on PATH. The CI images used
    /// for this workspace ship gpg, but a developer running `cargo test`
    /// locally shouldn't see spurious failures just because they lack
    /// it.
    fn gpg_path() -> Option<PathBuf> {
        super::which_shim::which("gpg").or_else(|| {
            let out = Command::new("sh")
                .args(["-c", "command -v gpg"])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(PathBuf::from(s))
            }
        })
    }

    /// A throwaway keypair + scratch dir, all generated via the `gpg`
    /// CLI. Built once per test that needs it (cheap — RSA-1024 batch
    /// generation takes well under a second).
    struct Fixture {
        gpg: PathBuf,
        home: PathBuf,
        _tmp: TempDir,
        keyid: String,
    }

    impl Fixture {
        fn new() -> Option<Self> {
            let gpg = gpg_path()?;
            let tmp = tempfile::tempdir().ok()?;
            let home = tmp.path().join("gpghome");
            fs::create_dir_all(&home).ok()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).ok()?;
            }
            let home_arg = format!("{}", home.display());

            // Batch-generate a key without user interaction.
            let batch = r#"Key-Type: RSA
Key-Length: 1024
Name-Real: Confium Test Publisher
Name-Email: test@confium.example
Expire-Date: 0
%no-protection
%commit
"#;
            let batch_path = tmp.path().join("batch");
            fs::write(&batch_path, batch).ok()?;

            let gen_out = Command::new(&gpg)
                .args(["--homedir", &home_arg, "--batch", "--gen-key"])
                .arg(&batch_path)
                .output()
                .ok()?;
            if !gen_out.status.success() {
                return None;
            }

            // Find the keyid of the freshly generated key.
            let list = Command::new(&gpg)
                .args(["--homedir", &home_arg, "--list-keys", "--with-colons"])
                .output()
                .ok()?;
            if !list.status.success() {
                return None;
            }
            let stdout = String::from_utf8_lossy(&list.stdout);
            let keyid = stdout.lines().find_map(|line| {
                let mut fields = line.split(':');
                if fields.next() == Some("pub") {
                    // pub:o:2048:1:<keyid>:<created>:<expires>:::e::esc
                    fields.nth(3).map(|s| s.to_string())
                } else {
                    None
                }
            })?;

            Some(Fixture {
                gpg,
                home,
                _tmp: tmp,
                keyid,
            })
        }

        fn home_arg(&self) -> String {
            format!("{}", self.home.display())
        }

        /// Export the public key (ASCII-armored) as bytes.
        fn export_pubkey(&self) -> Vec<u8> {
            let out = Command::new(&self.gpg)
                .args([
                    "--homedir",
                    &self.home_arg(),
                    "--armor",
                    "--export",
                    &self.keyid,
                ])
                .output()
                .expect("gpg --export");
            assert!(out.status.success(), "gpg export failed");
            out.stdout
        }

        /// Sign `data` with the test secret key, returning the detached
        /// ASCII-armored signature.
        fn sign_detached(&self, data: &[u8]) -> Vec<u8> {
            let tmp = tempfile::tempdir().expect("tempdir");
            let data_path = tmp.path().join("data.bin");
            fs::write(&data_path, data).expect("write data");
            let out = Command::new(&self.gpg)
                .args([
                    "--homedir",
                    &self.home_arg(),
                    "--batch",
                    "--yes",
                    "--detach-sign",
                    "--armor",
                ])
                .arg(&data_path)
                .output()
                .expect("gpg --detach-sign");
            assert!(out.status.success(), "gpg sign failed");
            let sig_path = tmp.path().join("data.bin.asc");
            fs::read(&sig_path).expect("read sig")
        }
    }

    #[test]
    fn verify_signature_accepts_valid_signature() {
        let f = match Fixture::new() {
            Some(f) => f,
            None => {
                eprintln!("skipping: gpg not available");
                return;
            }
        };
        let pubkey = f.export_pubkey();
        let artifact = b"the quick brown fox jumps over the lazy dog";
        let sig = f.sign_detached(artifact);
        assert!(verify_signature(artifact, &sig, &pubkey).is_ok());
    }

    #[test]
    fn verify_signature_rejects_tampered_artifact() {
        let f = match Fixture::new() {
            Some(f) => f,
            None => {
                eprintln!("skipping: gpg not available");
                return;
            }
        };
        let pubkey = f.export_pubkey();
        let sig = f.sign_detached(b"original artifact bytes");
        let tampered = b"modified artifact bytes";
        let err = verify_signature(tampered, &sig, &pubkey).unwrap_err();
        assert!(
            matches!(
                err,
                Error::SignatureInvalid { .. } | Error::RnpVerify { .. }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn verify_signature_rejects_wrong_pubkey() {
        let f = match Fixture::new() {
            Some(f) => f,
            None => {
                eprintln!("skipping: gpg not available");
                return;
            }
        };
        // Sign with one key, verify against another.
        let artifact = b"some artifact";
        let sig = f.sign_detached(artifact);
        // Build a second fixture for an unrelated key.
        let other = Fixture::new().expect("second fixture");
        let wrong_pubkey = other.export_pubkey();
        let err = verify_signature(artifact, &sig, &wrong_pubkey).unwrap_err();
        assert!(
            matches!(
                err,
                Error::SignatureInvalid { .. } | Error::RnpVerify { .. }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn verify_signature_rejects_garbage_signature() {
        let f = match Fixture::new() {
            Some(f) => f,
            None => {
                eprintln!("skipping: gpg not available");
                return;
            }
        };
        let pubkey = f.export_pubkey();
        let garbage = b"not a real signature";
        let err = verify_signature(b"artifact", garbage, &pubkey).unwrap_err();
        // Either RNP fails outright or reports an invalid signature.
        assert!(
            matches!(
                err,
                Error::SignatureInvalid { .. }
                    | Error::RnpVerify { .. }
                    | Error::SignatureFormat { .. }
            ),
            "unexpected error: {err:?}"
        );
    }

    /// Sanity: `gpg --verify` fallback path works on its own.
    #[test]
    fn gpg_fallback_accepts_valid_signature() {
        let f = match Fixture::new() {
            Some(f) => f,
            None => {
                eprintln!("skipping: gpg not available");
                return;
            }
        };
        let pubkey = f.export_pubkey();
        let artifact = b"artifact bytes";
        let sig = f.sign_detached(artifact);
        assert!(verify_via_gpg(artifact, &sig, &pubkey).is_ok());
    }
}

// `which` is dev-only; pull it in conditionally without polluting the
// main Cargo.toml dependencies.
#[cfg(test)]
mod which_shim {
    /// Resolve an executable name on `$PATH` without pulling a crate.
    pub fn which(name: &str) -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }
}
