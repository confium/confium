//! TPM 2.0 backend for [`confium-store`].
//!
//! Implements [`StoreBackend`](confium_store::backend::StoreBackend) and
//! [`StoreInstance`](confium_store::backend::StoreInstance) on top of
//! `tss-esapi`. The current revision wires the trait and configuration
//! plumbing; storage operations return
//! [`NotImplemented`](confium_store::Error::NotImplemented). The real
//! `tss-esapi` calls land behind the `tpm` feature flag in the next
//! revision — see `TODO.roadmap/18-hardware-keystore-backends.md`.
//!
//! ## Wire name
//!
//! The backend advertises itself as `"tpm"` so the FFI create path can
//! look it up via [`confium_store::backend::find`].
//!
//! ## Key-handle semantics
//!
//! Hardware backends typically do not return raw key bytes; they return
//! handles (TPM persistent object handles). Per the roadmap, `put_secret`
//! will seal the caller-supplied bytes under the parent key and store the
//! resulting object handle; `get_secret` will return the handle as the
//! opaque `*mut c_void`. Signature/KEM plugins that want to actually use
//! the key invoke the HSM-style `cfmp_sign_with_handle` symbol described
//! in `TODO.roadmap/18-hardware-keystore-backends.md`. The skeleton does
//! not yet wire this — every operation is a `NotImplemented` stub.

use std::ffi::c_void;

use confium_store::backend::{Compartment, Options, StoreBackend, StoreInstance};
use confium_store::error::{Error, NotImplementedSnafu, Result};
use confium_store::register_backend;

use crate::config::TpmConfig;

/// What is unimplemented in this skeleton. Centralised so the wire
/// message is consistent across every stub and the tests can match on
/// the string.
const SKELETON_NOT_IMPLEMENTED: &str = "tpm 2.0 backend (skeleton; enable the `tpm` feature)";

/// Factory for the TPM backend. Stateless — all per-keystore state lives
/// in [`TpmInstance`].
///
/// Construct directly (`TpmBackend`) or look up via the link-time
/// registry under the wire name `"tpm"`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TpmBackend;

impl StoreBackend for TpmBackend {
    fn name(&self) -> &'static str {
        "tpm"
    }

    fn open(&self, opts: &Options) -> Result<Box<dyn StoreInstance>> {
        // Parse the options eagerly so configuration errors surface at
        // open time rather than on the first storage call. The parsed
        // config is carried by the instance for the (future)
        // `tss-esapi` session establishment.
        let config = TpmConfig::from_options(opts)?;
        Ok(Box::new(TpmInstance::from_config(config)))
    }
}

register_backend!(TpmBackend);

/// One open TPM-backed keystore connection.
///
/// Carries the parsed [`TpmConfig`] as a public field so callers (and
/// tests) can inspect the resolved configuration after `open`. With the
/// `tpm` feature enabled it additionally owns a (future) `tss-esapi`
/// context; for now the field is a placeholder so the struct shape is
/// stable across the skeleton and the wired-up revision.
pub struct TpmInstance {
    /// Resolved configuration parsed from [`Options`] at open time.
    pub config: TpmConfig,

    /// Placeholder for the `tss-esapi` `Context`. Populated when the
    /// `tpm` feature lands the real session establishment; `None` for
    /// the skeleton.
    #[cfg(feature = "tpm")]
    session: Option<()>,
}

impl TpmInstance {
    /// Construct an instance directly from a parsed config. Useful for
    /// tests and for callers that already have a typed config rather
    /// than the string-keyed options map.
    pub fn from_config(config: TpmConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "tpm")]
            session: None,
        }
    }

    /// Helper that builds the canonical skeleton error. Centralised so
    /// the message stays uniform across every stub.
    fn not_implemented() -> Error {
        NotImplementedSnafu {
            what: SKELETON_NOT_IMPLEMENTED,
        }
        .build()
    }
}

impl StoreInstance for TpmInstance {
    fn put_secret(
        &mut self,
        _module: &str,
        _app: &str,
        _key_id: &str,
        _key: *mut c_void,
    ) -> Result<()> {
        // Skeleton: the wired-up revision will seal `key` under the
        // parent key (`self.config.parent_handle`) and persist the
        // resulting object under `(module, app, key_id)`.
        Err(Self::not_implemented())
    }

    fn get_secret(&self, _module: &str, _app: &str, _key_id: &str) -> Result<*mut c_void> {
        // Skeleton: look up the sealed object for `(module, app, key_id)`
        // and return its persistent handle as `*mut c_void`.
        Err(Self::not_implemented())
    }

    fn put_public(
        &mut self,
        _module: &str,
        _app: &str,
        _identity: &str,
        _key: *mut c_void,
        _sig: &[u8],
    ) -> Result<()> {
        // Skeleton: public compartments on a TPM are typically stored as
        // NV indices or as a public-area blob; deferred to the next
        // revision.
        Err(Self::not_implemented())
    }

    fn get_public(
        &self,
        _module: &str,
        _app: &str,
        _identity: &str,
    ) -> Result<(*mut c_void, Vec<u8>)> {
        Err(Self::not_implemented())
    }

    fn enumerate(
        &self,
        _module: &str,
        _app: &str,
        _compartment: Compartment,
    ) -> Result<Vec<(*mut c_void, String)>> {
        // Skeleton: enumerate the sealed objects (or NV indices) under
        // the (module, app) scope. The wired-up revision will read them
        // out of `tss-esapi`'s persistent-object list.
        Err(Self::not_implemented())
    }
}

// SAFETY: the skeleton carries only a parsed config (a `PathBuf`, an
// enum, an `Option<ParentHandle>`, and a `Vec<u8>`); nothing is
// thread-local or `!Send`. The future `tss-esapi::Context` is itself
// `Send + Sync` per upstream documentation, so adding it behind the
// `tpm` feature preserves soundness.
unsafe impl Send for TpmInstance {}
unsafe impl Sync for TpmInstance {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Hierarchy;
    use std::collections::HashMap;

    /// Open the backend with a minimal options map. Exercises the
    /// config-parse path that runs in `open`.
    fn open() -> TpmInstance {
        let mut opts: Options = HashMap::new();
        opts.insert("tpm_device".into(), "/dev/tpmrmis0".into());
        opts.insert("hierarchy".into(), "owner".into());
        opts.insert("parent_handle".into(), "0x81000001".into());
        let boxed = TpmBackend.open(&opts).expect("tpm backend opens");
        // The `open` contract returns a `Box<dyn StoreInstance>`; the
        // concrete type is `TpmInstance`. We downcast via the same trick
        // the in-tree tests use: leak the box and reconstruct.
        //
        // Tests reach the parsed config by reading `TpmInstance.config`
        // directly; we side-step the trait object by constructing the
        // instance via `from_config` for the config-asserting tests.
        //
        // For the trait-method tests below we keep the `Box<dyn
        // StoreInstance>` shape so we exercise the real open path.
        // SAFETY: `boxed` was just produced by `TpmBackend::open`; its
        // concrete type is `TpmInstance`.
        let raw = Box::into_raw(boxed) as *mut TpmInstance;
        unsafe { *Box::from_raw(raw) }
    }

    /// Sentinel non-null pointer; the backend treats `*mut c_void` as
    /// opaque in this skeleton so identity does not matter.
    fn sentinel(n: usize) -> *mut c_void {
        n as *mut c_void
    }

    #[test]
    fn backend_advertises_tpm_wire_name() {
        assert_eq!(TpmBackend.name(), "tpm");
    }

    #[test]
    fn backend_is_registered() {
        // The link-time registry must surface the tpm backend by its
        // wire name so the FFI create path can find it. This is the
        // single most important contract for a backend.
        let backend = confium_store::backend::find("tpm").expect("tpm backend registered");
        assert_eq!(backend.name(), "tpm");
    }

    #[test]
    fn open_parses_config() {
        let inst = open();
        // The parsed config survives the `open` path intact.
        assert_eq!(inst.config.hierarchy, Hierarchy::Owner);
        assert_eq!(
            inst.config.device.as_deref(),
            Some(std::path::Path::new("/dev/tpmrmis0"))
        );
        assert_eq!(inst.config.parent_handle.unwrap().raw(), 0x8100_0001);
    }

    #[test]
    fn put_secret_returns_not_implemented() {
        let mut ks = open();
        let err = ks
            .put_secret("mod", "app", "k1", sentinel(0x1000))
            .unwrap_err();
        assert!(matches!(err, Error::NotImplemented { .. }));
    }

    #[test]
    fn get_secret_returns_not_implemented() {
        let ks = open();
        let err = ks.get_secret("mod", "app", "k1").unwrap_err();
        assert!(matches!(err, Error::NotImplemented { .. }));
    }

    #[test]
    fn put_public_returns_not_implemented() {
        let mut ks = open();
        let err = ks
            .put_public("mod", "app", "id", sentinel(0x2000), &[0u8])
            .unwrap_err();
        assert!(matches!(err, Error::NotImplemented { .. }));
    }

    #[test]
    fn get_public_returns_not_implemented() {
        let ks = open();
        let err = ks.get_public("mod", "app", "id").unwrap_err();
        assert!(matches!(err, Error::NotImplemented { .. }));
    }

    #[test]
    fn enumerate_returns_not_implemented() {
        let ks = open();
        let err = ks
            .enumerate("mod", "app", Compartment::Private)
            .unwrap_err();
        assert!(matches!(err, Error::NotImplemented { .. }));
    }

    #[test]
    fn from_config_preserves_config() {
        // Callers that already have a typed config can construct the
        // instance directly without going through the options map.
        let cfg = TpmConfig {
            device: Some(std::path::PathBuf::from("/dev/tpm0")),
            hierarchy: Hierarchy::Endorsement,
            parent_handle: Some(crate::config::ParentHandle(0x8100_0042)),
            parent_password: b"pw".to_vec(),
        };
        let inst = TpmInstance::from_config(cfg.clone());
        assert_eq!(inst.config, cfg);
    }

    // -------------------------------------------------------------------
    // Hardware-backed tests (swtpm simulator).
    //
    // The following tests exercise the wired-up TPM operations against
    // the `swtpm` software TPM simulator. They are skipped unless the
    // `CFM_TPM_TEST` environment variable is set *and* the `tpm` feature
    // is enabled. The setup steps are documented here so a future
    // contributor can run them locally:
    //
    //   # Install swtpm and tpm2-tss (macOS):
    //   brew install swtpm tpm2-tss
    //
    //   # Start a simulator bound to a TCP TCTI:
    //   swtpm socket --tpm2 --server port=2321 \
    //     --ctrl type=tcp,port=2322 --flags not-need-init \
    //     --tpmstate dir=/tmp/swtpm-state --daemon
    //
    //   # Run the tests:
    //   CFM_TPM_TEST=1 cargo test -p confium-store-tpm --features tpm
    //
    // On CI (Linux), the simulator is provisioned by the workflow and
    // `CFM_TPM_TEST=1` is exported automatically. See
    // `TODO.roadmap/18-hardware-keystore-backends.md` for the full plan.
    #[cfg(feature = "tpm")]
    fn hw_available() -> bool {
        std::env::var_os("CFM_TPM_TEST").is_some()
    }

    #[cfg(feature = "tpm")]
    #[test]
    fn put_get_secret_round_trip_on_simulator() {
        if !hw_available() {
            eprintln!("skipping TPM simulator test: set CFM_TPM_TEST=1 and start swtpm to enable");
            return;
        }
        // TODO(skeleton): wire against `tss-esapi` once the `tpm` feature
        // lands the real session establishment. The test shape is
        // preserved here so the contract is obvious.
    }
}
