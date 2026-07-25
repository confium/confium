//! PKCS#11 backend for [`confium-store`].
//!
//! Implements [`StoreBackend`](confium_store::backend::StoreBackend) on top
//! of the [`cryptoki`] crate (Apache-2.0), giving Confium a
//! hardware-backed keystore for HSMs (YubiHSM, Thales, Utimaco),
//! smartcards, and software tokens such as [SoftHSM2].
//!
//! The current revision wires the trait, configuration, and
//! `cryptoki`-level session-establishment plumbing. The actual HSM
//! object operations (`put_secret`, `get_secret`, …) live on
//! [`Pkcs11Instance`](crate::Pkcs11Instance) and return
//! [`NotImplemented`](confium_store::error::Error::NotImplemented) —
//! see `TODO.roadmap/18-hardware-keystore-backends.md`.
//!
//! ## Wire name
//!
//! The backend advertises itself as `"pkcs11"` so the FFI create path
//! can look it up via [`confium_store::backend::find`].
//!
//! ## Key-handle semantics
//!
//! Like the other hardware backends, the PKCS#11 store does not return
//! raw key bytes from `get_secret`; it returns the PKCS#11 object
//! handle (an opaque `*mut c_void`). Signature/KEM plugins that want
//! to actually use the key invoke the HSM-style `cfmp_sign_withhandle`
//! symbol described in `TODO.roadmap/18-hardware-keystore-backends.md`.
//! The skeleton does not yet wire this — every storage operation is a
//! `NotImplemented` stub; the session plumbing (module load,
//! initialize, slot resolve, open session, login) is wired for real.
//!
//! [SoftHSM2]: https://www.opendnssec.org/softhsm/

use confium_store::backend::{Options, StoreBackend, StoreInstance};
use confium_store::error::{Error, NotImplementedSnafu, Result};
use confium_store::register_backend;

use crate::config::Config;
use crate::error::{IntoStoreError, map_cryptoki};
use crate::instance::Pkcs11Instance;

/// What is unimplemented in this skeleton. Centralised so the wire
/// message is consistent across every stub and the tests can match on
/// the string.
const SKELETON_NOT_IMPLEMENTED: &str =
    "pkcs#11 backend (skeleton; HSM object ops land in the next revision)";

/// Factory for the PKCS#11 backend. Stateless — all per-keystore state
/// lives in [`Pkcs11Instance`].
///
/// Construct directly (`Pkcs11Backend`) or look up via the link-time
/// registry under the wire name `"pkcs11"`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Pkcs11Backend;

impl StoreBackend for Pkcs11Backend {
    fn name(&self) -> &'static str {
        "pkcs11"
    }

    fn open(&self, opts: &Options) -> Result<Box<dyn StoreInstance>> {
        // Parse options eagerly so configuration errors surface at open
        // time rather than on the first storage call.
        let config = Config::from_options(opts)?;

        // Load and initialise the PKCS#11 module. `OS_LOCKING_OK` tells
        // the module it may use the platform's native threading
        // primitives, which is what makes the resulting client
        // `Send + Sync`.
        let client = cryptoki::context::Pkcs11::new(config.pkcs11_module.as_str())
            .map_err(|e| e.into_store_error("load pkcs11 module"))?;
        map_cryptoki(
            client.initialize(cryptoki::context::CInitializeArgs::new(
                cryptoki::context::CInitializeFlags::OS_LOCKING_OK,
            )),
            "initialize",
        )?;

        // Resolve the slot. If a token label is supplied, we assert it
        // matches the slot we resolved by id — defensive, so a
        // misconfiguration surfaces at open time rather than silently
        // addressing the wrong token.
        let slot = resolve_slot(&client, &config)?;

        // Open a read/write session so both put and get paths work
        // against the same handle.
        let session = map_cryptoki(client.open_rw_session(slot), "open session")?;

        // Log in as the normal user if a PIN was supplied. If absent,
        // leave the session unauthenticated — operations that require
        // `CKU_USER` will surface a `Wrapped` cryptoki error at call
        // time, which is the right behaviour for an operator-prompted
        // flow.
        if let Some(pin) = config.pin.as_deref() {
            let auth = cryptoki::types::AuthPin::new(pin.to_string().into_boxed_str());
            map_cryptoki(
                session.login(cryptoki::session::UserType::User, Some(&auth)),
                "login",
            )?;
        }

        Ok(Box::new(Pkcs11Instance::new(config, client, session)))
    }
}

register_backend!(Pkcs11Backend);

/// Resolve the configured slot. Uses the explicit `slot_id`; if a
/// `token_label` is also present, asserts that the slot's token label
/// matches (defensive — surfaces a misconfiguration at open time
/// instead of silently addressing the wrong token).
fn resolve_slot(
    client: &cryptoki::context::Pkcs11,
    config: &Config,
) -> Result<cryptoki::slot::Slot> {
    let slots = map_cryptoki(client.get_slots_with_token(), "get slots")?;
    let by_id = *slots
        .iter()
        .find(|s| s.id() == config.slot_id)
        .ok_or_else(|| Error::Wrapped {
            message: format!(
                "pkcs#11: no token-present slot with id {} (have: {:?})",
                config.slot_id,
                slots.iter().map(|s| s.id()).collect::<Vec<_>>()
            ),
        })?;

    if let Some(label) = config.token_label.as_deref() {
        let info = map_cryptoki(client.get_token_info(by_id), "get token info")?;
        // PKCS#11 pads the label to 32 bytes with trailing spaces; trim
        // before comparing.
        let actual = info.label().trim_end();
        if actual != label {
            return Err(Error::Wrapped {
                message: format!(
                    "pkcs#11: slot {} token label mismatch: expected {:?}, got {:?}",
                    config.slot_id, label, actual
                ),
            });
        }
    }

    Ok(by_id)
}

/// Helper used by the instance stubs. Kept here (rather than on
/// `Pkcs11Instance`) so the message source is co-located with the
/// backend's other skeleton plumbing.
pub(crate) fn not_implemented() -> Error {
    NotImplementedSnafu {
        what: SKELETON_NOT_IMPLEMENTED,
    }
    .build()
}

// SAFETY notes for the trait object: `cryptoki::context::Pkcs11` and
// `cryptoki::session::Session` are `Send + Sync` per upstream docs
// (the underlying `C_Initialize(CKF_OS_LOCKING_OK)` call makes the
// module thread-safe). `Config` is plain owned data. We therefore do
// not need a manual `unsafe impl Send/Sync`.

#[cfg(test)]
mod tests {
    use super::*;
    use confium_store::backend::Compartment;
    use std::collections::HashMap;
    use std::ffi::c_void;

    /// Sentinel non-null pointer; the backend treats `*mut c_void` as
    /// opaque in this skeleton so identity does not matter.
    fn sentinel(n: usize) -> *mut c_void {
        n as *mut c_void
    }

    #[test]
    fn backend_advertises_pkcs11_wire_name() {
        assert_eq!(Pkcs11Backend.name(), "pkcs11");
    }

    #[test]
    fn backend_is_registered() {
        // The link-time registry must surface the pkcs11 backend by its
        // wire name so the FFI create path can find it.
        let backend = confium_store::backend::find("pkcs11").expect("pkcs11 backend registered");
        assert_eq!(backend.name(), "pkcs11");
    }

    #[test]
    fn open_rejects_missing_module_option() {
        let opts: Options = HashMap::new();
        let err = match Pkcs11Backend.open(&opts) {
            Err(e) => e,
            Ok(_) => panic!("expected config error, got Ok"),
        };
        // Config parse failure surfaces as Wrapped.
        assert!(matches!(err, Error::Wrapped { .. }));
        assert!(format!("{err}").contains("pkcs11_module"));
    }

    #[test]
    fn open_rejects_missing_slot_option() {
        let mut opts: Options = HashMap::new();
        opts.insert("pkcs11_module".into(), "/nonexistent/libpkcs11.so".into());
        let err = match Pkcs11Backend.open(&opts) {
            Err(e) => e,
            Ok(_) => panic!("expected config error, got Ok"),
        };
        assert!(format!("{err}").contains("slot_id"));
    }

    #[test]
    fn not_implemented_carries_skeleton_message() {
        let err = not_implemented();
        assert!(matches!(err, Error::NotImplemented { .. }));
        assert!(format!("{err}").contains("pkcs#11 backend"));
    }

    // -----------------------------------------------------------------
    // Integration tests against SoftHSM2.
    //
    // These tests exercise the wired-up session plumbing (module load,
    // initialize, slot resolve, open R/W session, login) against a real
    // (software) token. They are skipped unless the `TEST_PKCS11_MODULE`
    // environment variable points at a usable PKCS#11 shared object.
    // The storage-operation stubs still return `NotImplemented`, so
    // these tests assert the open path succeeds rather than exercising
    // real object storage.
    //
    // Setup (macOS, with SoftHSM2 from Homebrew):
    //
    //   brew install softhsm
    //   softhsm2-util --init-token --slot 0 --label confium \
    //     --so-pin 1234 --pin 1234
    //
    //   TEST_PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so \
    //   TEST_PKCS11_SLOT=0 TEST_PKCS11_PIN=1234 \
    //     cargo test -p confium-store-pkcs11
    //
    // On CI (Linux) the workflow provisions SoftHSM2 and exports the
    // variables automatically. See
    // `TODO.roadmap/18-hardware-keystore-backends.md` for the full plan.
    fn integration_opts() -> Option<Options> {
        let module = std::env::var_os("TEST_PKCS11_MODULE")?;
        let slot = std::env::var_os("TEST_PKCS11_SLOT")?;
        let pin = std::env::var_os("TEST_PKCS11_PIN")?;
        let mut opts: Options = HashMap::new();
        opts.insert("pkcs11_module".into(), module.into_string().ok()?);
        opts.insert("slot_id".into(), slot.into_string().ok()?);
        opts.insert("pin".into(), pin.into_string().ok()?);
        if let Some(label) = std::env::var_os("TEST_PKCS11_LABEL") {
            opts.insert("token_label".into(), label.into_string().ok()?);
        }
        Some(opts)
    }

    #[test]
    fn open_against_softhsm2_opens_session() {
        let opts = match integration_opts() {
            Some(o) => o,
            None => {
                eprintln!(
                    "skipping SoftHSM2 test: set TEST_PKCS11_MODULE, TEST_PKCS11_SLOT, \
                     TEST_PKCS11_PIN to enable"
                );
                return;
            }
        };
        let _store = Pkcs11Backend.open(&opts).expect("open against SoftHSM2");
    }

    #[test]
    fn put_secret_against_softhsm2_is_not_implemented_in_skeleton() {
        let opts = match integration_opts() {
            Some(o) => o,
            None => {
                eprintln!(
                    "skipping SoftHSM2 test: set TEST_PKCS11_MODULE, TEST_PKCS11_SLOT, \
                     TEST_PKCS11_PIN to enable"
                );
                return;
            }
        };
        let mut store = Pkcs11Backend.open(&opts).expect("open against SoftHSM2");
        let result = store.put_secret("mod", "app", "k1", sentinel(0x1000));
        let err = match result {
            Err(e) => e,
            Ok(()) => panic!("expected NotImplemented, got Ok"),
        };
        assert!(matches!(err, Error::NotImplemented { .. }));
    }

    #[test]
    fn enumerate_against_softhsm2_is_not_implemented_in_skeleton() {
        let opts = match integration_opts() {
            Some(o) => o,
            None => {
                eprintln!(
                    "skipping SoftHSM2 test: set TEST_PKCS11_MODULE, TEST_PKCS11_SLOT, \
                     TEST_PKCS11_PIN to enable"
                );
                return;
            }
        };
        let store = Pkcs11Backend.open(&opts).expect("open against SoftHSM2");
        let result = store.enumerate("mod", "app", Compartment::Private);
        let err = match result {
            Err(e) => e,
            Ok(v) => panic!("expected NotImplemented, got {v:?}"),
        };
        assert!(matches!(err, Error::NotImplemented { .. }));
    }
}
