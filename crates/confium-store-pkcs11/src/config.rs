//! Configuration types for the PKCS#11 backend.
//!
//! The backend is configured entirely through the
//! [`Options`](confium_store::backend::Options) map passed to
//! [`StoreBackend::open`](confium_store::backend::StoreBackend::open).
//! This module names those option keys and parses them into a typed
//! [`Config`].

use confium_store::backend::Options;
use confium_store::error::{Error, Result};

/// Options key naming the PKCS#11 module path. Required: there is no
/// sensible default for the location of a vendor's `.so` / `.dylib`.
pub const OPT_PKCS11_MODULE: &str = "pkcs11_module";

/// Options key naming the HSM slot, as a decimal `u64`. Required: slot
/// discovery by label is supported, but a concrete slot must still be
/// resolved before opening a session.
pub const OPT_SLOT_ID: &str = "slot_id";

/// Options key carrying the user PIN. Optional at config time — if
/// absent, callers are expected to prompt the operator and supply the
/// PIN before the first HSM operation that requires it.
pub const OPT_PIN: &str = "pin";

/// Options key naming a token label, used for slot discovery when
/// `slot_id` is not known in advance. Optional.
pub const OPT_TOKEN_LABEL: &str = "token_label";

/// Typed view over the PKCS#11 backend's open-time options.
///
/// Construct with [`Config::from_options`]. All fields are owned so
/// the value can outlive the borrowed `Options` map.
#[derive(Debug, Clone)]
pub struct Config {
    /// Filesystem path to the PKCS#11 shared object. Required.
    pub pkcs11_module: String,
    /// HSM slot id. Required.
    pub slot_id: u64,
    /// User PIN. `None` means the caller will prompt for it.
    pub pin: Option<String>,
    /// Token label, used for slot discovery. `None` means slot id is
    /// authoritative.
    pub token_label: Option<String>,
}

impl Config {
    /// Parse a [`Config`] out of an [`Options`] map.
    ///
    /// Returns [`Error::Wrapped`] with a descriptive message when a
    /// required option is missing or malformed. We use `Wrapped`
    /// rather than adding PKCS#11-specific error variants so the
    /// backend does not leak its config grammar into the shared
    /// Store error enum — the Store contract is that backends surface
    /// failures through the existing variants.
    pub fn from_options(opts: &Options) -> Result<Self> {
        let pkcs11_module = opts
            .get(OPT_PKCS11_MODULE)
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Wrapped {
                message: format!(
                    "PKCS#11 backend requires the '{OPT_PKCS11_MODULE}' option \
                     (path to the PKCS#11 shared object)"
                ),
            })?
            .to_string();

        let slot_id = opts
            .get(OPT_SLOT_ID)
            .ok_or_else(|| Error::Wrapped {
                message: format!(
                    "PKCS#11 backend requires the '{OPT_SLOT_ID}' option \
                     (HSM slot id, decimal u64)"
                ),
            })
            .and_then(|raw| {
                raw.parse::<u64>().map_err(|_| Error::Wrapped {
                    message: format!(
                        "PKCS#11 backend: '{OPT_SLOT_ID}' must be a decimal u64, \
                         got '{raw}'"
                    ),
                })
            })?;

        let pin = opts.get(OPT_PIN).filter(|s| !s.is_empty()).cloned();
        let token_label = opts.get(OPT_TOKEN_LABEL).filter(|s| !s.is_empty()).cloned();

        Ok(Config {
            pkcs11_module,
            slot_id,
            pin,
            token_label,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn opts() -> Options {
        let mut o = Options::new();
        o.insert(
            OPT_PKCS11_MODULE.to_string(),
            "/opt/hsm/libpkcs11.so".into(),
        );
        o.insert(OPT_SLOT_ID.to_string(), "0".into());
        o.insert(OPT_PIN.to_string(), "123456".into());
        o.insert(OPT_TOKEN_LABEL.to_string(), "confium".into());
        o
    }

    #[test]
    fn parses_all_fields() {
        let cfg = Config::from_options(&opts()).expect("valid config");
        assert_eq!(cfg.pkcs11_module, "/opt/hsm/libpkcs11.so");
        assert_eq!(cfg.slot_id, 0);
        assert_eq!(cfg.pin.as_deref(), Some("123456"));
        assert_eq!(cfg.token_label.as_deref(), Some("confium"));
    }

    #[test]
    fn pin_and_label_optional() {
        let mut o = opts();
        o.remove(OPT_PIN);
        o.remove(OPT_TOKEN_LABEL);
        let cfg = Config::from_options(&o).expect("still valid");
        assert!(cfg.pin.is_none());
        assert!(cfg.token_label.is_none());
    }

    #[test]
    fn empty_pin_treated_as_absent() {
        let mut o = opts();
        o.insert(OPT_PIN.to_string(), String::new());
        let cfg = Config::from_options(&o).expect("empty pin is absent");
        assert!(cfg.pin.is_none());
    }

    #[test]
    fn missing_module_is_error() {
        let mut o = opts();
        o.remove(OPT_PKCS11_MODULE);
        let err = Config::from_options(&o).unwrap_err();
        assert!(matches!(err, Error::Wrapped { .. }));
        assert!(format!("{err}").contains(OPT_PKCS11_MODULE));
    }

    #[test]
    fn missing_slot_is_error() {
        let mut o = opts();
        o.remove(OPT_SLOT_ID);
        let err = Config::from_options(&o).unwrap_err();
        assert!(format!("{err}").contains(OPT_SLOT_ID));
    }

    #[test]
    fn non_numeric_slot_is_error() {
        let mut o = opts();
        o.insert(OPT_SLOT_ID.to_string(), "not-a-number".into());
        let err = Config::from_options(&o).unwrap_err();
        assert!(format!("{err}").contains("must be a decimal u64"));
    }

    #[test]
    fn empty_options_map_errors() {
        let empty: Options = HashMap::new();
        let err = Config::from_options(&empty).unwrap_err();
        assert!(matches!(err, Error::Wrapped { .. }));
    }
}
