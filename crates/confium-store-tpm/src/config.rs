//! Configuration model for the TPM 2.0 backend.
//!
//! [`TpmConfig`] captures everything the backend needs to locate and
//! authorise against a TPM: the device path, the hierarchy the parent
//! key lives under, the parent key's persistent handle, and the
//! authorisation value for that parent. The wire form (the
//! [`Options`](confium_store::backend::Options) string map surfaced at
//! the FFI boundary) is parsed by [`TpmConfig::from_options`].
//!
//! See `TODO.roadmap/18-hardware-keystore-backends.md` for the design.

use std::path::PathBuf;

use confium_store::backend::Options;
use confium_store::error::{Result, WrappedSnafu};

#[cfg(test)]
use confium_store::error::Error;

/// Options key naming the TPM device path.
pub const OPT_TPM_DEVICE: &str = "tpm_device";

/// Options key naming the hierarchy (one of `owner`, `platform`,
/// `endorsement`).
pub const OPT_HIERARCHY: &str = "hierarchy";

/// Options key naming the persistent parent handle, as a hex string
/// (e.g. `0x81000001`).
pub const OPT_PARENT_HANDLE: &str = "parent_handle";

/// Options key carrying the authorisation value for the parent key.
/// Empty by default — typical for owner-hierarchy parent keys.
pub const OPT_PARENT_PASSWORD: &str = "parent_password";

/// Default hierarchy when [`OPT_HIERARCHY`] is absent.
pub const DEFAULT_HIERARCHY: Hierarchy = Hierarchy::Owner;

/// A TPM 2.0 hierarchy. Maps to the three persistent hierarchies
/// defined by the TPM 2.0 specification: owner, platform, and
/// endorsement. The parent key under which Confium wraps its sealed
/// objects lives in one of these.
///
/// Wire form is the lowercase ASCII name (see [`Hierarchy::from_wire`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hierarchy {
    /// The owner hierarchy (`TPM_RH_OWNER`). Default for Confium;
    /// parent key authorisation usually uses an empty auth value.
    Owner,
    /// The platform hierarchy (`TPM_RH_PLATFORM`). Controlled by the
    /// platform firmware; clears on every reboot.
    Platform,
    /// The endorsement hierarchy (`TPM_RH_ENDORSEMENT`). Used for
    /// privacy-sensitive operations (attestation, EK-derived keys).
    Endorsement,
}

impl Hierarchy {
    /// Decode the wire value used by the FFI / options map. Accepts the
    /// case-insensitive ASCII name; unknown values map to
    /// [`Error::Wrapped`].
    pub fn from_wire(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "owner" | "o" => Ok(Hierarchy::Owner),
            "platform" | "p" => Ok(Hierarchy::Platform),
            "endorsement" | "e" => Ok(Hierarchy::Endorsement),
            other => Err(WrappedSnafu {
                message: format!("unknown TPM hierarchy: {other:?}"),
            }
            .build()),
        }
    }

    /// The wire name this hierarchy serialises to (lowercase ASCII).
    pub fn as_wire(self) -> &'static str {
        match self {
            Hierarchy::Owner => "owner",
            Hierarchy::Platform => "platform",
            Hierarchy::Endorsement => "endorsement",
        }
    }
}

impl std::fmt::Display for Hierarchy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_wire())
    }
}

/// A persistent TPM handle. Wraps a `u32` so the wire encoding (hex
/// string) is localised here and the call site reads naturally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParentHandle(pub u32);

impl ParentHandle {
    /// Parse a hex-encoded persistent handle (with or without a `0x`
    /// prefix). Used to read [`OPT_PARENT_HANDLE`] from the options map.
    pub fn from_wire(value: &str) -> Result<Self> {
        let stripped = value
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        let raw = u32::from_str_radix(stripped, 16).map_err(|e| {
            WrappedSnafu {
                message: format!("invalid parent handle {value:?}: {e}"),
            }
            .build()
        })?;
        Ok(ParentHandle(raw))
    }

    /// The raw `u32` handle, suitable for passing to `tss-esapi` as a
    /// `ESYS_TR` persistent handle.
    pub fn raw(self) -> u32 {
        self.0
    }
}

/// Resolved configuration for the TPM backend.
///
/// Produced by [`TpmConfig::from_options`]; consumed by
/// [`crate::backend::TpmBackend::open`]. Holds the post-parse, typed
/// form of every option the backend reads, so the open path does not
/// re-do string parsing on every call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmConfig {
    /// Path to the TPM device. `None` means "let `tss-esapi`
    /// auto-detect" (the common case on Linux where `tcti=tabrmd`
    /// finds the system TPM ResourceManager).
    pub device: Option<PathBuf>,

    /// Hierarchy the parent key lives under.
    pub hierarchy: Hierarchy,

    /// Persistent handle of the parent (wrapping) key. May be `None`
    /// at config time — the backend will then create a transient
    /// parent on the fly and evict it on close. Persistent handles
    /// survive reboot and are the production setting.
    pub parent_handle: Option<ParentHandle>,

    /// Authorisation value for the parent key. Empty by default
    /// (matches the typical owner-hierarchy deployment).
    pub parent_password: Vec<u8>,
}

impl Default for TpmConfig {
    fn default() -> Self {
        Self {
            device: None,
            hierarchy: DEFAULT_HIERARCHY,
            parent_handle: None,
            parent_password: Vec::new(),
        }
    }
}

impl TpmConfig {
    /// Parse the backend config out of the
    /// [`Options`](confium_store::backend::Options) string map. Unknown
    /// keys are ignored; malformed values surface as
    /// [`Error::Wrapped`].
    pub fn from_options(opts: &Options) -> Result<Self> {
        let device = opts.get(OPT_TPM_DEVICE).map(PathBuf::from);

        let hierarchy = opts
            .get(OPT_HIERARCHY)
            .map(|v| Hierarchy::from_wire(v))
            .transpose()?
            .unwrap_or(DEFAULT_HIERARCHY);

        let parent_handle = opts
            .get(OPT_PARENT_HANDLE)
            .map(|v| ParentHandle::from_wire(v))
            .transpose()?;

        let parent_password = opts
            .get(OPT_PARENT_PASSWORD)
            .map(String::as_bytes)
            .map(Vec::from)
            .unwrap_or_default();

        Ok(Self {
            device,
            hierarchy,
            parent_handle,
            parent_password,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn defaults_are_sane() {
        let cfg = TpmConfig::default();
        assert_eq!(cfg.hierarchy, Hierarchy::Owner);
        assert!(cfg.device.is_none());
        assert!(cfg.parent_handle.is_none());
        assert!(cfg.parent_password.is_empty());
    }

    #[test]
    fn parses_full_options_map() {
        let mut opts: Options = HashMap::new();
        opts.insert(OPT_TPM_DEVICE.into(), "/dev/tpmrmis0".into());
        opts.insert(OPT_HIERARCHY.into(), "endorsement".into());
        opts.insert(OPT_PARENT_HANDLE.into(), "0x81000001".into());
        opts.insert(OPT_PARENT_PASSWORD.into(), "hunter2".into());

        let cfg = TpmConfig::from_options(&opts).expect("parse");
        assert_eq!(
            cfg.device.as_deref(),
            Some(std::path::Path::new("/dev/tpmrmis0"))
        );
        assert_eq!(cfg.hierarchy, Hierarchy::Endorsement);
        assert_eq!(cfg.parent_handle.unwrap().raw(), 0x8100_0001);
        assert_eq!(cfg.parent_password, b"hunter2");
    }

    #[test]
    fn hierarchy_is_case_insensitive() {
        for (wire, expected) in [
            ("Owner", Hierarchy::Owner),
            ("PLATFORM", Hierarchy::Platform),
            ("Endorsement", Hierarchy::Endorsement),
        ] {
            assert_eq!(Hierarchy::from_wire(wire).unwrap(), expected);
        }
    }

    #[test]
    fn hierarchy_accepts_short_forms() {
        assert_eq!(Hierarchy::from_wire("o").unwrap(), Hierarchy::Owner);
        assert_eq!(Hierarchy::from_wire("p").unwrap(), Hierarchy::Platform);
        assert_eq!(Hierarchy::from_wire("e").unwrap(), Hierarchy::Endorsement);
    }

    #[test]
    fn unknown_hierarchy_errors() {
        let err = Hierarchy::from_wire("nonsense").unwrap_err();
        assert!(matches!(err, Error::Wrapped { .. }));
    }

    #[test]
    fn parent_handle_parses_with_and_without_prefix() {
        assert_eq!(
            ParentHandle::from_wire("0x81000001").unwrap().raw(),
            0x8100_0001
        );
        assert_eq!(
            ParentHandle::from_wire("81000001").unwrap().raw(),
            0x8100_0001
        );
        assert_eq!(
            ParentHandle::from_wire("0X81000002").unwrap().raw(),
            0x8100_0002
        );
    }

    #[test]
    fn parent_handle_rejects_garbage() {
        let err = ParentHandle::from_wire("not-a-handle").unwrap_err();
        assert!(matches!(err, Error::Wrapped { .. }));
    }

    #[test]
    fn empty_options_uses_defaults() {
        let opts: Options = HashMap::new();
        let cfg = TpmConfig::from_options(&opts).expect("parse");
        assert_eq!(cfg, TpmConfig::default());
    }

    #[test]
    fn display_round_trips_through_from_wire() {
        for h in [
            Hierarchy::Owner,
            Hierarchy::Platform,
            Hierarchy::Endorsement,
        ] {
            let wire = h.to_string();
            assert_eq!(Hierarchy::from_wire(&wire).unwrap(), h);
        }
    }
}
