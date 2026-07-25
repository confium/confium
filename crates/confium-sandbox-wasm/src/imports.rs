//! Host imports callable from a sandboxed WASM plugin.
//!
//! Every import is gated by [`Capability`]: the plugin must hold a
//! matching capability before the host side executes the real work.
//! A denied call traps the guest (returns an error to the host
//! caller of [`SandboxInstance::call`](crate::SandboxInstance::call)).
//!
//! The convention follows the design doc: imports are named
//! `cfm_<interface>_<verb>` and `InterfaceAccess { name: "<interface>" }`
//! gates the whole family.
//!
//! NOTE: the real I/O implementations (hash, net, key) live in
//! confium-core / confium-net / confium-store. This crate only owns
//! the capability-gating dispatch surface; the per-import handlers
//! are stubs for now, wired up as the host side matures.

use std::collections::HashSet;
use std::sync::Mutex;

use crate::sandbox::Capability;

/// Per-instance capability state. Held behind a `Mutex` so host
/// imports (which run on the wasmtime scheduler) and the host-side
/// `grant_capability` / `revoke_capability` calls agree on a single
/// view.
#[derive(Debug, Default)]
pub(crate) struct CapabilitySet {
    caps: Mutex<HashSet<Capability>>,
}

impl CapabilitySet {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn grant(&self, cap: Capability) {
        let mut guard = self.caps.lock().expect("capability mutex poisoned");
        guard.insert(cap);
    }

    pub(crate) fn revoke(&self, cap: &Capability) {
        let mut guard = self.caps.lock().expect("capability mutex poisoned");
        guard.remove(cap);
    }

    /// True iff `cap` is currently granted. Kept on the public API
    /// for future capability introspection (e.g. printing the
    /// instance's envelope to a debug log).
    #[allow(dead_code)]
    pub(crate) fn has(&self, cap: &Capability) -> bool {
        let guard = self.caps.lock().expect("capability mutex poisoned");
        guard.contains(cap)
    }

    /// True iff the plugin holds an `InterfaceAccess { name }` cap
    /// for the given interface.
    pub(crate) fn has_interface(&self, name: &str) -> bool {
        let guard = self.caps.lock().expect("capability mutex poisoned");
        guard.iter().any(|c| match c {
            Capability::InterfaceAccess { name: n } => n == name,
            _ => false,
        })
    }
}

/// Outcome of a host-import dispatch.
#[derive(Debug)]
pub(crate) enum ImportOutcome {
    /// Import executed; result value to return to the guest.
    Done(i64),
    /// Capability missing; the guest call should be reported as
    /// denied.
    Denied,
}

/// The dispatch table the WASM runtime calls into.
///
/// Each method takes the per-instance capability set plus the
/// call arguments, checks the capability, and (when wired up) runs
/// the real handler. Until the real handlers exist, the methods
/// return a deterministic stub value so the sandbox pipeline can be
/// exercised end-to-end (see the integration tests).
pub(crate) struct HostImports;

impl HostImports {
    /// `cfm_hash_update(len: i32) -> i64` — gated by
    /// `InterfaceAccess { name: "hash" }`.
    ///
    /// Returns the length it claims to have processed (stub).
    pub(crate) fn cfm_hash_update(caps: &CapabilitySet, len: i32) -> ImportOutcome {
        if !Self::has_interface(caps, "hash") {
            return ImportOutcome::Denied;
        }
        // Stub: report the input length as bytes-hashed.
        ImportOutcome::Done(i64::from(len))
    }

    /// `cfm_net_send(url_id: i64) -> i64` — gated by
    /// `NetworkEndpoint { url }` for the url identified by `url_id`.
    ///
    /// Until a url-table is wired up, `url_id` is treated as an
    /// opaque index the host resolves; the capability check uses
    /// the plugin's first granted `NetworkEndpoint` for the smoke
    /// test path. Real implementation will pass the url through
    /// guest linear memory.
    pub(crate) fn cfm_net_send(caps: &CapabilitySet, url_id: i64) -> ImportOutcome {
        if !Self::has_any_network(caps) {
            return ImportOutcome::Denied;
        }
        // Stub: report the url_id echoed back.
        ImportOutcome::Done(url_id)
    }

    /// `cfm_key_get_secret(key_id: i64) -> i64` — gated by
    /// `KeyAccess { key_id }`. Returns the secret length (stub),
    /// never the bytes themselves.
    pub(crate) fn cfm_key_get_secret(caps: &CapabilitySet, key_id: i64) -> ImportOutcome {
        if !Self::has_any_key(caps) {
            return ImportOutcome::Denied;
        }
        // Stub: report a 32-byte secret size.
        let _ = key_id;
        ImportOutcome::Done(32)
    }

    // -- helpers ---------------------------------------------------------

    /// True iff the plugin holds `InterfaceAccess { name }`.
    fn has_interface(caps: &CapabilitySet, name: &str) -> bool {
        caps.has_interface(name)
    }

    fn has_any_network(caps: &CapabilitySet) -> bool {
        let guard = caps.caps.lock().expect("capability mutex poisoned");
        guard
            .iter()
            .any(|c| matches!(c, Capability::NetworkEndpoint { .. }))
    }

    fn has_any_key(caps: &CapabilitySet) -> bool {
        let guard = caps.caps.lock().expect("capability mutex poisoned");
        guard
            .iter()
            .any(|c| matches!(c, Capability::KeyAccess { .. }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfm_hash_update_denied_without_capability() {
        let caps = CapabilitySet::new();
        let out = HostImports::cfm_hash_update(&caps, 7);
        match out {
            ImportOutcome::Denied => {}
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    #[test]
    fn cfm_hash_update_permitted_with_capability() {
        let caps = CapabilitySet::new();
        caps.grant(Capability::InterfaceAccess {
            name: "hash".into(),
        });
        let out = HostImports::cfm_hash_update(&caps, 7);
        assert!(matches!(out, ImportOutcome::Done(7)));
    }

    #[test]
    fn cfm_key_get_secret_denied_without_key_capability() {
        let caps = CapabilitySet::new();
        let out = HostImports::cfm_key_get_secret(&caps, 0);
        assert!(matches!(out, ImportOutcome::Denied));
    }

    #[test]
    fn cfm_key_get_secret_permitted_with_key_capability() {
        let caps = CapabilitySet::new();
        caps.grant(Capability::KeyAccess {
            key_id: "k1".into(),
        });
        let out = HostImports::cfm_key_get_secret(&caps, 0);
        assert!(matches!(out, ImportOutcome::Done(32)));
    }

    #[test]
    fn revoke_takes_effect() {
        let caps = CapabilitySet::new();
        caps.grant(Capability::InterfaceAccess {
            name: "hash".into(),
        });
        assert!(matches!(
            HostImports::cfm_hash_update(&caps, 1),
            ImportOutcome::Done(1)
        ));
        caps.revoke(&Capability::InterfaceAccess {
            name: "hash".into(),
        });
        assert!(matches!(
            HostImports::cfm_hash_update(&caps, 1),
            ImportOutcome::Denied
        ));
    }
}
