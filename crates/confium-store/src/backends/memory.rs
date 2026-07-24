//! In-memory HashMap backend.
//!
//! For development and tests: holds everything in process memory, no
//! persistence, no hardware backing. The structure mirrors the
//! compartment design from `TODO.finalize/12-keystore-interface.md`:
//!
//! - outer map keyed by `(module_id, app_id)`
//! - each entry has two inner maps:
//!   - private: `key_id → *mut c_void`
//!   - public:  `identity → (*mut c_void, Vec<u8> signature)`
//!
//! Key handles are opaque `*mut c_void`; the backend does not interpret
//! them. Ownership of the underlying memory stays with whoever produced
//! the handle (typically the Engine's keyfmt interface).

use std::collections::HashMap;
use std::ffi::c_void;

use crate::backend::{Compartment, Options, StoreBackend, StoreInstance};
use crate::error::{Result, ValueNotFoundSnafu};
use crate::register_backend;

/// One `(module_id, app_id)` scope's two compartments.
#[derive(Default)]
struct Scope {
    private: HashMap<String, *mut c_void>,
    public: HashMap<String, (*mut c_void, Vec<u8>)>,
}

/// Factory for the in-memory backend. Stateless — all state lives in
/// [`MemoryInstance`].
pub struct MemoryBackend;

impl StoreBackend for MemoryBackend {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn open(&self, _opts: &Options) -> Result<Box<dyn StoreInstance>> {
        Ok(Box::new(MemoryInstance::default()))
    }
}

register_backend!(MemoryBackend);

#[derive(Default)]
pub struct MemoryInstance {
    scopes: HashMap<(String, String), Scope>,
}

impl MemoryInstance {
    fn scope(&self, module: &str, app: &str) -> Option<&Scope> {
        self.scopes.get(&(module.to_string(), app.to_string()))
    }

    fn scope_mut(&mut self, module: &str, app: &str) -> &mut Scope {
        self.scopes
            .entry((module.to_string(), app.to_string()))
            .or_default()
    }
}

impl StoreInstance for MemoryInstance {
    fn put_secret(
        &mut self,
        module: &str,
        app: &str,
        key_id: &str,
        key: *mut c_void,
    ) -> Result<()> {
        self.scope_mut(module, app)
            .private
            .insert(key_id.to_string(), key);
        Ok(())
    }

    fn get_secret(&self, module: &str, app: &str, key_id: &str) -> Result<*mut c_void> {
        self.scope(module, app)
            .and_then(|s| s.private.get(key_id))
            .copied()
            .ok_or_else(|| ValueNotFoundSnafu.build())
    }

    fn put_public(
        &mut self,
        module: &str,
        app: &str,
        identity: &str,
        key: *mut c_void,
        sig: &[u8],
    ) -> Result<()> {
        self.scope_mut(module, app)
            .public
            .insert(identity.to_string(), (key, sig.to_vec()));
        Ok(())
    }

    fn get_public(
        &self,
        module: &str,
        app: &str,
        identity: &str,
    ) -> Result<(*mut c_void, Vec<u8>)> {
        self.scope(module, app)
            .and_then(|s| s.public.get(identity))
            .map(|(k, sig)| (*k, sig.clone()))
            .ok_or_else(|| ValueNotFoundSnafu.build())
    }

    fn enumerate(
        &self,
        module: &str,
        app: &str,
        compartment: Compartment,
    ) -> Result<Vec<(*mut c_void, String)>> {
        let Some(scope) = self.scope(module, app) else {
            return Ok(Vec::new());
        };
        let entries: Vec<(*mut c_void, String)> = match compartment {
            Compartment::Private => scope
                .private
                .iter()
                .map(|(k, v)| (*v, k.clone()))
                .collect(),
            Compartment::Public => scope
                .public
                .iter()
                .map(|(id, (k, _))| (*k, id.clone()))
                .collect(),
        };
        Ok(entries)
    }
}

// SAFETY: the backend stores raw `*mut c_void` handles provided by the
// caller. Those handles represent opaque key material owned by the
// Engine; the Store never dereferences them, only stores and returns
// them. Sending/sharing the handle across threads is sound because no
// thread reads through the pointer — it is an opaque token to the
// backend.
unsafe impl Send for MemoryInstance {}
unsafe impl Sync for MemoryInstance {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{StoreBackend, StoreInstance};

    fn open() -> Box<dyn StoreInstance> {
        MemoryBackend
            .open(&Options::new())
            .expect("memory backend opens")
    }

    // Use distinct non-null sentinel pointers so the tests can assert on
    // identity without allocating real key material. The backend treats
    // these as opaque tokens.
    fn sentinel(n: usize) -> *mut c_void {
        n as *mut c_void
    }

    #[test]
    fn put_get_secret_round_trip() {
        let mut ks = open();
        let key = sentinel(0x1000);
        ks.put_secret("mod", "app", "key-1", key)
            .expect("put_secret");
        let got = ks.get_secret("mod", "app", "key-1").expect("get_secret");
        assert_eq!(got, key);
    }

    #[test]
    fn put_get_public_round_trip() {
        let mut ks = open();
        let key = sentinel(0x2000);
        let sig = vec![0xDE, 0xAD, 0xBE, 0xEF];
        ks.put_public("mod", "app", "email:alice@example.com", key, &sig)
            .expect("put_public");
        let (got_key, got_sig) = ks
            .get_public("mod", "app", "email:alice@example.com")
            .expect("get_public");
        assert_eq!(got_key, key);
        assert_eq!(got_sig, sig);
    }

    #[test]
    fn wrong_module_returns_value_not_found() {
        let mut ks = open();
        ks.put_secret("mod", "app", "key-1", sentinel(0x10))
            .expect("put_secret");
        let err = ks.get_secret("other", "app", "key-1").unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::ValueNotFound
        ));
    }

    #[test]
    fn wrong_app_returns_value_not_found() {
        let mut ks = open();
        ks.put_secret("mod", "app", "key-1", sentinel(0x10))
            .expect("put_secret");
        let err = ks.get_secret("mod", "other", "key-1").unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::ValueNotFound
        ));
    }

    #[test]
    fn wrong_key_id_returns_value_not_found() {
        let mut ks = open();
        ks.put_secret("mod", "app", "key-1", sentinel(0x10))
            .expect("put_secret");
        let err = ks.get_secret("mod", "app", "missing").unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::ValueNotFound
        ));
    }

    #[test]
    fn wrong_identity_returns_value_not_found() {
        let mut ks = open();
        ks.put_public(
            "mod",
            "app",
            "email:alice@example.com",
            sentinel(0x20),
            &[1, 2, 3],
        )
        .expect("put_public");
        let err = ks
            .get_public("mod", "app", "email:bob@example.com")
            .unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::ValueNotFound
        ));
    }

    #[test]
    fn compartments_are_isolated() {
        let mut ks = open();
        // Put a secret in the private compartment.
        let secret = sentinel(0x30);
        ks.put_secret("mod", "app", "key-1", secret)
            .expect("put_secret");

        // The private key must not be visible via the public lookup
        // path, even using the same index string.
        let err = ks.get_public("mod", "app", "key-1").unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::ValueNotFound
        ));

        // And vice versa: a public entry is not visible via get_secret.
        let pub_key = sentinel(0x40);
        ks.put_public("mod", "app", "email:alice@example.com", pub_key, &[9])
            .expect("put_public");
        let err = ks
            .get_secret("mod", "app", "email:alice@example.com")
            .unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::ValueNotFound
        ));
    }

    #[test]
    fn enumerate_partitions_by_compartment() {
        let mut ks = open();
        ks.put_secret("mod", "app", "key-a", sentinel(0x1))
            .expect("put_secret");
        ks.put_secret("mod", "app", "key-b", sentinel(0x2))
            .expect("put_secret");
        ks.put_public("mod", "app", "email:a@b", sentinel(0x3), &[0])
            .expect("put_public");

        let private = ks
            .enumerate("mod", "app", Compartment::Private)
            .expect("enumerate private");
        assert_eq!(private.len(), 2, "two private entries expected");

        let public = ks
            .enumerate("mod", "app", Compartment::Public)
            .expect("enumerate public");
        assert_eq!(public.len(), 1, "one public entry expected");
        assert_eq!(public[0].1, "email:a@b");
    }

    #[test]
    fn put_secret_overwrites() {
        let mut ks = open();
        let first = sentinel(0x100);
        let second = sentinel(0x200);
        ks.put_secret("mod", "app", "key-1", first)
            .expect("put_secret first");
        ks.put_secret("mod", "app", "key-1", second)
            .expect("put_secret second");
        let got = ks.get_secret("mod", "app", "key-1").expect("get_secret");
        assert_eq!(got, second, "second put should win");
    }

    #[test]
    fn distinct_scopes_do_not_leak() {
        let mut ks = open();
        ks.put_secret("mod", "app-a", "key-1", sentinel(0x1))
            .expect("put_secret");
        let err = ks.get_secret("mod", "app-b", "key-1").unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::ValueNotFound
        ));
    }

    #[test]
    fn backend_is_registered() {
        // The link-time registry must surface the memory backend by its
        // wire name so the FFI create path can find it.
        let backend = crate::backend::find("memory").expect("memory backend registered");
        assert_eq!(backend.name(), "memory");
    }
}
