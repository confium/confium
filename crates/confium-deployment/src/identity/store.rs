//! Identity store abstraction.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use crate::identity::actor::{ActorIdentity, IdentityError};

/// Backend trait for persistent identity storage.
pub trait IdentityBackend: Send + Sync {
    /// Store an identity.
    fn store(&self, identity: &ActorIdentity) -> Result<(), IdentityError>;
    /// Look up an identity by ID.
    fn load(&self, actor_id: &str) -> Result<ActorIdentity, IdentityError>;
    /// Delete an identity.
    fn delete(&self, actor_id: &str) -> Result<(), IdentityError>;
    /// List all actor IDs.
    fn list(&self) -> Result<Vec<String>, IdentityError>;
}

/// In-memory identity store (testing only).
#[derive(Default)]
pub struct MemoryIdentityBackend {
    inner: Mutex<HashMap<String, ActorIdentity>>,
}

impl MemoryIdentityBackend {
    /// Construct a new empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<MutexGuard<'_, HashMap<String, ActorIdentity>>, IdentityError> {
        self.inner
            .lock()
            .map_err(|_| IdentityError::NotFound("lock poisoned".into()))
    }
}

impl IdentityBackend for MemoryIdentityBackend {
    fn store(&self, identity: &ActorIdentity) -> Result<(), IdentityError> {
        let mut map = self.lock()?;
        map.insert(identity.actor_id.clone(), identity.clone());
        Ok(())
    }

    fn load(&self, actor_id: &str) -> Result<ActorIdentity, IdentityError> {
        let map = self.lock()?;
        map.get(actor_id)
            .cloned()
            .ok_or_else(|| IdentityError::NotFound(actor_id.into()))
    }

    fn delete(&self, actor_id: &str) -> Result<(), IdentityError> {
        let mut map = self.lock()?;
        map.remove(actor_id);
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>, IdentityError> {
        let map = self.lock()?;
        Ok(map.keys().cloned().collect())
    }
}

/// High-level identity store.
pub struct IdentityStore {
    backend: Box<dyn IdentityBackend>,
}

impl IdentityStore {
    /// Construct a new store wrapping a backend.
    pub fn new(backend: Box<dyn IdentityBackend>) -> Self {
        Self { backend }
    }

    /// Construct an in-memory store (testing only).
    pub fn in_memory() -> Self {
        Self::new(Box::new(MemoryIdentityBackend::new()))
    }

    /// Register a new identity. Fails if the actor already exists.
    pub fn register(&self, identity: ActorIdentity) -> Result<(), IdentityError> {
        if self.backend.load(&identity.actor_id).is_ok() {
            return Err(IdentityError::AlreadyExists(identity.actor_id));
        }
        self.backend.store(&identity)
    }

    /// Look up an identity.
    pub fn lookup(&self, actor_id: &str) -> Result<ActorIdentity, IdentityError> {
        self.backend.load(actor_id)
    }

    /// Delete an identity.
    pub fn revoke(&self, actor_id: &str) -> Result<(), IdentityError> {
        self.backend.delete(actor_id)
    }

    /// List all actors.
    pub fn list(&self) -> Result<Vec<String>, IdentityError> {
        self.backend.list()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::actor::{ActorType, SigningKeyHandle};

    fn sample_identity(id: &str) -> ActorIdentity {
        ActorIdentity::builder()
            .actor_id(id)
            .actor_type(ActorType::BimlDirector)
            .signing_key(SigningKeyHandle::Software {
                key_id: "k".into(),
                algorithm: "Ed25519".into(),
            })
            .build()
            .unwrap()
    }

    #[test]
    fn in_memory_store_round_trip() {
        let store = IdentityStore::in_memory();
        let id = sample_identity("director-1");
        store.register(id.clone()).unwrap();
        let recovered = store.lookup("director-1").unwrap();
        assert_eq!(recovered.actor_id, "director-1");
        assert_eq!(recovered.actor_type, ActorType::BimlDirector);
    }

    #[test]
    fn duplicate_register_fails() {
        let store = IdentityStore::in_memory();
        let id = sample_identity("director-1");
        store.register(id.clone()).unwrap();
        let result = store.register(id);
        assert!(matches!(result, Err(IdentityError::AlreadyExists(_))));
    }

    #[test]
    fn lookup_missing_fails() {
        let store = IdentityStore::in_memory();
        let result = store.lookup("nobody");
        assert!(matches!(result, Err(IdentityError::NotFound(_))));
    }

    #[test]
    fn revoke_removes_actor() {
        let store = IdentityStore::in_memory();
        store.register(sample_identity("director-1")).unwrap();
        store.revoke("director-1").unwrap();
        let result = store.lookup("director-1");
        assert!(result.is_err());
    }
}
