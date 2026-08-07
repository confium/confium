//! Attribute-based encryption — encrypt to attributes, threshold decrypt.
//! Multi-tenancy isolation — per-quorum isolation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

// === Attribute-Based Encryption ===

/// An access policy for decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub required_attributes: Vec<String>,
    pub min_attributes: u32,
}

/// An ABE ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbeCiphertext {
    pub policy: AccessPolicy,
    pub encrypted_data_hex: String,
    pub attribute_keys_hex: HashMap<String, String>,
}

/// Encrypt data under an access policy.
pub fn encrypt(policy: AccessPolicy, data: &[u8]) -> AbeCiphertext {
    use sha2::{Digest, Sha256};
    let mut attribute_keys = HashMap::new();
    for attr in &policy.required_attributes {
        let mut h = Sha256::new();
        h.update(b"abe-key");
        h.update(attr.as_bytes());
        attribute_keys.insert(attr.clone(), hex::encode(h.finalize()));
    }
    // Simplified: XOR with hash of concatenated attribute keys
    let mut key_material = Vec::new();
    for attr in &policy.required_attributes {
        key_material.extend_from_slice(attr.as_bytes());
    }
    let mut h = Sha256::new();
    h.update(b"abe-encrypt");
    h.update(&key_material);
    let key = h.finalize();
    let encrypted: Vec<u8> = data.iter().enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();
    AbeCiphertext {
        policy,
        encrypted_data_hex: hex::encode(&encrypted),
        attribute_keys_hex: attribute_keys,
    }
}

/// Check if a set of attributes satisfies the policy.
pub fn satisfies(attributes: &[String], policy: &AccessPolicy) -> bool {
    let matching = policy.required_attributes.iter()
        .filter(|req| attributes.contains(req))
        .count();
    matching >= policy.min_attributes as usize
}

/// Decrypt with a set of attributes.
pub fn decrypt(ciphertext: &AbeCiphertext, attributes: &[String]) -> Option<Vec<u8>> {
    if !satisfies(attributes, &ciphertext.policy) {
        return None;
    }
    use sha2::{Digest, Sha256};
    let mut key_material = Vec::new();
    for attr in &ciphertext.policy.required_attributes {
        key_material.extend_from_slice(attr.as_bytes());
    }
    let mut h = Sha256::new();
    h.update(b"abe-encrypt");
    h.update(&key_material);
    let key = h.finalize();
    let encrypted = hex::decode(&ciphertext.encrypted_data_hex).ok()?;
    let decrypted: Vec<u8> = encrypted.iter().enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();
    Some(decrypted)
}

// === Multi-Tenancy Isolation ===

/// A tenant (quorum) with isolated resources.
#[derive(Debug, Clone)]
pub struct Tenant {
    pub quorum_id: String,
    pub max_sessions: usize,
    pub active_sessions: usize,
    pub rate_limit_per_minute: u32,
    pub allowed_schemes: Vec<String>,
}

/// Multi-tenant manager.
#[derive(Default)]
pub struct TenantManager {
    tenants: Mutex<HashMap<String, Tenant>>,
}

impl TenantManager {
    pub fn new() -> Self { Self::default() }

    pub fn register(&self, tenant: Tenant) {
        self.tenants.lock().unwrap().insert(tenant.quorum_id.clone(), tenant);
    }

    pub fn get(&self, quorum_id: &str) -> Option<Tenant> {
        self.tenants.lock().unwrap().get(quorum_id).cloned()
    }

    pub fn can_create_session(&self, quorum_id: &str) -> bool {
        self.tenants.lock().unwrap()
            .get(quorum_id)
            .map(|t| t.active_sessions < t.max_sessions)
            .unwrap_or(false)
    }

    pub fn increment_sessions(&self, quorum_id: &str) -> bool {
        let mut tenants = self.tenants.lock().unwrap();
        if let Some(t) = tenants.get_mut(quorum_id) {
            if t.active_sessions >= t.max_sessions {
                return false;
            }
            t.active_sessions += 1;
            return true;
        }
        false
    }

    pub fn decrement_sessions(&self, quorum_id: &str) {
        let mut tenants = self.tenants.lock().unwrap();
        if let Some(t) = tenants.get_mut(quorum_id) {
            t.active_sessions = t.active_sessions.saturating_sub(1);
        }
    }

    pub fn is_scheme_allowed(&self, quorum_id: &str, scheme: &str) -> bool {
        self.tenants.lock().unwrap()
            .get(quorum_id)
            .map(|t| t.allowed_schemes.iter().any(|s| s == scheme))
            .unwrap_or(false)
    }

    pub fn tenant_count(&self) -> usize {
        self.tenants.lock().unwrap().len()
    }

    pub fn remove(&self, quorum_id: &str) {
        self.tenants.lock().unwrap().remove(quorum_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ABE tests

    #[test]
    fn abe_encrypt_decrypt_with_attributes() {
        let policy = AccessPolicy {
            required_attributes: vec!["region:eu".into(), "role:director".into()],
            min_attributes: 2,
        };
        let data = b"secret data";
        let ct = encrypt(policy, data);
        let pt = decrypt(&ct, &["region:eu".into(), "role:director".into()]).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn abe_insufficient_attributes_rejected() {
        let policy = AccessPolicy {
            required_attributes: vec!["a".into(), "b".into()],
            min_attributes: 2,
        };
        let ct = encrypt(policy, b"data");
        assert!(decrypt(&ct, &["a".into()]).is_none());
    }

    #[test]
    fn abe_partial_satisfy() {
        let policy = AccessPolicy {
            required_attributes: vec!["a".into(), "b".into(), "c".into()],
            min_attributes: 2,
        };
        let ct = encrypt(policy, b"data");
        assert!(decrypt(&ct, &["a".into(), "b".into()]).is_some());
    }

    // Multi-tenancy tests

    fn make_tenant(quorum: &str) -> Tenant {
        Tenant {
            quorum_id: quorum.into(),
            max_sessions: 5,
            active_sessions: 0,
            rate_limit_per_minute: 100,
            allowed_schemes: vec!["CMP20".into(), "FROST-P256".into()],
        }
    }

    #[test]
    fn register_and_get_tenant() {
        let mgr = TenantManager::new();
        mgr.register(make_tenant("q1"));
        assert!(mgr.get("q1").is_some());
        assert!(mgr.get("q2").is_none());
    }

    #[test]
    fn session_limit_enforced() {
        let mgr = TenantManager::new();
        mgr.register(make_tenant("q1"));
        for _ in 0..5 {
            assert!(mgr.increment_sessions("q1"));
        }
        assert!(!mgr.increment_sessions("q1"));
    }

    #[test]
    fn decrement_sessions() {
        let mgr = TenantManager::new();
        mgr.register(make_tenant("q1"));
        mgr.increment_sessions("q1");
        mgr.increment_sessions("q1");
        mgr.decrement_sessions("q1");
        let t = mgr.get("q1").unwrap();
        assert_eq!(t.active_sessions, 1);
    }

    #[test]
    fn scheme_allowed_check() {
        let mgr = TenantManager::new();
        mgr.register(make_tenant("q1"));
        assert!(mgr.is_scheme_allowed("q1", "CMP20"));
        assert!(!mgr.is_scheme_allowed("q1", "RSA"));
    }

    #[test]
    fn unknown_tenant_denied() {
        let mgr = TenantManager::new();
        assert!(!mgr.can_create_session("unknown"));
        assert!(!mgr.increment_sessions("unknown"));
    }

    #[test]
    fn remove_tenant() {
        let mgr = TenantManager::new();
        mgr.register(make_tenant("q1"));
        assert_eq!(mgr.tenant_count(), 1);
        mgr.remove("q1");
        assert_eq!(mgr.tenant_count(), 0);
    }
}
