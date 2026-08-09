//! Distributed lock manager — TTL-based leases with fencing tokens.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// A distributed lock lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub resource: String,
    pub holder: String,
    pub fencing_token: u64,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Thread-safe distributed lock manager (in-memory; production
/// implementations use Redis or etcd).
pub struct DistributedLockManager {
    leases: Mutex<HashMap<String, Lease>>,
    next_token: Mutex<u64>,
}

impl DistributedLockManager {
    pub fn new() -> Self {
        Self {
            leases: Mutex::new(HashMap::new()),
            next_token: Mutex::new(1),
        }
    }

    /// Try to acquire a lock. Returns the fencing token if acquired,
    /// or None if the resource is held by another holder.
    pub fn try_acquire(&self, resource: &str, holder: &str, ttl: Duration) -> Option<u64> {
        let mut leases = self.leases.lock().unwrap();
        let now = Utc::now();

        if let Some(existing) = leases.get(resource) {
            if existing.holder != holder && existing.expires_at > now {
                return None;
            }
        }

        let mut next = self.next_token.lock().unwrap();
        let token = *next;
        *next += 1;

        leases.insert(
            resource.into(),
            Lease {
                resource: resource.into(),
                holder: holder.into(),
                fencing_token: token,
                acquired_at: now,
                expires_at: now + ttl,
            },
        );
        Some(token)
    }

    /// Release a lock. Only the holder can release.
    pub fn release(&self, resource: &str, holder: &str) -> bool {
        let mut leases = self.leases.lock().unwrap();
        if let Some(lease) = leases.get(resource) {
            if lease.holder == holder {
                leases.remove(resource);
                return true;
            }
        }
        false
    }

    /// Renew an existing lease. Returns the new expiry time.
    pub fn renew(&self, resource: &str, holder: &str, ttl: Duration) -> Option<DateTime<Utc>> {
        let mut leases = self.leases.lock().unwrap();
        let lease = leases.get_mut(resource)?;
        if lease.holder != holder {
            return None;
        }
        lease.expires_at = Utc::now() + ttl;
        Some(lease.expires_at)
    }

    /// Check if a resource is currently locked.
    pub fn is_locked(&self, resource: &str) -> bool {
        let leases = self.leases.lock().unwrap();
        leases
            .get(resource)
            .map(|l| l.expires_at > Utc::now())
            .unwrap_or(false)
    }

    /// Get the current holder of a resource.
    pub fn holder(&self, resource: &str) -> Option<String> {
        let leases = self.leases.lock().unwrap();
        leases.get(resource).map(|l| l.holder.clone())
    }

    /// Purge expired leases.
    pub fn purge_expired(&self) -> usize {
        let mut leases = self.leases.lock().unwrap();
        let now = Utc::now();
        let before = leases.len();
        leases.retain(|_, l| l.expires_at > now);
        before - leases.len()
    }

    /// Number of active leases.
    pub fn active_count(&self) -> usize {
        let leases = self.leases.lock().unwrap();
        let now = Utc::now();
        leases.values().filter(|l| l.expires_at > now).count()
    }
}

impl Default for DistributedLockManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_returns_token() {
        let mgr = DistributedLockManager::new();
        let token = mgr.try_acquire("res", "a", Duration::seconds(30));
        assert!(token.is_some());
        assert!(token.unwrap() > 0);
    }

    #[test]
    fn cannot_acquire_held_resource() {
        let mgr = DistributedLockManager::new();
        mgr.try_acquire("res", "a", Duration::seconds(30));
        let token = mgr.try_acquire("res", "b", Duration::seconds(30));
        assert!(token.is_none());
    }

    #[test]
    fn same_holder_can_reacquire() {
        let mgr = DistributedLockManager::new();
        mgr.try_acquire("res", "a", Duration::seconds(30));
        let token = mgr.try_acquire("res", "a", Duration::seconds(30));
        assert!(token.is_some());
    }

    #[test]
    fn release_by_holder() {
        let mgr = DistributedLockManager::new();
        mgr.try_acquire("res", "a", Duration::seconds(30));
        assert!(mgr.release("res", "a"));
        assert!(!mgr.is_locked("res"));
    }

    #[test]
    fn release_by_wrong_holder_fails() {
        let mgr = DistributedLockManager::new();
        mgr.try_acquire("res", "a", Duration::seconds(30));
        assert!(!mgr.release("res", "b"));
    }

    #[test]
    fn renew_extends_lease() {
        let mgr = DistributedLockManager::new();
        mgr.try_acquire("res", "a", Duration::seconds(10));
        let new_expiry = mgr.renew("res", "a", Duration::seconds(60));
        assert!(new_expiry.is_some());
    }

    #[test]
    fn renew_wrong_holder_fails() {
        let mgr = DistributedLockManager::new();
        mgr.try_acquire("res", "a", Duration::seconds(10));
        assert!(mgr.renew("res", "b", Duration::seconds(60)).is_none());
    }

    #[test]
    fn fencing_tokens_monotonic() {
        let mgr = DistributedLockManager::new();
        let t1 = mgr.try_acquire("r1", "a", Duration::seconds(30)).unwrap();
        mgr.release("r1", "a");
        let t2 = mgr.try_acquire("r2", "a", Duration::seconds(30)).unwrap();
        assert!(t2 > t1);
    }

    #[test]
    fn expired_lease_can_be_acquired() {
        let mgr = DistributedLockManager::new();
        mgr.try_acquire("res", "a", Duration::seconds(-1)); // already expired
        assert!(!mgr.is_locked("res"));
        let token = mgr.try_acquire("res", "b", Duration::seconds(30));
        assert!(token.is_some());
    }

    #[test]
    fn purge_expired_removes_stale() {
        let mgr = DistributedLockManager::new();
        mgr.try_acquire("r1", "a", Duration::seconds(-1)); // expired
        mgr.try_acquire("r2", "b", Duration::seconds(30));
        assert_eq!(mgr.purge_expired(), 1);
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn holder_returns_current() {
        let mgr = DistributedLockManager::new();
        mgr.try_acquire("res", "alice", Duration::seconds(30));
        assert_eq!(mgr.holder("res").as_deref(), Some("alice"));
    }
}
