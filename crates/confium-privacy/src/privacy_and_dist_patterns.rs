//! Privacy-preserving computation + distributed systems patterns.
//!
//! PSI, PIR, differential privacy, feature flags, API versioning,
//! schema registry, 2PC, WAL streaming, snapshot isolation,
//! homomorphic MAC.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Instant;

type HmacSha256 = Hmac<Sha256>;

// === Private Set Intersection ===

/// Hash-based PSI: both parties hash their sets, compare hashes.
pub fn psi_hash_based(set_a: &[Vec<u8>], set_b: &[Vec<u8>], salt: &[u8]) -> Vec<Vec<u8>> {
    let hashes_b: HashSet<[u8; 32]> = set_b.iter().map(|e| hash_with_salt(e, salt)).collect();
    set_a
        .iter()
        .filter(|e| hashes_b.contains(&hash_with_salt(e, salt)))
        .cloned()
        .collect()
}

fn hash_with_salt(data: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(data);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// PSI result size only (cardinality), not the actual intersection.
pub fn psi_cardinality(set_a: &[Vec<u8>], set_b: &[Vec<u8>], salt: &[u8]) -> usize {
    psi_hash_based(set_a, set_b, salt).len()
}

// === Private Information Retrieval ===

/// Simple PIR: client downloads entire database (trivial but private).
pub fn pir_trivial(database: &[Vec<u8>], _index: usize) -> Vec<Vec<u8>> {
    database.to_vec()
}

/// Batch PIR: retrieve multiple indices in one query.
pub fn pir_batch(database: &[Vec<u8>], indices: &[usize]) -> Vec<Vec<u8>> {
    indices
        .iter()
        .filter_map(|&i| database.get(i).cloned())
        .collect()
}

/// XOR-based PIR (2 servers): each server gets a random subset;
/// XOR of responses gives the desired element.
pub struct PirQuery {
    pub mask: Vec<bool>,
}
pub struct PirResponse {
    pub data: Vec<u8>,
}

pub fn pir_create_query(index: usize, db_size: usize) -> (PirQuery, PirQuery) {
    use rand_core::{OsRng, RngCore};
    let mut mask1 = vec![false; db_size];
    let mut mask2 = vec![false; db_size];
    let mut rng = OsRng;
    for i in 0..db_size {
        mask1[i] = rng.next_u32() & 1 == 1;
        mask2[i] = mask1[i];
    }
    mask2[index] = !mask2[index]; // flip the target index
    (PirQuery { mask: mask1 }, PirQuery { mask: mask2 })
}

pub fn pir_server_respond(database: &[Vec<u8>], query: &PirQuery) -> PirResponse {
    let mut result = vec![0u8; database.first().map(|e| e.len()).unwrap_or(0)];
    for (i, &selected) in query.mask.iter().enumerate() {
        if selected {
            if let Some(element) = database.get(i) {
                for (j, &b) in element.iter().enumerate() {
                    if j < result.len() {
                        result[j] ^= b;
                    }
                }
            }
        }
    }
    PirResponse { data: result }
}

pub fn pir_decode(r1: &PirResponse, r2: &PirResponse) -> Vec<u8> {
    r1.data
        .iter()
        .zip(r2.data.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

// === Differential Privacy ===

/// Laplace mechanism: add noise calibrated to sensitivity and epsilon.
pub fn laplace_noise(sensitivity: f64, epsilon: f64) -> f64 {
    use rand_core::{OsRng, RngCore};
    let scale = sensitivity / epsilon;
    let mut buf = [0u8; 8];
    OsRng.fill_bytes(&mut buf);
    let u = (u64::from_le_bytes(buf) as f64) / (u64::MAX as f64);
    let uniform = u - 0.5; // in [-0.5, 0.5)
    -scale * uniform.signum() * (1.0 - 2.0 * uniform.abs()).ln()
}

/// Add Laplace noise to a numeric query result.
pub fn dp_query(value: f64, sensitivity: f64, epsilon: f64) -> f64 {
    value + laplace_noise(sensitivity, epsilon)
}

/// Gaussian mechanism: add Gaussian noise.
pub fn gaussian_noise(sensitivity: f64, epsilon: f64, delta: f64) -> f64 {
    use rand_core::{OsRng, RngCore};
    let sigma = sensitivity * (2.0 * (1.25 / delta).ln()).sqrt() / epsilon;
    let mut buf = [0u8; 8];
    OsRng.fill_bytes(&mut buf);
    let u1 = (u64::from_le_bytes(buf) as f64) / (u64::MAX as f64) + 1e-10;
    OsRng.fill_bytes(&mut buf);
    let u2 = (u64::from_le_bytes(buf) as f64) / (u64::MAX as f64) + 1e-10;
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    z * sigma
}

/// Counting query with DP: report noisy count.
pub fn dp_count(true_count: usize, epsilon: f64) -> f64 {
    dp_query(true_count as f64, 1.0, epsilon)
}

// === Feature Flags ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlag {
    pub name: String,
    pub enabled: bool,
    pub rollout_percentage: u8,
}

#[derive(Default)]
pub struct FeatureFlags {
    flags: Mutex<HashMap<String, FeatureFlag>>,
}

impl FeatureFlags {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, name: &str, enabled: bool) {
        self.flags.lock().unwrap().insert(
            name.into(),
            FeatureFlag {
                name: name.into(),
                enabled,
                rollout_percentage: if enabled { 100 } else { 0 },
            },
        );
    }

    pub fn set_rollout(&self, name: &str, percentage: u8) {
        self.flags.lock().unwrap().insert(
            name.into(),
            FeatureFlag {
                name: name.into(),
                enabled: percentage > 0,
                rollout_percentage: percentage,
            },
        );
    }

    pub fn is_enabled(&self, name: &str) -> bool {
        let flags = self.flags.lock().unwrap();
        flags.get(name).map(|f| f.enabled).unwrap_or(false)
    }

    pub fn is_enabled_for(&self, name: &str, user_id: &str) -> bool {
        let flags = self.flags.lock().unwrap();
        let flag = match flags.get(name) {
            Some(f) => f,
            None => return false,
        };
        if !flag.enabled {
            return false;
        }
        if flag.rollout_percentage >= 100 {
            return true;
        }
        let hash = hash_with_salt(user_id.as_bytes(), name.as_bytes());
        let bucket = (u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 100) as u8;
        bucket < flag.rollout_percentage
    }

    pub fn count(&self) -> usize {
        self.flags.lock().unwrap().len()
    }
    pub fn remove(&self, name: &str) {
        self.flags.lock().unwrap().remove(name);
    }
}

// === API Versioning ===

#[derive(Debug, Clone)]
pub struct ApiVersion {
    pub version: u32,
    pub deprecated: bool,
    pub min_compatible: u32,
}

#[derive(Default)]
pub struct ApiVersionRegistry {
    versions: Mutex<Vec<ApiVersion>>,
}

impl ApiVersionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, version: u32, min_compatible: u32) {
        self.versions.lock().unwrap().push(ApiVersion {
            version,
            deprecated: false,
            min_compatible,
        });
    }

    pub fn deprecate(&self, version: u32) {
        if let Some(v) = self
            .versions
            .lock()
            .unwrap()
            .iter_mut()
            .find(|v| v.version == version)
        {
            v.deprecated = true;
        }
    }

    pub fn is_compatible(&self, client_version: u32) -> bool {
        let versions = self.versions.lock().unwrap();
        versions
            .iter()
            .any(|v| v.version >= client_version && v.version >= v.min_compatible)
    }

    pub fn latest(&self) -> Option<u32> {
        self.versions
            .lock()
            .unwrap()
            .iter()
            .map(|v| v.version)
            .max()
    }

    pub fn negotiate(&self, client_version: u32) -> Option<u32> {
        let versions = self.versions.lock().unwrap();
        versions
            .iter()
            .filter(|v| {
                !v.deprecated && v.version >= v.min_compatible && v.version >= client_version
            })
            .map(|v| v.version)
            .min()
    }

    pub fn count(&self) -> usize {
        self.versions.lock().unwrap().len()
    }
}

// === Schema Registry ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    pub name: String,
    pub version: u32,
    pub fields: Vec<String>,
}

#[derive(Default)]
pub struct SchemaRegistry {
    schemas: Mutex<HashMap<String, Vec<Schema>>>,
}

impl SchemaRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, schema: Schema) {
        self.schemas
            .lock()
            .unwrap()
            .entry(schema.name.clone())
            .or_default()
            .push(schema);
    }

    pub fn latest(&self, name: &str) -> Option<Schema> {
        self.schemas
            .lock()
            .unwrap()
            .get(name)
            .and_then(|versions| versions.last().cloned())
    }

    pub fn get(&self, name: &str, version: u32) -> Option<Schema> {
        self.schemas
            .lock()
            .unwrap()
            .get(name)
            .and_then(|versions| versions.iter().find(|s| s.version == version).cloned())
    }

    pub fn is_backward_compatible(&self, name: &str, new_version: u32) -> bool {
        let schemas = self.schemas.lock().unwrap();
        let versions = match schemas.get(name) {
            Some(v) => v,
            None => return true,
        };
        let old = match versions
            .iter()
            .filter(|s| s.version < new_version)
            .max_by_key(|s| s.version)
        {
            Some(s) => s,
            None => return true,
        };
        let new = match versions.iter().find(|s| s.version == new_version) {
            Some(s) => s,
            None => return true,
        };
        old.fields.iter().all(|f| new.fields.contains(f))
    }

    pub fn version_count(&self, name: &str) -> usize {
        self.schemas
            .lock()
            .unwrap()
            .get(name)
            .map(|v| v.len())
            .unwrap_or(0)
    }
}

// === Two-Phase Commit (2PC) ===

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TwoPcState {
    Init,
    Prepared,
    Committed,
    Aborted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoPcParticipant {
    pub id: String,
    pub state: TwoPcState,
}

pub struct TwoPcCoordinator {
    participants: Mutex<Vec<TwoPcParticipant>>,
    global_state: Mutex<TwoPcState>,
}

impl TwoPcCoordinator {
    pub fn new(participant_ids: &[&str]) -> Self {
        let participants = participant_ids
            .iter()
            .map(|id| TwoPcParticipant {
                id: id.to_string(),
                state: TwoPcState::Init,
            })
            .collect();
        Self {
            participants: Mutex::new(participants),
            global_state: Mutex::new(TwoPcState::Init),
        }
    }

    pub fn prepare(&self, participant_id: &str) -> Result<(), String> {
        let mut participants = self.participants.lock().unwrap();
        let p = participants
            .iter_mut()
            .find(|p| p.id == participant_id)
            .ok_or("unknown participant")?;
        if p.state != TwoPcState::Init {
            return Err("not in init state".into());
        }
        p.state = TwoPcState::Prepared;
        Ok(())
    }

    pub fn all_prepared(&self) -> bool {
        self.participants
            .lock()
            .unwrap()
            .iter()
            .all(|p| p.state == TwoPcState::Prepared)
    }

    pub fn commit(&self) -> Result<(), String> {
        if !self.all_prepared() {
            return Err("not all prepared".into());
        }
        let mut participants = self.participants.lock().unwrap();
        for p in participants.iter_mut() {
            p.state = TwoPcState::Committed;
        }
        *self.global_state.lock().unwrap() = TwoPcState::Committed;
        Ok(())
    }

    pub fn abort(&self) {
        let mut participants = self.participants.lock().unwrap();
        for p in participants.iter_mut() {
            if p.state != TwoPcState::Committed {
                p.state = TwoPcState::Aborted;
            }
        }
        *self.global_state.lock().unwrap() = TwoPcState::Aborted;
    }

    pub fn global_state(&self) -> TwoPcState {
        self.global_state.lock().unwrap().clone()
    }

    pub fn participant_count(&self) -> usize {
        self.participants.lock().unwrap().len()
    }
}

// === WAL Streaming ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalStreamEntry {
    pub sequence: u64,
    pub data_hex: String,
}

pub struct WalStreamer {
    entries: Mutex<Vec<WalStreamEntry>>,
    subscribers: Mutex<Vec<u64>>, // last_seq per subscriber
    next_seq: Mutex<u64>,
}

impl WalStreamer {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            subscribers: Mutex::new(Vec::new()),
            next_seq: Mutex::new(1),
        }
    }

    pub fn append(&self, data: &[u8]) -> u64 {
        let seq = {
            let mut s = self.next_seq.lock().unwrap();
            let v = *s;
            *s += 1;
            v
        };
        self.entries.lock().unwrap().push(WalStreamEntry {
            sequence: seq,
            data_hex: hex::encode(data),
        });
        seq
    }

    pub fn subscribe(&self) -> usize {
        let last_seq = self
            .entries
            .lock()
            .unwrap()
            .last()
            .map(|e| e.sequence)
            .unwrap_or(0);
        self.subscribers.lock().unwrap().push(last_seq);
        self.subscribers.lock().unwrap().len() - 1
    }

    pub fn stream_since(&self, subscriber_id: usize) -> Vec<WalStreamEntry> {
        let last_seen = self
            .subscribers
            .lock()
            .unwrap()
            .get(subscriber_id)
            .copied()
            .unwrap_or(0);
        let entries = self.entries.lock().unwrap();
        let new_entries: Vec<WalStreamEntry> = entries
            .iter()
            .filter(|e| e.sequence > last_seen)
            .cloned()
            .collect();
        if let Some(last) = entries.last() {
            if let Some(sub) = self.subscribers.lock().unwrap().get_mut(subscriber_id) {
                *sub = last.sequence;
            }
        }
        new_entries
    }

    pub fn entry_count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.lock().unwrap().len()
    }
}

impl Default for WalStreamer {
    fn default() -> Self {
        Self::new()
    }
}

// === Snapshot Isolation ===

#[derive(Debug, Clone)]
pub struct Snapshot<T: Clone> {
    pub data: T,
    pub version: u64,
    pub timestamp: Instant,
}

pub struct SnapshotStore<T: Clone> {
    snapshots: Mutex<Vec<Snapshot<T>>>,
    current: Mutex<T>,
    version: Mutex<u64>,
}

impl<T: Clone> SnapshotStore<T> {
    pub fn new(initial: T) -> Self {
        Self {
            snapshots: Mutex::new(Vec::new()),
            current: Mutex::new(initial),
            version: Mutex::new(0),
        }
    }

    pub fn write(&self, data: T) -> u64 {
        let mut current = self.current.lock().unwrap();
        let v = {
            let mut ver = self.version.lock().unwrap();
            let old = *ver;
            *ver += 1;
            old
        };
        let old_data = current.clone();
        *current = data;
        self.snapshots.lock().unwrap().push(Snapshot {
            data: old_data,
            version: v,
            timestamp: Instant::now(),
        });
        v + 1
    }

    pub fn read_current(&self) -> T {
        self.current.lock().unwrap().clone()
    }

    pub fn read_at_version(&self, version: u64) -> Option<T> {
        let snapshots = self.snapshots.lock().unwrap();
        if version >= *self.version.lock().unwrap() {
            return Some(self.current.lock().unwrap().clone());
        }
        snapshots
            .iter()
            .filter(|s| s.version <= version)
            .max_by_key(|s| s.version)
            .map(|s| s.data.clone())
    }

    pub fn current_version(&self) -> u64 {
        *self.version.lock().unwrap()
    }
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.lock().unwrap().len()
    }

    pub fn prune_older_than(&self, max_versions: usize) -> usize {
        let mut snapshots = self.snapshots.lock().unwrap();
        let total = snapshots.len();
        if total <= max_versions {
            return 0;
        }
        let to_remove = total - max_versions;
        snapshots.drain(..to_remove);
        to_remove
    }
}

// === Homomorphic MAC ===

/// MAC that supports homomorphic addition: MAC(m1+m2) = MAC(m1) + MAC(m2).
pub struct HomomorphicMac {
    key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub struct MacTag {
    pub tag: [u8; 32],
}

impl HomomorphicMac {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn mac(&self, message: &[u8]) -> MacTag {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC");
        mac.update(message);
        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&result);
        MacTag { tag }
    }

    pub fn verify(&self, message: &[u8], tag: &MacTag) -> bool {
        let expected = self.mac(message);
        expected.tag == tag.tag
    }

    /// Homomorphically combine two MAC tags (XOR).
    pub fn combine(a: &MacTag, b: &MacTag) -> MacTag {
        let mut combined = [0u8; 32];
        combined
            .iter_mut()
            .zip(a.tag.iter().zip(b.tag.iter()))
            .for_each(|(out, (x, y))| *out = x ^ y);
        MacTag { tag: combined }
    }

    /// Homomorphically scale a MAC tag by a scalar (repeated XOR).
    pub fn scale(tag: &MacTag, n: u32) -> MacTag {
        if n % 2 == 0 {
            MacTag { tag: [0u8; 32] }
        } else {
            tag.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PSI
    #[test]
    fn psi_finds_intersection() {
        let a = vec![b"apple".to_vec(), b"banana".to_vec(), b"cherry".to_vec()];
        let b = vec![b"banana".to_vec(), b"date".to_vec(), b"cherry".to_vec()];
        let intersection = psi_hash_based(&a, &b, b"salt");
        assert_eq!(intersection.len(), 2);
    }

    #[test]
    fn psi_empty_when_disjoint() {
        let a = vec![b"a".to_vec()];
        let b = vec![b"b".to_vec()];
        assert!(psi_hash_based(&a, &b, b"salt").is_empty());
    }

    #[test]
    fn psi_cardinality_works() {
        let a = vec![b"x".to_vec(), b"y".to_vec()];
        let b = vec![b"x".to_vec(), b"y".to_vec(), b"z".to_vec()];
        assert_eq!(psi_cardinality(&a, &b, b"s"), 2);
    }

    // PIR
    #[test]
    fn pir_trivial_returns_all() {
        let db = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let result = pir_trivial(&db, 1);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn pir_batch_retrieves_indices() {
        let db = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let result = pir_batch(&db, &[0, 2]);
        assert_eq!(result, vec![b"a".to_vec(), b"c".to_vec()]);
    }

    #[test]
    fn pir_xor_protocol() {
        let db = vec![vec![0xAA; 4], vec![0xBB; 4], vec![0xCC; 4]];
        let (q1, q2) = pir_create_query(1, db.len());
        let r1 = pir_server_respond(&db, &q1);
        let r2 = pir_server_respond(&db, &q2);
        let result = pir_decode(&r1, &r2);
        assert_eq!(result, vec![0xBB; 4]);
    }

    // Differential Privacy
    #[test]
    fn dp_query_adds_noise() {
        let noisy = dp_query(100.0, 1.0, 1.0);
        assert!(noisy != 100.0); // almost certainly noisy
    }

    #[test]
    fn dp_count_nonnegative_mostly() {
        for _ in 0..10 {
            let noisy = dp_count(100, 1.0);
            assert!(noisy > 50.0 && noisy < 150.0);
        }
    }

    #[test]
    fn gaussian_noise_is_finite() {
        let noise = gaussian_noise(1.0, 1.0, 0.001);
        assert!(noise.is_finite());
    }

    // Feature Flags
    #[test]
    fn flag_enabled() {
        let flags = FeatureFlags::new();
        flags.set("feature_x", true);
        assert!(flags.is_enabled("feature_x"));
    }

    #[test]
    fn flag_disabled() {
        let flags = FeatureFlags::new();
        flags.set("feature_y", false);
        assert!(!flags.is_enabled("feature_y"));
    }

    #[test]
    fn flag_not_set_defaults_false() {
        let flags = FeatureFlags::new();
        assert!(!flags.is_enabled("nonexistent"));
    }

    #[test]
    fn rollout_100_enables_all() {
        let flags = FeatureFlags::new();
        flags.set_rollout("beta", 100);
        assert!(flags.is_enabled_for("beta", "user1"));
        assert!(flags.is_enabled_for("beta", "user2"));
    }

    #[test]
    fn rollout_0_disables_all() {
        let flags = FeatureFlags::new();
        flags.set_rollout("alpha", 0);
        assert!(!flags.is_enabled_for("alpha", "user1"));
    }

    // API Versioning
    #[test]
    fn version_registration() {
        let reg = ApiVersionRegistry::new();
        reg.register(1, 1);
        reg.register(2, 1);
        assert_eq!(reg.latest(), Some(2));
        assert_eq!(reg.count(), 2);
    }

    #[test]
    fn version_negotiation() {
        let reg = ApiVersionRegistry::new();
        reg.register(1, 1);
        reg.register(2, 1);
        reg.register(3, 2);
        assert_eq!(reg.negotiate(1), Some(1));
        assert_eq!(reg.negotiate(3), Some(3));
    }

    #[test]
    fn version_deprecation() {
        let reg = ApiVersionRegistry::new();
        reg.register(1, 1);
        reg.register(2, 1);
        reg.deprecate(1);
        assert_eq!(reg.negotiate(1), Some(2));
    }

    // Schema Registry
    #[test]
    fn schema_register_and_get() {
        let reg = SchemaRegistry::new();
        reg.register(Schema {
            name: "user".into(),
            version: 1,
            fields: vec!["id".into(), "name".into()],
        });
        reg.register(Schema {
            name: "user".into(),
            version: 2,
            fields: vec!["id".into(), "name".into(), "email".into()],
        });
        assert_eq!(reg.version_count("user"), 2);
        let latest = reg.latest("user").unwrap();
        assert_eq!(latest.version, 2);
        assert!(latest.fields.contains(&"email".into()));
    }

    #[test]
    fn schema_backward_compat() {
        let reg = SchemaRegistry::new();
        reg.register(Schema {
            name: "event".into(),
            version: 1,
            fields: vec!["id".into()],
        });
        reg.register(Schema {
            name: "event".into(),
            version: 2,
            fields: vec!["id".into(), "ts".into()],
        });
        assert!(reg.is_backward_compatible("event", 2));
        reg.register(Schema {
            name: "event".into(),
            version: 3,
            fields: vec!["ts".into()],
        }); // removed "id"
        assert!(!reg.is_backward_compatible("event", 3));
    }

    // 2PC
    #[test]
    fn two_pc_success() {
        let coord = TwoPcCoordinator::new(&["a", "b", "c"]);
        coord.prepare("a").unwrap();
        coord.prepare("b").unwrap();
        coord.prepare("c").unwrap();
        assert!(coord.all_prepared());
        coord.commit().unwrap();
        assert_eq!(coord.global_state(), TwoPcState::Committed);
    }

    #[test]
    fn two_pc_abort() {
        let coord = TwoPcCoordinator::new(&["a", "b"]);
        coord.prepare("a").unwrap();
        assert!(!coord.all_prepared());
        coord.abort();
        assert_eq!(coord.global_state(), TwoPcState::Aborted);
    }

    #[test]
    fn two_pc_commit_without_all_prepared_fails() {
        let coord = TwoPcCoordinator::new(&["a", "b"]);
        coord.prepare("a").unwrap();
        assert!(coord.commit().is_err());
    }

    // WAL Streaming
    #[test]
    fn wal_stream_append_and_subscribe() {
        let streamer = WalStreamer::new();
        streamer.append(b"data1");
        streamer.append(b"data2");
        let sub_id = streamer.subscribe();
        assert!(streamer.stream_since(sub_id).is_empty());
        streamer.append(b"data3");
        let entries = streamer.stream_since(sub_id);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data_hex, hex::encode(b"data3"));
    }

    #[test]
    fn wal_stream_multiple_subscribers() {
        let streamer = WalStreamer::new();
        let sub1 = streamer.subscribe();
        streamer.append(b"a");
        let sub2 = streamer.subscribe();
        streamer.append(b"b");
        assert_eq!(streamer.stream_since(sub1).len(), 2);
        assert_eq!(streamer.stream_since(sub2).len(), 1);
    }

    // Snapshot Isolation
    #[test]
    fn snapshot_read_current() {
        let store = SnapshotStore::new(42);
        assert_eq!(store.read_current(), 42);
        store.write(100);
        assert_eq!(store.read_current(), 100);
    }

    #[test]
    fn snapshot_read_at_version() {
        let store = SnapshotStore::new(1);
        store.write(2);
        store.write(3);
        assert_eq!(store.read_at_version(0), Some(1));
        assert_eq!(store.read_at_version(1), Some(2));
        assert_eq!(store.read_at_version(2), Some(3));
    }

    #[test]
    fn snapshot_prune() {
        let store = SnapshotStore::new(0);
        for i in 1..=10 {
            store.write(i);
        }
        assert_eq!(store.snapshot_count(), 10);
        store.prune_older_than(3);
        assert!(store.snapshot_count() <= 3);
    }

    // Homomorphic MAC
    #[test]
    fn hmac_mac_and_verify() {
        let mac = HomomorphicMac::new([0x42; 32]);
        let tag = mac.mac(b"message");
        assert!(mac.verify(b"message", &tag));
        assert!(!mac.verify(b"wrong", &tag));
    }

    #[test]
    fn hmac_combine() {
        let mac = HomomorphicMac::new([0x42; 32]);
        let t1 = mac.mac(b"m1");
        let t2 = mac.mac(b"m2");
        let combined = HomomorphicMac::combine(&t1, &t2);
        assert_ne!(combined.tag, t1.tag);
        assert_ne!(combined.tag, t2.tag);
    }

    #[test]
    fn hmac_scale_even_to_zero() {
        let mac = HomomorphicMac::new([0x42; 32]);
        let tag = mac.mac(b"message");
        let scaled = HomomorphicMac::scale(&tag, 2);
        assert_eq!(scaled.tag, [0u8; 32]);
    }

    #[test]
    fn hmac_scale_odd_preserves() {
        let mac = HomomorphicMac::new([0x42; 32]);
        let tag = mac.mac(b"message");
        let scaled = HomomorphicMac::scale(&tag, 3);
        assert_eq!(scaled, tag);
    }
}
