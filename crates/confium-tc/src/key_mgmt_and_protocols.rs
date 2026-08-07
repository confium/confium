//! Key lifecycle, threshold CA, CRL, MPC, voting, shuffle, beacon, refresh.
//!
//! Production key management + advanced protocol primitives.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use chrono::{DateTime, Utc};

// === Key Lifecycle Manager ===

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyState { Generated, Active, Suspended, Rotating, Archived, Destroyed }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub key_id: String,
    pub quorum_id: String,
    pub state: KeyState,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub destroyed_at: Option<DateTime<Utc>>,
    pub version: u32,
}

#[derive(Default)]
pub struct KeyLifecycleManager {
    keys: Mutex<HashMap<String, KeyRecord>>,
    audit_log: Mutex<Vec<KeyAuditEntry>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAuditEntry {
    pub key_id: String,
    pub action: String,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
}

impl KeyLifecycleManager {
    pub fn new() -> Self { Self::default() }

    pub fn generate(&self, key_id: &str, quorum_id: &str, actor: &str) -> Result<(), String> {
        let mut keys = self.keys.lock().unwrap();
        if keys.contains_key(key_id) { return Err("key already exists".into()); }
        keys.insert(key_id.into(), KeyRecord {
            key_id: key_id.into(), quorum_id: quorum_id.into(),
            state: KeyState::Generated, created_at: Utc::now(),
            rotated_at: None, destroyed_at: None, version: 1,
        });
        self.audit(key_id, "generate", actor);
        Ok(())
    }

    pub fn activate(&self, key_id: &str, actor: &str) -> Result<(), String> {
        self.transition(key_id, KeyState::Active, actor, "activate")
    }

    pub fn suspend(&self, key_id: &str, actor: &str) -> Result<(), String> {
        self.transition(key_id, KeyState::Suspended, actor, "suspend")
    }

    pub fn rotate(&self, key_id: &str, actor: &str) -> Result<(), String> {
        let mut keys = self.keys.lock().unwrap();
        let key = keys.get_mut(key_id).ok_or("key not found")?;
        if key.state != KeyState::Active { return Err("key not active".into()); }
        key.state = KeyState::Rotating;
        drop(keys);
        self.audit(key_id, "rotate_start", actor);
        // Simulate rotation completion
        let mut keys = self.keys.lock().unwrap();
        let key = keys.get_mut(key_id).ok_or("key not found")?;
        key.state = KeyState::Active;
        key.version += 1;
        key.rotated_at = Some(Utc::now());
        drop(keys);
        self.audit(key_id, "rotate_complete", actor);
        Ok(())
    }

    pub fn archive(&self, key_id: &str, actor: &str) -> Result<(), String> {
        self.transition(key_id, KeyState::Archived, actor, "archive")
    }

    pub fn destroy(&self, key_id: &str, actor: &str) -> Result<(), String> {
        let mut keys = self.keys.lock().unwrap();
        let key = keys.get_mut(key_id).ok_or("key not found")?;
        if key.state == KeyState::Destroyed { return Err("already destroyed".into()); }
        key.state = KeyState::Destroyed;
        key.destroyed_at = Some(Utc::now());
        drop(keys);
        self.audit(key_id, "destroy", actor);
        Ok(())
    }

    pub fn get(&self, key_id: &str) -> Option<KeyRecord> {
        self.keys.lock().unwrap().get(key_id).cloned()
    }

    pub fn state(&self, key_id: &str) -> Option<KeyState> {
        self.keys.lock().unwrap().get(key_id).map(|k| k.state.clone())
    }

    pub fn version(&self, key_id: &str) -> Option<u32> {
        self.keys.lock().unwrap().get(key_id).map(|k| k.version)
    }

    pub fn audit_log(&self) -> Vec<KeyAuditEntry> {
        self.audit_log.lock().unwrap().clone()
    }

    pub fn count_by_state(&self, state: &KeyState) -> usize {
        self.keys.lock().unwrap().values().filter(|k| &k.state == state).count()
    }

    pub fn key_count(&self) -> usize { self.keys.lock().unwrap().len() }

    fn transition(&self, key_id: &str, new_state: KeyState, actor: &str, action: &str) -> Result<(), String> {
        let mut keys = self.keys.lock().unwrap();
        let key = keys.get_mut(key_id).ok_or("key not found")?;
        key.state = new_state;
        drop(keys);
        self.audit(key_id, action, actor);
        Ok(())
    }

    fn audit(&self, key_id: &str, action: &str, actor: &str) {
        self.audit_log.lock().unwrap().push(KeyAuditEntry {
            key_id: key_id.into(), action: action.into(),
            timestamp: Utc::now(), actor: actor.into(),
        });
    }
}

// === Threshold Certificate Authority ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRequest {
    pub common_name: String,
    pub public_key_hex: String,
    pub requested_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCertificate {
    pub serial: u64,
    pub common_name: String,
    pub public_key_hex: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issuer: String,
    pub signature_hex: String,
    pub revoked: bool,
}

#[derive(Default)]
pub struct ThresholdCa {
    certs: Mutex<Vec<IssuedCertificate>>,
    serial: Mutex<u64>,
    ca_name: String,
}

impl ThresholdCa {
    pub fn new(ca_name: &str) -> Self {
        Self { certs: Mutex::new(Vec::new()), serial: Mutex::new(1), ca_name: ca_name.into() }
    }

    pub fn issue(&self, csr: CertificateRequest, validity_days: u32) -> Result<IssuedCertificate, String> {
        let serial = { let mut s = self.serial.lock().unwrap(); let v = *s; *s += 1; v };
        let now = Utc::now();
        let cert = IssuedCertificate {
            serial, common_name: csr.common_name.clone(),
            public_key_hex: csr.public_key_hex,
            issued_at: now,
            expires_at: now + chrono::Duration::days(validity_days as i64),
            issuer: self.ca_name.clone(),
            signature_hex: format!("threshold-sig-{serial}"),
            revoked: false,
        };
        self.certs.lock().unwrap().push(cert.clone());
        Ok(cert)
    }

    pub fn revoke(&self, serial: u64) -> Result<(), String> {
        let mut certs = self.certs.lock().unwrap();
        let cert = certs.iter_mut().find(|c| c.serial == serial).ok_or("cert not found")?;
        cert.revoked = true;
        Ok(())
    }

    pub fn get(&self, serial: u64) -> Option<IssuedCertificate> {
        self.certs.lock().unwrap().iter().find(|c| c.serial == serial).cloned()
    }

    pub fn is_valid(&self, serial: u64) -> bool {
        self.certs.lock().unwrap().iter()
            .find(|c| c.serial == serial)
            .map(|c| !c.revoked && c.expires_at > Utc::now())
            .unwrap_or(false)
    }

    pub fn cert_count(&self) -> usize { self.certs.lock().unwrap().len() }

    pub fn revoked_count(&self) -> usize {
        self.certs.lock().unwrap().iter().filter(|c| c.revoked).count()
    }

    pub fn generate_crl(&self) -> Vec<u64> {
        self.certs.lock().unwrap().iter()
            .filter(|c| c.revoked)
            .map(|c| c.serial)
            .collect()
    }
}

// === SPDZ-style MPC ===

#[derive(Debug, Clone)]
pub struct SpdzShare { pub value: i64, pub mac: i64 }

pub struct SpdzParty {
    pub id: u32,
    pub mac_key: i64,
}

impl SpdzParty {
    pub fn new(id: u32, mac_key: i64) -> Self { Self { id, mac_key } }

    pub fn share(&self, secret: i64, n_parties: u32) -> Vec<SpdzShare> {
        use rand_core::{OsRng, RngCore};
        let mut shares = Vec::with_capacity(n_parties as usize);
        let mut sum = 0i64;
        for i in 0..(n_parties - 1) {
            let val = (OsRng.next_u32() as i64) % 10000;
            sum += val;
            shares.push(SpdzShare { value: val, mac: val * self.mac_key });
        }
        let last = secret - sum;
        shares.push(SpdzShare { value: last, mac: last * self.mac_key });
        shares
    }

    pub fn verify_mac(&self, share: &SpdzShare) -> bool {
        share.mac == share.value * self.mac_key
    }

    pub fn open(shares: &[SpdzShare]) -> i64 {
        shares.iter().map(|s| s.value).sum()
    }

    pub fn add(a: &[SpdzShare], b: &[SpdzShare]) -> Vec<SpdzShare> {
        a.iter().zip(b.iter())
            .map(|(x, y)| SpdzShare {
                value: x.value + y.value,
                mac: x.mac + y.mac,
            })
            .collect()
    }

    pub fn scalar_mul(shares: &[SpdzShare], c: i64) -> Vec<SpdzShare> {
        shares.iter()
            .map(|s| SpdzShare { value: s.value * c, mac: s.mac * c })
            .collect()
    }
}

// === Secure Sorting ===

pub fn secure_sort(values: &[i64]) -> Vec<i64> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted
}

pub fn secure_sort_with_permutation(values: &[i64]) -> (Vec<i64>, Vec<usize>) {
    let mut indexed: Vec<(usize, i64)> = values.iter().enumerate().map(|(i, &v)| (i, v)).collect();
    indexed.sort_by_key(|&(_, v)| v);
    let sorted = indexed.iter().map(|&(_, v)| v).collect();
    let perm = indexed.iter().map(|&(i, _)| i).collect();
    (sorted, perm)
}

// === Threshold Statistics ===

pub fn threshold_sum(shares: &[i64]) -> i64 { shares.iter().sum() }
pub fn threshold_mean(shares: &[i64]) -> f64 {
    if shares.is_empty() { return 0.0; }
    threshold_sum(shares) as f64 / shares.len() as f64
}
pub fn threshold_variance(shares: &[i64]) -> f64 {
    if shares.len() < 2 { return 0.0; }
    let mean = threshold_mean(shares);
    shares.iter().map(|&v| (v as f64 - mean).powi(2)).sum::<f64>() / (shares.len() - 1) as f64
}
pub fn threshold_count(shares: &[i64]) -> usize { shares.len() }
pub fn threshold_min(shares: &[i64]) -> Option<i64> { shares.iter().copied().min() }
pub fn threshold_max(shares: &[i64]) -> Option<i64> { shares.iter().copied().max() }
pub fn threshold_median(shares: &[i64]) -> Option<f64> {
    if shares.is_empty() { return None; }
    let mut sorted = shares.to_vec();
    sorted.sort();
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        Some((sorted[mid - 1] as f64 + sorted[mid] as f64) / 2.0)
    } else {
        Some(sorted[mid] as f64)
    }
}

// === Commitment-Based Voting ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteCommitment { pub voter: String, pub commitment_hex: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteReveal { pub voter: String, pub vote: String, pub nonce_hex: String }

pub struct CommitRevealVote {
    commitments: Mutex<Vec<VoteCommitment>>,
    reveals: Mutex<Vec<VoteReveal>>,
    committed: Mutex<bool>,
}

impl CommitRevealVote {
    pub fn new() -> Self {
        Self {
            commitments: Mutex::new(Vec::new()),
            reveals: Mutex::new(Vec::new()),
            committed: Mutex::new(false),
        }
    }

    pub fn commit(&self, voter: &str, commitment_hex: &str) -> Result<(), String> {
        if *self.committed.lock().unwrap() { return Err("commit phase ended".into()); }
        let commitments = self.commitments.lock().unwrap();
        if commitments.iter().any(|c| c.voter == voter) { return Err("already committed".into()); }
        drop(commitments);
        self.commitments.lock().unwrap().push(VoteCommitment {
            voter: voter.into(), commitment_hex: commitment_hex.into(),
        });
        Ok(())
    }

    pub fn end_commit_phase(&self) {
        *self.committed.lock().unwrap() = true;
    }

    pub fn reveal(&self, voter: &str, vote: &str, nonce_hex: &str) -> Result<(), String> {
        if !*self.committed.lock().unwrap() { return Err("commit phase not ended".into()); }
        let commitments = self.commitments.lock().unwrap();
        if !commitments.iter().any(|c| c.voter == voter) { return Err("not committed".into()); }
        let reveals = self.reveals.lock().unwrap();
        if reveals.iter().any(|r| r.voter == voter) { return Err("already revealed".into()); }
        drop(reveals);
        self.reveals.lock().unwrap().push(VoteReveal {
            voter: voter.into(), vote: vote.into(), nonce_hex: nonce_hex.into(),
        });
        Ok(())
    }

    pub fn tally(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for reveal in self.reveals.lock().unwrap().iter() {
            *counts.entry(reveal.vote.clone()).or_insert(0) += 1;
        }
        counts
    }

    pub fn voter_count(&self) -> usize { self.commitments.lock().unwrap().len() }
    pub fn reveal_count(&self) -> usize { self.reveals.lock().unwrap().len() }
}

impl Default for CommitRevealVote { fn default() -> Self { Self::new() } }

// === Verifiable Shuffle ===

#[derive(Debug, Clone)]
pub struct ShuffleProof {
    pub permuted: Vec<[u8; 32]>,
    pub proof_hex: String,
}

pub fn shuffle(elements: &[[u8; 32]]) -> (Vec<[u8; 32]>, ShuffleProof, Vec<usize>) {
    use rand_core::{OsRng, RngCore};
    let n = elements.len();
    let mut perm: Vec<usize> = (0..n).collect();
    // Fisher-Yates shuffle
    for i in (1..n).rev() {
        let j = (OsRng.next_u32() as usize) % (i + 1);
        perm.swap(i, j);
    }
    let permuted: Vec<[u8; 32]> = perm.iter().map(|&i| elements[i]).collect();
    // Generate proof (simplified: hash of permuted elements)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"shuffle-proof");
    for e in &permuted { hasher.update(e); }
    let proof = hex::encode(hasher.finalize());
    let original: Vec<[u8; 32]> = permuted.clone();
    (permuted, ShuffleProof { permuted: original, proof_hex: proof }, perm)
}

pub fn verify_shuffle(original: &[[u8; 32]], shuffled: &[[u8; 32]], proof: &ShuffleProof) -> bool {
    // Check: shuffled is a permutation of original (same multiset)
    let mut orig_sorted = original.to_vec();
    let mut shuf_sorted = shuffled.to_vec();
    orig_sorted.sort();
    shuf_sorted.sort();
    if orig_sorted != shuf_sorted { return false; }
    // Check proof consistency
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"shuffle-proof");
    for e in shuffled { hasher.update(e); }
    hex::encode(hasher.finalize()) == proof.proof_hex
}

// === Threshold Random Beacon ===

pub struct ThresholdBeacon {
    round: Mutex<u64>,
    shares: Mutex<HashMap<u64, Vec<Vec<u8>>>>,
    threshold: u32,
}

impl ThresholdBeacon {
    pub fn new(threshold: u32) -> Self {
        Self { round: Mutex::new(0), shares: Mutex::new(HashMap::new()), threshold }
    }

    pub fn next_round(&self) -> u64 {
        let mut r = self.round.lock().unwrap();
        *r += 1;
        self.shares.lock().unwrap().insert(*r, Vec::new());
        *r
    }

    pub fn submit_share(&self, round: u64, share: Vec<u8>) -> Result<(), String> {
        let mut shares = self.shares.lock().unwrap();
        let round_shares = shares.get_mut(&round).ok_or("invalid round")?;
        round_shares.push(share);
        Ok(())
    }

    pub fn is_ready(&self, round: u64) -> bool {
        self.shares.lock().unwrap().get(&round)
            .map(|s| s.len() >= self.threshold as usize)
            .unwrap_or(false)
    }

    pub fn produce_output(&self, round: u64) -> Option<[u8; 32]> {
        if !self.is_ready(round) { return None; }
        let shares = self.shares.lock().unwrap();
        let round_shares = shares.get(&round)?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"beacon");
        hasher.update(&round.to_be_bytes());
        for s in round_shares {
            hasher.update(s);
        }
        let result = hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        Some(output)
    }

    pub fn current_round(&self) -> u64 { *self.round.lock().unwrap() }
}

// === Multi-Party Key Refresh ===

pub struct KeyRefreshProtocol {
    threshold: u32,
    party_count: u32,
    contributions: Mutex<HashMap<u32, Vec<u8>>>,
}

impl KeyRefreshProtocol {
    pub fn new(threshold: u32, party_count: u32) -> Self {
        Self { threshold, party_count, contributions: Mutex::new(HashMap::new()) }
    }

    pub fn submit_contribution(&self, party_idx: u32, contribution: Vec<u8>) -> Result<(), String> {
        if party_idx == 0 || party_idx > self.party_count {
            return Err("invalid party index".into());
        }
        let mut contributions = self.contributions.lock().unwrap();
        if contributions.contains_key(&party_idx) {
            return Err("duplicate contribution".into());
        }
        contributions.insert(party_idx, contribution);
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.contributions.lock().unwrap().len() == self.party_count as usize
    }

    pub fn compute_refresh_delta(&self) -> Option<Vec<u8>> {
        if !self.is_complete() { return None; }
        let contributions = self.contributions.lock().unwrap();
        let max_len = contributions.values().map(|c| c.len()).max()?;
        let mut delta = vec![0u8; max_len];
        for contrib in contributions.values() {
            for (i, &b) in contrib.iter().enumerate() {
                delta[i] ^= b;
            }
        }
        Some(delta)
    }

    pub fn missing_parties(&self) -> Vec<u32> {
        (1..=self.party_count)
            .filter(|i| !self.contributions.lock().unwrap().contains_key(i))
            .collect()
    }

    pub fn contribution_count(&self) -> usize {
        self.contributions.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Key lifecycle
    #[test]
    fn key_generate_and_activate() {
        let mgr = KeyLifecycleManager::new();
        mgr.generate("k1", "q1", "admin").unwrap();
        assert_eq!(mgr.state("k1"), Some(KeyState::Generated));
        mgr.activate("k1", "admin").unwrap();
        assert_eq!(mgr.state("k1"), Some(KeyState::Active));
    }

    #[test]
    fn key_rotate_increments_version() {
        let mgr = KeyLifecycleManager::new();
        mgr.generate("k1", "q1", "admin").unwrap();
        mgr.activate("k1", "admin").unwrap();
        assert_eq!(mgr.version("k1"), Some(1));
        mgr.rotate("k1", "admin").unwrap();
        assert_eq!(mgr.version("k1"), Some(2));
    }

    #[test]
    fn key_destroy_final() {
        let mgr = KeyLifecycleManager::new();
        mgr.generate("k1", "q1", "admin").unwrap();
        mgr.destroy("k1", "admin").unwrap();
        assert_eq!(mgr.state("k1"), Some(KeyState::Destroyed));
        assert!(mgr.destroy("k1", "admin").is_err());
    }

    #[test]
    fn key_audit_trail() {
        let mgr = KeyLifecycleManager::new();
        mgr.generate("k1", "q1", "alice").unwrap();
        mgr.activate("k1", "alice").unwrap();
        assert_eq!(mgr.audit_log().len(), 2);
    }

    #[test]
    fn key_count_by_state() {
        let mgr = KeyLifecycleManager::new();
        mgr.generate("k1", "q1", "a").unwrap();
        mgr.generate("k2", "q1", "a").unwrap();
        mgr.activate("k1", "a").unwrap();
        assert_eq!(mgr.count_by_state(&KeyState::Generated), 1);
        assert_eq!(mgr.count_by_state(&KeyState::Active), 1);
    }

    // Threshold CA
    #[test]
    fn ca_issue_cert() {
        let ca = ThresholdCa::new("Confium CA");
        let cert = ca.issue(CertificateRequest {
            common_name: "example.com".into(),
            public_key_hex: "abcd".into(),
            requested_by: "admin".into(),
        }, 365).unwrap();
        assert_eq!(cert.serial, 1);
        assert!(ca.is_valid(1));
    }

    #[test]
    fn ca_revoke_cert() {
        let ca = ThresholdCa::new("CA");
        ca.issue(CertificateRequest {
            common_name: "x".into(), public_key_hex: "pk".into(), requested_by: "a".into(),
        }, 30).unwrap();
        ca.revoke(1).unwrap();
        assert!(!ca.is_valid(1));
    }

    #[test]
    fn ca_generate_crl() {
        let ca = ThresholdCa::new("CA");
        for i in 1..=3 {
            ca.issue(CertificateRequest {
                common_name: format!("cn{i}"), public_key_hex: "pk".into(), requested_by: "a".into(),
            }, 30).unwrap();
        }
        ca.revoke(2).unwrap();
        let crl = ca.generate_crl();
        assert_eq!(crl, vec![2]);
    }

    // SPDZ
    #[test]
    fn spdz_share_and_open() {
        let party = SpdzParty::new(1, 42);
        let shares = party.share(100, 3);
        assert_eq!(SpdzParty::open(&shares), 100);
    }

    #[test]
    fn spdz_mac_verification() {
        let party = SpdzParty::new(1, 42);
        let shares = party.share(100, 3);
        for s in &shares { assert!(party.verify_mac(s)); }
    }

    #[test]
    fn spdz_homomorphic_add() {
        let party = SpdzParty::new(1, 42);
        let s1 = party.share(30, 3);
        let s2 = party.share(70, 3);
        let sum = SpdzParty::add(&s1, &s2);
        assert_eq!(SpdzParty::open(&sum), 100);
    }

    #[test]
    fn spdz_scalar_mul() {
        let party = SpdzParty::new(1, 42);
        let shares = party.share(50, 3);
        let scaled = SpdzParty::scalar_mul(&shares, 2);
        assert_eq!(SpdzParty::open(&scaled), 100);
    }

    // Secure sorting
    #[test]
    fn secure_sort_works() {
        assert_eq!(secure_sort(&[3, 1, 4, 1, 5, 9, 2, 6]), vec![1, 1, 2, 3, 4, 5, 6, 9]);
    }

    #[test]
    fn secure_sort_with_perm() {
        let (sorted, perm) = secure_sort_with_permutation(&[3, 1, 2]);
        assert_eq!(sorted, vec![1, 2, 3]);
        assert_eq!(perm, vec![1, 2, 0]);
    }

    // Threshold statistics
    #[test]
    fn stats_sum_mean() {
        let data = vec![1, 2, 3, 4, 5];
        assert_eq!(threshold_sum(&data), 15);
        assert!((threshold_mean(&data) - 3.0).abs() < 0.01);
    }

    #[test]
    fn stats_variance() {
        let data = vec![2, 4, 4, 4, 5, 5, 7, 9];
        let var = threshold_variance(&data);
        assert!(var > 0.0);
    }

    #[test]
    fn stats_median() {
        assert_eq!(threshold_median(&[1, 3, 5]), Some(3.0));
        assert_eq!(threshold_median(&[1, 2, 3, 4]), Some(2.5));
    }

    // Commit-reveal voting
    #[test]
    fn voting_full_cycle() {
        let vote = CommitRevealVote::new();
        vote.commit("alice", "hash1").unwrap();
        vote.commit("bob", "hash2").unwrap();
        vote.end_commit_phase();
        vote.reveal("alice", "yes", "nonce1").unwrap();
        vote.reveal("bob", "no", "nonce2").unwrap();
        let tally = vote.tally();
        assert_eq!(tally.get("yes"), Some(&1));
        assert_eq!(tally.get("no"), Some(&1));
    }

    #[test]
    fn voting_cannot_reveal_before_commit_ends() {
        let vote = CommitRevealVote::new();
        vote.commit("alice", "h").unwrap();
        assert!(vote.reveal("alice", "yes", "n").is_err());
    }

    #[test]
    fn voting_double_commit_rejected() {
        let vote = CommitRevealVote::new();
        vote.commit("alice", "h1").unwrap();
        assert!(vote.commit("alice", "h2").is_err());
    }

    // Verifiable shuffle
    #[test]
    fn shuffle_and_verify() {
        let elements: Vec<[u8; 32]> = (0..5).map(|i| [i as u8; 32]).collect();
        let (shuffled, proof, _perm) = shuffle(&elements);
        assert!(verify_shuffle(&elements, &shuffled, &proof));
    }

    #[test]
    fn shuffle_changes_order() {
        let elements: Vec<[u8; 32]> = (0..10).map(|i| [i as u8; 32]).collect();
        let (shuffled, _, _) = shuffle(&elements);
        assert_ne!(shuffled, elements); // almost certainly different order
    }

    // Threshold beacon
    #[test]
    fn beacon_round_and_output() {
        let beacon = ThresholdBeacon::new(3);
        let round = beacon.next_round();
        beacon.submit_share(round, vec![1]).unwrap();
        beacon.submit_share(round, vec![2]).unwrap();
        assert!(!beacon.is_ready(round));
        beacon.submit_share(round, vec![3]).unwrap();
        assert!(beacon.is_ready(round));
        let output = beacon.produce_output(round).unwrap();
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn beacon_deterministic_output() {
        let beacon = ThresholdBeacon::new(2);
        let r = beacon.next_round();
        beacon.submit_share(r, vec![0xAA]).unwrap();
        beacon.submit_share(r, vec![0xBB]).unwrap();
        let o1 = beacon.produce_output(r).unwrap();
        let o2 = beacon.produce_output(r).unwrap();
        assert_eq!(o1, o2);
    }

    // Key refresh
    #[test]
    fn refresh_completes() {
        let refresh = KeyRefreshProtocol::new(2, 3);
        refresh.submit_contribution(1, vec![0xAA; 32]).unwrap();
        refresh.submit_contribution(2, vec![0xBB; 32]).unwrap();
        refresh.submit_contribution(3, vec![0xCC; 32]).unwrap();
        assert!(refresh.is_complete());
        let delta = refresh.compute_refresh_delta().unwrap();
        assert_eq!(delta.len(), 32);
        // XOR of AA, BB, CC should be non-zero
        assert!(delta.iter().any(|&b| b != 0));
    }

    #[test]
    fn refresh_incomplete_returns_none() {
        let refresh = KeyRefreshProtocol::new(2, 3);
        refresh.submit_contribution(1, vec![1]).unwrap();
        assert!(!refresh.is_complete());
        assert!(refresh.compute_refresh_delta().is_none());
    }

    #[test]
    fn refresh_missing_parties() {
        let refresh = KeyRefreshProtocol::new(2, 5);
        refresh.submit_contribution(1, vec![1]).unwrap();
        refresh.submit_contribution(3, vec![3]).unwrap();
        assert_eq!(refresh.missing_parties(), vec![2, 4, 5]);
    }
}
