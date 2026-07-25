# 36 — Transparency log and OpenTimestamps infrastructure

## Purpose

Prove every issued artifact was publicly logged. Catches compelled
issuance, rogue issuance, retroactive forgery.

Simpler than CT-style gossip. No academic witness network required.
Append-only Merkle tree with Bitcoin-anchored roots.

## Architecture

```
Deployment operates its own append-only Merkle tree of all issued
artifacts (certs, signatures, revocations, re-sharing events)
   ↓ tree root periodically committed to Bitcoin via OTS
   ↓ tree published on deployment's website + IPFS mirror
Verifier (offline): downloads Merkle branch + OTS proof
   → proves "this artifact was in the tree as of block N"
   → missing artifacts detectable via tree root comparison
```

## Components

### 1. Append-only Merkle tree (`confium-transparency`)

```rust
pub struct MerkleTree {
    entries: Vec<MerkleEntry>,
    storage: Box<dyn TransparencyStorage>,
}

pub struct MerkleEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub artifact_hash: [u8; 32],
    pub artifact_type: ArtifactType,
    pub metadata: serde_json::Value,
}

pub enum ArtifactType {
    CertificateIssuance,
    CertificateRevocation,
    ThresholdSignature,
    ThresholdEncryption,
    DirectorRotation,
    QuorumPolicy,
}

impl MerkleTree {
    pub fn append(&mut self, entry: MerkleEntry) -> Result<u64>;
    pub fn root(&self) -> Result<[u8; 32]>;
    pub fn inclusion_proof(&self, sequence: u64) -> Result<MerkleProof>;
    pub fn verify_inclusion(entry: &MerkleEntry, proof: &MerkleProof, root: [u8; 32]) -> Result<()>;
    pub fn consistency_proof(&self, from_root: [u8; 32]) -> Result<ConsistencyProof>;
    pub fn verify_consistency(from_root: [u8; 32], to_root: [u8; 32], proof: &ConsistencyProof) -> Result<()>;
}
```

RFC 6962-style inclusion and consistency proofs. Standard,
well-analyzed.

### 2. OTS anchoring (`confium-ots`)

```rust
pub struct OtsClient {
    calendar_servers: Vec<Url>,
}

impl OtsClient {
    pub async fn stamp(&self, hash: [u8; 32]) -> Result<OtsProof>;
    pub fn verify(proof: &OtsProof, hash: [u8; 32], bitcoin_height: u32) -> Result<OtsVerification>;
}
```

Periodic anchor: every N entries, compute tree root, OTS-stamp it,
publish (root, OTS proof, sequence range) in deployment transparency
log.

### 3. Publication

Tree published on deployment website. Mirror on IPFS for
tamper-resistance (BIML cannot retroactively rewrite history without
breaking IPNS).

JSON API for verifiers:
- `GET /log/entries?seq=N` → entry at sequence N
- `GET /log/root?leq_seq=N` → tree root as of sequence N
- `GET /log/proof/inclusion?seq=N` → Merkle branch
- `GET /log/proof/consistency?from=M&to=N` → consistency proof
- `GET /log/ots/root?seq=N` → OTS proof for root at sequence N

## Why this works without a witness network

OTS provides time-of-existence proof. The Merkle tree provides
inclusion proof. Bitcoin anchoring prevents retroactive rewriting.

Three properties combined:
1. **Time**: OTS proves root existed at Bitcoin block N
2. **Inclusion**: Merkle branch proves artifact in tree at root
3. **Public log**: tree published; missing artifacts detectable

A malicious CA cannot silently issue a fraudulent cert because:
- If they DON'T log it, verifier can't validate (cert not in tree)
- If they DO log it, public sees the issuance
- If they try to rewrite history, Bitcoin anchor catches it

## Optional: CoSi enhancement

Future work. CoSi-style witness co-signatures from NIST + BIPM +
independent academic institutions, providing offline-verifiable
transparency (witness signatures travel with the cert itself, no
log lookup required).

Useful for customs officers at borders (offline verification). Not
required for core deployment.

## Crate scope

### `confium-transparency` (P1)

- Merkle tree implementation
- Storage backends: SQLite (default), PostgreSQL (large deployments)
- HTTP API server (axum)
- Inclusion and consistency proofs (RFC 6962)
- Periodic root anchoring hook

### `confium-ots` (P1)

- OpenTimestamps client using public calendar servers
- Local calendar server for offline / private deployments
- Bitcoin Core RPC for direct anchoring (optional)
- Proof verification

## Operational

- Tree storage grows ~1KB per entry → 1M entries ~1GB (SQLite)
- OTS stamp cost: free (public calendars), or Bitcoin transaction
  fee (~$1) for direct anchoring
- Anchor cadence: every 1000 entries or every hour, whichever first

## References

- `TODO.roadmap/26-confium-framework.md`
- [RFC 6962 Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)
- [OpenTimestamps](https://opentimestamps.org/)
