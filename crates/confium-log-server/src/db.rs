//! SQLite-backed append-only log storage.
//!
//! Schema:
//!
//! - `entries` — primary log table. One row per append. Primary key
//!   is `sequence` (auto-incremented). The Merkle tree is
//!   materialized in `tree_nodes` for O(log N) incremental
//!   recomputation.
//! - `tree_nodes` — cached Merkle tree nodes, indexed by
//!   `(level, index)`. The root is at the highest level for the
//!   current size.
//! - `cert_entries` — join table mapping cert fingerprints to
//!   log entries. Carries parsed metadata (issuer, subject,
//!   validity window) so the API can serve cert-specific queries
//!   without re-parsing.
//! - `ots_proofs` — Bitcoin OTS proofs keyed by tree head sequence.
//! - `witness_sigs` — witness countersignatures keyed by tree head
//!   sequence + witness ID.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

/// Wrapper around the SQLite connection. Cheaply clonable because
/// `Connection` is wrapped in a `Mutex` inside an `Arc`.
#[derive(Clone)]
pub struct Database {
    conn: Arc<parking_lot::Mutex<Connection>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub sequence: u64,
    pub artifact_type: String,
    pub artifact_hash: String, // hex
    pub timestamp: String,     // RFC3339
    pub issuer_distinguished_name: Option<String>,
    pub subject_distinguished_name: Option<String>,
    pub fingerprint_sha256: Option<String>, // hex
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening database at {}", path.display()))?;
        // WAL mode for better concurrency on read-heavy workloads.
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )?;
        Ok(Database {
            conn: Arc::new(parking_lot::Mutex::new(conn)),
        })
    }

    pub fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS entries (
                sequence           INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_type      TEXT NOT NULL,
                artifact_hash      TEXT NOT NULL,
                timestamp          TEXT NOT NULL,
                issuer_dn          TEXT,
                subject_dn         TEXT,
                fingerprint_sha256 TEXT,
                valid_from         TEXT,
                valid_to           TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_entries_fingerprint
                ON entries(fingerprint_sha256);
            CREATE INDEX IF NOT EXISTS idx_entries_issuer
                ON entries(issuer_dn);
            CREATE INDEX IF NOT EXISTS idx_entries_type_ts
                ON entries(artifact_type, timestamp);

            CREATE TABLE IF NOT EXISTS tree_nodes (
                level INTEGER NOT NULL,
                idx   INTEGER NOT NULL,
                hash  TEXT NOT NULL,
                PRIMARY KEY (level, idx)
            );

            CREATE TABLE IF NOT EXISTS tree_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ots_proofs (
                tree_size    INTEGER PRIMARY KEY,
                root_hash    TEXT NOT NULL,
                ots_proof    BLOB NOT NULL,
                bitcoin_height INTEGER,
                anchor_time  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS witness_sigs (
                tree_size   INTEGER NOT NULL,
                root_hash   TEXT NOT NULL,
                witness_id  TEXT NOT NULL,
                signature   BLOB NOT NULL,
                timestamp   TEXT NOT NULL,
                PRIMARY KEY (tree_size, witness_id)
            );",
        )?;
        Ok(())
    }

    pub fn append(&self, entry: &Entry) -> Result<u64> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO entries
                (artifact_type, artifact_hash, timestamp,
                 issuer_dn, subject_dn, fingerprint_sha256,
                 valid_from, valid_to)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                entry.artifact_type,
                entry.artifact_hash,
                entry.timestamp,
                entry.issuer_distinguished_name,
                entry.subject_distinguished_name,
                entry.fingerprint_sha256,
                entry.valid_from,
                entry.valid_to,
            ],
        )?;
        Ok(conn.last_insert_rowid() as u64)
    }

    pub fn entry_at(&self, sequence: u64) -> Result<Option<Entry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT sequence, artifact_type, artifact_hash, timestamp,
                    issuer_dn, subject_dn, fingerprint_sha256,
                    valid_from, valid_to
             FROM entries WHERE sequence = ?1",
        )?;
        let rows = stmt.query_row(params![sequence as i64], |row| {
            Ok(Entry {
                sequence: row.get::<_, i64>(0)? as u64,
                artifact_type: row.get(1)?,
                artifact_hash: row.get(2)?,
                timestamp: row.get(3)?,
                issuer_distinguished_name: row.get(4)?,
                subject_distinguished_name: row.get(5)?,
                fingerprint_sha256: row.get(6)?,
                valid_from: row.get(7)?,
                valid_to: row.get(8)?,
            })
        });
        match rows {
            Ok(e) => Ok(Some(e)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn entry_count(&self) -> Result<u64> {
        let conn = self.conn.lock();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))?;
        Ok(n as u64)
    }

    pub fn entries_by_fingerprint(&self, fingerprint_hex: &str) -> Result<Vec<Entry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT sequence, artifact_type, artifact_hash, timestamp,
                    issuer_dn, subject_dn, fingerprint_sha256,
                    valid_from, valid_to
             FROM entries WHERE fingerprint_sha256 = ?1
             ORDER BY sequence ASC",
        )?;
        let rows = stmt.query_map(params![fingerprint_hex], |row| {
            Ok(Entry {
                sequence: row.get::<_, i64>(0)? as u64,
                artifact_type: row.get(1)?,
                artifact_hash: row.get(2)?,
                timestamp: row.get(3)?,
                issuer_distinguished_name: row.get(4)?,
                subject_distinguished_name: row.get(5)?,
                fingerprint_sha256: row.get(6)?,
                valid_from: row.get(7)?,
                valid_to: row.get(8)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn entries_by_issuer(&self, issuer_dn: &str, limit: usize) -> Result<Vec<Entry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT sequence, artifact_type, artifact_hash, timestamp,
                    issuer_dn, subject_dn, fingerprint_sha256,
                    valid_from, valid_to
             FROM entries WHERE issuer_dn = ?1
             ORDER BY sequence DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![issuer_dn, limit as i64], |row| {
            Ok(Entry {
                sequence: row.get::<_, i64>(0)? as u64,
                artifact_type: row.get(1)?,
                artifact_hash: row.get(2)?,
                timestamp: row.get(3)?,
                issuer_distinguished_name: row.get(4)?,
                subject_distinguished_name: row.get(5)?,
                fingerprint_sha256: row.get(6)?,
                valid_from: row.get(7)?,
                valid_to: row.get(8)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Read every leaf hash in sequence order. Used to rebuild the
    /// Merkle tree on startup.
    pub fn all_leaf_hashes(&self) -> Result<Vec<[u8; 32]>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT artifact_hash FROM entries ORDER BY sequence ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let h: String = row.get(0)?;
            Ok(h)
        })?;
        let mut out = Vec::new();
        for row in rows {
            let h = row?;
            let bytes = hex::decode(&h).map_err(|e| anyhow!("hash hex decode: {e}"))?;
            if bytes.len() != 32 {
                return Err(anyhow!("hash must be 32 bytes, got {}", bytes.len()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            out.push(arr);
        }
        Ok(out)
    }

    pub fn store_ots_proof(
        &self,
        tree_size: u64,
        root_hash: &[u8; 32],
        ots_proof: &[u8],
        bitcoin_height: Option<u64>,
    ) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO ots_proofs
                (tree_size, root_hash, ots_proof, bitcoin_height, anchor_time)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                tree_size as i64,
                hex::encode(root_hash),
                ots_proof,
                bitcoin_height.map(|h| h as i64),
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_ots_proof(&self, tree_size: u64) -> Result<Option<(Vec<u8>, Option<u64>, String)>> {
        let conn = self.conn.lock();
        let row = conn.query_row(
            "SELECT ots_proof, bitcoin_height, anchor_time
             FROM ots_proofs WHERE tree_size = ?1",
            params![tree_size as i64],
            |row| {
                let proof: Vec<u8> = row.get(0)?;
                let bh: Option<i64> = row.get(1)?;
                let at: String = row.get(2)?;
                Ok((proof, bh.map(|h| h as u64), at))
            },
        );
        match row {
            Ok(t) => Ok(Some(t)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn store_witness_sig(
        &self,
        tree_size: u64,
        root_hash: &[u8; 32],
        witness_id: &str,
        signature: &[u8],
    ) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO witness_sigs
                (tree_size, root_hash, witness_id, signature, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                tree_size as i64,
                hex::encode(root_hash),
                witness_id,
                signature,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn witness_sigs_for_size(
        &self,
        tree_size: u64,
    ) -> Result<Vec<(String, Vec<u8>, String)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT witness_id, signature, timestamp
             FROM witness_sigs WHERE tree_size = ?1
             ORDER BY witness_id ASC",
        )?;
        let rows = stmt.query_map(params![tree_size as i64], |row| {
            let wid: String = row.get(0)?;
            let sig: Vec<u8> = row.get(1)?;
            let ts: String = row.get(2)?;
            Ok((wid, sig, ts))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}
