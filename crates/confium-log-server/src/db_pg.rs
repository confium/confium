//! PostgreSQL backend for the log server.
//!
//! Enabled via the `postgres` Cargo feature. Production deployments
//! use this instead of the default SQLite backend. The schema is
//! identical; only the connection type and SQL dialect differ.
//!
//! ## Why PostgreSQL, not "just use SQLite"?
//!
//! SQLite is single-node, single-disk. For real `log.confium.org`:
//!
//! - **Replication**: PostgreSQL streams writes to read replicas
//!   in other regions via logical replication. SQLite can't.
//! - **Concurrent writers**: PostgreSQL handles thousands of
//!   concurrent appends via MVCC. SQLite serializes.
//! - **Backups**: PostgreSQL has point-in-time recovery, streaming
//!   backups, managed-service integration (RDS / Aurora / Cloud SQL).
//!   SQLite backups are "copy the file" — fine for dev, painful at
//!   scale.
//! - **Operational tooling**: PostgreSQL has decades of monitoring,
//!   alerting, query analysis tooling. SQLite has almost none.
//!
//! See `docs/use-cases/public-log-production-architecture.mdx` for
//! the full tiered-deployment design.

#![cfg(feature = "postgres")]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio_postgres::Client;

use crate::db::Entry;

/// PostgreSQL-backed storage. Async because PostgreSQL I/O is
/// naturally async (unlike SQLite's blocking calls).
pub struct PostgresBackend {
    client: Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgConfig {
    /// Connection string: `postgresql://user:pass@host:5432/db`
    pub connection_string: String,
    /// Maximum connections in the pool.
    pub max_connections: u32,
}

impl PostgresBackend {
    /// Connect to PostgreSQL and run schema migrations if needed.
    pub async fn connect(cfg: &PgConfig) -> Result<Self> {
        let (client, connection) =
            tokio_postgres::connect(&cfg.connection_string, tokio_postgres::NoTls)
                .await
                .context("connecting to PostgreSQL")?;

        // The connection object drives the async I/O; spawn it.
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::error!(?e, "postgres connection error");
            }
        });

        let backend = PostgresBackend { client };
        backend.init_schema().await?;
        Ok(backend)
    }

    /// Create the schema if missing. Same shape as the SQLite
    /// schema, with PostgreSQL-specific types.
    pub async fn init_schema(&self) -> Result<()> {
        self.client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS entries (
                    sequence           BIGSERIAL PRIMARY KEY,
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

                CREATE TABLE IF NOT EXISTS ots_proofs (
                    tree_size        BIGINT PRIMARY KEY,
                    root_hash        TEXT NOT NULL,
                    ots_proof        BYTEA NOT NULL,
                    bitcoin_height   BIGINT,
                    anchor_time      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS witness_sigs (
                    tree_size   BIGINT NOT NULL,
                    root_hash   TEXT NOT NULL,
                    witness_id  TEXT NOT NULL,
                    signature   BYTEA NOT NULL,
                    timestamp   TEXT NOT NULL,
                    PRIMARY KEY (tree_size, witness_id)
                );",
            )
            .await?;
        Ok(())
    }

    pub async fn append(&self, entry: &Entry) -> Result<u64> {
        let rows = self
            .client
            .query_one(
                "INSERT INTO entries
                    (artifact_type, artifact_hash, timestamp,
                     issuer_dn, subject_dn, fingerprint_sha256,
                     valid_from, valid_to)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 RETURNING sequence",
                &[
                    &entry.artifact_type,
                    &entry.artifact_hash,
                    &entry.timestamp,
                    &entry.issuer_distinguished_name,
                    &entry.subject_distinguished_name,
                    &entry.fingerprint_sha256,
                    &entry.valid_from,
                    &entry.valid_to,
                ],
            )
            .await?;
        let seq: i64 = rows.get(0);
        // Postgres SERIAL ids are 1-based; entry sequences are 0-based
        // to match the Merkle leaf index used by the proof endpoints.
        Ok((seq - 1) as u64)
    }

    pub async fn entry_count(&self) -> Result<u64> {
        let row = self
            .client
            .query_one("SELECT COUNT(*) FROM entries", &[])
            .await?;
        let n: i64 = row.get(0);
        Ok(n as u64)
    }

    pub async fn entries_by_fingerprint(&self, fingerprint_hex: &str) -> Result<Vec<Entry>> {
        let rows = self
            .client
            .query(
                "SELECT sequence, artifact_type, artifact_hash, timestamp,
                        issuer_dn, subject_dn, fingerprint_sha256,
                        valid_from, valid_to
                 FROM entries WHERE fingerprint_sha256 = $1
                 ORDER BY sequence ASC",
                &[&fingerprint_hex],
            )
            .await?;
        rows.into_iter().map(pg_row_to_entry).collect()
    }

    pub async fn entries_by_issuer(&self, issuer_dn: &str, limit: usize) -> Result<Vec<Entry>> {
        let rows = self
            .client
            .query(
                "SELECT sequence, artifact_type, artifact_hash, timestamp,
                        issuer_dn, subject_dn, fingerprint_sha256,
                        valid_from, valid_to
                 FROM entries WHERE issuer_dn = $1
                 ORDER BY sequence DESC
                 LIMIT $2",
                &[&issuer_dn, &(limit as i64)],
            )
            .await?;
        rows.into_iter().map(pg_row_to_entry).collect()
    }

    pub async fn all_leaf_hashes(&self) -> Result<Vec<[u8; 32]>> {
        let rows = self
            .client
            .query(
                "SELECT artifact_hash FROM entries ORDER BY sequence ASC",
                &[],
            )
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let h: String = row.get(0);
            let bytes = hex::decode(&h).context("hash hex decode")?;
            if bytes.len() != 32 {
                anyhow::bail!("hash must be 32 bytes, got {}", bytes.len());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            out.push(arr);
        }
        Ok(out)
    }

    pub async fn store_ots_proof(
        &self,
        tree_size: u64,
        root_hash: &[u8; 32],
        ots_proof: &[u8],
        bitcoin_height: Option<u64>,
    ) -> Result<()> {
        self.client
            .execute(
                "INSERT INTO ots_proofs
                    (tree_size, root_hash, ots_proof, bitcoin_height, anchor_time)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (tree_size) DO UPDATE SET
                    root_hash = EXCLUDED.root_hash,
                    ots_proof = EXCLUDED.ots_proof,
                    bitcoin_height = EXCLUDED.bitcoin_height,
                    anchor_time = EXCLUDED.anchor_time",
                &[
                    &(tree_size as i64),
                    &hex::encode(root_hash),
                    &ots_proof,
                    &bitcoin_height.map(|h| h as i64),
                    &chrono::Utc::now().to_rfc3339(),
                ],
            )
            .await?;
        Ok(())
    }

    pub async fn get_ots_proof(
        &self,
        tree_size: u64,
    ) -> Result<Option<(Vec<u8>, Option<u64>, String)>> {
        let row = self
            .client
            .query_opt(
                "SELECT ots_proof, bitcoin_height, anchor_time
                 FROM ots_proofs WHERE tree_size = $1",
                &[&(tree_size as i64)],
            )
            .await?;
        match row {
            Some(row) => {
                let proof: Vec<u8> = row.get(0);
                let bh: Option<i64> = row.get(1);
                let at: String = row.get(2);
                Ok(Some((proof, bh.map(|h| h as u64), at)))
            }
            None => Ok(None),
        }
    }

    pub async fn store_witness_sig(
        &self,
        tree_size: u64,
        root_hash: &[u8; 32],
        witness_id: &str,
        signature: &[u8],
    ) -> Result<()> {
        self.client
            .execute(
                "INSERT INTO witness_sigs
                    (tree_size, root_hash, witness_id, signature, timestamp)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (tree_size, witness_id) DO UPDATE SET
                    root_hash = EXCLUDED.root_hash,
                    signature = EXCLUDED.signature,
                    timestamp = EXCLUDED.timestamp",
                &[
                    &(tree_size as i64),
                    &hex::encode(root_hash),
                    &witness_id,
                    &signature,
                    &chrono::Utc::now().to_rfc3339(),
                ],
            )
            .await?;
        Ok(())
    }
}

fn pg_row_to_entry(row: tokio_postgres::Row) -> Result<Entry> {
    Ok(Entry {
        sequence: row.get::<_, i64>(0) as u64,
        artifact_type: row.get(1),
        artifact_hash: row.get(2),
        timestamp: row.get(3),
        issuer_distinguished_name: row.get(4),
        subject_distinguished_name: row.get(5),
        fingerprint_sha256: row.get(6),
        valid_from: row.get(7),
        valid_to: row.get(8),
    })
}
