-- Schema for the per-region D1 database. D1 is SQLite under the hood;
-- the same schema works for local dev and edge production.
--
-- Apply via:
--   npx wrangler d1 execute confium-log --file=./schema.sql
--   npx wrangler d1 execute confium-log --remote --file=./schema.sql

-- Regional append log. Sequence is region-prefixed (e.g. "us-east-42")
-- because regional writes happen before the global merger assigns a
-- global sequence.
CREATE TABLE IF NOT EXISTS regional_entries (
    regional_sequence  TEXT PRIMARY KEY,    -- e.g. "us-east-000123"
    region             TEXT NOT NULL,
    local_sequence     INTEGER NOT NULL,
    artifact_type      TEXT NOT NULL,
    artifact_hash      TEXT NOT NULL,
    timestamp          TEXT NOT NULL,
    activation_time    TEXT NOT NULL,        -- timestamp + activation delay
    issuer_dn          TEXT,
    subject_dn         TEXT,
    fingerprint_sha256 TEXT,
    valid_from         TEXT,
    valid_to           TEXT,
    -- NULL until the global merger assigns one.
    global_sequence    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_regional_fp
    ON regional_entries(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_regional_issuer
    ON regional_entries(issuer_dn);
CREATE INDEX IF NOT EXISTS idx_regional_pending
    ON regional_entries(global_sequence) WHERE global_sequence IS NULL;

-- Global tree heads, populated by the merger Durable Object.
CREATE TABLE IF NOT EXISTS global_tree_heads (
    tree_size     INTEGER PRIMARY KEY,
    root_hash     TEXT NOT NULL,
    timestamp     TEXT NOT NULL,
    ots_proof     BLOB,
    bitcoin_height INTEGER
);

-- Witness countersignatures.
CREATE TABLE IF NOT EXISTS witness_sigs (
    tree_size   INTEGER NOT NULL,
    witness_id  TEXT NOT NULL,
    signature   BLOB NOT NULL,
    timestamp   TEXT NOT NULL,
    PRIMARY KEY (tree_size, witness_id)
);
