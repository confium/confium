//! Session write-ahead log — crash recovery via append-only log.
//!
//! Every session state transition is appended to a WAL before being
//! applied to the in-memory state. On crash, the WAL is replayed to
//! reconstruct the session state up to the last persisted transition.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// A single WAL entry recording a state transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalEntry {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Session ID.
    pub session_id: String,
    /// The state transition.
    pub transition: StateTransition,
    /// When the entry was recorded.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// A session state transition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StateTransition {
    /// Session created.
    Created {
        quorum_id: String,
        scheme: String,
        threshold: u32,
    },
    /// Commitment received from signer.
    CommitmentReceived { signer_id: String },
    /// Share received from signer.
    ShareReceived { signer_id: String },
    /// Session completed (signature aggregated).
    Completed,
    /// Session expired.
    Expired,
    /// Session aborted.
    Aborted { reason: String },
}

/// Append-only write-ahead log backed by a file.
pub struct SessionWal {
    path: PathBuf,
    next_seq: Mutex<u64>,
}

impl SessionWal {
    /// Create or open a WAL at the given path.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let next_seq = if path.exists() {
            let max_seq = Self::read_all_from_path(&path)?
                .into_iter()
                .map(|e| e.seq)
                .max()
                .unwrap_or(0);
            max_seq + 1
        } else {
            1
        };
        Ok(Self {
            path,
            next_seq: Mutex::new(next_seq),
        })
    }

    /// Append a transition to the WAL. Returns the assigned sequence number.
    pub fn append(&self, session_id: &str, transition: StateTransition) -> std::io::Result<u64> {
        let seq = {
            let mut next = self.next_seq.lock().unwrap();
            let current = *next;
            *next += 1;
            current
        };
        let entry = WalEntry {
            seq,
            session_id: session_id.into(),
            transition,
            timestamp: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{json}")?;
        file.sync_data()?;
        Ok(seq)
    }

    /// Read all entries from the WAL (for replay).
    pub fn read_all(&self) -> std::io::Result<Vec<WalEntry>> {
        Self::read_all_from_path(&self.path)
    }

    /// Read all entries from a WAL file path.
    fn read_all_from_path(path: &Path) -> std::io::Result<Vec<WalEntry>> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = OpenOptions::new().read(true).open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<WalEntry>(&line) {
                Ok(entry) => entries.push(entry),
                Err(_) => continue,
            }
        }
        Ok(entries)
    }

    /// Truncate (clear) the WAL. Called after a successful checkpoint.
    pub fn truncate(&self) -> std::io::Result<()> {
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path)?;
        let mut next = self.next_seq.lock().unwrap();
        *next = 1;
        Ok(())
    }

    /// Current next-sequence number.
    pub fn next_seq(&self) -> u64 {
        *self.next_seq.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_read() {
        let tmp = tempfile::tempdir().unwrap();
        let wal_path = tmp.path().join("wal.jsonl");
        let wal = SessionWal::open(&wal_path).unwrap();
        wal.append(
            "s1",
            StateTransition::Created {
                quorum_id: "q".into(),
                scheme: "CMP20".into(),
                threshold: 2,
            },
        )
        .unwrap();
        wal.append(
            "s1",
            StateTransition::CommitmentReceived {
                signer_id: "alice".into(),
            },
        )
        .unwrap();
        wal.append("s1", StateTransition::Completed).unwrap();

        let entries = wal.read_all().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].seq, 1);
        assert_eq!(entries[1].seq, 2);
        assert_eq!(entries[2].seq, 3);
    }

    #[test]
    fn sequence_numbers_monotonic() {
        let tmp = tempfile::tempdir().unwrap();
        let wal = SessionWal::open(tmp.path().join("wal.jsonl")).unwrap();
        let s1 = wal.append("s1", StateTransition::Completed).unwrap();
        let s2 = wal.append("s1", StateTransition::Expired).unwrap();
        let s3 = wal.append("s2", StateTransition::Completed).unwrap();
        assert!(s1 < s2);
        assert!(s2 < s3);
    }

    #[test]
    fn reopen_continues_sequence() {
        let tmp = tempfile::tempdir().unwrap();
        let wal_path = tmp.path().join("wal.jsonl");
        {
            let wal = SessionWal::open(&wal_path).unwrap();
            wal.append("s1", StateTransition::Completed).unwrap();
            wal.append("s1", StateTransition::Expired).unwrap();
        }
        {
            let wal = SessionWal::open(&wal_path).unwrap();
            assert_eq!(wal.next_seq(), 3);
            let seq = wal.append("s2", StateTransition::Completed).unwrap();
            assert_eq!(seq, 3);
        }
    }

    #[test]
    fn truncate_clears_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let wal = SessionWal::open(tmp.path().join("wal.jsonl")).unwrap();
        wal.append("s1", StateTransition::Completed).unwrap();
        wal.truncate().unwrap();
        assert_eq!(wal.read_all().unwrap().len(), 0);
        assert_eq!(wal.next_seq(), 1);
    }

    #[test]
    fn empty_wal_returns_empty_vec() {
        let tmp = tempfile::tempdir().unwrap();
        let wal = SessionWal::open(tmp.path().join("nonexistent.jsonl")).unwrap();
        assert!(wal.read_all().unwrap().is_empty());
    }

    #[test]
    fn all_transition_types_serialize() {
        let transitions = vec![
            StateTransition::Created {
                quorum_id: "q".into(),
                scheme: "CMP20".into(),
                threshold: 2,
            },
            StateTransition::CommitmentReceived {
                signer_id: "a".into(),
            },
            StateTransition::ShareReceived {
                signer_id: "a".into(),
            },
            StateTransition::Completed,
            StateTransition::Expired,
            StateTransition::Aborted {
                reason: "test".into(),
            },
        ];
        for t in &transitions {
            let json = serde_json::to_string(t).unwrap();
            let recovered: StateTransition = serde_json::from_str(&json).unwrap();
            assert_eq!(t, &recovered);
        }
    }

    #[test]
    fn corrupt_lines_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("wal.jsonl");
        std::fs::write(&path, "not json\n{\"seq\":1,\"session_id\":\"s\",\"transition\":{\"created\":{\"quorum_id\":\"q\",\"scheme\":\"CMP20\",\"threshold\":2}},\"timestamp\":\"2026-01-01T00:00:00Z\"}\n").unwrap();
        let wal = SessionWal::open(&path).unwrap();
        let entries = wal.read_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].session_id, "s");
    }
}
