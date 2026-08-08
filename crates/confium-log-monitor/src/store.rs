//! Persistent state for the monitor.
//!
//! Stores the last-seen tree head so we can detect tree-size
//! regression and verify consistency between cycles. Backed by
//! sled for simplicity; production deployments might use Postgres
//! or LevelDB.

use std::path::Path;

use anyhow::Result;
use sled::Db;

use crate::client::TreeHead;

pub struct StateStore {
    db: Db,
}

impl StateStore {
    pub fn open(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)?;
        let db = sled::open(path)?;
        Ok(StateStore { db })
    }

    pub fn last_tree_size(&self) -> Result<u64> {
        Ok(self
            .db
            .get("last_size")?
            .map(|v| {
                let mut arr = [0u8; 8];
                if v.len() == 8 {
                    arr.copy_from_slice(&v);
                }
                u64::from_be_bytes(arr)
            })
            .unwrap_or(0))
    }

    pub fn last_root(&self) -> Result<String> {
        Ok(self
            .db
            .get("last_root")?
            .map(|v| String::from_utf8(v.to_vec()).unwrap_or_default())
            .unwrap_or_default())
    }

    pub fn put_head(&self, head: &TreeHead) -> Result<()> {
        self.db
            .insert("last_size", head.tree_size.to_be_bytes().as_slice())?;
        self.db.insert("last_root", head.root.as_bytes())?;
        self.db
            .insert("last_timestamp", head.timestamp.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }
}
