//! HTTP client for the transparency log server.

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct TreeHead {
    pub tree_size: u64,
    pub root: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub new_root: String,
    pub proof: Vec<String>,
}

pub struct LogClient {
    base_url: String,
    http: reqwest::Client,
}

impl LogClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
        }
    }

    pub async fn fetch_head(&self) -> Result<TreeHead> {
        let url = format!("{}/v1/head", self.base_url);
        let head = self.http.get(&url).send().await?.error_for_status()?
            .json::<TreeHead>().await
            .context("decoding /v1/head response")?;
        Ok(head)
    }

    pub async fn fetch_consistency(&self, old_size: u64) -> Result<ConsistencyProof> {
        let url = format!("{}/v1/consistency/{}", self.base_url, old_size);
        let proof = self.http.get(&url).send().await?.error_for_status()?
            .json::<ConsistencyProof>().await
            .context("decoding /v1/consistency response")?;
        Ok(proof)
    }
}
