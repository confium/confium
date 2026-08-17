//! Chain discovery strategies (SIGNATIF §7, §16).
//!
//! A signature wrapper shall carry or reference the full delegation
//! chain to a root anchor under one of three strategies:
//!
//! - [`ChainDelivery::Embedded`] — the full chain inline, fully
//!   offline-capable;
//! - [`ChainDelivery::LogReference`] — transparency-log sequence
//!   pointers, resolved on first encounter (then cacheable);
//! - [`ChainDelivery::Hybrid`] — the immediate chain inline plus log
//!   references for freshness.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{SignatifError, SignatifResult};

/// A pointer to a delegation credential stored in a transparency log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRef {
    /// Name of the log holding the entry.
    pub log: String,
    /// Sequence number of the certificate entry in that log.
    pub sequence: u64,
}

/// How an artifact carries its delegation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case")]
pub enum ChainDelivery {
    /// The full chain of DER certificates inline (offline-capable).
    Embedded {
        /// DER certificates from signer-adjacent to root-adjacent.
        chain: Vec<Vec<u8>>,
    },
    /// Transparency-log sequence pointers for every chain credential.
    LogReference {
        /// One pointer per delegation credential on the chain.
        refs: Vec<LogRef>,
    },
    /// Immediate chain inline, log references for freshness checks.
    Hybrid {
        /// The immediate (signer-adjacent) credentials inline.
        immediate: Vec<Vec<u8>>,
        /// Pointers for the remaining chain and freshness verification.
        refs: Vec<LogRef>,
    },
}

impl ChainDelivery {
    /// Whether the strategy alone can reconstruct the full chain with
    /// no network access.
    pub fn is_offline_capable(&self) -> bool {
        matches!(self, ChainDelivery::Embedded { .. })
    }
}

/// Resolves log references into certificate bytes. Production
/// implementations bind to a transparency log client (the confium
/// log-server `/v1/certificates` API); tests bind to in-memory fakes.
pub trait LogResolver {
    /// Fetch the certificate bytes for a log reference.
    ///
    /// # Errors
    ///
    /// Implementations return [`SignatifError::Encoding`] for misses.
    fn resolve(&mut self, r: &LogRef) -> SignatifResult<Vec<u8>>;
}

/// A caching resolver decorator: first-encounter fetches go to the
/// inner resolver, subsequent ones hit the cache — the §16 caching
/// requirement for connected delivery.
#[derive(Debug, Default)]
pub struct CachingResolver<R> {
    inner: R,
    cache: HashMap<(String, u64), Vec<u8>>,
}

impl<R: LogResolver> LogResolver for CachingResolver<R> {
    fn resolve(&mut self, r: &LogRef) -> SignatifResult<Vec<u8>> {
        CachingResolver::resolve(self, r)
    }
}

impl<R: LogResolver> CachingResolver<R> {
    /// Wrap an inner resolver with a cache.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            cache: HashMap::new(),
        }
    }

    /// Resolve with caching.
    ///
    /// # Errors
    ///
    /// Propagates inner resolver errors.
    pub fn resolve(&mut self, r: &LogRef) -> SignatifResult<Vec<u8>> {
        if let Some(hit) = self.cache.get(&(r.log.clone(), r.sequence)) {
            return Ok(hit.clone());
        }
        let fetched = self.inner.resolve(r)?;
        self.cache
            .insert((r.log.clone(), r.sequence), fetched.clone());
        Ok(fetched)
    }

    /// Number of cached entries (observable for tests and metrics).
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }
}

/// Reconstruct the full certificate chain from a delivery strategy,
/// using `resolver` only for non-embedded strategies.
///
/// # Errors
///
/// Returns [`SignatifError::Encoding`] when a reference cannot be
/// resolved.
pub fn reconstruct_chain(
    delivery: &ChainDelivery,
    resolver: Option<&mut dyn LogResolver>,
) -> SignatifResult<Vec<Vec<u8>>> {
    match delivery {
        ChainDelivery::Embedded { chain } => Ok(chain.clone()),
        ChainDelivery::LogReference { refs } => {
            let resolver = resolver.ok_or_else(|| {
                SignatifError::Encoding("log-reference delivery requires a resolver".into())
            })?;
            refs.iter().map(|r| resolver.resolve(r)).collect()
        }
        ChainDelivery::Hybrid { immediate, refs } => {
            let mut chain = immediate.clone();
            let resolver = resolver.ok_or_else(|| {
                SignatifError::Encoding("hybrid delivery requires a resolver".into())
            })?;
            for r in refs {
                chain.push(resolver.resolve(r)?);
            }
            Ok(chain)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeLog {
        entries: HashMap<(String, u64), Vec<u8>>,
        fetches: std::cell::Cell<u32>,
    }

    impl LogResolver for &FakeLog {
        fn resolve(&mut self, r: &LogRef) -> SignatifResult<Vec<u8>> {
            self.fetches.set(self.fetches.get() + 1);
            self.entries
                .get(&(r.log.clone(), r.sequence))
                .cloned()
                .ok_or_else(|| SignatifError::Encoding("miss".into()))
        }
    }

    #[test]
    fn embedded_is_offline() {
        let d = ChainDelivery::Embedded {
            chain: vec![vec![1]],
        };
        assert!(d.is_offline_capable());
        assert_eq!(reconstruct_chain(&d, None).unwrap(), vec![vec![1]]);
    }

    #[test]
    fn log_reference_resolves_and_caches() {
        let log = FakeLog {
            entries: [("pharma-log".to_string(), 7u64)]
                .iter()
                .map(|(l, s)| ((l.clone(), *s), vec![9, 9]))
                .collect(),
            fetches: std::cell::Cell::new(0),
        };
        let d = ChainDelivery::LogReference {
            refs: vec![LogRef {
                log: "pharma-log".into(),
                sequence: 7,
            }],
        };
        let mut cache = CachingResolver::new(&log);
        let chain = reconstruct_chain(&d, Some(&mut cache)).unwrap();
        assert_eq!(chain, vec![vec![9, 9]]);
        assert_eq!(cache.cache_len(), 1);
        // Second resolution is served from cache: one inner fetch total.
        reconstruct_chain(&d, Some(&mut cache)).unwrap();
        assert_eq!(log.fetches.get(), 1);
    }

    #[test]
    fn hybrid_combines_inline_and_resolved() {
        let log = FakeLog {
            entries: [("log".to_string(), 1u64)]
                .iter()
                .map(|(l, s)| ((l.clone(), *s), vec![2]))
                .collect(),
            fetches: std::cell::Cell::new(0),
        };
        let d = ChainDelivery::Hybrid {
            immediate: vec![vec![1]],
            refs: vec![LogRef {
                log: "log".into(),
                sequence: 1,
            }],
        };
        assert_eq!(
            reconstruct_chain(&d, Some(&mut &log)).unwrap(),
            vec![vec![1], vec![2]]
        );
    }
}
