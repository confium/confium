//! The five scheme-maintained registries (SIGNATIF Annex C).
//!
//! A scheme adopting the framework owns registries for the extensible
//! value spaces: trust dimensions, algorithms, ceremony types, format
//! profiles, and scope dimensions. Each entry carries a lifecycle
//! status consumed by the verification pipeline (`deprecated`
//! downgrades, `retired` rejects). Registries are deterministic,
//! serializable documents so a scheme can publish them.

use serde::{Deserialize, Serialize};

use crate::error::{SignatifError, SignatifResult};

/// Lifecycle status of a registry entry (algorithm agility §20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Recognized and usable.
    Active,
    /// Announced for removal: artifacts using it are downgraded.
    Deprecated,
    /// Removed: artifacts using it are rejected.
    Retired,
}

/// A registry entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Entry identifier (e.g. `Ed25519`, `data`, `/conf/format-cose`).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Lifecycle status.
    pub status: Status,
    /// Reference to the specification or standard.
    pub reference: String,
}

/// The trust dimension tags used in co-signature blocks.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DimensionTag(String);

impl DimensionTag {
    /// The `data` dimension — the primary content attestation.
    pub const DATA: &'static str = "data";
    /// The `person` dimension — a human witnessed or authorized.
    pub const PERSON: &'static str = "person";
    /// The `time` dimension — existence at a stated time.
    pub const TIME: &'static str = "time";
    /// The `location` dimension — occurrence at coordinates.
    pub const LOCATION: &'static str = "location";
    /// The `environment` dimension — ambient conditions in bounds.
    pub const ENVIRONMENT: &'static str = "environment";
    /// The `authorization` dimension — action permitted by policy.
    pub const AUTHORIZATION: &'static str = "authorization";
    /// The `identity` dimension — device or person is genuine.
    pub const IDENTITY: &'static str = "identity";
    /// The `oracle` dimension — external data had a stated value.
    pub const ORACLE: &'static str = "oracle";

    /// The `data` dimension — the primary content attestation.
    pub fn data() -> Self {
        Self(Self::DATA.into())
    }
    /// The `person` dimension — a human witnessed or authorized.
    pub fn person() -> Self {
        Self(Self::PERSON.into())
    }
    /// The `time` dimension — existence at a stated time.
    pub fn time() -> Self {
        Self(Self::TIME.into())
    }
    /// The `location` dimension — occurrence at coordinates.
    pub fn location() -> Self {
        Self(Self::LOCATION.into())
    }
    /// The `environment` dimension — ambient conditions in bounds.
    pub fn environment() -> Self {
        Self(Self::ENVIRONMENT.into())
    }
    /// The `authorization` dimension — action permitted by policy.
    pub fn authorization() -> Self {
        Self(Self::AUTHORIZATION.into())
    }
    /// The `identity` dimension — device or person is genuine.
    pub fn identity() -> Self {
        Self(Self::IDENTITY.into())
    }
    /// The `oracle` dimension — external data had a stated value.
    pub fn oracle() -> Self {
        Self(Self::ORACLE.into())
    }

    /// Build a custom dimension tag (scheme-registered extensions).
    pub fn custom(name: &str) -> Self {
        Self(name.into())
    }

    /// The tag's string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A named registry with entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueRegistry {
    /// Registry name (for error messages and publication).
    pub registry_name: String,
    /// The entries.
    pub entries: Vec<Entry>,
}

impl ValueRegistry {
    /// An empty registry.
    pub fn new(name: &str) -> Self {
        Self {
            registry_name: name.to_string(),
            entries: Vec::new(),
        }
    }

    /// Register an entry.
    pub fn register(&mut self, entry: Entry) {
        self.entries.push(entry);
    }

    /// Look up an entry by name.
    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Whether the entry exists with the given status usable by new
    /// attestations (active or deprecated).
    pub fn contains(&self, name: &str) -> bool {
        self.get(name)
            .map(|e| e.status != Status::Retired)
            .unwrap_or(false)
    }

    /// Returns the entry when it can be used for *new* attestations;
    /// retired entries cannot sign new artifacts.
    pub fn usable(&self, name: &str) -> Option<&Entry> {
        self.get(name).filter(|e| e.status != Status::Retired)
    }

    /// The status of an entry, if registered.
    pub fn status(&self, name: &str) -> Option<Status> {
        self.get(name).map(|e| e.status)
    }

    /// Transition an entry's status (the deprecation process §20).
    ///
    /// # Errors
    ///
    /// Returns a registry error when the entry is unknown.
    pub fn set_status(&mut self, name: &str, status: Status) -> SignatifResult<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.name == name)
            .ok_or_else(|| SignatifError::Registry {
                registry: self.registry_name.clone(),
                entry: name.to_string(),
            })?;
        entry.status = status;
        Ok(())
    }
}

/// The five scheme-maintained registries in one bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    /// Trust dimension tag registry.
    pub dimensions: ValueRegistry,
    /// Algorithm identifier registry (classical, post-quantum,
    /// composite) with status.
    pub algorithms: ValueRegistry,
    /// Ceremony type registry.
    pub ceremony_types: ValueRegistry,
    /// Format profile registry.
    pub format_profiles: ValueRegistry,
    /// Scope dimension registry.
    pub scope_dimensions: ValueRegistry,
}

impl Registry {
    /// The five registries populated with the framework's initial
    /// values (Annex C: initial content is the scheme's decision at
    /// establishment; these are Confium's defaults).
    pub fn with_initial_values() -> Self {
        let mut dimensions = ValueRegistry::new("trust-dimension");
        for (name, desc, anchor) in [
            (
                DimensionTag::DATA,
                "The primary content (measured value, record)",
                "Transparency log",
            ),
            (
                DimensionTag::PERSON,
                "A human witnessed or authorized the act",
                "Hardware token",
            ),
            (
                DimensionTag::TIME,
                "The artifact existed at a stated time",
                "External timestamp source",
            ),
            (
                DimensionTag::LOCATION,
                "The event occurred at stated coordinates",
                "Location authority signal",
            ),
            (
                DimensionTag::ENVIRONMENT,
                "Ambient conditions were within stated bounds",
                "Calibrated sensor",
            ),
            (
                DimensionTag::AUTHORIZATION,
                "The action was permitted under a policy",
                "Regulatory framework",
            ),
            (
                DimensionTag::IDENTITY,
                "The device or person is genuine",
                "Identity authority",
            ),
            (
                DimensionTag::ORACLE,
                "External data had a stated value at a time",
                "Multi-source agreement",
            ),
        ] {
            dimensions.register(Entry {
                name: name.to_string(),
                description: desc.into(),
                status: Status::Active,
                reference: anchor.into(),
            });
        }

        let mut algorithms = ValueRegistry::new("algorithm");
        for (name, description, reference) in [
            (
                "Ed25519",
                "Edwards-curve digital signature (classical)",
                "RFC 8032",
            ),
            (
                "ECDSA-P256",
                "ECDSA over NIST P-256 (classical)",
                "FIPS 186-4",
            ),
            (
                "ML-DSA-44",
                "Module-lattice signature (post-quantum)",
                "FIPS 204",
            ),
            (
                "ML-DSA-65",
                "Module-lattice signature (post-quantum)",
                "FIPS 204",
            ),
            (
                "ML-DSA-87",
                "Module-lattice signature (post-quantum)",
                "FIPS 204",
            ),
            (
                "SLH-DSA-128s",
                "Stateless hash-based signature (post-quantum)",
                "FIPS 205",
            ),
            (
                "Composite-Ed25519-MLDSA65",
                "AND-composition Ed25519 + ML-DSA-65 (composite)",
                "SIGNATIF §9.4",
            ),
            (
                "Threshold-CMP20-P256",
                "CMP20 threshold ECDSA P-256 aggregate",
                "Confium confium-tc-cmp20",
            ),
            (
                "Threshold-FROST-Ed25519",
                "FROST threshold Ed25519 aggregate",
                "Confium confium-tc-frost-ed25519",
            ),
        ] {
            algorithms.register(Entry {
                name: name.into(),
                description: description.into(),
                status: Status::Active,
                reference: reference.into(),
            });
        }

        let mut ceremony_types = ValueRegistry::new("ceremony-type");
        for name in ["dkg", "reshare", "sign", "revoke", "rotation"] {
            ceremony_types.register(Entry {
                name: name.into(),
                description: format!("Threshold {name} ceremony"),
                status: Status::Active,
                reference: "SIGNATIF §17".into(),
            });
        }

        let mut format_profiles = ValueRegistry::new("format-profile");
        for (name, reference) in [
            ("/conf/format-cose", "RFC 8152 COSE Sig_Structure"),
            ("/conf/format-jws", "RFC 7515 JWS detached content"),
            ("/conf/format-xmldsig", "W3C XML Signature + Exclusive C14N"),
        ] {
            format_profiles.register(Entry {
                name: name.into(),
                description: "Signature envelope format profile".into(),
                status: Status::Active,
                reference: reference.into(),
            });
        }

        let mut scope_dimensions = ValueRegistry::new("scope-dimension");
        for name in ["domain", "subdomain", "class", "instance", "identity"] {
            scope_dimensions.register(Entry {
                name: name.into(),
                description: format!("Scope dimension `{name}`"),
                status: Status::Active,
                reference: "SIGNATIF §11".into(),
            });
        }

        Self {
            dimensions,
            algorithms,
            ceremony_types,
            format_profiles,
            scope_dimensions,
        }
    }

    /// Deterministic publication bytes for a registry (JCS).
    ///
    /// # Errors
    ///
    /// Propagates canonicalization errors.
    pub fn publication_bytes(&self) -> SignatifResult<Vec<u8>> {
        let v = serde_json::to_value(self).expect("registry serializes");
        Ok(crate::jcs::canonicalize(&v)?.into_bytes())
    }

    /// Declare a scheme-registered extension dimension.
    pub fn register_dimension(&mut self, tag: &str, description: &str) {
        self.dimensions.register(Entry {
            name: tag.into(),
            description: description.into(),
            status: Status::Active,
            reference: "scheme-registered".into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_values_populate_all_five() {
        let r = Registry::with_initial_values();
        assert!(r.dimensions.entries.len() >= 8);
        assert!(r.algorithms.get("Ed25519").is_some());
        assert!(r.algorithms.get("ML-DSA-65").is_some());
        assert!(r.ceremony_types.get("dkg").is_some());
        assert!(r.format_profiles.get("/conf/format-cose").is_some());
        assert!(r.scope_dimensions.get("domain").is_some());
    }

    #[test]
    fn deprecation_lifecycle() {
        let mut r = Registry::with_initial_values();
        r.algorithms
            .set_status("ECDSA-P256", Status::Deprecated)
            .unwrap();
        assert_eq!(r.algorithms.status("ECDSA-P256"), Some(Status::Deprecated));
        assert!(r.algorithms.usable("ECDSA-P256").is_some());
        r.algorithms
            .set_status("ECDSA-P256", Status::Retired)
            .unwrap();
        assert!(r.algorithms.usable("ECDSA-P256").is_none());
        assert!(r.algorithms.set_status("nope", Status::Active).is_err());
    }

    #[test]
    fn scheme_extension_dimensions() {
        let mut r = Registry::with_initial_values();
        r.register_dimension("cnml:instrument-class", "CNML instrument classification");
        assert!(r.dimensions.contains("cnml:instrument-class"));
        let bytes = r.publication_bytes().unwrap();
        assert!(!bytes.is_empty());
    }
}
