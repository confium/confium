# 33 — Deployment manifest and configuration model

## Purpose

A Confium deployment is described by a **signed deployment manifest**
— the public charter of the deployment. Anyone can read it to
understand the rules.

This is what makes Confium a framework rather than a single-purpose
system. Different deployments write different manifests.

## Three manifest types

| Mode | Manifest | Required? |
|---|---|---|
| Mode 1 (peer TC) | None (session params in code) | No |
| Mode 2 (PKI replacement) | TOML with PKCS#11 server config | Yes |
| Mode 3 (certificate PKI) | Full deployment manifest | Yes |

## Mode 3 manifest schema

```toml
# confium.toml — OIML CNML deployment
[deployment]
name = "OIML CNML"
operator = "BIML"
charter_url = "https://oiml.org/..."
manifest_version = 1
mode = "certificate_pki"

[[tier]]
name = "biml_root"
role = "international root"
signing_algorithm = "FROST-ed25519+ML-DSA-65-composite"
encryption_algorithm = "ML-KEM-768-threshold"
threshold = { t = 5, n = 7 }
attributes = ["region", "expertise"]
ceremony = { sync_required = true, frequency = "annual" }

[[tier]]
name = "ia"
role = "national issuing authority"
signing_algorithm = "FROST-P256"
encryption_algorithm = "ElGamal-P256-threshold"
threshold = { t = 2, n = 3 }
delegated_by = "biml_root"
ceremony = { sync_required = false }

[[tier]]
name = "tl"
role = "testing laboratory"
signing_algorithm = "ECDSA-P256"
encryption_algorithm = "ECIES-P256"
threshold = { t = 1, n = 1 }
delegated_by = "ia"

[[tier]]
name = "manufacturer_model"
role = "manufacturer model authorization (scoped delegation)"
signing_algorithm = "ECDSA-P256"
threshold = { t = 1, n = 1 }
delegated_by = "ia"
delegation_scope = "model-bound"

[[tier]]
name = "manufacturer_instance"
role = "individual instrument instance"
signing_algorithm = "ECDSA-P256"
threshold = { t = 1, n = 1 }
delegated_by = "manufacturer_model"

[transparency]
log_operator = "biml"
anchors = ["bitcoin-ots"]
gossip = false
public_mirror_urls = ["https://log.confium.org/oiml-cnml", "ipfs://..."]

[async_signing]
default_unlock_window_minutes = 240
coordinator_operator = "biml"

[archival]
renewal_period_years = 5
re_sign_under = "current-algorithm-suite"
```

## Mode 2 manifest schema

```toml
# confium.toml — enterprise PKI replacement
[deployment]
name = "Acme Corp PKI"
operator = "Acme Corporation"
mode = "pkcs11_replacement"
manifest_version = 1

[pkcs11_server]
slot_count = 8
default_signing_algorithm = "FROST-P256"
default_threshold = { t = 3, n = 5 }
share_storage = "pkcs11-wrap"
hsm_module = "/usr/lib/pkcs11/yubihsm.so"

[quorum.enterprise_root]
threshold = { t = 3, n = 5 }
coordinator = "coordinator.acme.corp:443"
share_storage_backend = "yubihsm"

[quorum.code_signing]
threshold = { t = 2, n = 3 }
coordinator = "coordinator.acme.corp:443"

[pqc_migration]
current = "ECDSA-P256"
target_2027 = "composite-ECDSA-P256-ML-DSA-65"
target_2029 = "ML-DSA-65"
```

## Crate scope

### `confium-config` (P0)

```rust
pub struct Manifest {
    pub deployment: DeploymentHeader,
    pub mode: DeploymentMode,
    pub tiers: Vec<Tier>,           // Mode 3 only
    pub transparency: TransparencyConfig,
    pub async_signing: AsyncSigningConfig,
    pub archival: ArchivalConfig,
    pub quorums: Vec<Quorum>,       // Mode 2 only
    pub pkcs11_server: Option<Pkcs11ServerConfig>,
    pub pqc_migration: Option<PqcMigrationPlan>,
}

pub fn parse_manifest(toml_str: &str) -> Result<Manifest>;
pub fn validate_manifest(manifest: &Manifest) -> Result<ValidationReport>;
pub fn manifest_to_toml(manifest: &Manifest) -> Result<String>;

pub struct Tier {
    pub name: String,
    pub role: String,
    pub signing_algorithm: String,
    pub encryption_algorithm: Option<String>,
    pub threshold: Threshold,
    pub delegated_by: Option<String>,
    pub delegation_scope: Option<String>,
    pub ceremony: Option<Ceremony>,
    pub attributes: Vec<String>,
}

pub enum DeploymentMode {
    PeerToPeer,           // Mode 1
    Pkcs11Replacement,    // Mode 2
    CertificatePki,       // Mode 3
}
```

The manifest is signed by deployment operator. Verifiers check
signature before trusting manifest.

## Versioning

`manifest_version` field. As schema evolves, old manifests still
parseable via versioned deserializers.

This is the answer to "what happens when deployments evolve?":
manifest version field, semver-compatible schema changes.

## Per-deployment overrides

Manifest is the public charter. Per-environment overrides
(test/staging/prod) live in separate files (`confium.local.toml`),
not signed, used for non-security-critical params (log levels,
coordinator hostnames).

## CLI

```sh
confium manifest validate confium.toml
confium manifest sign confium.toml --key <keyfile>
confium manifest verify confium.toml --pubkey <pubkey>
confium manifest apply confium.toml  # deploy to local node
```

## References

- `TODO.roadmap/26-confium-framework.md`
- `TODO.roadmap/28-mode2-pki-replacement.md`
