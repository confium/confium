# 66 — Branding, trademark, and naming

## Trademark

"Confium" is a Ribose Inc. trademark for the threshold cryptography
framework project. The name evokes "trust" (Latin *confidere*, root of
"confidence") and "threshold" (multiple parties must agree).

## Permitted uses

- **"Powered by Confium"** — for software using the Confium framework
- **"Built on Confium"** — for plugins, integrations, deployments
- **"Confium [Crate Name]"** (e.g., "Confium FROST-P256") — for plugins
  that build on Confium interfaces
- Reference Confium in academic papers, talks, documentation with
  attribution

## Prohibited uses

- **Naming a fork "Confium"** or a confusingly similar name
- **Using the Confium logo** without Ribose permission
- **Implying Ribose endorsement** of a fork or competing product
- **"Confium-certified"** without explicit certification program
- **Misrepresenting** the relationship to Ribose or the Confium project

## Naming conventions

### Crates

- Core: `confium-*` (e.g., `confium-core`, `confium-tc`, `confium-pki`)
- Algorithms: `confium-tc-<scheme>-<curve>` (e.g., `confium-tc-frost-p256`)
- Storage backends: `confium-store-<backend>` (e.g., `confium-store-pkcs11`)
- Mode 2 shims: `confium-<host>` (e.g., `confium-openssl-provider`)

### Plugins (third-party)

- Format: `confium-plugin-<name>` or `<name>-confium`
- Must clearly indicate publisher in manifest

### Examples

- Format: `<descriptive_name>` (e.g., `p256_threshold_signing`)
- Each example has its own `[[example]]` entry in `confium-examples/Cargo.toml`

### Tools

- `confium` — main CLI binary
- `confium-publish` — author tool
- `confium-bench` — benchmarking tool (future)
- `confium-<tool>` — additional tools

## Visual identity

### Logo

The Confium logo (in `confium.github.io/assets/img/logo.svg`):

- Conceptual: multiple nodes forming a single shape
- Color palette: TBD (likely deep blue + accent)
- Must be readable at small sizes (favicon) and large (website header)

Variants:

- Primary (full color)
- Monochrome (single color)
- Reversed (on dark background)
- Mark only (no wordmark)

### Typography

- Headers: TBD (likely Inter or similar geometric sans)
- Body: system font stack
- Code: monospace (JetBrains Mono or similar)

### Color

| Use | Color | Hex |
|---|---|---|
| Primary | Deep blue | TBD |
| Accent | Threshold orange | TBD |
| Background | Off-white | TBD |
| Text | Near-black | TBD |

## Voice and tone

- **Technical but accessible**: domain expertise assumed for crypto, but
  explained for application developers
- **Authoritative without arrogance**: confidence from spec compliance,
  not attitude
- **International**: simple English, translatable
- **Patient**: this is complex; we explain without condescension

## Documentation voice

- Active voice: "Generate a keypair" not "A keypair is generated"
- Imperative for instructions: "Install Confium with..."
- Declarative for concepts: "Confium provides..."

## Public materials

### Website (confium.org)

- Top-level positioning
- Three deployment modes
- CNML case study
- Get started
- Documentation
- Community

### GitHub README

- Quickstart at top
- Three-mode summary
- Links to docs.confium.org
- Test count, crate count badges

### Academic papers

- "Confium: A Framework for Multi-Stakeholder Threshold Cryptography"
- "Sovereign Threshold PKI: International Metrology as a Case Study"
- "Threshold ML-KEM with Proactive Security for Long-Term Archival"
- "Attribute-Based Threshold Signatures for Cross-Jurisdictional Governance"

## Anti-goals

- **Not** multiple logos for different deployments (consistency matters)
- **Not** cutesy names for crypto primitives (use spec names)
- **Not** "lite" / "pro" / "enterprise" tiers (one open framework)

## References

- `TODO.roadmap/47-documentation-strategy.md`
- `TODO.roadmap/65-project-governance.md`
