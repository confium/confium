# 65 — Project governance

## Decision-making philosophy

Confium is an open-source project led by Ribose Inc. Decisions aim for:

1. **Technical merit**: supported by spec, evidence, or formal analysis
2. **Stakeholder awareness**: NIST, BIML, OIML member states informed
3. **Reversibility**: prefer choices that can be undone (only root signing key
   changes are irreversible, and those go through annual ceremony)
4. **Transparency**: decisions and rationale are public

## Roles

### Lead maintainer (Ribose)

- Final say on architectural decisions
- Approves release tags
- Represents Confium to NIST MPTS, OIML, partner organizations
- Owns trademark, infrastructure, security response process

### Maintainers

- Review and merge PRs in their area of expertise
- Approve feature additions
- Participate in ADR discussions

Current maintainer areas:
- Cryptography (Ribose + academic collaborators)
- PKI / certificates
- Network / coordinator
- Storage / hardware
- Documentation
- CI / release

### Contributors

- Anyone with a merged PR
- Earn maintainer role through sustained quality contribution
- Code of Conduct applies to all

### Partner organizations

- **Ribose**: project lead, operator of OIML SMART program
- **BIML**: institutional partner for CNML deployment
- **NIST**: MPTS evaluation partner
- **EPFL DeDiS** (potential): transparency log + CoSi research
- **Boneh group at Stanford** (potential): PQ threshold research

Partnerships are governed by formal MOUs, not by this open-source
project governance doc.

## Decision-making process

### Tier 1: Routine (PR by contributor + 1 maintainer review)

- Bug fixes
- Documentation
- Test improvements
- New examples
- Dependency updates
- Performance optimizations

### Tier 2: Significant (PR + 2 maintainer reviews)

- New features in existing crates
- New crates
- Public API changes (non-breaking)
- New test infrastructure
- New deployment modes within an existing pattern

### Tier 3: Architectural (ADR + lead maintainer approval)

- New top-level concepts (e.g., a fourth deployment mode)
- Crate consolidation / split
- Breaking API changes
- New algorithmic dependencies
- Changes to plugin contract

### Tier 4: Strategic (Ribose + partner sign-off)

- New institutional partnership
- Trademark / licensing changes
- Public positioning shifts (e.g., new deployment vertical)
- Major release (1.0.0, 2.0.0)

## Voting

For Tier 3 decisions, simple majority of active maintainers + lead
maintainer approval. Maintainers can abstain.

For Tier 4, Ribose leadership decides; maintainer consensus is advisory.

## Conflict resolution

1. **Discuss** in PR comments or GitHub Discussions
2. **Mediate** by lead maintainer if discussion stalls
3. **ADR** if dispute is architectural
4. **Final call** by Ribose for Tier 4

## Trademark and licensing

- "Confium" is a Ribose trademark. Project name + logo are protected.
- Code is BSD-2-Clause — permissive, commercial-friendly.
- Documentation is CC-BY-4.0.
- Other organizations can fork (BSD allows) but cannot use the Confium
  trademark without permission.

See `TODO.roadmap/66-branding-and-trademark.md`.

## Financial sustainability

Current model:

- **Ribose sponsorship**: development lead, infrastructure
- **NIST grants** (potential): MPTS evaluation
- **EU Horizon** (potential): research collaborator funding
- **Enterprise support contracts** (future): Mode 2 deployment support
- **Integrator model** (future): Ribose deploys Confium for institutions

Anti-goal: Confium never becomes "open-core" (proprietary extensions
behind a paywall). The framework stays fully open-source.

## Anti-goals

- **Not** consensus-based decision-making (too slow for security framework)
- **Not** rotating maintainer roles (continuity matters)
- **Not** anonymous decision-makers (transparency requires attribution)

## References

- `TODO.roadmap/64-community-and-contribution.md`
- `TODO.roadmap/61-architecture-decision-records.md`
- `GOVERNANCE.md` (to be created from this document)
