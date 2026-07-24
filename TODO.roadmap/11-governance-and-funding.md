# 11 — Governance and Funding

## Why this matters

Open-source crypto projects die two ways: technically (abandoned) or politically (vendor capture). Governance and funding decisions made early determine which fate awaits. Confium's mission — NIST TC standardization — is a multi-year play. The governance model has to survive multiple funding cycles and at least one maintainer transition.

## Current state

- **Copyright holder**: Ribose Inc.
- **License**: BSD-2-Clause (permissive, OSI-approved, GPL-compatible)
- **Funding**: Mozilla MOSS + NLNet NGI Zero (both foundational-tech grants)
- **Maintainers**: Ribose employees (Ronald Tse, Daniel Wyatt, et al.)
- **Contributors**: small (mostly Ribose), no external committers with write access today

## Target governance model

### Phase 1 (now – Q3 2026): Ribose-led, contribution-friendly

- Ribose retains BDFL role; all merges via PR review.
- Establish CONTRIBUTING.md (done in modernization PR), CODE_OF_CONDUCT.md, SECURITY.md.
- Public roadmap (this document + TODO.finalize).
- Open issue triage process — every issue gets a response within 5 business days.

### Phase 2 (Q4 2026 – Q3 2027): Multi-stakeholder advisory

- Form a **Technical Steering Committee (TSC)** with representatives from:
  - Ribose (maintainer)
  - Mozilla (RNP consumer)
  - At least one academic institution (TC researcher voice)
  - At least one industry user (HSM vendor / cloud KMS provider)
- TSC reviews RFC documents (major architectural changes) and ratifies releases.
- Day-to-day maintenance stays with Ribose; TSC sets direction.

### Phase 3 (Q4 2027+): Foundation-hosted

- Move copyright/trademark to a foundation (likely **NLnet**'s stewardship, or a Linux Foundation project, or a Ribose-spun-out non-profit).
- Establish formal spec process for the plugin contract (similar to a JSR or IETF working group).
- Multi-vendor funding model — no single funder contributes >50%.

## Decision-making

Three tiers, scaled by impact:

| Tier | Examples | Process |
|---|---|---|
| Trivial | Bug fixes, docs, dependency bumps | Single maintainer approval + CI |
| Standard | New algorithm interface, new plugin contract version | PR + at least one TSC member sign-off |
| Constitutional | License change, foundation move, breaking contract changes | TSC supermajority + community comment period (≥4 weeks) |

## Funding sources (current + target)

| Source | Status | Use | Restrictions |
|---|---|---|---|
| Mozilla MOSS | Active (foundational tech) | Core framework | None (open-source) |
| NLNet NGI Zero | Active (PET) | Privacy features | EU grant terms |
| NIST MCTS | Pursuing | Harness development | US gov grant terms |
| Ribose in-kind | Active | Maintainer time | None |
| Industry sponsorship | Recruiting (Phase 3) | Specific plugin work | No commit-access guarantees |
| Support contracts (via Ribose) | Future (Phase 4) | Enterprise support | None (commercial) |

## Conflict of interest policy

- Maintainers with commercial Confium-related products (e.g. HSM vendors) declare their interest.
- TSC members recuse themselves from votes directly affecting their employer's product.
- All sponsorship is publicly listed in `docs/governance/sponsors.md`.

## Trademark

"Confium" is a trademark of Ribose Inc. Use of the name is freely granted for:
- Plugin names (e.g. `confium-botan`)
- Documentation and educational materials
- Community tools

Use of the name is **not** granted for:
- Proprietary forks that don't ship source
- Products claiming official Confium certification without TSC approval

Trademark policy documented in `TRADEMARK.md`.

## License

BSD-2-Clause chosen for:
- Permissive — no viral restriction on plugin authors
- GPL-compatible — Linux distributions can package
- Tivo-compatible — Apple platforms can ship
- Short and well-understood

Plugins are NOT required to be BSD. A plugin can be GPL, AGPL, proprietary, anything. The plugin manifest declares the license; the registry displays it; the user decides.

## Patent policy

- Confium core: BSD-2-Clause includes an implicit patent grant.
- Plugins: each plugin's manifest declares whether its author claims patents on the implementation.
- For NIST-standardized algorithms: NIST's patent disclosures apply.

## Reference

- `TODO.roadmap/00-vision-and-mission.md` — what the funding is for
- `TODO.roadmap/10-distribution-and-adoption.md` — phase plan
- `SECURITY.md` (in repo) — vulnerability reporting
- `CONTRIBUTING.md` (in repo) — contribution process
