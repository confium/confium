# Confium Governance

This document describes how decisions are made in the Confium project. It complements [CONTRIBUTING.md](./CONTRIBUTING.md) (how to contribute) and [SECURITY.md](./SECURITY.md) (how to report vulnerabilities).

## Roles

| Role | Who | What they can do |
|------|-----|------------------|
| **Contributor** | Anyone with a merged PR | Submit PRs, participate in discussions |
| **Reviewer** | Maintained in CODEOWNERS | Review PRs in their area, block merges with feedback |
| **Maintainer** | Listed below | Approve PRs, merge to main, cut releases |
| **Lead Maintainer** | Ronald Tse | Final escalation, release authority, security disclosure coordination |

## Maintainers

Current maintainers (alphabetical):

- **Ronald Tse** — Lead Maintainer. Engine, plugin SDK, threshold cryptography. Ribose.

Maintainer status is reviewed annually. A maintainer who is inactive for 6+ months may be moved to emeritus status (kept in CODEOWNERS but no longer merge-blocking).

## Decision-making

Decisions are made by **lazy consensus** by default:

1. Anyone opens a discussion (GitHub Discussions or a design doc PR).
2. Maintainers and the community discuss.
3. If no maintainer objects within **7 days**, the proposal is accepted.
4. If a maintainer objects, the proposal goes to a **vote** of maintainers.

Votes require a simple majority of maintainers to pass. The lead maintainer's vote breaks ties.

### When lazy consensus doesn't apply

- **Breaking API changes**: require explicit maintainer approval (no lazy consensus).
- **Adding a new product** (e.g., a hypothetical 7th product): requires a published architecture decision record (ADR) plus a vote.
- **Security-sensitive changes**: handled under [SECURITY.md](./SECURITY.md), not in public discussion.
- **Licensing changes**: require unanimous maintainer consent plus sponsor approval (NLnet / Mozilla MOSS).

## Becoming a maintainer

- Contribute consistently for 6+ months across at least two of: code, reviews, specs, docs.
- Demonstrate sound judgment on at least 10 non-trivial PRs.
- Be nominated by an existing maintainer and approved by majority vote.

There is no fixed number of maintainers; the bar is judgment, not headcount.

## Working groups

For focus areas that warrant sustained attention, the project may charter working groups. A WG:

- Has a documented scope and deliverable.
- Reports monthly to the broader community.
- Can have its own meeting cadence and chat channel.
- Cannot change governance; that stays with the maintainer set.

Current WGs: none active. Past WGs are archived in `docs/governance/past-wgs/`.

## Spec process

Confium follows "specs lead, code follows":

1. Non-trivial behavior starts as a draft in the [specs repo](https://github.com/confium/specs).
2. The spec is reviewed by at least one maintainer and one external party (researcher, partner, or auditor).
3. Implementation begins only after spec status moves from `Draft` → `Accepted`.
4. Breaking spec changes follow the breaking-API-change rule above.

## Conflict resolution

Disagreements between contributors should first be worked out in the relevant issue/PR. If unresolved:

1. A maintainer mediates.
2. If still unresolved, the lead maintainer decides.

Behavioral disputes (harassment, CoC violations) follow [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) and are NOT subject to technical decision-making.

## Funding transparency

Confium accepts sponsorship via the channels in [`.github/FUNDING.yml`](./.github/FUNDING.yml). All sponsors are acknowledged in `docs/funding.mdx`. No sponsor receives preferential treatment in technical decisions.

## Changes to this document

This document is versioned. Material changes require maintainer consensus. The latest version is always at <https://github.com/confium/confium/blob/main/GOVERNANCE.md>.
