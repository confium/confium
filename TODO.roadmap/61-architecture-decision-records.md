# 61 — Architecture Decision Records (ADRs)

## Purpose

Capture significant architectural decisions in a durable, discoverable
format. Each ADR records:

- **Context**: what problem demanded a decision
- **Options considered**: alternatives evaluated
- **Decision**: what was chosen and why
- **Consequences**: what we accept by this choice

ADRs are immutable once merged; supersession is a new ADR that references
the old.

## Location

`docs/adr/<NNNN>-<kebab-case-title>.md` — numbered sequentially.

Index: `docs/adr/README.md` lists all ADRs with current status.

## Status values

- **Proposed**: PR open, not yet adopted
- **Accepted**: merged; in effect
- **Deprecated**: superseded by later ADR; kept for history
- **Superseded**: replaced by ADR-XXXX (referenced)
- **Rejected**: considered and declined (kept for the record)

## ADR template

```markdown
# ADR-NNNN: Title

**Status**: Proposed | Accepted | Deprecated | Superseded by ADR-XXXX | Rejected
**Date**: YYYY-MM-DD
**Deciders**: <names>

## Context

<What problem demands a decision? What constraints apply?>

## Options considered

### Option A: <name>
- Pros: ...
- Cons: ...

### Option B: <name>
- Pros: ...
- Cons: ...

## Decision

<What was chosen, in one paragraph. Reference specific options above.>

## Consequences

### Positive
- ...

### Negative
- ...

### Neutral
- ...

## References

- <Links to relevant docs, papers, prior ADRs>
```

## ADRs Confium should adopt

Pre-populated decisions made during the framework's evolution that
deserve ADRs:

| # | Title | Status | Year |
|---|---|---|---|
| 0001 | Adopt three-mode deployment model | Accepted | 2026 |
| 0002 | Use `p256` crate for P-256 group operations | Accepted | 2026 |
| 0003 | Per-algorithm crate separation | Accepted | 2026 |
| 0004 | Standards-only hardware interfaces (no vendor SDKs) | Accepted | 2026 |
| 0005 | TOML for deployment manifests | Accepted | 2026 |
| 0006 | `thiserror` for new crates; `snafu` for legacy | Accepted | 2026 |
| 0007 | Consolidate 5 logical crate groups (53→43) | Accepted | 2026 |
| 0008 | OpenTimestamps (not witness network) for transparency anchor | Accepted | 2026 |
| 0009 | RNP (not Sequoia) for OpenPGP operations | Accepted | 2026 |
| 0010 | Sync ceremony for root operations, async for everything else | Accepted | 2026 |
| 0011 | Share re-sharing preserves public key (committee evolution) | Accepted | 2026 |
| 0012 | PQ migration via composite signatures, not algorithm swap | Accepted | 2026 |
| 0013 | Mode 2 cornerstone is PKCS#11 server | Accepted | 2026 |
| 0014 | OTS-anchored Merkle log over CoSi witness network | Accepted | 2026 |
| 0015 | Plugin registry is publisher-signed, framework is content-neutral | Accepted | 2026 |

## ADR workflow

1. **Propose**: author writes ADR markdown, opens PR
2. **Discuss**: reviewers comment on Context / Options / Decision
3. **Revise**: author updates ADR based on feedback
4. **Accept**: PR merged; ADR status → Accepted
5. **Reference**: future PRs cite the ADR when relevant

## When to write an ADR

Write an ADR when:

- The decision is **hard to reverse** (architecture, dependencies, crypto choices)
- The decision **affects multiple crates** or the public API
- The decision involves **trade-offs** that future maintainers should understand
- The same question has been asked more than once

Don't write an ADR for:

- Implementation details (use code comments)
- Bug fixes (use commit messages)
- Documentation improvements (just do them)

## Anti-goals

- **Not** ADRs for every PR (only architectural decisions)
- **Not** ADRs as a substitute for discussion (talk first, write second)
- **Not** rewriting history (deprecated ADRs stay; superseded ADRs reference successor)

## References

- [Michael Nygard's ADR template](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
- `docs/adr/` directory (to be created with the initial ADRs above)
