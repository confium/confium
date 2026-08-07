# TODO.restructure/ Phase 2 — Product Depth (TODOs 19-32)

Phase 1 (TODOs 00-18) shipped the 6-product restructuring: extracted crates, published facades, shipped one minisite index page per product. All complete.

Phase 2 (TODOs 19-32) fills the **depth** gaps:
- Three product facades still missing (threshold, keyless, verify)
- Minisite nav links 404 (subpages don't exist)
- Audience ↔ use-case matrix is implicit
- Specs are mode-tagged not product-tagged
- No per-product docs in the Rust workspace
- CLI has no product-umbrella commands
- Repo strategy undocumented

## Audit

Start with [19-deep-architecture-audit.md](19-deep-architecture-audit.md) — it explains the gap analysis and links to all TODOs below.

## TODOs

| # | Title | Priority | Status |
|---|-------|----------|--------|
| 19 | Deep architecture audit | — | ✅ Done (this doc is it) |
| 20 | [Product facade crates](20-product-facade-crates.md) | CRITICAL | ☐ Blocked: requires committing 19 prior-session crate directories (tc-core, coordinator, crypto-vss, etc.) before facades can reference them |
| 21 | [Audience/use-case matrix](21-audience-use-case-matrix.md) | HIGH | ✅ Done (PR confium.github.io#76) |
| 22 | [Minisite shared subpage templates](22-minisite-shared-templates.md) | HIGH | ✅ Done (PR confium.github.io#77) |
| 23 | [Threshold minisite depth](23-minisite-threshold.md) | HIGH | ✅ Done (PR confium.github.io#78) |
| 24 | [Transparency minisite depth](24-minisite-transparency.md) | HIGH | ✅ Done (PR confium.github.io#79) |
| 25 | [PKI minisite depth](25-minisite-pki.md) | HIGH | ✅ Done (PR confium.github.io#79) |
| 26 | [Keyless minisite depth](26-minisite-keyless.md) | HIGH | ✅ Done (PR confium.github.io#79) |
| 27 | [Privacy minisite depth](27-minisite-privacy.md) | HIGH | ✅ Done (PR confium.github.io#79) |
| 28 | [Verify minisite depth](28-minisite-verify.md) | HIGH | ✅ Done (PR confium.github.io#79) |
| 29 | [Specs product-tagging](29-specs-product-tagging.md) | MEDIUM | ✅ Done (PR specs#5) |
| 30 | [Per-product docs in Rust workspace](30-per-product-docs.md) | MEDIUM | ☐ |
| 31 | [CLI product subcommands](31-cli-product-subcommands.md) | MEDIUM | ☐ |
| 32 | [Repo strategy decision record](32-repo-strategy-decision.md) | LOW | ✅ Done (PR confium#107) |

## Execution order

1. **Foundation** (TODOs 20, 21, 22) — must land first; everything else consumes them.
2. **Per-product depth** (TODOs 23-28) — can land in parallel once foundation is in.
3. **Cross-cutting** (TODOs 29-32) — independent of foundation and depth.

## How to run a TODO

Each TODO has:
- **Problem**: why this exists
- **Solution**: what to build
- **Acceptance criteria**: definition of done
- **Files to touch**: exact paths

For code TODOs: open a PR per TODO, rebase-merge (per existing memory). For docs TODOs: same. For website TODOs: build site locally before PR.

## Out of scope for Phase 2

- New cryptographic primitives
- Per-product repos (decision: stay in monorepo — see TODO 32)
- Marketing site redesign
- Rebranding
