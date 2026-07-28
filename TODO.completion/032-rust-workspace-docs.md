# 032 — Rust workspace `docs/` tree

**Category**: Documentation
**Severity**: High (per-repo docs are the canonical developer reference; needed before website pull-through)
**Effort**: Medium (one PR — many AsciiDoc files)
**Status**: ✅ done (PR #70 + #71)

## Problem

The Rust workspace at `confium/` ships 43 crates with deep functionality
but no consolidated `docs/` tree. The README points at the workspace
README and `CLAUDE.md`, but neither is structured for public
consumption. Per the plan at `/Users/mulgogi/.claude/plans/prancy-riding-honey.md`,
each repo owns its `/docs/` and the central Astro site at
`confium.github.io` pulls them via sparse-checkout.

Without `confium/docs/`, `www.confium.org/software/rust/docs/` will be
empty.

## Acceptance criteria

- [x] `docs/index.mdx` — landing page that orients the reader: what
  Confium is, how to install, where to go next.
- [x] `docs/installation.mdx` — three paths: `cargo add confium-core`,
  Nix flake (`nix develop`), build from source.
- [x] `docs/workspace-map.mdx` — 43 crates grouped by category
  (Engine, TC, TC-encryption, PKI, Storage, Mode 2, Network, Research).
  Links to docs.rs for each.
- [x] `docs/architecture.mdx` — engine, plugin loader, registry,
  FFI entry points, the 10 shipped interfaces.
- [x] `docs/plugin-author-guide.mdx` — `#[plugin_interface]`,
  `#[export]`, `register_interface!`, the `cfmp_*` contract.
- [x] `docs/conventions.mdx` — Snafu 0.8 (`NullPointerSnafu`),
  edition 2024 quirks (`#[unsafe(no_mangle)]`), `#![forbid(unsafe_code)]`,
  `#![warn(missing_docs)]`.
- [x] `docs/crates/{composite,transparency,frost-p256}.mdx`
  — per-crate deep dives (purpose, public API, security notes).
- [x] `docs/examples/threshold-signing.mdx`
  — runnable end-to-end example in Rust.
- [x] Every file is MDX with YAML frontmatter (`title`, `description`).
- [x] No "OIML" anywhere; CNML OK as one example among many.
- [x] No "TODO", "coming soon", "planned", "milestone", or "roadmap"
  language — read as shipped.

**Format note:** Originally written as `.adoc` per the RNP-mimic plan,
then converted to `.mdx` in PR #71 per user directive that "adoc
doesn't work with the system". See `docs-format-mdx-not-adoc.md`
memory.

**Deferred to follow-up PRs:** `crates/{frost-ed25519,cmp20,gg18,elgamal-p256,coordinator,reshare}.mdx`
deep dives and `examples/{pq-migration,transparency-log}.mdx` —
not blocking website launch.

## Anti-patterns

- Dumping `cargo doc` output — that's at `docs.confium.org`, not here.
- Copying `CLAUDE.md` verbatim — it's an LLM-oriented file, not a user doc.
- Cross-linking into `TODO.roadmap/` or `TODO.finalize/` — those are
  internal; public docs link only to public artifacts.

## Approach

One PR per logical group if review load is high, otherwise one bundled
PR. Each file is 100–300 lines, AsciiDoc with code blocks and tables.
Pull workspace structure from `Cargo.toml` and `CLAUDE.md`. Verify
anchors render correctly with `asciidoctor docs/index.adoc` locally
before pushing.

## Related

- [033-ruby-docs-augmentation.md](033-ruby-docs-augmentation.md) —
  parallel work in the Ruby gem.
- [041-software-bindings-specs-pull-through.md](041-software-bindings-specs-pull-through.md)
  — consumes this tree via `fetch-sources.mjs`.
