# 033 — Ruby gem `docs/` augmentation

**Category**: Documentation
**Severity**: High (Ruby is the launch language binding; per-repo docs are sparse today)
**Effort**: Medium (one PR — AsciiDoc + RBS extraction)

## Problem

`confium-ruby/docs/` already has three good documents
(`executive/why-confium.adoc`, `pq-migration/composite-signatures.adoc`,
`quickstarts/sinatra-verifier.adoc`) but is missing the canonical
reference docs a Ruby developer expects: installation, API reference,
error handling, policy/configuration, examples index.

## Acceptance criteria

- [ ] `docs/index.adoc` — landing page orienting Ruby developers.
- [ ] `docs/installation.adoc` — `gem install confium`, Bundler, building
  the native extension from source, platform support (Linux/macOS,
  Windows via rake-compiler-dock).
- [ ] `docs/api-reference.adoc` — every public class and module:
  `Confium::PKI::Certificate`, `Confium::PKI::CMS::SignedData`,
  `Confium::Composite::Signature`, `Confium::Transparency::MerkleTree`,
  `Confium::TC::FrostP256`, `Confium::TC::ElGamalP256`,
  `Confium::Attributes::Predicate`, `Confium::Identity::*`,
  `Confium::Config::Manifest`, `Confium::SecureBytes`, `Confium::Policy`.
  Generated/curated from the RBS signatures in `sig/`.
- [ ] `docs/error-handling.adoc` — the typed error hierarchy
  (`Confium::Error` + 9 subclasses), rescue patterns, `details` accessor.
- [ ] `docs/policy.adoc` — jurisdictional policies (`Confium::Policy`),
  FIPS 140 mode toggle, algorithm allow-lists.
- [ ] `docs/cnml-profile.adoc` — the CNML certificate profile (required
  extensions, cert roles). **No "OIML" branding in body** — refer to
  CNML as a "reference institutional deployment".
- [ ] `docs/examples/index.adoc` — index over `examples/*.rb` with one
  paragraph of motivation per example.
- [ ] No `require_relative` in any example code — use `require "confium"`.
- [ ] No `double()` in any spec referenced from docs.
- [ ] No "OIML" anywhere; CNML OK as one example.

## Anti-patterns

- Auto-generating the API reference purely from yardocs — curated prose
  beats raw yardoc output for orientation.
- Inlining long Ruby code blocks — link to `examples/*.rb` for full
  source, show only the essence inline.
- Cross-linking to internal `TODO.*` directories.

## Approach

Extract class/method lists from `sig/confium/*.rbs` (the source of
truth for the Ruby surface). For each class, write a 1-paragraph
orientation + key method signatures + one usage snippet. Cross-link to
`examples/` for full demos. One PR; land before TODO 041 so the website
has content to pull.

## Related

- [032-rust-workspace-docs.md](032-rust-workspace-docs.md) — parallel
  work in the Rust workspace.
- [017-sinatra-verifier-quickstart.md](017-sinatra-verifier-quickstart.md)
  — already shipped; this TODO does not touch it.
- [041-software-bindings-specs-pull-through.md](041-software-bindings-specs-pull-through.md)
  — consumes this tree via `fetch-sources.mjs`.
