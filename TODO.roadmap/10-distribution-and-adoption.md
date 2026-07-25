# 10 — Distribution and Adoption

## The chicken-and-egg problem

Confium only matters if:
1. Real apps use it (Thunderbird/RNP is the launch vehicle, but not the only target).
2. Plugin authors publish to the registry.
3. End users install plugins.
4. NIST evaluators use the harness.

Each audience waits on the others. Breaking the cycle requires deliberate sequencing.

## Phase 0 (done) — Framework foundation

- Plugin loader with OCP registry (`0.2.0` shipped)
- Hash, RNG, cipher, AEAD, KDF interfaces (`0.3.0`, in flight)
- Error chain, Sensitive memory (`0.2.0` shipped)

## Phase 1 — Single-party surface (target: end of Q3 2026)

- Land signature, KEM, keyfmt interfaces (TODOs #09–#11)
- Ship Botan and OpenSSL provider plugins (in their separate repos) covering the full algorithm matrix
- Get RNP using Confium for at least one algorithm class (probably hash + cipher first, then signature)
- First NIST demo: "look, Botan's algorithms work through Confium from inside Thunderbird"

Success criterion: an external contributor writes a non-trivial Confium plugin and it works.

## Phase 2 — Threshold surface (target: end of Q1 2027)

- Land TC session interface (#04)
- Land networking primitives (#05)
- Implement 2-3 reference TC plugins (FROST-ed25519, FROST-ECDSA-P256, GG18)
- First NIST MPTS demo: "5-party FROST signing session, executed through Confium, with full Byzantine-fault detection"

Success criterion: a TC researcher publishes a scheme as a Confium plugin and it runs without modifying Confium.

## Phase 3 — Registry and ecosystem (target: end of Q3 2027)

- Stand up the static-site registry (#06)
- Stand up the CLI install/publish commands (#07)
- Recruit 3-5 plugin authors to publish through the registry
- First NIST conformance test run using the harness (#09)

Success criterion: an end user installs a third-party plugin from the registry and it works in their mail client.

## Phase 4 — Production hardening (target: end of Q1 2028)

- Sandboxing (WASM or out-of-process) — #08
- Audit logging
- 1.0 release of `confium-api`, `confium-core`, `confium-ffi`
- Performance benchmarks within 10% of direct Botan usage

Success criterion: an enterprise deploys Confium in production.

## Plugin ecosystem strategy

### Launch partners

- **Ribose** maintains `confium-botan` and `confium-openssl` (full algorithm coverage).
- **CFRG FROST implementers** maintain `confium-frost-*` (threshold signatures).
- **Academic teams** recruited via NIST MPTS meetings to publish their schemes.

### In-repo plugins (the `plugins/` directory)

For testing and demonstration:

- `plugins/mock-hash` — deterministic hash for tests
- `plugins/mock-cipher` — XOR cipher for tests
- `plugins/mock-rng` — seeded RNG for tests
- `plugins/example-tc-frost` — minimal FROST impl showing the TC plugin pattern

These are NOT for production. They live in the main repo so tests can use them without external deps.

### Plugin SDK

`crates/confium-api/` exposes helpers that make plugin authoring ergonomic:

```rust
use confium_api::plugin;

#[plugin::interface(name = "hash", version = 0)]
impl HashProvider {
    fn create(algo: &str) -> Result<Self> { ... }
    fn update(&mut self, data: &[u8]) -> Result<()> { ... }
    fn finalize(&mut self) -> Result<Vec<u8>> { ... }
}

confium_api::export!();
```

The proc-macro generates the FFI boilerplate (`cfmp_hash_create`, etc.). Plugin authors focus on the algorithm, not the wire protocol.

## Documentation strategy

- `docs/plugin-author-guide.md` — step-by-step tutorial for writing a plugin
- `docs/application-integration.md` — how to embed Confium in an application
- `docs/api/rust/` — rustdoc
- `docs/api/c/` — cbindgen-generated headers + Doxygen
- `docs/api/ruby/` — Ruby bindings docs
- `docs/algorithms/` — per-algorithm reference (which interfaces, which plugins, which vectors)
- `docs/registry/` — registry policy, publisher onboarding

All docs are AsciiDoc (`*.adoc`), built to HTML via Antora and deployed to `docs.confium.org` (GitHub Pages).

## Demo applications

- `examples/rust-sign-demo/` — sign a message with a Confium-loaded RSA key
- `examples/ruby-hash-bench/` — hash 1MB through Confium via Ruby bindings
- `examples/c-tc-demo/` — 3-party FROST signing via C API
- `examples/thunderbird-integration/` — proof-of-concept patch for Thunderbird's RNP integration

## Funding and sustainability

- **MOSS (Mozilla Open Source Support)** — already funded the foundational work
- **NLNet / NGI Zero** — already funded privacy-enhancing-tech work
- **NIST MCTS** — potential direct funding for harness development
- **Ribose** — ongoing in-kind maintenance
- **Industry sponsors** — HSM vendors (Yubico, Thales), cloud KMS providers, mail client vendors (Mozilla) — to be recruited as Phase 3 approaches

Funding model: open-source core, optional commercial support contracts through Ribose. Plugin authors can charge for their plugins if they choose (Confium doesn't enforce a license).

## Anti-goals

- Confium is not a service. No SaaS deployment.
- Confium is not a single-vendor product. Governance must be multi-stakeholder by Phase 3.
- Confium is not a "Mozilla project" or a "Ribose project" — it's a community project that Mozilla and Ribose happen to fund.

## Reference

- All other `TODO.roadmap/*.md` documents
- `TODO.finalize/01-gap-analysis.md` for current algorithm coverage
