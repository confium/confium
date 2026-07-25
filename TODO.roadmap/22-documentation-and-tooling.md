# 22 — Documentation, tooling, and CI hardening

## Documentation site
- Antora/AsciiDoc docs at docs.confium.org (GitHub Pages)
- Plugin author guide, application integration guide, API reference
- cbindgen-generated C header (confium.h) for consumers

## CI hardening
- Fuzzing targets (cargo-fuzz / OSS-Fuzz integration)
- Performance benchmarks comparing overhead vs direct library usage
- Dependabot/Renovate config for automated dep updates
- CODE_OF_CON.md

## Quality
- Unify error codes across crates (currently scattered: core=1-100, tc=0x1000+, sandbox=0x2000+, store=0x1000+)
- Replace Box<dyn Any> downcast with sealed trait (type safety)
- Proto schema for daemon RPC
