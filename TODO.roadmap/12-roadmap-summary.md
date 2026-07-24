# 12 — Roadmap Summary

## At-a-glance

| Doc | Topic | Status |
|---|---|---|
| [00](00-vision-and-mission.md) | Why Confium exists (NIST TC standardization) | reference |
| [01](01-architecture-overview.md) | Three pillars: Engine, Store, Registry, Network | reference |
| [02](02-workspace-layout.md) | Rust workspace crate layout | proposed |
| [03](03-plugin-contract.md) | FFI contract, versioning, dependencies | partially shipped |
| [04](04-threshold-cryptography.md) | TC session, rounds, DKG (THE headline) | not started |
| [05](05-networking-primitives.md) | Multi-party transport | not started |
| [06](06-module-registry.md) | Static-site plugin catalog | not started |
| [07](07-cli-tools.md) | `confium`, `confium-publish`, `confiumd` | not started |
| [08](08-security-model.md) | Trust, signing, memory, sandboxing | partial (Sensitive shipped) |
| [09](09-nist-evaluation-harness.md) | Test bench for MPTS candidates | not started |
| [10](10-distribution-and-adoption.md) | Phase plan to 1.0 and beyond | in Phase 1 |
| [11](11-governance-and-funding.md) | Project governance | active |

## Critical path to 1.0

```
Phase 1 (now – Q3 2026) — single-party surface
  ✅ Plugin loader + OCP registry
  ✅ Hash, RNG, cipher, AEAD, KDF
  ⏳ Signature, KEM, keyfmt (TODO.finalize #09–#11)
  ⏳ Botan plugin covers full algorithm matrix
  ⏳ First app integration (RNP)
       ↓
Phase 2 (Q4 2026 – Q1 2027) — threshold surface
  ⏳ TC session interface
  ⏳ Networking primitives
  ⏳ Reference TC plugins (FROST, GG18)
       ↓
Phase 3 (Q2 – Q3 2027) — registry and ecosystem
  ⏳ Static-site registry live
  ⏳ CLI install/publish
  ⏳ 3–5 external plugin authors publishing
       ↓
Phase 4 (Q4 2027 – Q1 2028) — production hardening
  ⏳ Sandboxing
  ⏳ Audit logging
  ⏳ 1.0 release
```

## Tactical vs strategic

- **`TODO.finalize/`** = tactical, one-PR-per-file coding tasks. Stuff you can do today.
- **`TODO.roadmap/`** = strategic, multi-quarter direction. The why behind the what.

When picking up work: read the relevant roadmap doc first (for context), then the matching finalize doc (for the specific PR).

## What "done" means

Confium is done when:

1. NIST MPTS publishes candidate threshold schemes as Confium plugins.
2. Thunderbird (or another major OpenPGP app) ships a Confium-backed feature using a threshold scheme.
3. Independent plugin authors publish through the Confium registry and reach real users.
4. An enterprise deploys Confium in production with confidence in the security model.

We're at step 0. Each roadmap doc above describes how to get one step closer.

## What's intentionally missing from this roadmap

- **Concrete Gantt charts** — open-source projects that try to plan to the week fail; we plan to the quarter.
- **Specific algorithm picks** — Confium is algorithm-neutral. The community picks.
- **Hard feature commitments** — items may slip between phases based on funding, contributor availability, and NIST timing.

## Reference

- `TODO.finalize/README.md` (if you write one) — index of tactical tasks
- NIST MPTS 2020 presentation — the originating slide deck
