# 00 — Vision and Mission

## What Confium is for

Confium exists to **accelerate NIST threshold-cryptography (TC) standardization** by giving cryptographic researchers a single, application-ready substrate on which their schemes can be implemented once and immediately reach real-world users.

Source: NIST MPTS 2020 presentation by Ribose ("Confium: an open-source framework to support threshold cryptography standardization").

## The problem

Threshold cryptography has been stuck in academic-paper purgatory for two decades:

1. Researchers publish a scheme (GG18, CMP20, FROST, ROAST, …).
2. To take it to production, they have to either:
   - Convince Botan / OpenSSL / BoringSSL to accept a patch — a multi-year political and technical battle most lose.
   - Build a custom application — which never reaches users.
3. Standardization bodies (NIST MPTS) end up evaluating schemes against ad-hoc implementations with no common API, no common test harness, no common deployment path.
4. The result: good schemes die in papers; bad schemes reach users because they happened to ship first.

## The Confium play

Make the **crypto-primitive boundary pluggable**. A researcher implements their TC scheme as a Confium provider plugin. The plugin exposes Confium's standard threshold-signature / threshold-KEM API. The application (Thunderbird → RNP → Confium) calls Confium, which routes to whatever plugin the user installed. The researcher's scheme is now reachable from 35M+ Thunderbird installations **without modifying Thunderbird, RNP, Botan, or OpenSSL**.

This **decouples four stages** that are currently tangled together (slide 3 of the deck):

| Stage | Today | With Confium |
|---|---|---|
| **Design** | Cryptographer publishes | Cryptographer publishes |
| **Implementation** | Must land inside Botan/OpenSSL | Anyone (including the researcher) writes a plugin |
| **Distribution** | Bundled with a major library | Distributed via the Confium registry (static site) |
| **Adoption** | Years after design | Days after design |

## The two audiences

1. **Cryptographers** — the primary users. They want to test-drive their scheme in real apps, run benchmarks against competing schemes, get their work standardized and deployed. Confium's job: make this take a weekend, not a multi-year campaign.

2. **End users / applications** — Thunderbird, RNP, eventually mail clients, code-signing tools, HSM-fronted services. They want one stable crypto API, the ability to swap algorithms without recompiling, and a credible trust path for installing third-party plugins.

Confium's design has to serve both — the cryptographer's plugin authoring experience has to be excellent, AND the end-user trust model has to be defensible.

## The NIST angle specifically

NIST MPTS evaluates candidate TC schemes against common criteria. If every candidate has a Confium plugin exposing the same API, NIST can:
- Benchmark them apples-to-apples on identical workloads
- Run conformance and interop tests against shared vectors
- Publish results that map directly to deployable artifacts

Confium is, in effect, the **reference test harness** for MPTS. That positioning is what makes this project matter to NIST funding-wise (MOSS, NLNet) and to Ribose's broader OpenPGP work.

## What success looks like

1. NIST MPTS publishes candidate schemes with Confium plugin implementations.
2. At least one major application (Thunderbird / RNP) ships a Confium-backed feature that uses a threshold scheme.
3. Independent plugin authors publish TC schemes through the Confium registry and reach real users.
4. The Confium registry becomes a credible CPAN/CTAN-style distribution point for crypto algorithms, including but not limited to TC.

## What Confium is NOT

- Not a cryptography library (it doesn't implement algorithms; plugins do).
- Not a competitor to Botan / OpenSSL / BoringSSL (it bridges to them).
- Not a replacement for HSMs (it integrates with them as Store plugins).
- Not just an OpenPGP thing (OpenPGP/RNP is the launch vehicle, but the framework is general).

## Reference

- `TODO.finalize/01-gap-analysis.md` — current algorithm coverage against RNP
- `TODO.roadmap/04-threshold-cryptography.md` — the TC-specific design
- `TODO.roadmap/09-nist-evaluation-harness.md` — how NIST uses Confium
