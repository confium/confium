# 40 — Spec coverage audit + status tags

## Problem

The specs repo had 34 spec files, but 14 of them had no `:status:`
tag at all. Without a status, a reader can't tell whether a spec is
authoritative (accepted), in-progress (draft), or a concept doc
(framework).

This mattered specifically because:
- The 6 implemented specs (threshold-session, async-coordinator,
  share-reshare, transparency-log, frost-p256, elgamal-p256) were
  tagged nothing — readers couldn't tell they had shipped
  implementations.
- The 8 framework / concept docs were tagged nothing — readers
  couldn't tell they were descriptive rather than prescriptive.

## Audit

Cross-referenced every spec against the implementation:

| Spec | Status before | Implementation | Status after |
|------|---------------|----------------|--------------|
| 22-threshold-session | none | confium-tc-core/session.rs | **accepted** |
| 23-async-coordinator | none | confium-coordinator crate | **accepted** |
| 24-share-reshare | none | confium-tc/reshare/ | **accepted** |
| 42-transparency-log | none | confium-transparency crate | **accepted** |
| 51-frost-p256 | none | confium-tc-frost-p256 crate | **accepted** |
| 54-elgamal-p256 | none | confium-tc-elgamal-p256 crate | **accepted** |
| 00-framework-overview | none | (concept doc) | **framework** |
| 01-three-modes | none | (concept doc) | **framework** |
| 02-workspace-organization | none | (concept doc) | **framework** |
| 10-mode1-peer-tc | none | (deployment mode doc) | **framework** |
| 11-mode2-pki-replacement | none | (deployment mode doc) | **framework** |
| 12-mode3-certificate-pki | none | (deployment mode doc) | **framework** |
| 80-cnml-deployment | none | (use case doc) | **framework** |
| 90-security-model | none | (threat model doc) | **framework** |

## Status counts after

- **15 accepted** (was 9): 6 new — all have shipped implementations.
- **10 draft**: 11 existing drafts minus PRODUCTS.adoc (which is a
  meta index, not a spec).
- **8 framework** (new tag): concept / architecture / deployment
  docs that don't need implementation tracking.
- **1 meta**: PRODUCTS.adoc (the product-tagged spec index).

Every spec now has a status. The 4-tuple taxonomy (`accepted` /
`draft` /`framework` / `meta`) is exhaustive and mutually exclusive.

## Identified gaps (no spec exists yet)

The audit also identified implemented crates that have NO
corresponding spec:

- `confium-tc-bls` (threshold BLS — research, may not need spec)
- `confium-tc-ml-kem` (threshold ML-KEM — research)
- `confium-tc-fhe-bfv` (threshold FHE — research)
- `confium-tc-frost-ml-dsa-65` (threshold ML-DSA — research)
- `confium-tc-ecies-p256` (threshold ECIES — needs spec)
- `confium-pki` (X.509 / CSR / CMS — needs spec)
- `confium-attributes` (attribute DSL — needs spec)
- `confium-store` (storage compartment model — needs spec)
- `confium-patterns` (key escrow / revocation — needs spec)

These will be addressed in follow-up TODOs (specs repo PRs).

## Verification

The specs repo's CI builds the site via Asciidoctor → GitHub Pages.
After PR confium/specs#8 merges, all 15 accepted specs will render
with their status badge visible at https://www.confium.org/specs/.

## Status

Done. PR confium/specs#8 opened.
