# Confium domain glossary

The nouns and verbs this codebase uses, so architecture reviews and
new contributors share one vocabulary. Architecture terms (module,
interface, depth, seam, adapter, leverage, locality) come from the
`/codebase-design` skill; this file is the *domain* layer on top.

## SIGNATIF framework layer (`confium-signatif`)

- **Trusted artifact** — the signed document under verification:
  a canonical payload hash plus dimension-tagged co-signature blocks
  (`artifact::TrustedArtifact`).
- **Trust graph** — the delegation DAG of authorities (roots,
  federated authorities, end certificates) that path-finding walks to
  justify a co-signature (`graph::TrustGraph`).
- **Anchor bundle** — the versioned, signed set of trust anchors a
  verifier bootstraps from (`bundle::TrustAnchorBundle`).
- **Registry** — the five scheme-maintained registries (dimensions,
  algorithms, ceremony types, format profiles, scope dimensions)
  a scheme publishes (`registry::Registry`).
- **Pipeline** — the ordered hard/soft check engine over the four
  trust inputs (`pipeline::Pipeline`). Hard checks fail the run;
  soft checks downgrade the label.
- **Coverage report** — the objective record of what was checked
  (`coverage::CoverageReport`).
- **Classification label** — the scheme's pure function from coverage
  report to label; the reference ladder is `unverified → basic →
  verified → attested → certified` (`coverage::ClassificationLabel`).
- **Acceptance** — the verifier's own decision: does this label pass
  *my* policy, in this decision context (`coverage::Acceptance`).
- **Verdict** — the graduated outcome triple every surface serializes:
  coverage report + classification label + acceptance decision
  (`verify::Verdict`).
- **Verifier fleet** — which signature algorithms a verifier checks,
  as named policy rather than hand-written code: `ed25519` (the
  browser profile) or `ed25519_p256` (the default registry's
  classical set) (`verify::Fleet`). The `SignatureVerifier` seam stays
  open for threshold or HSM fleets.
- **Surface** — a transport that exposes verification: Rust library,
  browser WASM, HTTP, CLI, Python. Surfaces are adapters; the
  verification assembly lives in `verify::verify_trusted_artifact`.

## Products

The workspace is organized into six products — **Threshold** (T-of-N
signing), **Transparency** (append-only logs and proofs), **PKI**
(threshold CA and PKCS#11/OpenSSL/JCE bridges), **Keyless** (OIDC
release signing), **Privacy** (PSI/DP/MPC), **Verify** (the five
surfaces). See `docs/<product>/` in this repo and
`TODO.restructure/` for the restructuring history.
