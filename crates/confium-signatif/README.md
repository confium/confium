# confium-signatif

Implementation of the [SIGNATIF](https://signatif.github.io) framework
(Sealed Interoperable Graduated Non-repudiable Anchored Trust
Infrastructure Framework, ISO/TC 154 working draft) on top of the Confium
cryptographic substrate.

SIGNATIF is the framework; Confium is the implementation tool; domain
schemes (e.g. CNML for metrology) adopt the framework through this crate:

- **Trust graph** — delegation DAG from root trust authorities through
  delegated authorities to end certificates, with path-finding that
  collects every valid verification path and validates signature and
  scope narrowing at each link.
- **Trust anchor bundles** — versioned, signed, offline-distributable
  root sets with quorum metadata.
- **Trusted artifacts** — co-signature blocks tagged by trust dimension,
  all attesting the same canonical payload hash; living artifacts
  accumulate dimension attestations over time.
- **Verification pipeline** — ordered hard and soft checks, an objective
  coverage report, and scheme-defined classification plus verifier
  acceptance policies producing graduated trust decisions.
- **Revocation** — signed CRLs, artifact-to-authority-state hash
  bindings, transitive propagation, and forward/reverse queries.
- **Ceremony records** — verifiable transcripts of threshold ceremonies.
- **Registries** — the five scheme-maintained registries (dimensions,
  algorithms, ceremony types, format profiles, scope dimensions).
- **Delivery** — machine-readable passports, challenge-response, and
  transparency-log reference discovery.

Everything verifies offline against a trust anchor bundle: no phone-home,
no proprietary component.

## Composing domain data models

Two worked examples compose external data models with the framework
(the informative annexes G and H):

- **W3C Verifiable Credentials** (Annex G): the VC is the SIGNATIF
  payload and co-signatures serve as its proof — see
  `examples/cnml_profile.rs`.
- **EU Digital Product Passport** (Annex H): the DPP record is the
  payload, manufacturer + engineer attestations converge on it, and
  the DPP registry maps to the M-of-K multi-operator transparency
  policy — see `examples/dpp_composition.rs`.

Run them:

```sh
cargo run -p confium-signatif --example cnml_profile
cargo run -p confium-signatif --example dpp_composition
```
