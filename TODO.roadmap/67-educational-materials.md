# 67 — Educational materials and curriculum

## Audience

Educational materials serve three distinct audiences:

1. **University students** (cryptography, distributed systems, security)
2. **Industry practitioners** (developers, DevSecOps, security engineers)
3. **Institutional decision-makers** (CIOs, regulators, standards bodies)

## Materials by audience

### University curriculum

#### Undergraduate (CS / Crypto intro)

- **Lecture: Threshold Cryptography 101**
  - What it is, why it matters
  - Shamir secret sharing intuition
  - Threshold signing demo with `p256_threshold_signing` example
  - Slides + speaker notes (50 min)

- **Lab: Implement Shamir**
  - Given a Curve25519 group, implement split/recover
  - Verify against Confium's `confium-tc-frost-p256` as oracle
  - 2-3 hours

- **Reading: Confium vision paper**
  - "Confium: A Framework for Multi-Stakeholder Threshold Cryptography"
  - 10-page academic-style paper suitable for course reading

#### Graduate (Applied cryptography, distributed systems)

- **Lecture: Threshold ECDSA vs Threshold Schnorr**
  - MtA protocol, FROST protocol comparison
  - Performance + security tradeoffs
  - Confium's `confium-tc-cmp20` vs `confium-tc-frost-ed25519` as case study

- **Project: Build a Confium plugin**
  - Implement a new threshold scheme as Confium plugin
  - Demo it under NIST MPTS evaluation harness
  - 4-6 weeks

- **Reading list**: FROST paper, CMP20, GG18, CMZ'15, GJKR'99

### Industry practitioners

#### Self-paced tutorials

- **Tutorial: Mode 1 Peer Threshold Signing**
  - 30 minutes; run `p256_threshold_signing` example, modify parameters
- **Tutorial: Mode 2 PKCS#11 Drop-in**
  - 2 hours; deploy coordinator, configure OpenSSL, sign via threshold
- **Tutorial: Mode 3 Mini CNML**
  - Half day; build complete 3-tier cert hierarchy with transparency log

#### Workshops

- **"Threshold Crypto for Enterprise"** — 1-day workshop
  - Target: DevSecOps engineers
  - Hands-on: PKCS#11 server, transparency log, PQ migration
- **"Threshold PKI for Regulators"** — 1-day workshop
  - Target: regulatory technology leads
  - Concepts: sovereignty, transparency, compelled-issuance defense

#### Certification (future)

- **Confium Certified Developer** — implements plugins, integrations
- **Confium Certified Operator** — deploys/manages coordinator infrastructure

### Institutional decision-makers

#### White papers

- **"Why Threshold Cryptography for International Institutions"**
  - 20-page strategic document
  - Audience: treaty organization CIOs
  - Case study: OIML CNML
- **"PQ Migration Without Fork-Lift Upgrades"**
  - Audience: enterprise CIOs facing PQ deadline
  - Confium's composite signature approach

#### Conference talks

- **RSA Conference** (annual): "Threshold PKI in Production"
- **Real World Crypto** (annual): research contributions
- **NIST MPTS workshops**: Confium as reference implementation

## Open educational resources

All materials are CC-BY-4.0 (free to use, adapt, redistribute with
attribution). Hosted at `https://learn.confium.org`.

### Source formats

- Slides: AsciiDoc → reveal.js (preserves source control)
- Labs: Markdown + runnable examples
- Workshops: Markdown + Docker images
- Reading lists: BibTeX in `docs/education/bibliography.bib`

## Translations

Priority languages for educational materials:

1. English (canonical)
2. French (BIML official language)
3. German (PTB partner)
4. Chinese (NIM partner)
5. Japanese (NMIJ/AIST partner)
6. Spanish (LATAM expansion)

Translations are informational; English is authoritative for technical
content per `TODO.roadmap/50-internationalization.md`.

## Course adoption program

Universities teaching with Confium:

- Listed in `docs/education/adopters.md`
- Ribose provides: guest lectures (when feasible), example datasets,
  office hours for instructors
- Anti-goal: Confium becomes dependent on any single university

## Anti-goals

- **Not** proprietary certifications ($$$) — open materials
- **Not** vendor lock-in via training — graduates can use any threshold system
- **Not** "Confium 101 only" — also publish research-frontier material

## References

- `TODO.roadmap/47-documentation-strategy.md`
- `TODO.roadmap/50-internationalization.md`
- `TODO.roadmap/45-integration-examples.md`
