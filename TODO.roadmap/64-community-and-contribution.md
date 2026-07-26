# 64 — Community and contribution guidelines

## Community values

Confium is an open framework. The community is:

- **Open**: anyone can contribute
- **Respectful**: Code of Conduct applies
- **Technical**: decisions based on merit, not politics
- **Patient**: complex work takes time

## Code of Conduct

Standard [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

Enforcement: Ribose project leads. Reports to `open.source@ribose.com`.

## Contribution paths

### Tier 1: Bug reports and feature requests

Anyone. Open a GitHub issue.

Bug report template:
```
**Describe the bug**: <one paragraph>
**To reproduce**: <steps>
**Expected behavior**: <what should happen>
**Actual behavior**: <what does happen>
**Environment**: Confium version, OS, Rust version
**Additional context**: <logs, screenshots, etc.>
```

### Tier 2: Documentation improvements

Anyone. Open a PR against `docs/` or `TODO.roadmap/`.

Docs review is fast-tracked — no crypto expertise required.

### Tier 3: Code contributions (non-crypto)

For non-cryptographic code: CLI, network transports, store backends,
documentation tooling, CI improvements, tests, examples.

PR review by 1 maintainer. CI must pass.

### Tier 4: Cryptographic contributions

For cryptographic code: threshold schemes, new algorithms, signature
verification, key derivation.

PR review by 2 maintainers. Fuzzing required. NIST MPTS vectors where
applicable. Additional scrutiny per `TODO.roadmap/48-security-audit-checklist.md`.

### Tier 5: Architectural changes

For changes affecting public API, crate boundaries, security model.

Requires an ADR per `TODO.roadmap/61-architecture-decision-records.md`.
Review by all active maintainers.

## Maintainer roles

### Contributor

Anyone with a merged PR. No special rights.

### Triager

Can label/close issues, edit wiki. Earned after several quality
contributions.

### Reviewer

Can approve PRs (non-crypto). Earned after sustained contribution.

### Maintainer

Can merge PRs, can approve cryptographic PRs. Invited by existing
maintainers.

### Lead maintainer

Final say on disputes. Currently Ribose project leads.

## Contribution workflow

1. **Open issue** for non-trivial work (avoid surprise)
2. **Fork and branch** from `main`
3. **Implement** following `TODO.roadmap/60-code-review-checklist.md`
4. **Test** thoroughly: `cargo test --workspace`, new tests for new code
5. **Document**: doc comments, README updates, examples
6. **Commit** with conventional commits
7. **Push** and open PR
8. **Respond** to review feedback
9. **Merge** when approved

## Good first issues

Label `good first issue` on GitHub for issues suitable for newcomers:

- Documentation typos / clarifications
- Test coverage improvements
- Example additions
- Small bug fixes
- Clippy suggestion fixes

## Mentorship

New contributors can request a mentor via Discord/Matrix. Mentor helps
with:
- Setting up dev environment
- Choosing a first issue
- Navigating the codebase
- Understanding the architecture

## Recognition

- **Contributors list** in `README.md` (auto-generated via all-contributors bot)
- **Release notes** mention significant contributions
- **Annual contributor summit** (in person, when feasible)

## Communication channels

- **GitHub Discussions**: long-form Q&A, design discussion
- **Discord/Matrix**: real-time chat
- **Mailing list**: announcements only (low traffic)
- **Office hours**: weekly video call (optional)

## Licensing

Confium is BSD-2-Clause. Contributions must be compatible.

We DO NOT accept GPL-only or AGPL contributions to core Confium.
Per-algorithm crates may use more permissive licenses.

Contributions are licensed under the project's BSD-2-Clause unless
explicitly noted.

## DCO and CLA

- **DCO** (Developer Certificate of Origin): required. `git commit -s`
  signs off that you wrote the contribution.
- **CLA** (Contributor License Agreement): NOT required for Confium.
  BSD-2-Clause is permissive enough.

## Anti-goals

- **Not** accepting contributions without review (no direct commits to main)
- **Not** accepting crypto contributions without 2 maintainer reviews
- **Not** accepting architectural changes without an ADR
- **Not** accepting contributions that violate standards (e.g., MD5)

## References

- `TODO.roadmap/60-code-review-checklist.md`
- `TODO.roadmap/61-architecture-decision-records.md`
- `CONTRIBUTING.md`
- `CODE_OF_CON.md`
- `SECURITY.md`
