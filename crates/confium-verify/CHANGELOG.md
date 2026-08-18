# Changelog — confium-verify

All notable changes to the **Confium uverify** product facade are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project follows [Semantic Versioning](https://semver.org/).

For cross-product changes, see the workspace CHANGELOG at <https://github.com/confium/confium/releases>.

## [Unreleased]

### Other

- Release v0.5.1 by @[object]

### Other

- Release v0.5.1 by @[object]
- Release v0.5.0 by @[object]

### Other

- Release v0.5.0 by @[object]

### Added

- The framework layer reaches the Verify product and the browser by @[object]

### Other

- Release v0.5.0 by @[object]

### Added

- The framework layer reaches the Verify product and the browser by @[object]

No unreleased changes yet.

## [0.4.0] — 2026-08-07

### Added
- Real CLI implementations: `confium verify {dkg,sign,verify,psi,dp,...}` now wires to
  underlying crates instead of printing "coming soon".
- Cookbook recipes for verify flows.
- Browser playground at <https://www.confium.org/playground/> for interactive demos.
- Production deployment artifacts (K8s manifests, Docker Compose, Grafana dashboards).
- Per-product CHANGELOG (this file).

### Changed
- Workspace version bumped to 0.4.0; all confium-* crates now require 0.4.0 deps.

## [0.3.0] — 2026-08-07

### Added
- Initial release of the `confium-verify` product facade.
- Re-exports all component crates behind feature flags.
- See <https://www.confium.org/verify/> for the product overview.

### Migration from 0.2.x
- See <https://github.com/confium/confium/blob/main/docs/migrations/0.2-to-0.3.mdx>.
