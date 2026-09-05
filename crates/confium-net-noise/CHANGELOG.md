# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Bound the handshake with a 10s read deadline by @[object]

### Added

- Noise_XX encrypted transport for coordinator sessions (BREAKING) by @[object]

### Fixed

- Correct unused-dependency findings by @[object]

### Other

- Clippy-clean tamper assertion by @[object]
- Clippy-clean listen_url construction by @[object]
- Clippy-clean lock handling in noise tests by @[object]
