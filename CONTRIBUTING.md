# Contributing to Confium

Thank you for your interest in contributing to Confium! This document covers the basics. For design context, see [Architecture](docs/architecture.mdx) and [Product Architecture](docs/architecture/products.mdx).

## Development Setup

Confium requires Rust stable (1.85+ for edition 2024). The toolchain is pinned via `rust-toolchain.toml`. To enter a Nix-based dev shell with all dependencies:

```sh
nix develop
```

Or install Rust directly via [rustup](https://rustup.rs/).

## Workspace structure

Confium is organized into **6 products** (Threshold, Transparency, PKI, Keyless, Privacy, Verify), each with a **facade crate** that re-exports its component crates:

| Product | Facade | Component crates |
|---------|--------|-----------------|
| Threshold | `confium-threshold` | tc-core, coordinator, tc-keys, tc-cmp20, tc-gg18, tc-frost-*, signerd |
| Transparency | `confium-transparency` | transparency, log-server, log-monitor, log-edge |
| PKI | `confium-pki` | pki, composite, attributes, pkcs11-server, openssl-provider, jce-provider, tls-signer |
| Keyless | `confium-keyless` | oidc |
| Privacy | `confium-privacy` | privacy, crypto-zk, crypto-vss, ring |
| Verify | `confium-verify` | wasm, verify-server, composite, python, node, go |

See [docs/architecture/repo-strategy.mdx](docs/architecture/repo-strategy.mdx) for why we stay in one workspace.

## Common commands

```sh
cargo build --workspace                       # build all crates
cargo test --workspace                        # run all tests (1733+)
cargo fmt --all --check                       # format check
cargo clippy --workspace --all-targets        # lint
cargo doc --workspace --no-deps               # doc build
```

Single test: `cargo test -p confium-tc-cmp20 integration`.

## Adding a new crate

1. Create `crates/confium-{name}/` with `Cargo.toml`, `src/lib.rs`, `README.md`
2. Add to workspace `members` in root `Cargo.toml`
3. Add to `[workspace.dependencies]` in root `Cargo.toml`
4. Use `version.workspace = true` for the crate version
5. Run `cargo check -p confium-{name}` to verify

## Adding a new product

1. Create the facade crate (`confium-{product}`)
2. Add to `confium.github.io/src/data/products/index.ts`
3. Create minisite pages (`confium.github.io/src/pages/{product}/`)
4. Add specs in the `specs` repo
5. Add CLI subcommands in `confium-cli`
6. Update `docs/` with product-specific docs root

See [TODO.restructure/README.phase2.md](TODO.restructure/README.phase2.md) for the last time this was done (6-product restructuring).

## Spec process

Confium follows "specs lead, code follows":

1. Write a draft spec in the [specs repo](https://github.com/confium/specs)
2. Mark `:status: draft`
3. Get at least one maintainer + one external reviewer
4. Move to `:status: accepted`
5. Implement

See [GOVERNANCE.md](GOVERNANCE.md) for the full decision-making process.

## Coding standards

- `#![forbid(unsafe_code)]` on every crate
- `#![warn(missing_docs)]` or `#![allow(missing_docs)]` (with TODO comment) on every crate
- Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`)
- All PRs go through branch → PR → rebase-merge
- Branch protection on `main` (3 required status checks)

## Testing

- Unit tests in `#[cfg(test)] mod tests` within each source file
- Integration tests in `tests/` directory per crate
- Cross-binding integration tests in `scripts/cross-binding-integration-test.sh`
- E2E threshold lifecycle tests in `confium-tc/tests/`

## Reporting issues

- **Bugs**: [Bug report template](https://github.com/confium/confium/issues/new?template=bug_report.md)
- **Features**: [Feature request template](https://github.com/confium/confium/issues/new?template=feature_request.md)
- **Security**: See [SECURITY.md](SECURITY.md) — do NOT open public issues for vulnerabilities
- **Questions**: [GitHub Discussions](https://github.com/confium/confium/discussions)

## License

By contributing, you agree that your contributions are licensed under BSD-2-Clause. No CLA required.

## Funding

Confium is sponsored by [NLnet Foundation](https://nlnet.nl/) and [Mozilla MOSS](https://www.mozilla.org/moss/). See [`.github/FUNDING.yml`](https://github.com/confium/confium/blob/main/.github/FUNDING.yml).
