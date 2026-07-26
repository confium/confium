# 52 — Packaging and distribution

## Distribution channels

Confium ships through multiple channels for different audiences:

| Channel | Audience | Format |
|---|---|---|
| **crates.io** | Rust developers | Cargo crate per package |
| **GitHub Releases** | System administrators | Static binaries per platform |
| **npm** | Web/browser developers | `@confium/confium-wasm` package |
| **Maven Central** | Java/JCE consumers | `.jar` with JNI bindings |
| **RubyGems** | Ruby consumers | `confium-ruby` gem (existing) |
| **PyPI** | Python consumers | (future) `pyconfium` |
| **Homebrew** | macOS users | `brew install confium` |
| **APT** | Debian/Ubuntu | `apt install confium` |
| **MSI** | Windows | `confium.msi` installer |
| **Nixpkgs** | Nix users | `nixpkgs.confium` |
| **Docker** | Container users | `ghcr.io/confium/confium` image |

## crates.io publishing

Per-crate, automated via release-plz on push to main.

Workspace `[workspace.package]` provides shared metadata:

```toml
[workspace.package]
version = "0.3.0"
edition = "2024"
rust-version = "1.85"
authors = ["Ribose Open <open.source@ribose.com>"]
license = "BSD-2-Clause"
homepage = "https://www.confium.org/"
repository = "https://github.com/confium/confium"
categories = ["authentication", "cryptography"]
```

Per-crate metadata adds: `description`, `documentation`, `keywords`,
`readme`, `metadata.docs.rs`.

## Static binary release

GitHub Releases with 6 artifacts per tag (release-binary.yml):

- `confium-linux-x86_64.tar.gz` (musl, fully static)
- `confium-linux-aarch64.tar.gz` (musl, fully static)
- `confium-macos-x86_64.tar.gz`
- `confium-macos-aarch64.tar.gz` (Apple Silicon)
- `confium-windows-x86_64.zip`
- `confium-windows-aarch64.zip` (when Windows aarch64 runners available)

Each tarball contains:
- `confium` (CLI binary)
- `LICENSE`
- `README.txt` (pointers to docs.confium.org)

## npm publishing

`@confium/confium-wasm` on npm (wasm.yml):

```json
{
  "name": "@confium/confium-wasm",
  "version": "0.3.0",
  "main": "confium_wasm.js",
  "types": "confium_wasm.d.ts",
  "files": ["confium_wasm_bg.wasm", "confium_wasm.js", "confium_wasm.d.ts"]
}
```

Consumed by browser-based director/lab/manufacturer UIs.

## Maven Central (Java/JCE)

`com.confium:confium-jce-provider`:
- `.jar` containing JNI bindings
- Native libraries for major platforms (.so, .dylib, .dll)
- Maven metadata pointing at GitHub Releases for sources

## RubyGems

`confium-ruby` is published separately from `confium-ruby/` repo. Existing
pipeline handles this.

## PyPI (future)

`pyconfium` PyO3-based bindings. Future work.

## Homebrew tap

`homebrew-confium` tap with formula:

```ruby
class Confium < Formula
  desc "Open-source framework for threshold cryptography"
  homepage "https://confium.org"
  url "https://github.com/confium/confium/releases/download/v0.3.0/confium-0.3.0.tar.gz"
  sha256 "..."
  depends_on "openssl@3"
  def install
    bin.install "confium"
  end
end
```

## APT repository

Hosted at `apt.confium.org` (Debian package). Published via reprepro
on every release. Provides:
- `confium` (CLI + libraries)
- `libconfium-dev` (development headers + static libs)
- `confium-dbgsym` (debug symbols)

## Nixpkgs

`pkgs/tools/security/confium/default.nix`. Updates via Nixpkgs PR
on every release.

## Docker image

`ghcr.io/confium/confium`:
- Multi-arch (amd64, arm64)
- `:latest`, `:0.3`, `:0.3.0`, `:0.3.0-bookworm`, `:0.3.0-alpine`
- Provides the CLI + coordinator service
- Volume-mounted config + HSM socket

## Provenance and SBOM

Every release artifact ships with:
- **SLSA Provenance**: signed metadata describing the build
- **SBOM** (CycloneDX format): all dependencies + versions
- **SHA256SUMS** + SHA256SUMS.sig (signed by Ribose release key)

## Versioning policy

Semver 2.0.0 strict. 0.x allows minor breaking; 1.0+ commits to back-compat.

MSRV policy: minimum supported Rust version. Bumped only with minor version
bump. Documented in `rust-toolchain.toml` and per-crate `rust-version`.

## Anti-goals

- **Not** bundling dependencies in static binaries (use dynamic linking
  where possible for security updates)
- **Not** supporting legacy platforms (32-bit, very old OS versions)
- **Not** auto-publishing to all channels (some require manual review)

## References

- `TODO.roadmap/26-confium-framework.md`
- `.github/workflows/release*.yml` — actual release workflows
