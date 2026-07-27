# Releasing `@confium/confium-wasm`

This package uses npm's **trusted publishing** model — no long-lived
`NPM_TOKEN` secret. The setup is a one-time per-package ritual; subsequent
releases happen automatically from the `wasm.yml` workflow on tag push.

## First-time setup (do this once)

1. **Build the package locally**:
   ```sh
   wasm-pack build crates/confium-wasm \
     --target bundler \
     --release \
     --scope confium
   ```

2. **First publish (manual)** — creates the package on the npm registry:
   ```sh
   cd crates/confium-wasm/pkg
   npm publish --access public
   ```
   This must be done by an owner of the `@confium` scope on npm.

3. **Configure trusted publishing** on npm:
   - Visit <https://www.npmjs.com/package/@confium/confium-wasm/access>
   - Under **Configured GitHub Actions**, add:
     - **Repository**: `confium/confium`
     - **Workflow**: `.github/workflows/wasm.yml`
     - **Environment**: `release`

4. **Configure the `release` environment** on GitHub:
   - Visit <https://github.com/confium/confium/settings/environments>
   - Create environment `release`
   - (Optional but recommended) Add required reviewers + deployment-branch
     protection (`v*` tags only).

## Subsequent releases

From now on, releasing is just:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The `wasm.yml` workflow will:
1. Build the WASM package via `wasm-pack`
2. Request an OIDC token from GitHub Actions
3. Publish to npm with `--provenance` (so consumers can verify the
   published tarball was built from this repo's source)

## Verifying a release

Once published, consumers can install:

```sh
npm install @confium/confium-wasm
```

And check provenance:

```sh
npm view @confium/confium-wasm --json | jq '.dist.attestation'
```

## Why trusted publishing?

The classic flow (long-lived `NPM_TOKEN` secret) has two problems:
- The token leaks if the repo is compromised.
- The token expires and breaks releases silently.

Trusted publishing fixes both: npm trusts a *transient* OIDC token
minted by GitHub Actions for this specific workflow + environment. No
secret to leak, nothing to expire.

See <https://docs.npmjs.com/guides/open-source-from-github#enabling-trusted-publishing-on-npm>
for npm's docs on this flow.
