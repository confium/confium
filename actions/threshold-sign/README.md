# `confium/threshold-sign` — GitHub Action

Threshold-sign artifacts in your CI pipeline using Confium's CMP20 /
GG18 in-process DKG + sign. Produces standard 64-byte ECDSA-P256
signatures verifiable by OpenSSL, npm, cosign, or any RFC 3279
verifier.

## Why threshold signing in CI?

Single-key CI signing has a fundamental problem: the signing key
has to live somewhere the runner can access. That somewhere is
either:

- **In a CI secret** — every maintainer with admin access can
  exfiltrate it.
- **In an HSM** — expensive, hard to operate, and the runner still
  has to authenticate to it (so the auth credential is the new key).
- **In an OIDC-issued token** — good for *authentication*, doesn't
  solve *what key gets used*.

Threshold signing solves this differently: the key never exists in
full on any one host. The CI runner holds one share; a quorum of
signers (release engineer's laptop, security officer's HSM,
independent CI bot) hold the others. The CI alone can't sign.

## Usage

```yaml
- uses: confium/threshold-sign@v1
  with:
    shares: path/to/share-blob.json      # one of N shares
    threshold: 3                          # 3-of-N quorum required
    message: path/to/release.tar.gz       # sign this file
    scheme: cmp20                         # or gg18
    out: release.tar.gz.sig               # 64-byte (r || s) signature
```

The action auto-installs `confium-cli` from crates.io if it's not
already on the runner (cached via `actions/cache` for follow-up
runs).

## Production setup

### 1. Generate the threshold keyset once

```sh
$ confium tc keygen --scheme cmp20 --threshold 3 --party-count 5 --out keyset.json
# keyset.json contains 5 shares + the joint public key.
# Distribute: 1 share to CI, 1 to release engineer, 1 to security
# officer, 1 to backup HSM, 1 to auditor.
```

### 2. Store the CI share as a GitHub Actions secret

Each share blob is 71 bytes; encode as base64 and store as
`CONFIUM_CI_SHARE` in the repository's Actions secrets. The
workflow decrypts the share on the runner and writes it to a
temporary file the action can read.

### 3. Wire up the quorum

CI alone can't sign — it only has 1 of 3 shares. The other two
signers participate via:

- **HTTP ceremony endpoint** (a small service running on each
  signer's machine that receives signing requests, validates them,
  and contributes its share's signature).
- **Manual ceremony** (release engineer runs `confium tc sign`
  locally with their share + the CI share's partial signature).

The first option is what most production deployments do; the
second is the fallback for air-gapped environments.

### 4. Verify in downstream jobs

The signature is a normal P-256 signature; verify with OpenSSL:

```sh
openssl dgst -sha256 -verify publisher-pubkey.pem \
             -signature release.tar.gz.sig release.tar.gz
```

## Inputs

| input | description | required | default |
|---|---|---|---|
| `shares` | Path to a JSON share file from `confium tc keygen`. | yes | — |
| `threshold` | T — must match the keygen threshold. | yes | — |
| `message` | Path to the message file. Reads from stdin if empty. | no | `""` |
| `scheme` | `cmp20` or `gg18`. | no | `cmp20` |
| `out` | Path to write the signature. Default: stdout. | no | `""` |

## Security notes

- **Never commit share blobs to git.** Use OIDC-issued credentials
  to fetch the CI share from a secret store at workflow runtime.
- **Rotate shares** when CI runners are decommissioned. Confium
  supports proactive share refresh without changing the joint
  public key.
- **Audit-log every ceremony.** Wire `Confium::Audit.sink` to a
  transparency log (RFC 6962) anchored to Bitcoin via OTS.

## See also

- [Confium CLI docs](https://www.confium.org/cli/)
- [Threshold code signing blog post](https://www.confium.org/blog/threshold-code-signing/)
- [Code signing example](https://github.com/confium/confium-ruby/blob/main/examples/code_signing.rb)

## License

BSD-2-Clause.
