# Detached signatures

This directory holds detached PGP signatures over the plugin artifact (the
`.dylib`/`.so`/`.dll` referenced by `manifest.toml`'s `artifact.url`).

A signature file is named `<publisher>.asc`, where `<publisher>` matches a
publisher identifier from the top-level `index.toml` `publishers` list and
a public key file under [`publishers/`](../../../../publishers/) (e.g.
`publishers/ribose.asc`).

## Multiple signatures

Multiple publishers may endorse the same artifact by each placing a
signature here. The Confium install policy is satisfied when **at least
one** signature verifies against a publisher the user trusts (see
[`trust-roots.toml`](../../../../trust-roots.toml) for the default trust set).
Endorsements from additional publishers strengthen, but never weaken, trust.

## How a signature is produced

```sh
gpg --local-user <publisher-key-id> \
    --detach-sign --armor \
    --output sigs/<publisher>.asc \
    libcfm-botan-3.2.0.dylib
```

The signature is over the raw artifact bytes, not over the manifest. The
manifest is verified separately against the artifact via `artifact.sha256`.

## Status

This is a placeholder directory. No real signatures have been uploaded yet.
The botan 3.2.0 entry is scaffolding; once the `confium-publish` tool and
the signing ceremony land, real detached signatures from `ribose` and `ni4`
will replace this file.
