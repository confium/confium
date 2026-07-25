# Publishers

This directory holds the long-term public keys of plugin publishers. Each
publisher is identified by a short, lowercase name (e.g. `ribose`, `ni4`)
and has exactly one file here: `<name>.asc`, containing their ASCII-armored
OpenPGP public key.

A publisher is listed in a plugin's `index.toml` `publishers` array and in
the top-level [`index.toml`](../index.toml) `[[plugin]]` entries. A
publisher's key is anchored as trusted via
[`trust-roots.toml`](../trust-roots.toml).

## Format

Files are ASCII-armored OpenPGP public key blocks. Example:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBF...
... (full key material) ...
-----END PGP PUBLIC KEY BLOCK-----
```

## Adding a new publisher

See [Publisher onboarding](../docs/publisher-onboarding.md). In short:

1. Generate a keypair locally (`gpg --gen-key` or your preferred OpenPGP
   implementation). The key should be long-lived (it is your publisher
   identity) and stored offline or on a hardware token.
2. Export the public key: `gpg --armor --export <key-id> > ribose.asc`.
3. Open a PR adding `publishers/<name>.asc` and a `[[publisher]]` entry to
   `trust-roots.toml`.
4. Registry reviewers verify the key fingerprint out-of-band (e.g. via a
   signed email, keybase, or an in-person signing) before merging.

## Key rotation

Publisher keys should be long-lived. If a key is compromised:

1. The publisher opens a PR removing the `<name>.asc` file and the matching
   entry from `trust-roots.toml`.
2. Plugins previously signed by that key remain installable only if another
   trusted publisher has counter-signed them; otherwise they become
   untrusted until re-signed.
3. The publisher onboards a fresh key via the normal PR flow.

The old key material stays in git history as an audit trail.

## Status

This directory currently contains only the placeholder
[`ribose.asc.placeholder`](ribose.asc.placeholder). Real publisher keys
will be added as part of publisher onboarding.
