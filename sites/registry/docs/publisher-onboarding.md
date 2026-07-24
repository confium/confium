---
layout: default
title: Publisher onboarding
---

# Publisher onboarding

Publishers are the entities whose signatures vouch for plugin artifacts.
Onboarding a new publisher is a PR that adds their public key and anchors
their identity in the trust roots. It requires out-of-band verification of
the key fingerprint — this is the human step the model relies on.

## 1. Generate a publisher key

Use a long-lived OpenPGP key. It is your publisher identity; rotating it
invalidates every signature you have made, so generate it on dedicated
hardware (a YubiKey, smartcard, or offline machine) if at all possible.

```sh
gpg --gen-key
```

Record the key ID and fingerprint:

```sh
gpg --list-secret-keys --keyid-format=long
```

## 2. Export the public key

```sh
gpg --armor --export <key-id> > publishers/<name>.asc
```

`<name>` is a short, lowercase identifier (e.g. `ribose`, `ni4`). It must
be unique among existing publishers (check the `publishers/` directory).

## 3. Add the trust-root entry

Append a `[[publisher]]` block to [`trust-roots.toml`](../trust-roots.toml):

```toml
[[publisher]]
name = "<name>"
key-id = "0x<long key id>"
fingerprint = "<formatted fingerprint with spaces>"
key-url = "/publishers/<name>.asc"
```

## 4. Out-of-band verification

Registry maintainers must verify the key fingerprint out of band before
merging your PR. Acceptable channels:

- A signed email from an address already associated with you, sent to the
  registry maintainers.
- A post on a platform where you are already established identity (e.g.
  Keybase, a verified social account, your project's official channel)
  quoting the fingerprint.
- An in-person or video-call key signing.

This step exists because the static trust model's integrity depends on the
publisher keys in `publishers/` actually belonging to who they claim to
belong to. There is no CA to fall back on.

## 5. Open the PR

The PR adds:

- `publishers/<name>.asc`
- A `[[publisher]]` block in `trust-roots.toml`

In the PR description, include:

- The key fingerprint.
- A pointer to the out-of-band verification (a link to the signed email, a
  screenshot of the Keybase post, etc.).
- A short note on what plugins you intend to publish.

## 6. Merge

Once maintainers verify the fingerprint and sign off, the PR is merged and
the publisher becomes globally trusted for all fresh installs. Existing
installs pick up the new trust root on their next `confium trust refresh`
(or when the user runs `confium trust add <name>`).

## After onboarding

You can now [publish plugins](publishing.md) signed with your key.
