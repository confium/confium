---
layout: default
title: Trust model
---

# Trust model

Confium's registry is a static catalog. Trust does not come from the
registry being "official" — it comes from **publisher signatures** verified
against a set of **trust roots** the user has accepted. The registry only
provides the key material and the default trust set; the verification
itself happens on the user's machine at install time.

## The three layers

1. **Publisher identity** — an OpenPGP key registered under
   [`publishers/`](../publishers/). Each publisher has one
   `publishers/<name>.asc` file. A publisher's canonical identifier is the
   key fingerprint, not the short name (names can collide; fingerprints
   cannot).
2. **Artifact signature** — a detached PGP signature placed under
   `plugins/<name>/<version>/sigs/<publisher>.asc`. Multiple publishers may
   sign the same artifact (multi-publisher endorsement). The signature is
   over the raw artifact bytes.
3. **Trust roots** — [`trust-roots.toml`](../trust-roots.toml) lists the
   publisher keys the official registry vouches for. This is the default
   trust set shipped with fresh installs. Users can override it locally in
   `~/.config/confium/trust.toml`.

## Install policy

An artifact installs without prompting only if **at least one** detached
signature in its `sigs/` directory verifies against a publisher the user
trusts. The threshold is configurable via `min-signatures` in
`trust-roots.toml`; the default is `1`.

If no trusted signature is present, the install is refused with
`Error::UntrustedPlugin`. The user can then either:

- `confium trust add <publisher>` to accept the publisher locally (after
  out-of-band verification of the key fingerprint), or
- Decline the install.

## Why static

A static registry has no service to compromise. The trust root is the git
history of this repository (every change is reviewable and revertable) plus
the PGP signatures on the artifacts themselves. An attacker who hijacks
the GitHub Pages deployment can serve altered manifests, but cannot forge
publisher signatures — and the user's client verifies signatures against
the trust roots it already has, not against whatever the registry happens
to serve today.

This is why the trust roots are shipped with the client and only updated
deliberately (via `confium trust`), not silently.

## Mirrors

Anyone can mirror this registry by forking the repository and hosting it
via their own GitHub Pages, S3 bucket, or CDN. Mirrors add their URLs to a
plugin's `manifest.toml` `artifact.mirrors` array so that `confium install`
can fall back if the primary URL is unavailable.

Mirroring does not weaken trust: the publisher signatures and the user's
trust roots are the same regardless of where the bytes come from. A mirror
that serves a tampered artifact fails signature verification just as a
compromised primary would.

See [TODO.roadmap/08-security-model.md](https://github.com/confium/confium/blob/main/TODO.roadmap/08-security-model.md)
for the broader security model.
