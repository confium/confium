# 016 — Hello-world examples

**Category**: Usability
**Severity**: Medium
**Effort**: Small (1 PR each for Ruby + WASM = 2 PRs)

## Problem

Neither binding ships a runnable "hello world" example. New users have
to read the README, copy-paste snippets, and figure out the rest.

## Acceptance criteria

### Ruby (`examples/`)

- [ ] `examples/transparency_anchor.rb` — anchor a string in a Merkle
     tree, print the root, generate a proof, verify it.
- [ ] `examples/composite_verify.rb` — generate an Ed25519 keypair,
     sign a message, build a composite, verify.
- [ ] `examples/threshold_signing.rb` — Shamir-split a secret, recover
     from 3 of 5 shares.
- [ ] `examples/cert_parse.rb` — parse a PEM cert, print fingerprint +
     validity window.
- [ ] `examples/cms_round_trip.rb` — build a CMS envelope, parse it,
     verify signatures.

### WASM (`examples/`)

- [ ] `examples/browser/index.html` + `index.js` — load the WASM,
     verify a composite signature, render result.
- [ ] `examples/node/verify.js` — Node.js CJS entry point that
     verifies a transparency proof.
- [ ] `examples/vite/` — minimal Vite app showing the WASM package
     integrated with a bundler.

### Documentation

- [ ] `examples/README.md` in each binding explaining how to run each
     example.
- [ ] The main README links to `examples/` as the first stop.

## Anti-patterns

- Examples that depend on a real PKI/HSM/etc. — keep them standalone.
- Examples with no comments — explain each step.

## Approach

Pure additive: write the example files, run each to confirm it works,
commit. No core-code changes required.

## Related

- [015-wasm-jsdoc-comments.md](015-wasm-jsdoc-comments.md) — JSDoc
  should link to the relevant example.
- [017-sinatra-verifier-quickstart.md](017-sinatra-verifier-quickstart.md) —
  the Sinatra quickstart is a more opinionated example.
