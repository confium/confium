# `@confium/confium-node` — Node.js bindings for Confium

[![npm version](https://img.shields.io/npm/v/@confium/confium-node.svg)](https://www.npmjs.com/package/@confium/confium-node)
[![license](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

Server-side Node.js bindings for the
[Confium](https://www.confium.org/) threshold cryptography
framework. Wraps the same Rust crates as the Ruby and Python
bindings — full parity across all three languages.

## Why Node.js when WASM exists?

The companion package
[`@confium/confium-wasm`](https://www.npmjs.com/package/@confium/confium-wasm)
is **verifier-only by design** — browsers verify, servers sign.
Node.js is server-side. This binding exposes the *signing* surface
for Node consumers: CI release pipelines, signing microservices,
scheduled-ceremony workers.

## Install

```sh
npm install @confium/confium-node
# or
yarn add @confium/confium-node
# or
pnpm add @confium/confium-node
```

Pre-built wheels ship for:

- Linux x86_64 + aarch64 (glibc 2.28+)
- macOS x86_64 + arm64 (11+)
- Windows x86_64

## Quickstart

```javascript
const { Cmp20, Gg18 } = require("@confium/confium-node");
const { createVerify, createPublicKey } = require("node:crypto");

// 1. Threshold keygen (2-of-3 CMP20).
const kg = Cmp20.keygen(2, 3);
console.log(`Generated ${kg.shares.length} shares`);
console.log(`Joint public key: ${kg.publicKey.toString("hex").slice(0, 24)}...`);

// 2. Sign with any 2 of the 3 shares.
const message = Buffer.from("hello threshold");
const sig = Cmp20.sign(kg.shares.slice(0, 2), 2, message);
console.log(`Signature: ${sig.toString("hex").slice(0, 24)}... (${sig.length} bytes)`);

// 3. Verify via Node's built-in P-256 verifier.
const spkiDer = sec1ToSpki(kg.publicKey); // wrap SEC1 point in SubjectPublicKeyInfo
const pub = createPublicKey({ key: spkiDer, format: "der", type: "spki" });
const verifier = createVerify("SHA256");
verifier.update(message);
verifier.end();
const ok = verifier.verify(pub, rsToDer(sig));
console.log(`Verified: ${ok}`);
```

Helpers `sec1ToSpki` and `rsToDer` are minimal ASN.1 wrappers —
copy them from `examples/verify.js` or use any ASN.1 library.

## API surface

| Class / function | Description |
|---|---|
| `Cmp20.keygen(threshold, partyCount)` | CMP20 DKG → `{shares: Buffer[], publicKey: Buffer}` |
| `Cmp20.sign(shares, threshold, message)` | Threshold sign → 64-byte `(r,s)` signature |
| `Cmp20.signBatch(shares, threshold, messages)` | Sign N messages in one call (binding-overhead amortized) |
| `Gg18.keygen(threshold, partyCount)` | Same shape as Cmp20, GG18 protocol underneath |
| `Gg18.sign(shares, threshold, message)` | Same shape as Cmp20, GG18 protocol underneath |
| `FrostP256.generateKeypair()` | Single-party P-256 keypair for Shamir workflows |
| `version()` | Package version string |

## TypeScript types

The package ships with auto-generated `.d.ts`. Every public method
has a TypeScript signature. The Rust doc comments surface as JSDoc
in your IDE.

## Feature parity

This package mirrors the Ruby + Python binding surfaces. See the
[parity matrix](https://www.confium.org/bindings/parity) for the
cross-language coverage table. Cross-binding share-blob format is
identical — files saved in Ruby load in Node and vice versa.

## License

BSD-2-Clause, same as the rest of Confium.

## See also

- [Confium project](https://www.confium.org/)
- [`@confium/confium-wasm`](https://www.npmjs.com/package/@confium/confium-wasm) — browser verifier.
- [Ruby binding](https://github.com/confium/confium-ruby)
- [Python binding](https://pypi.org/project/confium/)
