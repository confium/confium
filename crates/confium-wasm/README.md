# confium-wasm

Browser / Node.js **verifier** package for [Confium](https://www.confium.org/).
WASM-bindgen surface, verifier-only by design.

> **Design principle:** browsers verify, servers sign. This crate exposes
> only the operations that a browser-side consumer needs to validate
> signatures, certificates, CMS envelopes, composite signatures, and
> transparency proofs. Signing, threshold session participation, and
> PKCS#11/OpenSSL provider dispatch all stay server-side — they have no
> place in a browser context.

## What's inside

| Module | What it verifies |
|---|---|
| `CompositeSignature` | PQ-migration composite signatures (Ed25519 + future ML-DSA-65). |
| `MerkleTree`, `InclusionProof` | RFC 6962 transparency log proofs. |
| `Predicate` | Attribute-based threshold policy DSL. |

## Usage (from JS/TS)

```js
import init, { CompositeSignature, verify_ed25519 } from "@confium/confium-wasm";

await init();

const sig = CompositeSignature.from_json(jsonString);
const ok = sig.verify(messageBytes);  // -> { all_verified: bool, per_component: [...] }
```

## Crate features

Each `verify-*` feature gates a verifier subtree so consumers can
tree-shake. All are on by default for out-of-the-box ergonomics.

| Feature | Gates |
|---|---|
| `verify-composite` | `CompositeSignature` |
| `verify-transparency` | `MerkleTree`, `InclusionProof` |
| `verify-attributes` | `Predicate` |

## Building

```sh
wasm-pack build crates/confium-wasm --target web --release --scope confium
```

Output lands in `crates/confium-wasm/pkg/`, ready for npm publish as
`@confium/confium-wasm`.

## License

BSD-2-Clause, same as the rest of the Confium workspace.
