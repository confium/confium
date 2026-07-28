# Confium Python bindings

Native Python extension wrapping the Confium Rust engine via PyO3.

## Install

```sh
pip install confium
```

## Quick start

```python
import confium

# Version
print(confium.version())        # "0.3.0"
print(confium.core_version())   # "0.2.0"

# Composite signature verification
sig = confium.CompositeSignature.from_json(json_string)
result = sig.verify(message_bytes, {
    "Ed25519": "builtin",
    "ECDSA-P256": "builtin",
})
print(result.all_verified)      # True
print(result.per_component)     # {"Ed25519": True, "ECDSA-P256": True}

# Transparency log
tree = confium.MerkleTree()
seq = tree.append(
    artifact_type="certificate_issuance",
    artifact_hash=hash_bytes,
)
print(tree.root.hex())          # root hash as hex string
proof = tree.inclusion_proof(seq)
confium.MerkleTree.verify_inclusion(
    entry_hash=hash_bytes,
    proof=proof,
    root=tree.root,
)  # raises on failure
```

## API surface

| Class / function | Description |
| --- | --- |
| `confium.version()` | CLI/gem version string. |
| `confium.core_version()` | Underlying `confium-core` engine version. |
| `confium.CompositeSignature` | Load and verify composite (multi-algorithm) signatures. |
| `confium.MerkleTree` | Append-only Merkle tree (RFC 6962). |
| `confium.InclusionProof` | Inclusion proof for a Merkle tree entry. |

## Building from source

```sh
# Requires Rust stable 1.85+ and Python 3.9+
pip install maturin
maturin develop --release  # builds and installs into current venv
```
