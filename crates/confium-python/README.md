# Confium Python bindings

Native Python extension wrapping the Confium Rust engine via PyO3 0.22.

Surface: version info, composite signature verification, RFC 6962
transparency log. Built-in verifiers cover Ed25519 and ECDSA-P256.
Custom verifiers via Python callbacks.

## Install

```sh
pip install confium
```

## Quick start

```python
import confium

print(confium.version())          # "0.3.0"
print(confium.core_version())     # engine version
```

### Composite signature verification

```python
from confium import composite

# Build a composite from components
cs = composite.CompositeSignature([
    composite.ComponentSignature(
        algorithm=composite.ED25519,
        public_key=pk_bytes,      # 32 bytes
        signature=sig_bytes,      # 64 bytes
    ),
    composite.ComponentSignature(
        algorithm=composite.ECDSA_P256,
        public_key=pk_bytes,      # SEC1 compressed or uncompressed
        signature=sig_der_bytes,  # DER-encoded
    ),
])

result = cs.verify(message_bytes)
if not result.all_verified:
    for c in result.per_component:
        print(c["index"], c["algorithm"], c["verified"], c.get("error"))
```

Or parse from JSON:

```python
cs = composite.CompositeSignature.from_json(json_payload)
result = cs.verify(message)
assert result.all_verified
```

Custom verifier for unsupported algorithms (e.g. ML-DSA):

```python
def my_verifier(alg: str, pk: bytes, msg: bytes, sig: bytes) -> str | None:
    # Return None on success, str error on failure
    return None if my_lib.verify(alg, pk, msg, sig) else "bad signature"

result = cs.verify_with(message, my_verifier)
```

### Transparency log (RFC 6962 Merkle tree)

```python
import hashlib
from confium import transparency

tree = transparency.MerkleTree()
artifact_hash = hashlib.sha256(b"my artifact").digest()
seq = tree.append("certificate_issuance", artifact_hash)
root = tree.root                  # 32 bytes
proof = tree.inclusion_proof(seq)
tree.verify_inclusion(seq, proof, root)  # raises ValueError on failure
```

External auditor (no access to the tree, just published data):

```python
# Auditor has: published sequence, timestamp, artifact_hash, root, proof
entry = transparency.MerkleTree().entry  # placeholder; in practice:
timestamp = "2026-07-29T12:34:56Z"       # published by the log

leaf = transparency.compute_leaf_hash(
    seq, timestamp, artifact_hash,
)
transparency.verify_inclusion_with_leaf(leaf, proof, root)
```

## API surface

| Symbol | Description |
| --- | --- |
| `confium.version()` / `confium.core_version()` | Version info. |
| `confium.composite.ComponentSignature` | Single component (algorithm + pubkey + signature). |
| `confium.composite.CompositeSignature` | Composite of one or more components. |
| `confium.composite.CompositeSignature.from_json(s)` | Parse from JSON. |
| `confium.composite.CompositeSignature.verify(msg)` | Verify with built-in Ed25519 + ECDSA-P256. |
| `confium.composite.CompositeSignature.verify_with(msg, cb)` | Verify with caller-supplied callback. |
| `confium.composite.VerificationResult` | Aggregate result (`all_verified`, `per_component`). |
| `confium.composite.verify_ed25519(pk, msg, sig)` | Standalone Ed25519 verifier. |
| `confium.composite.verify_ecdsa_p256(pk, msg, sig)` | Standalone ECDSA-P256 verifier. |
| `confium.composite.ED25519` / `ECDSA_P256` / `ML_DSA_65` | Algorithm name constants. |
| `confium.transparency.MerkleTree` | Append-only RFC 6962 Merkle tree. |
| `confium.transparency.InclusionProof` | Direction-aware inclusion proof. |
| `confium.transparency.compute_leaf_hash(seq, ts, hash)` | Recompute the published leaf hash. |
| `confium.transparency.verify_inclusion_with_leaf(leaf, proof, root)` | External auditor entry point. |
| `confium.transparency.ARTIFACT_TYPES` | Allowed `artifact_type` strings. |

## Building from source

Requires Rust stable 1.85+ and Python 3.9+:

```sh
pip install maturin
maturin develop --release   # build + install into the current venv
```

Run the test suite:

```sh
pip install pytest cryptography
pytest tests/
```

## License

BSD-2-Clause. Same as the rest of the Confium project.
