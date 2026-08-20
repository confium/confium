# confium-anchor-release

A GitHub Action that anchors release artifacts into a Confium
transparency log and attaches verifiable Merkle inclusion proofs.

Every anchored artifact gets a `<name>.confium-proof.json` sidecar
containing everything an offline verifier needs: the artifact's SHA-256,
its log sequence number, the entry hash and timestamp, the inclusion
proof steps, the tree head at anchor time, and the log's URL.

The action verifies the log's answers before trusting them: it
recomputes the entry hash from (sequence, timestamp, artifact
SHA-256), hashes the leaf (`0x01` prefix), walks the proof steps
(`0x02`-prefixed pairwise nodes), and fails the build if the result
does not match the root the log reported — a compromised or lying log
cannot produce a passing step.

## Usage

```yaml
      - uses: confium/confium/integrations/github-actions/anchor-release@main
        with:
          artifacts: "dist/*"
          log-url: "${{ secrets.CONFIUM_LOG_URL }}"
          token: "${{ secrets.CONFIUM_LOG_TOKEN }}"
```

Then upload the sidecars with your artifacts:

```yaml
      - uses: actions/upload-artifact@v4
        with:
          path: |
            dist/*
            dist/*.confium-proof.json
```

## Inputs

| input           | required | default                | description                              |
| --------------- | -------- | ---------------------- | ---------------------------------------- |
| `artifacts`     | yes      | —                      | Glob of files to anchor.                 |
| `log-url`       | yes      | —                      | Base URL of the log server.              |
| `artifact-type` | no       | `threshold_signature`  | Type label recorded in the log entry.    |
| `token`         | no       | —                      | Bearer token forwarded to the log.       |

## Outputs

`anchored` — a JSON map from artifact path to
`{sequence, root, tree_size, proof_file}`.

## Verifying an anchored artifact

Anyone (no GitHub or log access needed) can verify a downloaded
artifact against its sidecar:

```python
import hashlib, json
from datetime import datetime, timezone

sidecar = json.load(open("app.tar.gz.confium-proof.json"))
digest = hashlib.sha256(open("app.tar.gz", "rb").read()).hexdigest()
assert digest == sidecar["sha256"]

ts = datetime.fromisoformat(sidecar["entry_timestamp"].replace("Z", "+00:00"))
micros = int(ts.timestamp() * 1_000_000)
entry = hashlib.sha256(
    sidecar["sequence"].to_bytes(8, "little", signed=True)
    + micros.to_bytes(8, "little", signed=True)
    + bytes.fromhex(digest)
).digest()
assert entry.hex() == sidecar["entry_hash"]

cur = hashlib.sha256(b"\x01" + entry).digest()
for step in sidecar["steps"]:
    sib = bytes.fromhex(step["sibling"])
    l, r = (sib, cur) if step["side"] == "left" else (cur, sib)
    cur = hashlib.sha256(b"\x02" + l + r).digest()
assert cur.hex() == sidecar["root"]
```

Trusting the root is a policy decision: compare it against an
independently published tree head (gossip witness, the project's
`/v1/head` endpoint, or a checkpoint you recorded earlier).

## Roadmap: threshold signing

The long-term plan for this action is quorum code signing: artifacts
hashed, submitted to a Confium coordinator, signed by an M-of-N
threshold (FROST/CMP20), with the composite signature and the
transparency proof attached together. That half arrives when the
coordinator service exposes its session API over the network; this
action already delivers the tamper-evident anchoring half end to end,
and the sidecar format is designed to gain a `composite_signature`
field without a breaking change.
