#!/usr/bin/env python3
"""Anchor release artifacts into a Confium transparency log.

For every artifact matching the glob: SHA-256 it, append the hash to
the log (POST /v1/append), fetch the inclusion proof (GET
/v1/proof/<sequence>), independently verify the whole chain, and fail
if anything the log said does not check out:

1. recompute the entry hash from (sequence, entry timestamp, artifact
   SHA-256) with the log's construction —
   SHA-256(le64(sequence) || le64(micros) || artifact_hash) — and
   compare against the log's entry_hash;
2. hash the leaf (0x01 prefix) and walk the proof steps (0x02-prefixed
   pairwise nodes) to recompute the root;
3. compare against the root the log reported.

A lying or compromised log cannot make this step pass. Writes a
self-contained sidecar next to each artifact for offline verification.
"""

import glob
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

GLOB = os.environ["CONFIUM_ANCHOR_GLOB"]
LOG_URL = os.environ["CONFIUM_ANCHOR_LOG_URL"].rstrip("/")
ARTIFACT_TYPE = os.environ.get("CONFIUM_ANCHOR_TYPE", "threshold_signature")
TOKEN = os.environ.get("CONFIUM_ANCHOR_TOKEN", "")
GITHUB_OUTPUT = os.environ.get("GITHUB_OUTPUT")
GITHUB_STEP_SUMMARY = os.environ.get("GITHUB_STEP_SUMMARY")

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def request(method, path, body=None):
    url = f"{LOG_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("content-type", "application/json")
    if TOKEN:
        req.add_header("authorization", f"Bearer {TOKEN}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def parse_rfc3339(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def micros_since_epoch(dt: datetime) -> int:
    delta = dt.astimezone(timezone.utc) - EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def entry_hash(sequence: int, timestamp: str, artifact_hash_hex: str) -> bytes:
    h = hashlib.sha256()
    h.update(sequence.to_bytes(8, "little", signed=True))
    h.update(micros_since_epoch(parse_rfc3339(timestamp)).to_bytes(8, "little", signed=True))
    h.update(bytes.fromhex(artifact_hash_hex))
    return h.digest()


def recompute_root(entry_hash_bytes: bytes, steps) -> str:
    current = hashlib.sha256(b"\x01" + entry_hash_bytes).digest()
    for step in steps:
        sibling = bytes.fromhex(step["sibling"])
        if step["side"] == "left":
            current = hashlib.sha256(b"\x02" + sibling + current).digest()
        elif step["side"] == "right":
            current = hashlib.sha256(b"\x02" + current + sibling).digest()
        else:
            raise ValueError(f"bad proof side: {step['side']!r}")
    return current.hex()


def die(msg: str) -> None:
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    paths = sorted(
        p
        for p in glob.glob(GLOB, recursive=True)
        if os.path.isfile(p) and not p.endswith(".confium-proof.json")
    )
    if not paths:
        die(f"no artifacts match {GLOB!r}")

    anchored = {}
    for path in paths:
        with open(path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()

        appended = request(
            "POST",
            "/v1/append",
            {"artifact_type": ARTIFACT_TYPE, "artifact_hash": digest},
        )
        sequence = appended["sequence"]
        proof = request("GET", f"/v1/proof/{sequence}")

        if proof["sequence"] != sequence:
            die(f"{path}: proof sequence {proof['sequence']} != {sequence}")

        local_entry_hash = entry_hash(sequence, proof["entry_timestamp"], digest)
        if local_entry_hash.hex() != proof["entry_hash"]:
            die(
                f"{path}: log entry_hash {proof['entry_hash']} does not match "
                f"locally recomputed {local_entry_hash.hex()}"
            )

        expected_root = recompute_root(local_entry_hash, proof["steps"])
        if expected_root != proof["root"]:
            die(
                f"{path}: log root {proof['root']} does not match locally "
                f"recomputed root {expected_root}; refusing to trust this log"
            )

        sidecar = {
            "artifact": path,
            "sha256": digest,
            "artifact_type": ARTIFACT_TYPE,
            "sequence": sequence,
            "tree_size": proof["tree_size"],
            "root": proof["root"],
            "entry_hash": proof["entry_hash"],
            "entry_timestamp": proof["entry_timestamp"],
            "steps": proof["steps"],
            "log_url": LOG_URL,
            "anchored_at": appended.get("timestamp"),
        }
        sidecar_path = f"{path}.confium-proof.json"
        with open(sidecar_path, "w") as f:
            json.dump(sidecar, f, indent=2, sort_keys=True)
            f.write("\n")

        anchored[path] = {
            "sequence": sequence,
            "root": proof["root"],
            "tree_size": proof["tree_size"],
            "proof_file": sidecar_path,
        }
        print(f"anchored {path} sha256={digest[:16]}... sequence={sequence}")

    if GITHUB_OUTPUT:
        with open(GITHUB_OUTPUT, "a") as f:
            f.write(f"anchored={json.dumps(anchored, sort_keys=True)}\n")
    if GITHUB_STEP_SUMMARY:
        with open(GITHUB_STEP_SUMMARY, "a") as f:
            f.write("## Confium transparency anchors\n\n")
            f.write("| artifact | sequence | tree size | root |\n")
            f.write("|---|---|---|---|\n")
            for path, info in anchored.items():
                f.write(
                    f"| `{path}` | {info['sequence']} | "
                    f"{info['tree_size']} | `{info['root'][:16]}...` |\n"
                )


if __name__ == "__main__":
    main()
