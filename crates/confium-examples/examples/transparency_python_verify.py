#!/usr/bin/env python3
"""Verify a transparency inclusion proof in Python."""

import json
from confium.transparency import verify_inclusion_with_head

with open("proof.json") as f:
    proof = f.read()
with open("head.json") as f:
    head = f.read()

ok = verify_inclusion_with_head(proof, head)
print(f"✅ In log: {ok}")
