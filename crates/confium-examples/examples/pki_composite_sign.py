#!/usr/bin/env python3
"""Composite sign (Ed25519 + ECDSA-P256) in Python."""

from confium import CompositeSignature

# Build a composite from component signatures
sig = CompositeSignature.from_json('{"components":[{"algorithm":"Ed25519","public_key":"hex","signature":"hex"}]}')
result = sig.verify(b"message")
print(f"All verified: {result.all_verified}")
for c in result.per_component:
    print(f"  {c.algorithm}: {c.valid}")
