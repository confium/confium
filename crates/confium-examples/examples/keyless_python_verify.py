#!/usr/bin/env python3
"""Verify a keyless Confium signature in Python."""

from confium.keyless import verify

verify(
    artifact="release.tar.gz",
    signature="sig.bin",
    certificate="cert.pem",
)
print("✅ Keyless signature verified")
