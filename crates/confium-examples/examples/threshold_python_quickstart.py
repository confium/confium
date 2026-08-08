#!/usr/bin/env python3
"""Confium CMP20 DKG + sign in Python.

    pip install confium
    python threshold_python_quickstart.py
"""

from confium.tc import Cmp20

# DKG: 2-of-3 threshold key
kg = Cmp20.keygen(threshold=2, parties=3)
print(f"Public key: {len(kg.public_key)} bytes")
print(f"Shares: {len(kg.shares)}")

# Sign with threshold shares
sig = Cmp20.sign(kg.shares, threshold=2, message=b"hello, threshold world")
print(f"Signature: {len(sig)} bytes")
print("✅ Done")
