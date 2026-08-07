#!/usr/bin/env python3
"""Threshold CMP20 ceremony — generate, sign, verify.

Run with:
    python examples/threshold_cmp20.py
"""

from __future__ import annotations

import hashlib

import confium
from confium import tc
from ecdsa import NIST256p, VerifyingKey
from ecdsa.util import sigdecode_string


def main() -> None:
    # 1. DKG: produce 3 share blobs + joint public key.
    kg = tc.Cmp20.keygen(threshold=2, party_count=3)
    print("dkg complete:")
    print(f"  shares:       {len(kg['shares'])} ({len(kg['shares'][0])} bytes each)")
    print(f"  public_key:   0x{kg['public_key'].hex()[:16]}...")

    # 2. Threshold sign with the first 2 shares.
    message = b"threshold cmp20 signature"
    signature = tc.Cmp20.sign(kg["shares"][:2], threshold=2, message=message)
    print("signed with shares [0, 1]:")
    print(f"  message:      {message!r}")
    print(f"  signature:    0x{signature.hex()[:16]}... ({len(signature)} bytes)")

    # 3. Verify under the joint public key using the standalone ecdsa
    #    package (independent of the binding).
    vk = VerifyingKey.from_string(kg["public_key"], curve=NIST256p)
    digest = hashlib.sha256(message).digest()
    if vk.verify_digest(signature, digest, sigdecode=sigdecode_string):
        print("verify: OK (ecdsa package confirms under joint public key)")
    else:
        raise SystemExit("verify: FAIL")

    # 4. Below-threshold attempt raises a typed error.
    print("below-threshold attempt:")
    try:
        tc.Cmp20.sign(kg["shares"][:1], threshold=2, message=message)
        raise SystemExit("should have raised")
    except RuntimeError as e:
        print(f"  raised RuntimeError: {e}")


if __name__ == "__main__":
    main()
