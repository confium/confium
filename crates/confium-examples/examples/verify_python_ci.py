#!/usr/bin/env python3
"""CI verification gate — block deploys on signature failure."""

import sys
from confium import CompositeSignature

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <sig.json> <message>")
    sys.exit(1)

sig = CompositeSignature.from_json(open(sys.argv[1]).read())
result = sig.verify(sys.argv[2].encode())

if result.all_verified:
    print("✅ Signature valid — proceeding with deploy")
    sys.exit(0)
else:
    print("❌ Signature invalid — blocking deploy", file=sys.stderr)
    sys.exit(1)
