# 14 — Real threshold cryptography schemes

**Status**: 4 of ~10 shipped.

Shipped:
- mock-tc-sig (demonstration scheme)
- FROST-ed25519 (draft-irtf-cfrg-frost, real curve25519-dalek impl)
- GG18-ECDSA-P256 (Gennaro & Goldfeder 2018, real p256 impl)
- CMP20-ECDSA-P256 (Canetti et al. 2020, 3-round signing)

Remaining:
- FROST-ECDSA-P256 (different curve)
- Mask-FROST (2-round variant from MPTS 2026)
- Pedersen DKG standalone
- Feldman DKG standalone
- Shoup threshold RSA
- Threshold BLS
- PQC threshold schemes (awaiting NIST specs)
