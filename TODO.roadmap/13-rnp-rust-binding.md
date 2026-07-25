# 13 — RNP Rust binding (rnp-rs)

**Status**: SHIPPED. Sibling repo at github.com/rnpgp/rnp-rs, PR #1 merged.

Provides idiomatic Rust access to RNP's C FFI for OpenPGP operations.
Confium uses it for plugin artifact verification, OpenPGP key format,
and TC party authentication.

**Shipped**: Context, Key (generate/import/export/locate), Signature
(sign/verify/detached), keygen (RSA/EdDSA/ECDSA/ECDH/SM2/DSA), PQC
support (ML-KEM/ML-DSA via feature flags), vendored RNP build,
callbacks, secret memory, parity tests.
