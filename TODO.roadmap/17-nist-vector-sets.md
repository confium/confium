# 17 — NIST vector sets

**Status**: SHIPPED (schema + mock vectors). FROST/GG18 spec vectors pending.

TOML schema with conformance levels: MUST_PASS, SHOULD_PASS,
INFORMATIONAL. Runner honors levels (SHOULD_PASS failure = warning,
not error).

Shipped vectors:
- mock-3-of-5.toml, mock-2-of-3.toml, mock-byzantine-drop.toml
- Registry catalog at sites/registry/vectors/

Pending: extract official KAT vectors from FROST/GG18/CMP20 specs.
