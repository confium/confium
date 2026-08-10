# 48 — Update outdated CLI stub message; verify examples run end-to-end

## Problem

The CLI's `threshold recover` subcommand had a stale message:
"recovery API is in development." In reality, `confium-tc-cmp20`
has had `recovery::recover_share` for several releases — it just
wasn't exposed via the CLI. The message misled users into thinking
the feature was missing.

Also audited the 8 example binaries in `confium-examples` to verify
they actually run end-to-end. If any of them broke silently, the
cookbook recipes and docs that reference them would mislead users.

## What was done

### Updated CLI recover message

`crates/confium-cli/src/commands/threshold.rs`: changed the
"recovery API is in development" message to:

> confium threshold recover: not exposed via the CLI yet.
> Use the Rust API: confium_tc_cmp20::recovery::recover_share.
> See https://docs.rs/confium-tc-cmp20/latest/confium_tc_cmp20/recovery/

Now users know (a) recovery IS available, (b) it's not yet wired
into the CLI, (c) where the API docs live.

### Verified all 8 example binaries run successfully

```sh
cargo run --bin threshold_signing -p confium-examples        # ✓
cargo run --bin p256_threshold_signing -p confium-examples   # ✓
cargo run --bin transparency_log_demo -p confium-examples   # ✓
cargo run --bin plugin_load_and_hash -p confium-examples    # ✓
cargo run --bin keystore_roundtrip -p confium-examples      # ✓
cargo run --bin mini_cnml_demo -p confium-examples          # ✓
cargo run --bin audit_log_stream -p confium-examples        # ✓
cargo run --bin pkcs11_server_demo -p confium-examples      # ✓
```

Each one ran to completion without panicking. Sample outputs:

- `threshold_signing`: prints the 2-of-3 DKG + sign + verify
  round-trip.
- `p256_threshold_signing`: ends with "Real P-256 Shamir + ECDSA
  verified end-to-end."
- `transparency_log_demo`: ends with "RFC 6962 inclusion proof
  verifier working."

The other examples verified similarly.

## Verification

```sh
cargo run --bin threshold_signing -p confium-examples | tail -5
# All 8 examples exit 0 with meaningful output.
```

## Status

Done. CLI stub message corrected; 8/8 example binaries verified.
