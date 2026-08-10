# 43 — Improve error type documentation

## Problem

Several public error enums had terse one-line doc comments like
`/// Threshold not met.` that didn't tell the caller:
- WHEN the variant fires.
- WHY it fires.
- WHAT action to take.

Errors are part of the public API. A poorly-documented error forces
the caller to read the source code to understand how to react. For
crypto code this is especially important — a misdiagnosed error
could mean "Byzantine peer" vs "transient network glitch."

## What was done

Improved the doc comments on three high-traffic error enums,
adding a "Caller action" line to each variant so consumers know
how to react without reading source.

### `crates/confium-tc-cmp20/src/error.rs` — Cmp20ErrorCode

Six variants (BAD_SHARE, VSS_VERIFY_FAILED, BELOW_THRESHOLD,
BAD_ROUND_MESSAGE, BAD_PARTIAL_SIGNATURE, INTERNAL) gained:

- A one-sentence "when" explanation.
- A "Caller action" line describing the recommended response.

For example:
- BAD_SHARE: "A share blob failed to deserialize or had the wrong
  magic / version. Caller action: regenerate shares via DKG."
- BELOW_THRESHOLD: "Fewer than T shares were supplied for a sign /
  decapsulation session. Caller action: collect more shares before
  retrying."

### `crates/confium-tc-gg18/src/error.rs` — Gg18ErrorCode

Same treatment for GG18's six variants. The BAD_PARTIAL_SIGNATURE
comment notes that GG18 lacks identifiable abort and points to
CMP20 for that capability — important context for callers choosing
a scheme.

### `crates/confium-tc-bls/src/lib.rs` — BlsError

Three variants (ThresholdNotMet, AggregationFailed,
InvalidSignature) gained explanations + caller actions.

## Verification

```sh
cargo build -p confium-tc-cmp20 -p confium-tc-gg18 -p confium-tc-bls   # clean
cargo doc -p confium-tc-cmp20 -p confium-tc-gg18 -p confium-tc-bls --no-deps  # renders
```

## Why this matters

Typed errors with rich documentation let callers write match arms
that are semantically meaningful:

```rust
match result {
    Err(Cmp20ErrorCode::BELOW_THRESHOLD) => {
        // wait for more peers — recoverable
    }
    Err(Cmp20ErrorCode::IDENTIFIED_BYZANTINE) => {
        // eject peer `idx` from the quorum
    }
    _ => return Err(...),
}
```

Without per-variant docs, callers either ignore errors or panic.
With docs, callers can react intelligently.

## Status

Done. 15 error variants across 3 crates now have full docs.
