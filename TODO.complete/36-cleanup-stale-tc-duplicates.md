# 36 — Cleanup 76 stale duplicate files in confium-tc/src

## Problem

The confium-tc god-crate was "extracted" into 8 focused crates
(confium-tc-core, confium-tc-keys, confium-coordinator, etc.) in
commit `a29d9b6` ("feat: product restructuring — extract 15 crates,
expand workspace to 61 packages"). The extraction COPIED the
modules to the new crates but left the originals behind in
`crates/confium-tc/src/`.

Result: 66 of 77 `.rs` files in `confium-tc/src/` were not declared
in `lib.rs` and therefore never compiled. The actual compiled code
lived in the extracted crates. The dead files in `confium-tc/src/`
were stale snapshots — every one of them has a more-evolved twin in
an extracted crate.

This is a DRY violation in spirit (two copies of every module), a
maintainability trap (a future maintainer might edit the dead copy
and wonder why nothing changes), and a confusion source for tooling
(IDE indexing, grep for symbols returns duplicate hits).

## What was done

`git mv`'d the 66 orphan files from `crates/confium-tc/src/` to
`crates/confium-tc/attic/`. They remain in git history (no
deletion), just outside the crate's source tree so cargo / rustc /
rustdoc / rust-analyzer ignore them.

Extracted crates whose modules had been the canonical versions all
along:
- confium-tc-core (error, message, party, registry, session, share,
  share_adapter, share_envelope, commitment, nonce, error_codes,
  inprocess, unified_error)
- confium-tc-keys (key_mgmt_and_protocols, hsm_protection,
  integrity, production_hardening, stealth_address,
  threshold_bip32)
- confium-coordinator (async_event_store, async_session_manager,
  chaos_testing, circuit_breaker, config_validator,
  coordinator_factory, coordinator_proptest, dkg_coordinator,
  di_container, distributed_lock, event_sourced, marketplace,
  noise_transport, perf_baseline, plugin_manifest, refresh_coordinator,
  request_coalescing, resilience_and_circuits, retry,
  round_coordinator, saga, shutdown, wal)
- confium-crypto-vss (vss, pedersen_vss, paillier (already live),
  schnorr, threshold_schnorr, range_proof, nizk)
- confium-crypto-zk (zk_set_membership, zk_sig_possession,
  accumulator, threshold_abs)
- confium-privacy (privacy_and_dist_patterns, oblivious_transfer,
  differential, distributed_prf, distributed_prg, secure_aggregation,
  proxy_reencryption, blind_ecdsa, adaptor_sig, multi_sig,
  jsonld_signing, side_channel, threshold_decryption, vdf, vrf)
- confium-observability (observability_and_enterprise,
  data_structures_and_utils)
- confium-pki-tc (ct_log, abe_and_multitenancy, ibe_ocsp_acme)

Two orphans have no clear home in the extracted-crate structure and
remain in the attic pending evaluation:
- `protocol_optimization.rs` (optimization passes for protocol
  message overhead — could live in confium-coordinator or a new
  confium-protocol-utils crate)
- `ring_sig.rs` (ring signatures — already a `confium-ring` crate
  but that one is empty; this file is the actual content)

These will be evaluated in TODO.complete/37.

## Verification

```sh
cargo build --workspace              # clean (no missing modules)
cargo test --workspace               # all tests still pass
cargo clippy --workspace --all-targets  # 0 warnings
cargo fmt --all --check              # clean
```

The `attic/` directory is excluded from cargo's view (no `mod.rs`
declares it), so its contents don't affect compilation. It exists
purely to preserve git history of the stale copies for one
release cycle before being removed.

## Status

Done. PR follows.
