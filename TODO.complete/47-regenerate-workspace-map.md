# 47 — Regenerate workspace-map.mdx from actual Cargo.toml metadata

## Problem

`docs/workspace-map.mdx` was severely outdated:

- Stated "43 crates" — actual workspace has 65 crates (48% drift).
- Listed 6 crates that no longer exist: `confium-escrow`,
  `confium-revocation-service`, `confium-identity`, `confium-config`,
  `confium-ots`, `confium-ers`. (The functionality was either merged
  into other crates or never built out as separate crates.)
- Was missing 28 crates that DO exist: `confium-tc-core`,
  `confium-tc-cmp20`, `confium-tc-gg18`, `confium-tc-frost-p256`,
  `confium-tc-frost-ed25519`, `confium-tc-keys`, `confium-coordinator`,
  `confium-crypto-vss`, `confium-crypto-zk`, `confium-privacy`,
  `confium-observability`, `confium-pki-tc`, `confium-signerd`,
  `confium-log-server`, `confium-log-monitor`, `confium-verify-server`,
  `confium-operator`, `confium-oidc`, `confium-node`, `confium-fuzz`,
  `confium-threshold`, `confium-keyless`, `confium-verify`,
  `confium-store-cloud`, `confium-store-openpgp-card`,
  `confium-store-pkcs11`, `confium-store-tpm`, `confium-benchmarks`.
- Was missing whole categories: "Shared crypto primitives",
  "Privacy primitives", "Product facades", "Deployable services",
  "Tooling", "Patterns", "Language bindings".

A new contributor reading this doc would have an entirely wrong
mental model of what the workspace contains.

## What was done

Wrote `/tmp/gen_workspace_map.py` (Python, uses `tomli` to parse
Cargo.toml) that:

1. Enumerates every `crates/*/Cargo.toml`.
2. Extracts the `description` field.
3. Groups crates into 16 categories.
4. Flags any uncategorized crate or any categorized crate that no
   longer exists (so the script fails loudly on future drift).
5. Emits the MDX directly.

The script is reproducible — re-running it against a future
workspace state will produce an updated `workspace-map.mdx` with
no manual editing.

The new doc:
- States "65 crates" (matches actual workspace).
- Lists every actual crate by name with its Cargo description.
- Has 16 categories covering all 65 crates.
- Ends with a "Choosing a crate" quickstart for the 5 most common
  entry points.

## Verification

```sh
python3 /tmp/gen_workspace_map.py > docs/workspace-map.mdx
# 65 crates total, 65 categorized
# 0 uncategorized, 0 missing
```

## Status

Done. Generator script kept at `/tmp/gen_workspace_map.py`; re-run
any time the workspace crate set changes.
