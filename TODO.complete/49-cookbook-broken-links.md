# 49 — Fix broken cookbook recipe links

## Problem

`docs/cookbook/index.mdx` linked to 7 recipes that don't exist:

- `verify-threshold-signature-with-openssl.mdx`
- `large-quorum-ceremony.mdx`
- `threshold-ca-issue.mdx`
- `keyless-new-oidc-provider.mdx`
- `anonymous-credentials.mdx`
- `batch-verification.mdx`

These would 404 on the published docs site.

## What was done

Removed the 6 dead links (plus a 7th typo: `composite-sign-pq-mdx.mdx`
→ `composite-sign-pq-migration.mdx`).

The index now only links to recipes that actually exist (15 files).
The "Implementation status" table at the bottom of the page is
preserved — it accurately flags which Rust APIs ship vs which CLI
wrappers are pending.

For each removed link:
- The underlying Rust API may exist (e.g. share backup), but the
  recipe file doesn't.
- Future PRs that add a recipe should also add the index link.

## Verification

```sh
ls docs/cookbook/                           # 16 files
grep -c "^\- \[" docs/cookbook/index.mdx    # 16 links (matches)
```

## Status

Done. No more 404 links in the cookbook index.
