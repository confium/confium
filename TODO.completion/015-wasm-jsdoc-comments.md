# 015 — WASM JSDoc comments

**Category**: Usability
**Severity**: Medium
**Effort**: Small (1 PR)

## Problem

The auto-generated `confium_wasm.d.ts` has no JSDoc comments. Consumers
in TypeScript see the function/class signatures but no documentation.
They have to leave their IDE and read the source.

## Acceptance criteria

- [ ] Every `#[wasm_bindgen]` function, method, and struct in
     `crates/confium-wasm/src/*.rs` has a `///` doc comment.
- [ ] The doc comment includes:
  - A one-line summary.
  - Parameter semantics (units, format, encoding).
  - Return semantics.
  - At least one code example for public-facing functions.
  - `@throws` notes when the function can return `Err`.
- [ ] wasm-bindgen surfaces these into the generated `confium_wasm.d.ts`.
- [ ] The published npm package's `d.ts` reflects the comments.

## Anti-patterns

- Repeating the function signature in the doc — noise.
- "See the docs at..." — link rot.

## Approach

Walk every file in `crates/confium-wasm/src/`, add or expand `///`
blocks per the criteria. Run `wasm-pack build` and inspect the
generated `pkg/confium_wasm.d.ts`.

## Related

- [016-hello-world-examples.md](016-hello-world-examples.md) — examples
  referenced from JSDoc.
