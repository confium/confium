# 50 — Internationalization and localization

## Audience

Confium is a global framework — OIML alone has 60+ member states.
Documentation, error messages, and CLI output must be internationalizable.

## Scope

### Tier 1: Documentation

- **English** is the canonical language for `docs/`, README, code comments
- **Translations** live in `docs/locale/<LANG>/` for OIML priority languages:
  - French (BIML official language)
  - German (PTB, major metrology institute)
  - Chinese (NIM, major metrology institute)
  - Japanese (NMIJ/AIST, major metrology institute)
  - Spanish, Russian, Arabic as community-contributed

Translations are *informational*; English is authoritative for technical
content. When in doubt, the English doc wins.

### Tier 2: Error messages

Error messages use fluent templates (`fluent-rs`) for translation:

```rust
use fluent_templates::Loader;
fluent_loader! {
    locales: &["en", "fr", "de", "zh", "ja"],
    fallback: "en",
}
let msg = format!("manifest-invalid-version", version = 0);
```

Default English. Locale determined by:
1. `CIUM_LANG` env var
2. `LC_MESSAGES` / `LANG` (POSIX)
3. Default to English

### Tier 3: CLI output

`clap`'s built-in i18n support (when available) for help text. Otherwise
explicit `--lang <code>` flag.

### Tier 4: API and code identifiers

**Always English**. Variable names, function names, types: English.
Translation is for user-facing strings only.

## Date and time

All timestamps are RFC 3339 UTC by default. Locale-specific formatting
only for display.

```rust
let ts: chrono::DateTime<Utc> = Utc::now();
let display = ts.format("%Y-%m-%d %H:%M:%S UTC").to_string();
```

## Number formatting

Internal storage: integers / floats (no formatting). Display: locale-aware
via `icu` crate where needed.

## Right-to-left

Not yet a concern. If needed for Arabic/Hebrew UI, use `icu::bidirectional`.

## Character encoding

- All files: UTF-8 (no BOM)
- All I/O: UTF-8 with explicit error on invalid byte
- File names: NFC-normalized Unicode

## Currency

Out of scope for crypto framework.

## Paper sizes

Documentation prints to PDF (US Letter + A4 + A3 versions of major docs).

## Anti-goals

- **Not** translating every TODO.roadmap doc (English-only for engineering)
- **Not** maintaining translations as separate code branches (single source
  of truth: English)
- **Not** blocking code changes on translation completeness

## References

- `TODO.roadmap/47-documentation-strategy.md`
- [fluent-rs](https://github.com/projectfluent/fluent-rs)
