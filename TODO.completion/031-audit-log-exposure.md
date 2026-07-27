# 031 — Audit log exposure

**Category**: Security
**Severity**: High (compliance requirement)
**Effort**: Medium (1 PR)

## Problem

The Rust workspace has `confium-core::audit` modules. They aren't
exposed to Ruby or WASM. For compliance (CNML, government), every
signing operation must produce an auditable record: who signed, when,
what algorithm, what payload hash, what signature was produced.

## Acceptance criteria

- [ ] `Confium::Audit` Ruby module:
  - `Confium::Audit::Sink` base class — abstract `#write(record)`.
  - `Confium::Audit::FileSink.new(path)` — append-only file.
  - `Confium::Audit::MemorySink.new` — in-memory (testing).
  - `Confium::Audit::StderrSink` — write to stderr.
- [ ] `Confium.audit_sink = sink` (singleton) routes audit records.
- [ ] Every signing operation produces a record with:
  - `:timestamp` (ISO8601 UTC)
  - `:operation` (e.g. `:composite_sign`, `:cms_verify`)
  - `:actor` (the actor_id from the Identity if available)
  - `:algorithm`
  - `:payload_hash` (SHA-256 of the signed bytes)
  - `:result` (`:success` / `:failure`)
  - `:error` (if failed)
- [ ] Spec: signing with a FileSink attached writes a record.
- [ ] Spec: signing with no sink is silent (backward compat).

## Anti-patterns

- "Log everything to STDOUT" — that's a file or stderr, not a sink.
- "Use `Rails.logger`" — confium-ruby has no Rails dep. Use sinks.
- Allowing user to skip audit for signing ops — defeats compliance.

## Approach

Wire `confium_core::audit::AuditEvent` through to Ruby. The Rust side
fires events on every signing op; the Ruby side routes them to the
configured sink. Default sink is `MemorySink` for testing; production
deployments configure `FileSink` or a custom sink (HTTP, syslog).

## Related

- [009-multi-party-tc-sessions.md](009-multi-party-tc-sessions.md) —
  every session ceremony must produce an audit record.
- [018-cnml-walkthrough.md](018-cnml-walkthrough.md) — CNML requires
  audit trails.
