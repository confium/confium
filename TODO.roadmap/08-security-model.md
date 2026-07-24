# 08 — Security Model

## Threat surface

Confium is a framework for executing third-party crypto code inside applications that handle secrets. The threat surface is substantial:

1. **Malicious plugin** — a plugin could exfiltrate keys, leak randomness, produce incorrect signatures, or compromise the host process.
2. **Tampered artifact** — a registry attack that swaps a legitimate plugin binary for a malicious one.
3. **Rogue publisher** — a publisher with trusted status goes rogue and ships a backdoored update.
4. **Network MITM** — for TC sessions, a malicious peer or network observer.
5. **Memory disclosure** — secrets left in process memory after use (heap dumps, core dumps, swap).
6. **Plugin dependency confusion** — a plugin declares a dependency that's resolved to a malicious substitute.

## Trust roots

The trust model is **publisher-centric**. Confium does not vet algorithms or implementations. It only verifies that an artifact was signed by a publisher the user has chosen to trust.

- **Default trust roots** ship with the registry (`trust-roots.toml`). These are the publishers the Confium project vouches for at the framework level.
- **User trust roots** live in `~/.config/confium/trust/`. Users can add publishers (e.g. their employer's internal signing key).
- **Install policy** (default strict): refuse to install any plugin lacking at least one signature from a trusted publisher. Users can opt into laxer policies (`--allow-untrusted`) for development.

## Artifact verification flow

```
1. Download artifact from registry URL (or mirror)
2. Download manifest.toml from same version dir
3. Verify manifest.toml hash matches the version's index entry
4. For each .asc in sigs/:
   a. Verify signature against artifact bytes
   b. Identify publisher by signing key fingerprint
   c. If publisher in user trust roots → mark as trusted
5. If no trusted publisher → refuse install
6. (Optional) Verify publisher key is in the registry's publishers/ dir
   (i.e., the registry itself vouches for the publisher's identity)
```

## Memory security

`Sensitive<T>` (shipped in 0.2.0) zeroizes secrets on drop. This roadmap expands memory hygiene:

- **`Secret<T>`** (post-0.3) — AEAD-encrypted-at-rest wrapper. The inner value is encrypted with a per-process ephemeral key; plaintext exists only briefly during use. Defends against `process_vm_readv`, `/proc/<pid>/mem`, cold-boot attacks, and certain speculative-execution leaks.
- **`mlock` sensitive pages** — `mlock(2)` on buffers holding secrets to prevent them being paged to swap.
- **Disable core dumps** while secrets are live — `prctl(PR_SET_DUMPABLE, 0)` on Linux, equivalent on others.
- **Zeroize on `Drop`** for all internal buffers holding key material.

A new `sensitive-memory` interface lets plugins advertise their memory-hygiene capabilities:

```c
uint32_t cfmp_sensitive_zeroize(void *ptr, size_t len);
uint32_t cfmp_sensitive_mlock(void *ptr, size_t len);
uint32_t cfmp_sensitive_munlock(void *ptr, size_t len);
```

Plugins opt in. Confium calls them when handing secret bytes to the plugin.

## Plugin sandboxing (2.0+)

For 1.0, plugins are in-process and fully trusted. For 2.0, two sandboxing tracks:

### Track A: WASM plugins

- Plugins compile to `wasm32-wasi`.
- Confium embeds a WASM runtime (wasmtime, BSD-2-Clause).
- Plugins get a limited API surface (only Confium FFI functions, no direct file/network access).
- Performance hit: ~10-30% vs native, depending on scheme.

### Track B: Out-of-process plugins

- Each plugin is a separate process.
- Confium communicates via length-prefixed JSON-RPC over Unix socket.
- Plugin process runs under seccomp/AppSandbox with no network access (TC network access is proxied through Confium's transport plugins).
- Performance hit: IPC overhead per call, ~1-10μs per FFI call.

Either track is opt-in. Performance-sensitive deployments continue to use in-process.

## TC session authentication

Threshold sessions authenticate peer parties via:

1. **Transport-layer TLS** — required for `quic://` and `tcp+tls://` URLs.
2. **Per-message signatures** — each TC round message signed by the sender's long-term key. Receiver verifies before processing. Works over any transport.
3. **Identity binding** — party IDs in the session roster are bound to public keys; messages from unknown parties are rejected.

A malicious peer who can sign (i.e., one of the T threshold parties) can produce invalid protocol output. The TC scheme itself must provide **detectable failure** for Byzantine peers (most modern schemes do — they abort with proof of misbehavior).

## Random number generation

- All RNG output used for crypto goes through the `rng` interface.
- The "System" RNG algorithm (OS CSPRNG) is always available.
- For tests, plugins can declare `"MockRng"` which uses a seeded deterministic stream — never available in production builds (compile-time gate).
- The `Sensitive<Vec<u8>>` returned by `Rng::generate_sensitive` is zeroized on drop.

## Auditability

Every plugin load, every secret access, every TC session is logged via `slog` (already in deps) to a configurable sink. Default sink: `~/.local/share/confium/log/audit.jsonl`. Format:

```json
{"ts": "2026-07-24T13:05:22.123Z", "event": "plugin_load", "plugin": "botan", "version": "3.2.0", "publisher": "ribose"}
{"ts": "2026-07-24T13:05:22.456Z", "event": "key_access", "key_id": "abc123", "interface": "signature", "operation": "sign"}
{"ts": "2026-07-24T13:05:23.789Z", "event": "tc_session_start", "scheme": "FROST-ed25519", "parties": 3, "threshold": 2}
```

No secret bytes in logs. Logging is on by default; can be disabled.

## Disclosed vulnerabilities

`SECURITY.md` already covers the reporting process. The release flow:

1. Reporter emails `open.source@ribose.com` with details.
2. Maintainers triage, propose fix timeline.
3. Fix developed in a private fork.
4. Coordinated disclosure: CVE assigned, fix released simultaneously with public advisory.
5. CHANGELOG entry + GitHub Security Advisory.

## Out of scope for security

- **Algorithm choice** — Confium doesn't prevent users from installing cryptographically weak algorithms (MD5, RSA-1024). The plugin manifest could carry strength hints; the CLI could warn. But the framework doesn't enforce.
- **Plugin code review** — Confium doesn't review plugin source. That's the publisher's responsibility.
- **Quantum resistance** — Confium supports PQC algorithms (ML-KEM, ML-DSA, SLH-DSA, composites) but doesn't require them. Algorithm selection is user-driven.

## Reference

- `TODO.finalize/13-sensitive-memory.md` — Sensitive implementation
- `TODO.roadmap/06-module-registry.md` — trust model for install
