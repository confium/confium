# 16 — confiumd daemon

**Status**: SHIPPED. crates/confium-daemon.

Long-running JSON-RPC 2.0 daemon over Unix socket or TCP. 14 method
groups mirroring the C FFI (plugin, hash, cipher, aead, kdf, rng,
signature, kem, keyfmt, keystore, tc, registry, audit, meta).

Length-prefix framing (4-byte big-endian). LocalSet-based concurrency
for the !Send Confium engine. CancellationToken for graceful shutdown.

Integration test: spin up daemon on ephemeral port, JSON-RPC version()
call, verify response.
