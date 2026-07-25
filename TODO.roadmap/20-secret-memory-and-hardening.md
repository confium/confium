# 20 — Secret<T> and memory hardening

## Secret<T>

AEAD-encrypted-at-rest wrapper for high-value secrets. Inner value encrypted with a per-process ephemeral key; decrypted briefly during use. Defends against process_vm_readv, /proc/pid/mem, cold-boot, speculative-execution leaks.

## mlock/munlock

mlock(2) sensitive pages to prevent swap. prctl(PR_SET_DUMPABLE, 0) on Linux. Equivalent on macOS/Windows.

## cfmp_sensitive_* interface

Plugin-facing memory hygiene: zeroize, mlock, munlock.
