//! Best-effort memory locking helpers.
//!
//! `mlock_bytes` / `munlock_bytes` pin pages so the OS is less likely to
//! page sensitive material out to swap while it lives in process RAM.
//! These are best-effort: on platforms without `mlock`/`VirtualLock`
//! (or when the process lacks the privilege to lock pages), both
//! functions return `Ok(())` so callers can lock defensively without
//! gating on the platform.
//!
//! Locking is advisory for defense-in-depth. Pair it with
//! [`crate::sensitive::Sensitive`] (zeroize-on-drop) and
//! [`crate::secret::Secret`] (AEAD-encrypted-at-rest) for a layered
//! defense of in-memory secrets.
//!
//! The FFI bindings are declared inline (no `libc`/`winapi` crate
//! dependency) so this module is self-contained and compiles on any
//! target where the symbols exist.

use crate::Result;

/// Lock the pages backing `bytes` into RAM. Best-effort: returns `Ok`
/// on platforms that don't support page locking or when the caller
/// lacks the required privilege.
pub fn mlock_bytes(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    mlock_impl(bytes)
}

/// Unlock the pages backing `bytes`, allowing the OS to reclaim them.
/// Best-effort: returns `Ok` on unsupported platforms.
pub fn munlock_bytes(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    munlock_impl(bytes)
}

// --- Unix -----------------------------------------------------------------

#[cfg(unix)]
unsafe extern "C" {
    fn mlock(addr: *const core::ffi::c_void, len: usize) -> core::ffi::c_int;
    fn munlock(addr: *const core::ffi::c_void, len: usize) -> core::ffi::c_int;
}

#[cfg(unix)]
fn mlock_impl(bytes: &[u8]) -> Result<()> {
    // SAFETY: `mlock(2)` only needs a valid address+length; we pass a
    // slice that is guaranteed live for the call duration. Errors are
    // surfaced as a nonzero return and treated as non-fatal
    // (best-effort).
    let ret = unsafe { mlock(bytes.as_ptr() as *const core::ffi::c_void, bytes.len()) };
    if ret != 0 {
        // Best-effort: permission denied (EPERM) or resource limit
        // (ENOMEM/again) are not fatal to the caller.
        return Ok(());
    }
    Ok(())
}

#[cfg(unix)]
fn munlock_impl(bytes: &[u8]) -> Result<()> {
    // SAFETY: as above; the slice is live and the address range is the
    // same one we (may have) locked.
    let ret = unsafe { munlock(bytes.as_ptr() as *const core::ffi::c_void, bytes.len()) };
    if ret != 0 {
        return Ok(());
    }
    Ok(())
}

// --- Windows --------------------------------------------------------------

#[cfg(windows)]
unsafe extern "system" {
    fn VirtualLock(lpAddress: *const core::ffi::c_void, dwSize: usize) -> core::ffi::c_int;
    fn VirtualUnlock(lpAddress: *const core::ffi::c_void, dwSize: usize) -> core::ffi::c_int;
}

#[cfg(windows)]
fn mlock_impl(bytes: &[u8]) -> Result<()> {
    // SAFETY: `VirtualLock` requires a valid pointer and byte count
    // within the process address space; the slice provides both. The
    // page must be committed, which heap/stack pages always are.
    let ok = unsafe { VirtualLock(bytes.as_ptr() as *const core::ffi::c_void, bytes.len()) };
    if ok == 0 {
        // Best-effort: ignore failures (privilege, quota).
        return Ok(());
    }
    Ok(())
}

#[cfg(windows)]
fn munlock_impl(bytes: &[u8]) -> Result<()> {
    // SAFETY: as above.
    let ok = unsafe { VirtualUnlock(bytes.as_ptr() as *const core::ffi::c_void, bytes.len()) };
    if ok == 0 {
        return Ok(());
    }
    Ok(())
}

// --- Unsupported ---------------------------------------------------------

// On platforms without `mlock`/`VirtualLock` (e.g. wasm, miri), the
// lock is a no-op. This keeps the API callable everywhere without
// conditional compilation at call sites.
#[cfg(not(any(unix, windows)))]
fn mlock_impl(_bytes: &[u8]) -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn munlock_impl(_bytes: &[u8]) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlock_and_munlock_round_trip_returns_ok() {
        // A modest buffer is well within typical RLIMIT_MEMLOCK; on
        // systems where it isn't, we still expect Ok (best-effort).
        let mut buf = vec![0u8; 4096];
        let res = mlock_bytes(&buf);
        assert!(res.is_ok(), "mlock_bytes should be best-effort Ok");
        let res = munlock_bytes(&buf);
        assert!(res.is_ok(), "munlock_bytes should be best-effort Ok");
        // Touch the bytes so the compiler doesn't elide the allocation.
        buf[0] = 1;
        assert_eq!(buf[0], 1);
    }

    #[test]
    fn mlock_empty_slice_is_ok() {
        let empty: [u8; 0] = [];
        assert!(mlock_bytes(&empty).is_ok());
        assert!(munlock_bytes(&empty).is_ok());
    }
}
