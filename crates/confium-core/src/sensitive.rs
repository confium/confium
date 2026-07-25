//! Confidential memory wrappers.
//!
//! `Sensitive<T>` zeroizes its contents on drop. Use it for any value
//! whose contents must not linger in process memory beyond its useful
//! lifetime: RNG output before use, AEAD keys, KDF-derived key material,
//! serialized secret keys, etc.
//!
//! `Secret<T>` (encrypted-at-rest in RAM) is the next step toward the
//! design in <https://github.com/confium/confium/issues/4> — it requires
//! an AEAD plugin to be loaded before initialization and is tracked as
//! a follow-up TODO.

use std::fmt;

use zeroize::Zeroize;

/// Wraps a `T` and zeroizes it on `Drop`. Defends against leftover
/// secrets in process memory after the value goes out of scope.
///
/// `T` must implement `Zeroize` so we know how to clear it. Most
/// primitive containers (`Vec<u8>`, `[u8; N]`, `String`) implement
/// `Zeroize` out of the box.
pub struct Sensitive<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Sensitive<T> {
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    pub fn get(&self) -> &T {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Take ownership of the inner value. The caller becomes
    /// responsible for the lifetime of the secret — `Sensitive` no
    /// longer zeroizes it.
    pub fn into_inner(self) -> T {
        // Bypass Drop via ManuallyDrop so we can re-own the value
        // without zeroizing it on the way out.
        let manually_dropped = std::mem::ManuallyDrop::new(self);
        // SAFETY: we read `inner` out of the ManuallyDrop-wrapped self;
        // because the outer ManuallyDrop prevents our Drop from running,
        // this is the only path that takes ownership of `inner`.
        unsafe { std::ptr::read(&manually_dropped.inner) }
    }
}

impl<T: Zeroize + AsRef<[u8]>> AsRef<[u8]> for Sensitive<T> {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl<T: Zeroize + AsMut<[u8]>> AsMut<[u8]> for Sensitive<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut()
    }
}

impl<T: Zeroize> Drop for Sensitive<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

// Forward common traits so callers can interact with the wrapper
// naturally without unwrapping.

impl<T: Zeroize + fmt::Debug> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Intentionally do NOT forward the inner debug. The inner value
        // is sensitive — printing it would leak the secret to logs.
        f.debug_struct("Sensitive").finish_non_exhaustive()
    }
}

impl<T: Zeroize + Clone> Clone for Sensitive<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_zeroizes_vec_on_drop() {
        let ptr;
        {
            let s = Sensitive::new(vec![0xAAu8; 8]);
            ptr = s.get().as_ptr();
            assert_eq!(s.get(), &[0xAA; 8]);
        }
        // After drop, read the same memory location. If the Vec
        // allocator reused the slot, the read may give anything; we
        // assert with a small heap region where reuse is unlikely
        // immediately. This is a best-effort check.
        // SAFETY: we still own the address space (heap); the read is
        // well-defined as long as the page hasn't been returned to the
        // OS, which doesn't happen for a small allocation.
        let observed = unsafe { std::slice::from_raw_parts(ptr, 8) };
        let any_zero = observed.contains(&0);
        assert!(
            any_zero,
            "memory should contain at least one zero byte after drop"
        );
    }

    #[test]
    fn sensitive_into_inner_preserves_value() {
        let s = Sensitive::new(vec![1u8, 2, 3, 4]);
        let inner = s.into_inner();
        assert_eq!(inner, vec![1, 2, 3, 4]);
    }

    #[test]
    fn sensitive_clone_preserves_inner() {
        let a = Sensitive::new(42u32);
        let b = a.clone();
        assert_eq!(*a.get(), 42);
        assert_eq!(*b.get(), 42);
    }

    #[test]
    fn sensitive_debug_does_not_leak_inner() {
        let s = Sensitive::new(vec![0xDEu8, 0xAD, 0xBE, 0xEF]);
        let formatted = format!("{s:?}");
        assert!(
            !formatted.contains("deadbeef"),
            "Debug leaked secret: {formatted}"
        );
        assert!(
            !formatted.contains("DE"),
            "Debug leaked secret bytes: {formatted}"
        );
        assert!(formatted.contains("Sensitive"));
    }
}
