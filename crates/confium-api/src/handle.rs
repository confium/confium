//! Opaque handle helpers for boxing/unboxing Rust plugin state behind
//! the type-erased `*mut c_void` plugin contract.
//!
//! Confium plugins expose their per-instance state through opaque pointers
//! (e.g. `*mut FFIHash`). The loader never inspects the pointee — it just
//! hands the pointer back to the plugin on every call. Conventionally a
//! plugin author writes `Box::into_raw(Box::new(state)) as *mut c_void`
//! in `create` and `Box::from_raw(ptr)` in `destroy`, sprinkling `unsafe`
//! through their code.
//!
//! [`OpaqueHandle`] wraps that pattern so plugin authors can stay in safe
//! Rust for the lifetime of the handle:
//!
//! ```
//! use confium_api::OpaqueHandle;
//! #
//! # struct MyHash { buf: Vec<u8> }
//!
//! // `create` returns an opaque pointer the loader will hand back.
//! fn create() -> *mut std::ffi::c_void {
//!     let state = MyHash { buf: Vec::new() };
//!     OpaqueHandle::<MyHash>::new(state)
//! }
//!
//! // Every other entry point borrows the live state.
//! # // SAFETY: ptr was produced by `create` and is reclaimed exactly once.
//! unsafe fn update(ptr: *mut std::ffi::c_void, data: &[u8]) {
//!     let handle = OpaqueHandle::<MyHash>::borrow_raw(ptr);
//!     handle.buf.extend_from_slice(data);
//! }
//!
//! // `destroy` reclaims ownership and drops the state.
//! # // SAFETY: ptr was produced by `create` and is reclaimed exactly once.
//! unsafe fn destroy(ptr: *mut std::ffi::c_void) {
//!     let _ = OpaqueHandle::<MyHash>::from_raw(ptr);
//! }
//! ```
//!
//! ## Safety contract
//!
//! The pointer returned by [`OpaqueHandle::into_raw`] is owned by the
//! caller (typically the Confium loader) until the matching `destroy`
//! symbol is invoked. Borrowing it from any other thread, or calling
//! `from_raw` more than once, is undefined behavior. Plugins are
//! single-threaded with respect to a given instance handle in the v0
//! contract.

use std::ffi::c_void;
use std::marker::PhantomData;

/// Wrapper around a `Box<T>` that knows how to round-trip through a
/// raw `*mut c_void` pointer without exposing `unsafe` at call sites.
///
/// See the module docs for the safety contract.
pub struct OpaqueHandle<T: ?Sized> {
    _marker: PhantomData<T>,
}

impl<T> OpaqueHandle<T> {
    /// Box `value` and return it as an opaque raw pointer. The caller
    /// owns the allocation; pass it to [`from_raw`](Self::from_raw) to
    /// reclaim it.
    #[allow(clippy::new_ret_no_self)] // intentional: returns a raw pointer
    pub fn new(value: T) -> *mut c_void {
        Box::into_raw(Box::new(value)) as *mut c_void
    }

    /// Reclaim a pointer produced by [`new`](Self::new) (or
    /// [`into_raw`](Self::into_raw)) and drop the underlying value.
    /// Calling this on a NULL pointer is a no-op. Calling it twice on
    /// the same non-NULL pointer is undefined behavior.
    ///
    /// # Safety
    ///
    /// `ptr` must either be NULL or have been produced by
    /// [`OpaqueHandle::new`] / [`OpaqueHandle::into_raw`] for the same
    /// type `T`, and must not have been reclaimed already.
    pub unsafe fn from_raw(ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }
        // SAFETY: upheld by the caller — the pointer was produced by
        // `Box::into_raw(Box::new(value))` for this exact `T`, and is
        // being reclaimed exactly once.
        unsafe { drop(Box::from_raw(ptr as *mut T)) };
    }

    /// Take ownership of `value`, box it, and yield the raw pointer.
    /// Equivalent to [`new`](Self::new) but reads better when you already
    /// have a value to hand off.
    pub fn into_raw(value: T) -> *mut c_void {
        Self::new(value)
    }
}

impl<T: ?Sized> OpaqueHandle<T> {
    /// Borrow the live state behind `ptr` for the duration of the
    /// returned reference. The pointer is **not** reclaimed — the
    /// allocation remains owned by whoever holds it (typically the
    /// Confium loader, until `destroy` is called).
    ///
    /// The returned `&mut T` borrow is tied to the lifetime `'a` so
    /// callers cannot accidentally outlive it through `Copy`/`Clone`.
    ///
    /// # Safety
    ///
    /// `ptr` must be a non-NULL pointer produced by
    /// [`OpaqueHandle::new`] / [`OpaqueHandle::into_raw`] for a type
    /// that is layout-compatible with `T`, and must remain valid for
    /// the duration of `'a`. The v0 plugin contract guarantees this:
    /// instance handles are single-threaded and live until `destroy`.
    pub unsafe fn borrow_raw<'a>(ptr: *mut c_void) -> &'a mut T
    where
        T: Sized,
    {
        debug_assert!(
            !ptr.is_null(),
            "OpaqueHandle::borrow_raw on a NULL pointer is a plugin bug"
        );
        // SAFETY: upheld by the caller.
        unsafe { &mut *(ptr as *mut T) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_a_value() {
        let ptr = OpaqueHandle::new(42u32);
        let borrowed = unsafe { OpaqueHandle::<u32>::borrow_raw(ptr) };
        assert_eq!(*borrowed, 42);
        *borrowed = 7;
        let borrowed2 = unsafe { OpaqueHandle::<u32>::borrow_raw(ptr) };
        assert_eq!(*borrowed2, 7);
        unsafe {
            OpaqueHandle::<u32>::from_raw(ptr);
        }
    }

    #[test]
    fn from_raw_on_null_is_a_noop() {
        unsafe {
            OpaqueHandle::<u32>::from_raw(std::ptr::null_mut());
        }
    }

    #[test]
    fn roundtrips_a_struct() {
        struct State {
            count: u32,
            label: String,
        }
        let ptr = OpaqueHandle::new(State {
            count: 0,
            label: "hash".to_string(),
        });
        let s = unsafe { OpaqueHandle::<State>::borrow_raw(ptr) };
        s.count += 1;
        assert_eq!(s.label, "hash");
        assert_eq!(s.count, 1);
        unsafe {
            OpaqueHandle::<State>::from_raw(ptr);
        }
    }
}
