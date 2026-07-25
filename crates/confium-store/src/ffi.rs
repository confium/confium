//! FFI surface for the Store crate.
//!
//! Exposes the `cfm_keystore_*` C ABI. The wire protocol mirrors
//! `TODO.finalize/12-keystore-interface.md`. Key material is opaque
//! (`*mut c_void`) — the Store never interprets key bytes, it only
//! indexes and returns handles owned by the caller (typically the
//! Engine's `keyfmt` interface).
//!
//! Entry points follow the conventions established by `confium-core`'s
//! FFI layer: raw-pointer parameters, null-checked on entry, and a
//! `u32` result encoding either `0` for success or a numeric
//! [`crate::error::ErrorCode`].

use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::c_void;
use std::os::raw::c_char;

use snafu::{ResultExt, ensure};

use crate::backend::Options;
use crate::error::{InvalidUTF8Snafu, NullPointerSnafu, Result};
use crate::keystore::Keystore;

/// Opaque handle returned to C callers. Never dereferenced by C; only
/// passed back into the FFI.
pub enum FFIKeystore {}

/// Opaque key iterator handle.
pub enum FFIKeyIterator {}

/// Opaque key handle. The Store treats this as a caller-owned token; it
/// stores and returns the pointer verbatim and never dereferences it.
pub type FFIKey = c_void;

// --- helpers --------------------------------------------------------------

/// Null-check that returns an `Error` rather than a numeric code — used
/// by the inner `_` functions that return `Result`.
fn require<T>(ptr: *const T, param: &'static str) -> Result<()> {
    if ptr.is_null() {
        Err(NullPointerSnafu { param }.build())
    } else {
        Ok(())
    }
}

/// Copy a NUL-terminated C string into an owned `String`, surfacing
/// invalid UTF-8 as [`Error::InvalidUTF8`].
fn cstring(cstr: *const c_char, param: &'static str) -> Result<String> {
    require(cstr, param)?;
    unsafe {
        CStr::from_ptr(cstr)
            .to_str()
            .context(InvalidUTF8Snafu {})
            .map(str::to_string)
    }
}

/// Build an empty [`Options`] from a possibly-null pointer. The current
/// wire protocol passes options opaquely; for now we accept `NULL` and
/// produce an empty map. A richer option model can be layered in
/// without changing the entry-point signatures.
fn options_from_ptr(_opts: *const c_void) -> Options {
    // The Store's Options is `HashMap<String, String>`. The Engine
    // passes a typed `*const Options`; here we deliberately stay
    // decoupled and treat the pointer as opaque. When the keystore
    // becomes a loaded plugin, the loader will translate the Engine's
    // option map into this crate's `Options` before calling `open`.
    HashMap::new()
}

// --- create / destroy -----------------------------------------------------

fn cfm_keystore_create_(
    out: *mut *mut FFIKeystore,
    backend_name: *const c_char,
    opts: *const c_void,
) -> Result<()> {
    require(out, "out")?;
    require(backend_name, "backend_name")?;
    let name = cstring(backend_name, "backend_name")?;
    let opts = options_from_ptr(opts);
    let ks = Keystore::new(&name, &opts)?;
    // SAFETY: the caller receives a heap-allocated handle; they must
    // return it via `cfm_keystore_destroy`.
    unsafe {
        *out = Box::into_raw(Box::new(ks)) as *mut FFIKeystore;
    }
    Ok(())
}

/// Create a keystore backed by `backend_name` (e.g. `"memory"`).
///
/// Returns `0` on success, or a numeric
/// [`ErrorCode`](crate::error::ErrorCode) on failure.
#[unsafe(no_mangle)]
pub extern "C" fn cfm_keystore_create(
    out: *mut *mut FFIKeystore,
    backend_name: *const c_char,
    opts: *const c_void,
) -> u32 {
    cfm_keystore_create_(out, backend_name, opts).map_or_else(|e| e.code(), |_| 0)
}

/// Drop a keystore handle. Safe to call with `NULL`.
#[unsafe(no_mangle)]
pub extern "C" fn cfm_keystore_destroy(ks: *mut FFIKeystore) {
    if !ks.is_null() {
        // SAFETY: the handle was produced by `cfm_keystore_create` as a
        // `Box::into_raw`; reclaiming it here is the matching drop.
        unsafe {
            drop(Box::from_raw(ks as *mut Keystore));
        }
    }
}

// --- private compartment --------------------------------------------------

fn keystore_mut(ks: *mut FFIKeystore) -> Result<&'static mut Keystore> {
    require(ks, "ks")?;
    // SAFETY: the caller owns the handle and guarantees exclusive access
    // for the duration of this mutable call. The `'static` lifetime is
    // a convenience so the inner functions can return a borrow — the
    // caller must not retain the reference beyond the FFI call.
    Ok(unsafe { &mut *(ks as *mut Keystore) })
}

fn keystore_ref(ks: *mut FFIKeystore) -> Result<&'static Keystore> {
    require(ks, "ks")?;
    Ok(unsafe { &*(ks as *mut Keystore) })
}

/// Insert a secret key into the private compartment.
#[unsafe(no_mangle)]
pub extern "C" fn cfm_keystore_put_secret(
    ks: *mut FFIKeystore,
    module_id: *const c_char,
    app_id: *const c_char,
    key_id: *const c_char,
    secret_key: *mut FFIKey,
) -> u32 {
    let inner = || -> Result<()> {
        let ks = keystore_mut(ks)?;
        let module = cstring(module_id, "module_id")?;
        let app = cstring(app_id, "app_id")?;
        let key_id = cstring(key_id, "key_id")?;
        require(secret_key, "secret_key")?;
        ks.put_secret(&module, &app, &key_id, secret_key)
    };
    inner().map_or_else(|e| e.code(), |_| 0)
}

/// Fetch a secret key from the private compartment.
///
/// On success writes the opaque key handle into `*out`.
#[unsafe(no_mangle)]
pub extern "C" fn cfm_keystore_get_secret(
    ks: *mut FFIKeystore,
    module_id: *const c_char,
    app_id: *const c_char,
    key_id: *const c_char,
    out: *mut *mut FFIKey,
) -> u32 {
    let inner = || -> Result<()> {
        let ks = keystore_ref(ks)?;
        let module = cstring(module_id, "module_id")?;
        let app = cstring(app_id, "app_id")?;
        let key_id = cstring(key_id, "key_id")?;
        require(out, "out")?;
        let key = ks.get_secret(&module, &app, &key_id)?;
        unsafe {
            *out = key as *mut FFIKey;
        }
        Ok(())
    };
    inner().map_or_else(|e| e.code(), |_| 0)
}

// --- public compartment ---------------------------------------------------

/// Insert a public key into the public compartment with a detached
/// identity signature.
#[unsafe(no_mangle)]
pub extern "C" fn cfm_keystore_put_public(
    ks: *mut FFIKeystore,
    module_id: *const c_char,
    app_id: *const c_char,
    identity: *const c_char,
    public_key: *mut FFIKey,
    signature: *const u8,
    sig_len: u32,
) -> u32 {
    let inner = || -> Result<()> {
        let ks = keystore_mut(ks)?;
        let module = cstring(module_id, "module_id")?;
        let app = cstring(app_id, "app_id")?;
        let identity = cstring(identity, "identity")?;
        require(public_key, "public_key")?;
        // signature may legitimately be empty (sig_len == 0); a NULL
        // pointer with non-zero length is an error.
        let sig: &[u8] = if signature.is_null() {
            ensure!(sig_len == 0, NullPointerSnafu { param: "signature" });
            &[]
        } else {
            // SAFETY: the caller vouches for `sig_len` bytes being
            // readable from `signature`.
            unsafe { std::slice::from_raw_parts(signature, sig_len as usize) }
        };
        ks.put_public(&module, &app, &identity, public_key, sig)
    };
    inner().map_or_else(|e| e.code(), |_| 0)
}

/// Fetch a public key from the public compartment by identity.
///
/// On success writes the opaque key handle into `*out`.
#[unsafe(no_mangle)]
pub extern "C" fn cfm_keystore_get_public(
    ks: *mut FFIKeystore,
    module_id: *const c_char,
    app_id: *const c_char,
    identity: *const c_char,
    out: *mut *mut FFIKey,
) -> u32 {
    let inner = || -> Result<()> {
        let ks = keystore_ref(ks)?;
        let module = cstring(module_id, "module_id")?;
        let app = cstring(app_id, "app_id")?;
        let identity = cstring(identity, "identity")?;
        require(out, "out")?;
        let (key, _sig) = ks.get_public(&module, &app, &identity)?;
        unsafe {
            *out = key as *mut FFIKey;
        }
        Ok(())
    };
    inner().map_or_else(|e| e.code(), |_| 0)
}

// --- enumeration ----------------------------------------------------------

/// Snapshot of one entry yielded by an iterator.
struct IterEntry {
    key: *mut c_void,
    /// The index string (`key_id` for private, canonical identity for
    /// public). Kept so a future `iterator_next_with_index` entry point
    /// can surface it without an extra enumerate round-trip; the current
    /// `cfm_keystore_iterator_next` only returns the key handle.
    #[allow(dead_code)]
    index: String,
}

/// Backing storage for an iterator handle. Owns a `Vec` snapshot taken
/// at enumerate time — iteration does not hold a borrow on the
/// keystore, so the caller may continue mutating the store while
/// iterating over a past snapshot.
pub struct KeyIterator {
    entries: std::vec::IntoIter<IterEntry>,
}

fn cfm_keystore_enumerate_(
    ks: *mut FFIKeystore,
    module_id: *const c_char,
    app_id: *const c_char,
    compartment: u32,
    out: *mut *mut FFIKeyIterator,
) -> Result<()> {
    let ks = keystore_ref(ks)?;
    let module = cstring(module_id, "module_id")?;
    let app = cstring(app_id, "app_id")?;
    require(out, "out")?;
    let comp = crate::backend::Compartment::from_wire(compartment)?;
    let raw = ks.enumerate(&module, &app, comp)?;
    let entries: Vec<IterEntry> = raw
        .into_iter()
        .map(|(key, index)| IterEntry { key, index })
        .collect();
    let it = KeyIterator {
        entries: entries.into_iter(),
    };
    unsafe {
        *out = Box::into_raw(Box::new(it)) as *mut FFIKeyIterator;
    }
    Ok(())
}

/// Enumerate entries in one compartment of one `(module, app)` scope.
///
/// `compartment`: `0` = public, `1` = private. The returned iterator
/// holds a snapshot; mutating the keystore during iteration is safe.
#[unsafe(no_mangle)]
pub extern "C" fn cfm_keystore_enumerate(
    ks: *mut FFIKeystore,
    module_id: *const c_char,
    app_id: *const c_char,
    compartment: u32,
    out: *mut *mut FFIKeyIterator,
) -> u32 {
    cfm_keystore_enumerate_(ks, module_id, app_id, compartment, out)
        .map_or_else(|e| e.code(), |_| 0)
}

/// Advance the iterator. Returns `0` and writes the next key handle into
/// `*out`, or `Error::ValueNotFound` when the iterator is exhausted (in
/// which case `*out` is left untouched).
#[unsafe(no_mangle)]
pub extern "C" fn cfm_keystore_iterator_next(
    it: *mut FFIKeyIterator,
    out: *mut *mut FFIKey,
) -> u32 {
    let inner = || -> Result<()> {
        require(it, "it")?;
        require(out, "out")?;
        // SAFETY: handle produced by `cfm_keystore_enumerate`.
        let it = unsafe { &mut *(it as *mut KeyIterator) };
        match it.entries.next() {
            Some(entry) => {
                unsafe {
                    *out = entry.key as *mut FFIKey;
                }
                Ok(())
            }
            None => Err(crate::error::ValueNotFoundSnafu.build()),
        }
    };
    inner().map_or_else(|e| e.code(), |_| 0)
}

/// Drop an iterator handle. Safe to call with `NULL`.
#[unsafe(no_mangle)]
pub extern "C" fn cfm_keystore_iterator_destroy(it: *mut FFIKeyIterator) {
    if !it.is_null() {
        // SAFETY: handle produced by `cfm_keystore_enumerate`.
        unsafe {
            drop(Box::from_raw(it as *mut KeyIterator));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use std::ffi::CString;
    use std::ptr;

    fn sentinel(n: usize) -> *mut FFIKey {
        n as *mut FFIKey
    }

    // Leaked CString raw pointers are acceptable in tests; the process
    // exits shortly after. Using `CString::into_raw` avoids the borrow
    // checker fighting the FFI call boundary.

    #[test]
    fn create_and_destroy_memory_keystore() {
        let mut ks: *mut FFIKeystore = ptr::null_mut();
        let name = CString::new("memory").unwrap().into_raw();
        let rc = cfm_keystore_create(&mut ks, name, ptr::null());
        assert_eq!(rc, 0, "create should succeed");
        assert!(!ks.is_null());
        cfm_keystore_destroy(ks);
    }

    #[test]
    fn create_unknown_backend_returns_error() {
        let mut ks: *mut FFIKeystore = ptr::null_mut();
        let name = CString::new("nope").unwrap().into_raw();
        let rc = cfm_keystore_create(&mut ks, name, ptr::null());
        assert_eq!(
            rc,
            Error::UnknownBackend {
                name: String::new()
            }
            .code()
        );
        assert!(ks.is_null());
    }

    #[test]
    fn put_get_secret_round_trip() {
        let mut ks: *mut FFIKeystore = ptr::null_mut();
        let name = CString::new("memory").unwrap().into_raw();
        cfm_keystore_create(&mut ks, name, ptr::null());
        let key = sentinel(0x1000);

        let m = CString::new("mod").unwrap().into_raw();
        let a = CString::new("app").unwrap().into_raw();
        let k = CString::new("key-1").unwrap().into_raw();
        let rc = cfm_keystore_put_secret(ks, m, a, k, key);
        assert_eq!(rc, 0, "put_secret");

        let m = CString::new("mod").unwrap().into_raw();
        let a = CString::new("app").unwrap().into_raw();
        let k = CString::new("key-1").unwrap().into_raw();
        let mut out: *mut FFIKey = ptr::null_mut();
        let rc = cfm_keystore_get_secret(ks, m, a, k, &mut out);
        assert_eq!(rc, 0, "get_secret");
        assert_eq!(out, key);

        cfm_keystore_destroy(ks);
    }

    #[test]
    fn get_secret_missing_returns_value_not_found() {
        let mut ks: *mut FFIKeystore = ptr::null_mut();
        let name = CString::new("memory").unwrap().into_raw();
        cfm_keystore_create(&mut ks, name, ptr::null());

        let m = CString::new("mod").unwrap().into_raw();
        let a = CString::new("app").unwrap().into_raw();
        let k = CString::new("missing").unwrap().into_raw();
        let mut out: *mut FFIKey = ptr::null_mut();
        let rc = cfm_keystore_get_secret(ks, m, a, k, &mut out);
        assert_eq!(rc, Error::ValueNotFound.code());
    }

    #[test]
    fn put_get_public_round_trip() {
        let mut ks: *mut FFIKeystore = ptr::null_mut();
        let name = CString::new("memory").unwrap().into_raw();
        cfm_keystore_create(&mut ks, name, ptr::null());

        let key = sentinel(0x2000);
        let sig = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let m = CString::new("mod").unwrap().into_raw();
        let a = CString::new("app").unwrap().into_raw();
        let id = CString::new("email:alice@example.com").unwrap().into_raw();
        let rc = cfm_keystore_put_public(ks, m, a, id, key, sig.as_ptr(), sig.len() as u32);
        assert_eq!(rc, 0, "put_public");

        let m = CString::new("mod").unwrap().into_raw();
        let a = CString::new("app").unwrap().into_raw();
        let id = CString::new("email:alice@example.com").unwrap().into_raw();
        let mut out: *mut FFIKey = ptr::null_mut();
        let rc = cfm_keystore_get_public(ks, m, a, id, &mut out);
        assert_eq!(rc, 0, "get_public");
        assert_eq!(out, key);

        cfm_keystore_destroy(ks);
    }

    #[test]
    fn enumerate_private_then_exhaust() {
        let mut ks: *mut FFIKeystore = ptr::null_mut();
        let name = CString::new("memory").unwrap().into_raw();
        cfm_keystore_create(&mut ks, name, ptr::null());

        for (kid, key) in [("a", sentinel(1)), ("b", sentinel(2))] {
            let m = CString::new("mod").unwrap().into_raw();
            let a = CString::new("app").unwrap().into_raw();
            let k = CString::new(kid).unwrap().into_raw();
            let rc = cfm_keystore_put_secret(ks, m, a, k, key);
            assert_eq!(rc, 0);
        }

        let m = CString::new("mod").unwrap().into_raw();
        let a = CString::new("app").unwrap().into_raw();
        let mut it: *mut FFIKeyIterator = ptr::null_mut();
        let rc = cfm_keystore_enumerate(ks, m, a, 1, &mut it); // 1 = private
        assert_eq!(rc, 0);

        let mut seen = Vec::new();
        loop {
            let mut out: *mut FFIKey = ptr::null_mut();
            let rc = cfm_keystore_iterator_next(it, &mut out);
            if rc == Error::ValueNotFound.code() {
                break;
            }
            assert_eq!(rc, 0);
            seen.push(out as usize);
        }
        assert_eq!(seen.len(), 2);
        cfm_keystore_iterator_destroy(it);
        cfm_keystore_destroy(ks);
    }

    #[test]
    fn enumerate_invalid_compartment_returns_error() {
        let mut ks: *mut FFIKeystore = ptr::null_mut();
        let name = CString::new("memory").unwrap().into_raw();
        cfm_keystore_create(&mut ks, name, ptr::null());

        let m = CString::new("mod").unwrap().into_raw();
        let a = CString::new("app").unwrap().into_raw();
        let mut it: *mut FFIKeyIterator = ptr::null_mut();
        let rc = cfm_keystore_enumerate(ks, m, a, 99, &mut it);
        assert_eq!(rc, crate::error::ErrorCode::INVALID_COMPARTMENT as u32);
    }

    #[test]
    fn filesystem_open_succeeds() {
        // The filesystem backend now opens against a real root directory.
        // Without a configured root it falls back to the default under
        // $HOME, so this asserts the FFI create path no longer surfaces
        // NotImplemented.
        let mut ks: *mut FFIKeystore = ptr::null_mut();
        let name = CString::new("filesystem").unwrap().into_raw();
        let rc = cfm_keystore_create(&mut ks, name, ptr::null());
        assert_eq!(rc, 0, "filesystem create should succeed");
        assert!(!ks.is_null());
        cfm_keystore_destroy(ks);
    }

    #[test]
    fn null_keystore_pointer_returns_null_pointer_code() {
        let m = CString::new("mod").unwrap().into_raw();
        let a = CString::new("app").unwrap().into_raw();
        let k = CString::new("key-1").unwrap().into_raw();
        let rc = cfm_keystore_put_secret(ptr::null_mut(), m, a, k, sentinel(1));
        assert_eq!(rc, crate::error::ErrorCode::NULL_POINTER as u32);
    }

    #[test]
    fn destroy_null_is_safe() {
        // Must not crash.
        cfm_keystore_destroy(ptr::null_mut());
        cfm_keystore_iterator_destroy(ptr::null_mut());
    }
}
