// FFI entry points accept raw pointers and null-check them before
// dereferencing; they are not `unsafe` from the C caller's perspective.
// This mirrors the same suppression used in confium-core's ffi module.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! `cfm_tc_*` C ABI for the threshold-cryptography session interface.
//!
//! These symbols are declared `#[unsafe(no_mangle)] pub extern "C"` and
//! linked into whichever cdylib depends on `confium-tc` (today,
//! `confium-core`'s `libconfium` cdylib, eventually a dedicated
//! `confium-ffi`). The crate itself is an `rlib`, not a `cdylib`.
//!
//! See `TODO.roadmap/04-threshold-cryptography.md` for the protocol
//! rationale and `crates/confium-core/src/ffi/rng.rs` for the FFI
//! pattern these entry points mirror.
//!
//! ## Memory ownership
//!
//! - `CFMTcMessage **outgoing` produced by `cfm_tc_session_round` is a
//!   heap array allocated by the framework; the caller frees it with
//!   [`cfm_tc_messages_destroy`].
//! - `CFMTcShare *` produced by `cfm_tc_dkg_output_share` is a heap
//!   allocation; the caller frees it with [`cfm_tc_share_destroy`].
//! - `FFITcSession *` is owned by the caller; destroy with
//!   [`cfm_tc_session_destroy`].

use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;

use snafu::ResultExt;

use crate::error;
use crate::error::Result as TcResult;
use crate::message::Message;
use crate::party::{Party, PartyList};
use crate::session::{Session, SessionParams};
use crate::share::Share;

/// Opaque session handle returned to C.
pub enum FFITcSession {}

/// Roster of parties, C view.
///
/// `party_ids` and `transport_endpoints` are parallel arrays of
/// NUL-terminated C strings. `transport_endpoints[i]` may be NULL when
/// party `i` has no network endpoint (in-process sessions).
#[repr(C)]
pub struct CFMTcPartyList {
    pub party_ids: *const *const c_char,
    pub transport_endpoints: *const *const c_char,
    pub count: u32,
}

/// One inter-party message, C view. `to_party_id == NULL` means
/// broadcast.
#[repr(C)]
pub struct CFMTcMessage {
    pub from_party_id: *const c_char,
    pub to_party_id: *const c_char,
    pub round: u8,
    pub payload: *const u8,
    pub payload_len: u32,
}

/// A party's share of a distributed secret, C view.
#[repr(C)]
pub struct CFMTcShare {
    pub scheme: *const c_char,
    pub bytes: *const u8,
    pub len: u32,
}

/// Heap allocation returned by `cfm_tc_session_round` for the outgoing
/// messages array. The framework owns the backing storage; the caller
/// frees the whole bundle with [`cfm_tc_messages_destroy`].
#[repr(C)]
pub struct CFMTcMessageArray {
    pub items: *mut CFMTcMessage,
    pub count: u32,
}

fn cstr_to_string(ptr: *const c_char, param: &'static str) -> TcResult<String> {
    if ptr.is_null() {
        return error::NullPointerSnafu { param }.fail();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .context(error::InvalidUTF8Snafu {})
        .map(str::to_string)
}

fn opt_cstr_to_string(ptr: *const c_char) -> TcResult<Option<String>> {
    if ptr.is_null() {
        return Ok(None);
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .context(error::InvalidUTF8Snafu {})
        .map(|s| Some(s.to_string()))
}

/// Read a parallel-array `CFMTcPartyList` into an owned [`PartyList`].
fn party_list_from_c(cpl: &CFMTcPartyList) -> TcResult<PartyList> {
    let count = cpl.count as usize;
    let ids = if cpl.party_ids.is_null() {
        return error::NullPointerSnafu { param: "party_ids" }.fail();
    } else {
        unsafe { std::slice::from_raw_parts(cpl.party_ids, count) }
    };
    let endpoints = if cpl.transport_endpoints.is_null() {
        // endpoints array may be NULL meaning "no party has an endpoint".
        vec![std::ptr::null::<c_char>(); count]
    } else {
        unsafe { std::slice::from_raw_parts(cpl.transport_endpoints, count) }.to_vec()
    };
    if endpoints.len() != count {
        return error::NullPointerSnafu {
            param: "transport_endpoints",
        }
        .fail();
    }
    let mut parties = Vec::with_capacity(count);
    for (i, id_ptr) in ids.iter().enumerate() {
        let id = cstr_to_string(*id_ptr, "party_id")?;
        let ep = if endpoints[i].is_null() {
            None
        } else {
            Some(cstr_to_string(endpoints[i], "transport_endpoint")?)
        };
        parties.push(Party::new(id, ep));
    }
    Ok(PartyList::from_parties(parties))
}

/// Read an optional `CFMTcShare *` into an owned [`Share`].
fn share_from_c(cshare: *const CFMTcShare) -> TcResult<Option<Share>> {
    if cshare.is_null() {
        return Ok(None);
    }
    let cshare = unsafe { &*cshare };
    let scheme = cstr_to_string(cshare.scheme, "share.scheme")?;
    if cshare.bytes.is_null() && cshare.len != 0 {
        return error::NullPointerSnafu {
            param: "share.bytes",
        }
        .fail();
    }
    let bytes = if cshare.len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(cshare.bytes, cshare.len as usize) }.to_vec()
    };
    Ok(Some(Share::new(scheme, bytes)))
}

/// Build a heap-allocated `CFMTcShare` from an owned [`Share`]. The
/// caller frees it with [`cfm_tc_share_destroy`].
fn share_to_c(share: Share) -> TcResult<*mut CFMTcShare> {
    let scheme_c = CString::new(share.scheme()).context(error::NulByteSnafu {})?;
    let bytes = share.into_bytes();
    let bytes_len = bytes.len() as u32;
    let bytes_box = bytes.into_boxed_slice();
    let bytes_ptr = Box::into_raw(bytes_box) as *const u8;
    let scheme_ptr = scheme_c.into_raw();
    let cshare = Box::new(CFMTcShare {
        scheme: scheme_ptr,
        bytes: bytes_ptr,
        len: bytes_len,
    });
    Ok(Box::into_raw(cshare))
}

/// Build a heap-allocated `CFMTcMessageArray` from owned [`Message`]s.
/// Each message's string fields and payload are separately heap-allocated
/// and owned by the bundle; the caller frees the whole array with
/// [`cfm_tc_messages_destroy`].
fn messages_to_c_array(msgs: Vec<Message>) -> TcResult<*mut CFMTcMessageArray> {
    let count = msgs.len() as u32;
    if msgs.is_empty() {
        let bundle = Box::new(CFMTcMessageArray {
            items: std::ptr::null_mut(),
            count: 0,
        });
        return Ok(Box::into_raw(bundle));
    }
    let mut items: Vec<CFMTcMessage> = Vec::with_capacity(msgs.len());
    for m in msgs {
        let from_c = CString::new(m.from_party_id).context(error::NulByteSnafu {})?;
        let to_c = match m.to_party_id {
            Some(t) => Some(CString::new(t).context(error::NulByteSnafu {})?),
            None => None,
        };
        let payload_len = m.payload.len() as u32;
        let payload_box = m.payload.into_boxed_slice();
        let payload_ptr = Box::into_raw(payload_box) as *const u8;
        let from_ptr = from_c.into_raw();
        let to_ptr: Option<*mut c_char> = to_c.map(|c| c.into_raw());
        // to_ptr may be null; that's the broadcast sentinel.
        items.push(CFMTcMessage {
            from_party_id: from_ptr,
            to_party_id: to_ptr.unwrap_or(std::ptr::null_mut()),
            round: m.round,
            payload: payload_ptr,
            payload_len,
        });
    }
    let items_box = items.into_boxed_slice();
    let items_ptr = Box::into_raw(items_box) as *mut CFMTcMessage;
    let bundle = Box::new(CFMTcMessageArray {
        items: items_ptr,
        count,
    });
    Ok(Box::into_raw(bundle))
}

/// Free a single message's owned fields. Does NOT free the message
/// struct itself (it lives inside the array's backing slice).
unsafe fn free_message_fields(m: &CFMTcMessage) {
    unsafe {
        if !m.from_party_id.is_null() {
            drop(CString::from_raw(m.from_party_id as *mut c_char));
        }
        if !m.to_party_id.is_null() {
            drop(CString::from_raw(m.to_party_id as *mut c_char));
        }
        if m.payload_len != 0 && !m.payload.is_null() {
            let slice =
                std::slice::from_raw_parts_mut(m.payload as *mut u8, m.payload_len as usize);
            drop(Box::from_raw(slice as *mut [u8]));
        }
    }
}

/// Convert a `TcResult<()>` into a `u32` FFI return code, zero on
/// success. Mirrors `confium-core`'s `ffi_return_err!` but without the
/// out-error-pointer machinery (the TC ABI returns codes only).
#[allow(dead_code)]
fn code_of<T>(r: TcResult<T>) -> u32 {
    match r {
        Ok(_) => 0,
        Err(e) => e.code(),
    }
}

// ---------------------------------------------------------------------------
// FFI entry points
// ---------------------------------------------------------------------------

/// Create a new threshold session.
///
/// On success, `*out` is a heap-allocated `FFITcSession *` owned by the
/// caller. Destroy with [`cfm_tc_session_destroy`].
#[unsafe(no_mangle)]
pub extern "C" fn cfm_tc_session_create(
    out: *mut *mut FFITcSession,
    scheme: *const c_char,
    party_list: *const CFMTcPartyList,
    threshold: u32,
    this_party_idx: u32,
    local_share: *const CFMTcShare,
    message: *const u8,
    message_len: u32,
) -> u32 {
    if out.is_null() {
        return error::ErrorCode::NULL_POINTER.into();
    }
    let result = (|| -> TcResult<*mut FFITcSession> {
        let scheme_name = cstr_to_string(scheme, "scheme")?;
        if party_list.is_null() {
            return error::NullPointerSnafu {
                param: "party_list",
            }
            .fail();
        }
        let cpl = unsafe { &*party_list };
        let parties = party_list_from_c(cpl)?;
        let local_share = share_from_c(local_share)?;
        let message = if message.is_null() || message_len == 0 {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts(message, message_len as usize) }.to_vec())
        };
        let params = SessionParams {
            scheme: scheme_name,
            parties,
            threshold,
            this_party_idx: this_party_idx as usize,
            local_share,
            message,
        };
        let session = Session::create(&params)?;
        Ok(Box::into_raw(Box::new(session)) as *mut FFITcSession)
    })();
    match result {
        Ok(ptr) => {
            unsafe { *out = ptr };
            0
        }
        Err(e) => e.code(),
    }
}

/// Step the session forward one round.
///
/// - `incoming` / `incoming_count`: messages received since the last
///   round (may be NULL / 0 for the first round).
/// - `outgoing` / `outgoing_count`: on success set to a heap-allocated
///   [`CFMTcMessageArray`]; free with [`cfm_tc_messages_destroy`].
/// - `complete`: set to 1 when the session has produced its result.
#[unsafe(no_mangle)]
pub extern "C" fn cfm_tc_session_round(
    session: *mut FFITcSession,
    incoming: *const CFMTcMessage,
    incoming_count: u32,
    outgoing: *mut *mut CFMTcMessageArray,
    outgoing_count: *mut u32,
    complete: *mut u8,
) -> u32 {
    if session.is_null() {
        return error::ErrorCode::NULL_POINTER.into();
    }
    if outgoing.is_null() || outgoing_count.is_null() || complete.is_null() {
        return error::ErrorCode::NULL_POINTER.into();
    }
    let session = unsafe { &mut *(session as *mut Session) };

    // Materialize incoming messages into owned Rust values.
    let incoming_vec: TcResult<Vec<Message>> = (|| {
        if incoming.is_null() || incoming_count == 0 {
            return Ok(Vec::new());
        }
        let slice = unsafe { std::slice::from_raw_parts(incoming, incoming_count as usize) };
        let mut out = Vec::with_capacity(slice.len());
        for cm in slice {
            let from = cstr_to_string(cm.from_party_id, "incoming.from_party_id")?;
            let to = opt_cstr_to_string(cm.to_party_id)?;
            let payload = if cm.payload_len == 0 || cm.payload.is_null() {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(cm.payload, cm.payload_len as usize) }.to_vec()
            };
            out.push(Message {
                from_party_id: from,
                to_party_id: to,
                round: cm.round,
                payload,
            });
        }
        Ok(out)
    })();
    let incoming_vec = match incoming_vec {
        Ok(v) => v,
        Err(e) => return e.code(),
    };

    match session.round_step(&incoming_vec) {
        Ok(rr) => match messages_to_c_array(rr.outgoing) {
            Ok(arr_ptr) => {
                let arr = unsafe { &mut *arr_ptr };
                unsafe {
                    *outgoing = arr_ptr;
                    *outgoing_count = arr.count;
                    *complete = if rr.complete { 1 } else { 0 };
                }
                0
            }
            Err(e) => e.code(),
        },
        Err(e) => e.code(),
    }
}

/// Read the final session artifact into `out`.
///
/// Returns `INSUFFICIENT_BUFFER` when `out_max` is too small; `*out_len`
/// is always set to the required length.
#[unsafe(no_mangle)]
pub extern "C" fn cfm_tc_session_result(
    session: *mut FFITcSession,
    out: *mut u8,
    out_max: u32,
    out_len: *mut u32,
) -> u32 {
    if session.is_null() {
        return error::ErrorCode::NULL_POINTER.into();
    }
    if out_len.is_null() {
        return error::ErrorCode::NULL_POINTER.into();
    }
    let session = unsafe { &*(session as *mut Session) };
    match session.result() {
        Ok(bytes) => {
            let needed = bytes.len();
            unsafe { *out_len = needed as u32 };
            if (out_max as usize) < needed {
                return error::ErrorCode::INSUFFICIENT_BUFFER.into();
            }
            if !out.is_null() {
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, needed);
                }
            }
            0
        }
        Err(e) => e.code(),
    }
}

/// For DKG sessions: extract the per-party share and the shared public
/// key.
///
/// - `share_out`: set to a heap-allocated [`CFMTcShare`]; free with
///   [`cfm_tc_share_destroy`].
/// - `public_key_out` / `pk_max` / `pk_len`: shared public key bytes.
#[unsafe(no_mangle)]
pub extern "C" fn cfm_tc_dkg_output_share(
    session: *mut FFITcSession,
    share_out: *mut *mut CFMTcShare,
    public_key_out: *mut u8,
    pk_max: u32,
    pk_len: *mut u32,
) -> u32 {
    if session.is_null() {
        return error::ErrorCode::NULL_POINTER.into();
    }
    if share_out.is_null() || pk_len.is_null() {
        return error::ErrorCode::NULL_POINTER.into();
    }
    let session = unsafe { &*(session as *mut Session) };

    // The public key is the session result (shared across all parties).
    let pk = match session.dkg_public_key() {
        Ok(b) => b,
        Err(e) => return e.code(),
    };
    let needed = pk.len();
    unsafe { *pk_len = needed as u32 };
    if (pk_max as usize) < needed {
        return error::ErrorCode::INSUFFICIENT_BUFFER.into();
    }
    if !public_key_out.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(pk.as_ptr(), public_key_out, needed);
        }
    }

    // The framework skeleton does not yet synthesize a per-party share
    // from the session state — that requires scheme cooperation. Return
    // an empty share tagged with the session's scheme so the caller
    // shape is exercised; scheme plugins override this via their own
    // protocol-specific entry point in a later iteration.
    let empty_share = Share::new(session.scheme_name(), Vec::new());
    match share_to_c(empty_share) {
        Ok(ptr) => {
            unsafe { *share_out = ptr };
            0
        }
        Err(e) => e.code(),
    }
}

/// Destroy a session. Safe to call with NULL.
#[unsafe(no_mangle)]
pub extern "C" fn cfm_tc_session_destroy(session: *mut FFITcSession) {
    if session.is_null() {
        return;
    }
    unsafe {
        let session = Box::from_raw(session as *mut Session);
        let mut session = session;
        session.destroy();
        drop(session);
    }
}

/// Free a `CFMTcMessageArray` returned by [`cfm_tc_session_round`]. Safe
/// to call with NULL.
#[unsafe(no_mangle)]
pub extern "C" fn cfm_tc_messages_destroy(arr: *mut CFMTcMessageArray) {
    if arr.is_null() {
        return;
    }
    unsafe {
        let bundle = Box::from_raw(arr);
        if bundle.count == 0 || bundle.items.is_null() {
            return;
        }
        let items = std::slice::from_raw_parts_mut(bundle.items, bundle.count as usize);
        for m in items.iter() {
            free_message_fields(m);
        }
        let _ = Box::from_raw(items as *mut [CFMTcMessage]);
    }
}

/// Free a `CFMTcShare` returned by [`cfm_tc_dkg_output_share`]. Safe to
/// call with NULL.
#[unsafe(no_mangle)]
pub extern "C" fn cfm_tc_share_destroy(share: *mut CFMTcShare) {
    if share.is_null() {
        return;
    }
    unsafe {
        let cshare = Box::from_raw(share);
        if !cshare.scheme.is_null() {
            drop(CString::from_raw(cshare.scheme as *mut c_char));
        }
        if cshare.len != 0 && !cshare.bytes.is_null() {
            let slice =
                std::slice::from_raw_parts_mut(cshare.bytes as *mut u8, cshare.len as usize);
            let _ = Box::from_raw(slice as *mut [u8]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{SessionImpl, TcScheme, TcSchemeKind};
    use crate::session::SessionParams;

    /// Round-trip a `CFMTcPartyList` through [`party_list_from_c`].
    #[test]
    fn party_list_round_trip_c() {
        let id1 = CString::new("a").unwrap();
        let id2 = CString::new("b").unwrap();
        let ep1 = CString::new("quic://a:443").unwrap();
        let ids = [id1.as_ptr(), id2.as_ptr()];
        let eps = [ep1.as_ptr(), std::ptr::null()];
        let cpl = CFMTcPartyList {
            party_ids: ids.as_ptr(),
            transport_endpoints: eps.as_ptr(),
            count: 2,
        };
        let list = party_list_from_c(&cpl).expect("parse");
        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0).unwrap().id, "a");
        assert_eq!(
            list.get(0).unwrap().transport_endpoint.as_deref(),
            Some("quic://a:443")
        );
        assert_eq!(list.get(1).unwrap().id, "b");
        assert!(list.get(1).unwrap().transport_endpoint.is_none());
    }

    /// A scheme that produces a broadcast then completes, used to test
    /// the full FFI lifecycle.
    struct FfiTestScheme;
    impl TcScheme for FfiTestScheme {
        fn name(&self) -> &'static str {
            "ffi-test"
        }
        fn kind(&self) -> TcSchemeKind {
            TcSchemeKind::Signature
        }
        fn create_session(
            &self,
            params: &SessionParams,
        ) -> crate::error::Result<Box<dyn SessionImpl>> {
            let our_id = params.parties.get(params.this_party_idx)?.id.clone();
            Ok(Box::new(FfiTestSession {
                our_id,
                round_done: 0,
                payload: params.message.clone().unwrap_or_default(),
            }))
        }
    }
    struct FfiTestSession {
        our_id: String,
        round_done: u8,
        payload: Vec<u8>,
    }
    impl SessionImpl for FfiTestSession {
        fn round(
            &mut self,
            _incoming: &[Message],
        ) -> crate::error::Result<crate::registry::RoundResult> {
            self.round_done += 1;
            if self.round_done == 1 {
                Ok(crate::registry::RoundResult::new(
                    vec![Message::broadcast(&self.our_id, 1, self.payload.clone())],
                    false,
                ))
            } else {
                Ok(crate::registry::RoundResult::done())
            }
        }
        fn result(&self) -> crate::error::Result<Vec<u8>> {
            Ok(self.payload.clone())
        }
        fn destroy(&mut self) {
            self.payload.fill(0);
        }
    }
    inventory::submit! {
        crate::registry::RegisteredScheme {
            scheme: &FfiTestScheme as &dyn TcScheme
        }
    }

    fn build_party_list_c() -> (
        Vec<CString>,
        Vec<CString>,
        Vec<*const c_char>,
        Vec<*const c_char>,
    ) {
        let ids = vec![
            CString::new("a").unwrap(),
            CString::new("b").unwrap(),
            CString::new("c").unwrap(),
        ];
        let id_ptrs: Vec<*const c_char> = ids.iter().map(|c| c.as_ptr()).collect();
        let eps: Vec<CString> = Vec::new();
        let ep_ptrs: Vec<*const c_char> = vec![std::ptr::null(); 3];
        (ids, eps, id_ptrs, ep_ptrs)
    }

    #[test]
    fn ffi_full_session_lifecycle() {
        let (_ids, _eps, id_ptrs, ep_ptrs) = build_party_list_c();
        let cpl = CFMTcPartyList {
            party_ids: id_ptrs.as_ptr(),
            transport_endpoints: ep_ptrs.as_ptr(),
            count: 3,
        };
        let scheme = CString::new("ffi-test").unwrap();
        let msg = b"sign-this-message";
        let mut session_ptr: *mut FFITcSession = std::ptr::null_mut();
        let code = cfm_tc_session_create(
            &mut session_ptr,
            scheme.as_ptr(),
            &cpl,
            2,
            0,
            std::ptr::null(),
            msg.as_ptr(),
            msg.len() as u32,
        );
        assert_eq!(code, 0, "create should succeed");
        assert!(!session_ptr.is_null());

        // Round 1.
        let mut outgoing: *mut CFMTcMessageArray = std::ptr::null_mut();
        let mut outgoing_count: u32 = 0;
        let mut complete: u8 = 99;
        let code = cfm_tc_session_round(
            session_ptr,
            std::ptr::null(),
            0,
            &mut outgoing,
            &mut outgoing_count,
            &mut complete,
        );
        assert_eq!(code, 0, "round 1 should succeed");
        assert_eq!(complete, 0, "round 1 not complete");
        assert_eq!(outgoing_count, 1);
        assert!(!outgoing.is_null());
        // Read the broadcast message.
        unsafe {
            let arr = &*outgoing;
            let m = &*arr.items.add(0);
            assert_eq!(CStr::from_ptr(m.from_party_id).to_str().unwrap(), "a");
            assert!(m.to_party_id.is_null(), "broadcast to_party_id is null");
            assert_eq!(m.round, 1);
            assert_eq!(m.payload_len, msg.len() as u32);
        }
        cfm_tc_messages_destroy(outgoing);

        // Round 2 — completes.
        let code = cfm_tc_session_round(
            session_ptr,
            std::ptr::null(),
            0,
            &mut outgoing,
            &mut outgoing_count,
            &mut complete,
        );
        assert_eq!(code, 0, "round 2 should succeed");
        assert_eq!(complete, 1, "round 2 complete");
        assert_eq!(outgoing_count, 0);
        cfm_tc_messages_destroy(outgoing);

        // Read the result.
        let mut out_buf = [0u8; 64];
        let mut out_len: u32 = 0;
        let code = cfm_tc_session_result(
            session_ptr,
            out_buf.as_mut_ptr(),
            out_buf.len() as u32,
            &mut out_len,
        );
        assert_eq!(code, 0, "result should succeed");
        assert_eq!(out_len as usize, msg.len());
        assert_eq!(&out_buf[..out_len as usize], msg);

        cfm_tc_session_destroy(session_ptr);
    }

    #[test]
    fn ffi_session_result_insufficient_buffer() {
        let (_ids, _eps, id_ptrs, ep_ptrs) = build_party_list_c();
        let cpl = CFMTcPartyList {
            party_ids: id_ptrs.as_ptr(),
            transport_endpoints: ep_ptrs.as_ptr(),
            count: 3,
        };
        let scheme = CString::new("ffi-test").unwrap();
        let msg = b"twelve-bytes";
        let mut session_ptr: *mut FFITcSession = std::ptr::null_mut();
        cfm_tc_session_create(
            &mut session_ptr,
            scheme.as_ptr(),
            &cpl,
            2,
            0,
            std::ptr::null(),
            msg.as_ptr(),
            msg.len() as u32,
        );
        // Drive to completion.
        let mut outgoing: *mut CFMTcMessageArray = std::ptr::null_mut();
        let mut outgoing_count: u32 = 0;
        let mut complete: u8 = 0;
        cfm_tc_session_round(
            session_ptr,
            std::ptr::null(),
            0,
            &mut outgoing,
            &mut outgoing_count,
            &mut complete,
        );
        cfm_tc_messages_destroy(outgoing);
        cfm_tc_session_round(
            session_ptr,
            std::ptr::null(),
            0,
            &mut outgoing,
            &mut outgoing_count,
            &mut complete,
        );
        cfm_tc_messages_destroy(outgoing);

        // Too-small buffer.
        let mut out_buf = [0u8; 4];
        let mut out_len: u32 = 0;
        let code = cfm_tc_session_result(session_ptr, out_buf.as_mut_ptr(), 4, &mut out_len);
        assert_eq!(code, error::ErrorCode::INSUFFICIENT_BUFFER as u32);
        assert_eq!(out_len as usize, msg.len(), "out_len reports required size");

        cfm_tc_session_destroy(session_ptr);
    }

    #[test]
    fn ffi_create_rejects_null_out() {
        let scheme = CString::new("ffi-test").unwrap();
        let code = cfm_tc_session_create(
            std::ptr::null_mut(),
            scheme.as_ptr(),
            std::ptr::null(),
            1,
            0,
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert_eq!(code, error::ErrorCode::NULL_POINTER as u32);
    }

    #[test]
    fn ffi_share_round_trip() {
        let original = Share::new("ffi-test", vec![0xCA, 0xFE]);
        let ptr = share_to_c(original).expect("to_c");
        let back = share_from_c(ptr).expect("from_c").expect("Some");
        cfm_tc_share_destroy(ptr);
        assert_eq!(back.scheme(), "ffi-test");
        assert_eq!(back.bytes(), &[0xCA, 0xFE]);
    }

    #[test]
    fn ffi_destroy_null_is_safe() {
        cfm_tc_session_destroy(std::ptr::null_mut());
        cfm_tc_messages_destroy(std::ptr::null_mut());
        cfm_tc_share_destroy(std::ptr::null_mut());
    }
}
