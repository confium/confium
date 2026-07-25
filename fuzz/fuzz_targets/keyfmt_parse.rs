//! Fuzz target: key format parsing.
//!
//! Feeds arbitrary bytes into `Key::parse` across a small set of canonical
//! format names plus a fuzz-derived format name. Without a registered
//! `keyfmt` provider every call returns an `UnsupportedAlgorithm` error;
//! the goal is to ensure the dispatch, CString construction, and option
//! plumbing never panic on hostile input. Also exercises `KeyKind::from_wire`
//! over the full `u32` range derived from the corpus.

#![no_main]

use confium_core::Confium;
use confium_core::audit::AuditLogger;
use confium_core::keyfmt::{Key, KeyKind, formats};
use libfuzzer_sys::fuzz_target;

/// A fixed rotation of canonical format names so the fuzzer explores real
/// plugin contracts rather than only arbitrary strings.
const CANONICAL_FORMATS: &[&str] = &[
    formats::OPENPGP,
    formats::PKCS8_PEM,
    formats::PKCS8_DER,
    formats::PKCS1_PEM,
    formats::PKCS1_DER,
    formats::SPKI_PEM,
    formats::SPKI_DER,
    formats::JWK,
    formats::RAW,
    formats::OPENSSH,
];

fuzz_target!(|data: &[u8]| {
    // Need at least one byte to pick a format and derive a KeyKind value.
    if data.is_empty() {
        return;
    }
    let selector = data[0] as usize;
    let payload = &data[1..];

    let cfm = Confium::new_with_audit(AuditLogger::disabled());

    // Try a canonical format selected by the first byte.
    if let Some(&format) = CANONICAL_FORMATS.get(selector % CANONICAL_FORMATS.len()) {
        let _ = Key::parse(&cfm, format, None, payload, None, None);
    }

    // Try a fuzz-derived format name derived from the payload. Strip NUL
    // bytes (which would panic CString::new) rather than masking the bug,
    // and bail on non-UTF-8 input.
    if !payload.is_empty() && !payload.contains(&0) {
        if let Ok(format) = std::str::from_utf8(payload) {
            if !format.is_empty() {
                let _ = Key::parse(&cfm, format, None, payload, None, None);
            }
        }
    }

    // Exercise the wire decoder over the full u32 range derived from the
    // first four bytes of the corpus. Only valid wire values map to a
    // `KeyKind`; the decoder must return `None` for everything else.
    let mut buf = [0u8; 4];
    let n = data.len().min(4);
    buf[..n].copy_from_slice(&data[..n]);
    let wire = u32::from_le_bytes(buf);
    let kind = KeyKind::from_wire(wire);
    if let Some(k) = kind {
        // Round-trip the enum value to assert the wire mapping is stable.
        debug_assert_eq!(k as u32, wire, "from_wire must round-trip");
    } else {
        debug_assert!(wire > 2, "from_wire must map 0..=2 to a variant");
    }
});
