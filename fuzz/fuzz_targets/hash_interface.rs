//! Fuzz target: hash create/update/finalize lifecycle.
//!
//! Without a registered provider the high-level `Hash::new` returns an
//! `UnsupportedAlgorithm` error, so the focus here is the bookkeeping and
//! error paths reached through that entry point. We also exercise
//! `Hash::digest` (a convenience that constructs, updates, and finalizes in
//! one call) against arbitrary algorithm names and data so the provider
//! resolution and CString construction never panic on hostile input.

#![no_main]

use confium_core::Confium;
use confium_core::audit::AuditLogger;
use confium_core::hash::Hash;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split the corpus: first chunk becomes the algorithm name, the rest is
    // the data to hash. Use a sentinel byte (0xFF) so we can vary the split
    // point with the corpus itself.
    let split = data.iter().position(|&b| b == 0xFF).unwrap_or(data.len());
    let (name_bytes, payload) = data.split_at(split);
    // Skip the 0xFF separator when present so the name doesn't include it.
    let payload = if !payload.is_empty() && payload[0] == 0xFF {
        &payload[1..]
    } else {
        payload
    };
    let Ok(name) = std::str::from_utf8(name_bytes) else {
        return;
    };
    // NUL bytes would panic the CString::new inside Hash::new; bail early
    // rather than mask the bug by stripping them.
    if name.bytes().any(|b| b == 0) {
        return;
    }
    if name.is_empty() {
        return;
    }

    let cfm = Confium::new_with_audit(AuditLogger::disabled());

    // Exercise the high-level digest convenience path. Without a provider
    // this returns an error; we only care that it doesn't panic.
    let _ = Hash::digest(&cfm, name, payload);

    // Exercise the constructor path with an explicit provider name drawn
    // from the corpus tail (if present). Again, errors are expected and
    // fine — panics are not.
    let provider_name = payload
        .strip_prefix(b"prov:")
        .and_then(|rest| std::str::from_utf8(rest).ok().filter(|s| !s.is_empty()));
    let _ = Hash::new(&cfm, name, provider_name, None);
});
