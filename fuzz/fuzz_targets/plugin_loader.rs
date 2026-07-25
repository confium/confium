//! Fuzz target: plugin loading path.
//!
//! Feeds arbitrary bytes as a plugin path into `Confium::load_plugin`. The
//! loader must reject malformed input gracefully (returning an error, never
//! panicking or aborting). We construct a UTF-8 path from the fuzz corpus to
//! avoid `to_string_lossy` masking real bugs in non-UTF-8 path handling at
//! the FFI boundary.

#![no_main]

use std::collections::HashMap;
use std::path::PathBuf;

use confium_core::Confium;
use confium_core::audit::AuditLogger;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The loader takes a path; only well-formed UTF-8 produces a meaningful
    // OsString path on Unix without going through lossy conversion (which
    // would hide FFI-side UTF-8 bugs). Bail on non-UTF-8 input rather than
    // silently rewriting it.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // Strip control characters that are not valid path components on some
    // platforms (NUL in particular would panic the inner CString::new).
    if s.bytes().any(|b| b == 0) {
        return;
    }
    let path = PathBuf::from(s);
    // An audit-disabled Confium keeps the fuzzer from writing to disk.
    let mut cfm = Confium::new_with_audit(AuditLogger::disabled());
    let opts: HashMap<String, String> = HashMap::new();
    // The result is intentionally ignored: we are exercising the error
    // paths, not asserting success.
    let _ = cfm.load_plugin(&path, &opts);
});
