//! Structured audit events emitted by the framework.
//!
//! Every event corresponds to a security-relevant action: a plugin load,
//! a secret access, a threshold-computing session boundary, or a
//! configuration change. Events are serialized to a single JSON Lines
//! record by [`AuditEvent::to_json`] — they never carry secret bytes
//! (key material, plaintexts, RNG output) by construction: the variants
//! only hold identifiers and counts.
//!
//! The wire shape is fixed by `TODO.roadmap/08-security-model.md`:
//!
//! ```json
//! {"ts":"2026-07-25T13:05:22.123Z","event":"plugin_load","plugin":"botan","version":"3.2.0","publisher":"ribose"}
//! {"ts":"2026-07-25T13:05:22.456Z","event":"key_access","key_id":"abc123","interface":"signature","operation":"sign"}
//! ```
//!
//! Long identifier fields are truncated before serialization so a
//! malformed or hostile value cannot blow up the audit log. The cap is
//! applied by [`AuditEvent::to_json`]; callers always pass the full
//! value.

/// Maximum number of characters retained from a long identifier field
/// before it is written to the audit log. Anything beyond this is
/// dropped (no ellipsis — the truncation point is the only signal).
///
/// 64 is enough for any reasonable key id, plugin name, or interface
/// name, while keeping log lines bounded against hostile inputs.
pub const MAX_FIELD_LEN: usize = 64;

/// One auditable action. Lifetime parameters borrow the caller's
/// identifier strings so an event can be logged without allocation in
/// the common case.
///
/// The variant set mirrors the Auditability section of
/// `TODO.roadmap/08-security-model.md`. Add new variants by appending
/// here and extending [`AuditEvent::event_tag`] / [`AuditEvent::write_fields`].
#[derive(Debug, Clone)]
pub enum AuditEvent<'a> {
    /// A plugin was successfully loaded and registered as a provider.
    PluginLoad {
        name: &'a str,
        version: &'a str,
        publisher: &'a str,
    },
    /// A plugin was unloaded. (Currently informational — the unload
    /// path is not yet wired through the audit logger.)
    PluginUnload { name: &'a str },
    /// A secret was handed to (or received from) a plugin interface.
    ///
    /// `operation` is the logical action (`"sign"`, `"verify"`,
    /// `"decrypt"`, ...) — never the secret itself.
    KeyAccess {
        key_id: &'a str,
        interface: &'a str,
        operation: &'a str,
    },
    /// A threshold-computing session started.
    TcSessionStart {
        scheme: &'a str,
        parties: u32,
        threshold: u32,
    },
    /// A threshold-computing session ended.
    TcSessionEnd { scheme: &'a str, success: bool },
    /// A configuration key was changed at runtime.
    ConfigChange { key: &'a str },
}

impl<'a> AuditEvent<'a> {
    /// The `"event"` field value written to the JSONL record. Kept
    /// separate from the Rust variant name so the wire name is stable
    /// even if the variant is renamed.
    fn event_tag(&self) -> &'static str {
        match self {
            AuditEvent::PluginLoad { .. } => "plugin_load",
            AuditEvent::PluginUnload { .. } => "plugin_unload",
            AuditEvent::KeyAccess { .. } => "key_access",
            AuditEvent::TcSessionStart { .. } => "tc_session_start",
            AuditEvent::TcSessionEnd { .. } => "tc_session_end",
            AuditEvent::ConfigChange { .. } => "config_change",
        }
    }

    /// Serialize this event plus its timestamp to a single JSON object
    /// (no trailing newline). The caller — [`super::AuditLogger`] —
    /// appends the `\n` that turns each record into a JSON Lines line.
    ///
    /// Serialization is hand-rolled rather than going through `serde`
    /// to avoid pulling a new workspace dependency for what is a tiny,
    /// fixed shape. Strings are JSON-escaped via [`json_escape`]; this
    /// is the only place untrusted plugin-supplied text enters the log,
    /// so the escaper is the security boundary against log injection.
    pub(crate) fn to_json(&self, ts_iso: &str) -> String {
        // Pre-size to a reasonable lower bound; most records are well
        // under 200 bytes once truncated.
        let mut out = String::with_capacity(256);
        out.push('{');
        json_field(&mut out, "ts", ts_iso, true);
        // `event` is always followed by at least one event-specific
        // field (every variant in `write_fields` emits something), so
        // `more` is unconditionally true here.
        json_field(&mut out, "event", self.event_tag(), true);
        self.write_fields(&mut out);
        out.push('}');
        out
    }

    /// Append the event-specific fields after `ts` and `event`. Each
    /// field is responsible for its own leading comma.
    fn write_fields(&self, out: &mut String) {
        match self {
            AuditEvent::PluginLoad {
                name,
                version,
                publisher,
            } => {
                json_field(out, "plugin", name, true);
                json_field(out, "version", version, true);
                json_field(out, "publisher", publisher, false);
            }
            AuditEvent::PluginUnload { name } => {
                json_field(out, "plugin", name, false);
            }
            AuditEvent::KeyAccess {
                key_id,
                interface,
                operation,
            } => {
                json_field(out, "key_id", key_id, true);
                json_field(out, "interface", interface, true);
                json_field(out, "operation", operation, false);
            }
            AuditEvent::TcSessionStart {
                scheme,
                parties,
                threshold,
            } => {
                json_field(out, "scheme", scheme, true);
                json_field_num(out, "parties", *parties, true);
                json_field_num(out, "threshold", *threshold, false);
            }
            AuditEvent::TcSessionEnd { scheme, success } => {
                json_field(out, "scheme", scheme, true);
                json_field_bool(out, "success", *success, false);
            }
            AuditEvent::ConfigChange { key } => {
                json_field(out, "key", key, false);
            }
        }
    }
}

/// Append a `"name":"truncated_and_escaped_value"` field. `more` says
/// whether another field follows, so the comma placement is explicit
/// rather than guessed by trimming after the fact.
fn json_field(out: &mut String, name: &str, value: &str, more: bool) {
    out.push('"');
    out.push_str(name);
    out.push_str("\":\"");
    json_escape_into(out, truncate(value));
    out.push('"');
    if more {
        out.push(',');
    }
}

/// Append a `"name":number` field.
fn json_field_num(out: &mut String, name: &str, value: u32, more: bool) {
    use std::fmt::Write as _;
    out.push('"');
    out.push_str(name);
    out.push_str("\":");
    let _ = write!(out, "{value}");
    if more {
        out.push(',');
    }
}

/// Append a `"name":true|false` field.
fn json_field_bool(out: &mut String, name: &str, value: bool, more: bool) {
    out.push('"');
    out.push_str(name);
    out.push_str("\":");
    out.push_str(if value { "true" } else { "false" });
    if more {
        out.push(',');
    }
}

/// Return `s` trimmed to [`MAX_FIELD_LEN`] characters. Characters are
/// counted as `char`s (Unicode scalar values), not bytes — a
/// truncated UTF-8 boundary would produce invalid JSON.
fn truncate(s: &str) -> &str {
    match s.char_indices().nth(MAX_FIELD_LEN) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

/// Append `s` to `out` with the characters that JSON requires escaped
/// (`"`, `\`, and the JSON control-character short escapes) replaced by
/// their escape sequences. Non-ASCII bytes are passed through as-is —
/// the output is UTF-8 and JSON allows raw UTF-8 in strings.
///
/// This is the only path by which plugin-supplied text reaches the log
/// file, so it doubles as the log-injection defense: a plugin cannot
/// forge a newline, close the JSON string, or smuggle in a fake record.
fn json_escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: &str = "2026-07-25T13:05:22.123Z";

    #[test]
    fn plugin_load_serializes_to_expected_shape() {
        let ev = AuditEvent::PluginLoad {
            name: "botan",
            version: "3.2.0",
            publisher: "ribose",
        };
        let json = ev.to_json(TS);
        assert_eq!(
            json,
            "{\"ts\":\"2026-07-25T13:05:22.123Z\",\"event\":\"plugin_load\",\
             \"plugin\":\"botan\",\"version\":\"3.2.0\",\"publisher\":\"ribose\"}"
        );
    }

    #[test]
    fn key_access_serializes_to_expected_shape() {
        let ev = AuditEvent::KeyAccess {
            key_id: "abc123",
            interface: "signature",
            operation: "sign",
        };
        let json = ev.to_json(TS);
        assert_eq!(
            json,
            "{\"ts\":\"2026-07-25T13:05:22.123Z\",\"event\":\"key_access\",\
             \"key_id\":\"abc123\",\"interface\":\"signature\",\"operation\":\"sign\"}"
        );
    }

    #[test]
    fn tc_session_start_has_numeric_parties_and_threshold() {
        let ev = AuditEvent::TcSessionStart {
            scheme: "FROST-ed25519",
            parties: 3,
            threshold: 2,
        };
        let json = ev.to_json(TS);
        assert_eq!(
            json,
            "{\"ts\":\"2026-07-25T13:05:22.123Z\",\"event\":\"tc_session_start\",\
             \"scheme\":\"FROST-ed25519\",\"parties\":3,\"threshold\":2}"
        );
    }

    #[test]
    fn tc_session_end_emits_boolean_success() {
        let ev = AuditEvent::TcSessionEnd {
            scheme: "FROST-ed25519",
            success: true,
        };
        assert!(ev.to_json(TS).ends_with("\"success\":true}"));

        let ev = AuditEvent::TcSessionEnd {
            scheme: "FROST-ed25519",
            success: false,
        };
        assert!(ev.to_json(TS).ends_with("\"success\":false}"));
    }

    #[test]
    fn config_change_shape() {
        let ev = AuditEvent::ConfigChange { key: "default_rng" };
        assert_eq!(
            ev.to_json(TS),
            "{\"ts\":\"2026-07-25T13:05:22.123Z\",\"event\":\"config_change\",\
             \"key\":\"default_rng\"}"
        );
    }

    #[test]
    fn long_key_id_is_truncated_at_64_chars() {
        let long = "x".repeat(200);
        let ev = AuditEvent::KeyAccess {
            key_id: &long,
            interface: "signature",
            operation: "sign",
        };
        let json = ev.to_json(TS);
        // The key_id value between the quotes must be exactly 64 chars.
        let value = json
            .split("\"key_id\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("key_id field present");
        assert_eq!(value.len(), MAX_FIELD_LEN);
        assert_eq!(value, &"x".repeat(MAX_FIELD_LEN));
    }

    #[test]
    fn exactly_64_chars_is_not_truncated() {
        let exact = "k".repeat(MAX_FIELD_LEN);
        let ev = AuditEvent::KeyAccess {
            key_id: &exact,
            interface: "signature",
            operation: "sign",
        };
        let json = ev.to_json(TS);
        let value = json
            .split("\"key_id\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("key_id field present");
        assert_eq!(value.len(), MAX_FIELD_LEN);
    }

    #[test]
    fn quotes_and_backslashes_are_escaped() {
        // A hostile plugin name must not be able to break out of the
        // JSON string and forge a second record.
        let ev = AuditEvent::PluginLoad {
            name: "evil\",\"bogus\":\"1\\",
            version: "1.0",
            publisher: "nobody",
        };
        let json = ev.to_json(TS);
        assert!(
            !json.contains("\"bogus\":\"1\""),
            "unescaped input forged a field: {json}"
        );
        // The record must remain a single line (no raw newline).
        assert_eq!(json.matches('\n').count(), 0);
    }

    #[test]
    fn control_characters_are_escaped() {
        let ev = AuditEvent::PluginLoad {
            name: "a\tb\nc",
            version: "1.0",
            publisher: "x",
        };
        let json = ev.to_json(TS);
        assert!(!json.contains('\t'), "raw tab leaked: {json}");
        assert!(!json.contains('\n'), "raw newline leaked: {json}");
        assert!(json.contains("\\t"));
        assert!(json.contains("\\n"));
    }

    #[test]
    fn truncation_respects_unicode_boundaries() {
        // 70 emoji = 70 chars, 280 bytes. Truncation must slice at a
        // char boundary so the resulting JSON string is valid UTF-8.
        let s: String = "😀".repeat(70);
        let ev = AuditEvent::KeyAccess {
            key_id: &s,
            interface: "signature",
            operation: "sign",
        };
        let json = ev.to_json(TS);
        let value = json
            .split("\"key_id\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("key_id field present");
        // value is valid UTF-8 by construction in Rust's String; the
        // count of chars must equal the cap.
        assert_eq!(value.chars().count(), MAX_FIELD_LEN);
    }

    #[test]
    fn truncate_helper_is_correct() {
        assert_eq!(truncate("short"), "short");
        assert_eq!(truncate(&"x".repeat(MAX_FIELD_LEN)).len(), MAX_FIELD_LEN);
        let long = "x".repeat(MAX_FIELD_LEN + 10);
        let trimmed = truncate(&long);
        assert_eq!(trimmed.chars().count(), MAX_FIELD_LEN);
    }
}
