//! RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! Produces the deterministic byte string that all co-signatures and
//! bundle signatures attest: same logical content, same bytes, for any
//! conforming implementation. The rules implemented here:
//!
//! - object keys sorted by UTF-16 code unit sequence;
//! - no insignificant whitespace;
//! - strings serialized with the JSON minimal-escape set (`\b \t \n \f
//!   \r` `\"` `\\` and lowercase `\u00xx` for other control characters),
//!   all other characters emitted verbatim as UTF-8;
//! - numbers: integers exactly; floats in shortest round-trip form
//!   (ECMAScript number-to-string), negative zero normalized to `0`,
//!   NaN and infinities rejected;
//! - booleans and null as `true` / `false` / `null`.

use crate::error::{SignatifError, SignatifResult};
use serde_json::Value;

/// Canonicalize a JSON value to its RFC 8785 byte string.
///
/// # Errors
///
/// Returns [`SignatifError::Encoding`] for values that cannot appear in
/// canonical JSON (non-finite numbers).
pub fn canonicalize(value: &Value) -> SignatifResult<String> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// SHA-256 over the JCS canonicalization — the SIGNATIF canonical
/// payload hash of a JSON object.
///
/// # Errors
///
/// Propagates canonicalization errors.
pub fn canonical_hash(value: &Value) -> SignatifResult<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let canon = canonicalize(value)?;
    Ok(Sha256::digest(canon.as_bytes()).into())
}

fn write_value(v: &Value, out: &mut String) -> SignatifResult<()> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 §3.2.3: lexicographic order by UTF-16 code units.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[*key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = a.encode_utf16();
    let mut bi = b.encode_utf16();
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(x), Some(y)) => match x.cmp(&y) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            },
        }
    }
}

fn write_number(n: &serde_json::Number, out: &mut String) -> SignatifResult<()> {
    if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
        return Ok(());
    }
    if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
        return Ok(());
    }
    let f = n
        .as_f64()
        .ok_or_else(|| SignatifError::Encoding("number is not finite".into()))?;
    if !f.is_finite() {
        return Err(SignatifError::Encoding(
            "NaN and Infinity are not allowed".into(),
        ));
    }
    if f == 0.0 {
        // RFC 8785 §3.2.2.3: negative zero becomes 0.
        out.push('0');
        return Ok(());
    }
    // serde_json serializes f64 with shortest round-trip (ryu), matching
    // the ECMAScript number serialization JCS specifies.
    out.push_str(&serde_json::to_string(&Value::from(f)).expect("finite f64 serializes"));
    Ok(())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn control_chars_escaped_lowercase_hex() {
        assert_eq!(
            canonicalize(&json!("\u{0007}\u{001f}")).unwrap(),
            "\"\\u0007\\u001f\""
        );
    }

    #[test]
    fn verbatim_characters_pass_through() {
        // RFC 8785: U+20AC etc. are not escaped.
        assert_eq!(canonicalize(&json!("€ßé")).unwrap(), "\"€ßé\"");
    }

    #[test]
    fn sorts_keys_by_utf16() {
        let v = json!({"b": 1, "a": 2});
        assert_eq!(canonicalize(&v).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn utf16_ordering_beats_codepoint_ordering() {
        // U+FF21 (FULLWIDTH A) sorts before U+10000 in UTF-16, and after
        // in UTF-32. Constructing such keys checks the comparator.
        // U+10000 is the surrogate pair D800 DE00 in UTF-16, which
        // sorts before U+FF21 — but after it in codepoint order.
        let v = json!({"\u{10000}": 1, "\u{FF21}": 2});
        let c = canonicalize(&v).unwrap();
        let surrogate_pos = c.find('\u{10000}').expect("surrogate char present");
        let fullwidth_pos = c.find('\u{FF21}').expect("fullwidth char present");
        assert!(surrogate_pos < fullwidth_pos, "got {c}");
    }

    #[test]
    fn deterministic_nested_structures() {
        let a = json!({"z": [1, 2.5, true, null], "a": {"y": "x"}});
        let b = json!({"a": {"y": "x"}, "z": [1, 2.5, true, null]});
        assert_eq!(canonicalize(&a).unwrap(), canonicalize(&b).unwrap());
    }

    #[test]
    fn negative_zero_normalizes() {
        let v: Value = serde_json::from_str("-0.0").unwrap();
        assert_eq!(canonicalize(&v).unwrap(), "0");
    }

    #[test]
    fn floats_shortest_round_trip() {
        assert_eq!(canonicalize(&json!(2.5)).unwrap(), "2.5");
        assert_eq!(canonicalize(&json!(1e30)).unwrap(), "1e+30");
    }

    #[test]
    fn canonical_hash_is_sha256_of_canonical_bytes() {
        use sha2::{Digest, Sha256};
        let h = canonical_hash(&json!({"a":1})).unwrap();
        let expect: [u8; 32] = Sha256::digest(b"{\"a\":1}").into();
        assert_eq!(h, expect);
    }
}
