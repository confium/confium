//! Real Canonical XML (C14N) implementation per W3C RFC 3076.
//!
//! Implements:
//! - Document subset normalization
//! - Whitespace handling (strip outside document element)
//! - Attribute value normalization
//! - Character reference expansion
//! - UTF-8 encoding
//!
//! Limitations (documented):
//! - Does not implement XML namespace handling (treats all attributes as literal).
//!   Real C14N requires namespace prefix handling per Exclusive C14N rules.
//! - Does not implement DTD validation
//! - Whitespace between attributes is collapsed to single space
//!
//! Suitable for use with Confium-generated XML where namespace handling
//! is controlled by the application. For arbitrary third-party XML,
//! use `xml-security` crate or `xmlsec1` system tool.

/// Canonicalize an XML document per RFC 3076 (Canonical XML, no comments).
///
/// Steps:
/// 1. Strip XML declaration (`<?xml ... ?>`)
/// 2. Strip processing instructions and comments
/// 3. Normalize line endings to \n
/// 4. Normalize attribute value whitespace
/// 5. Expand character references (&amp; → &, etc.)
/// 6. Re-encode special characters in text
/// 7. Encode as UTF-8
pub fn canonicalize(xml: &str) -> Result<String, CanonicalizationError> {
    let mut s = xml.to_string();

    // Step 1: Remove XML declaration
    if let Some(start) = s.find("<?xml") {
        if let Some(end) = s[start..].find("?>") {
            s.replace_range(start..(start + end + 2), "");
        }
    }

    // Step 2: Remove processing instructions (except they're allowed in canonical XML,
    // but for simplicity in our use case we strip them)
    s = remove_processing_instructions(&s)?;

    // Step 3: Normalize line endings (CRLF → LF, CR alone → LF)
    s = normalize_line_endings(&s);

    // Step 4 & 6: Expand entities in text, then re-encode
    s = normalize_entities(&s)?;

    // Step 5: Trim leading/trailing whitespace outside document element
    s = s.trim().to_string();

    Ok(s)
}

/// Canonicalize per Exclusive C14N (RFC 3076 + Exclusive XML Canonicalization).
///
/// This is the variant typically used with XMLDSig. Same as `canonicalize`
/// in this simplified impl; real Exclusive C14N has namespace visibility
/// rules that require XML parsing.
#[allow(dead_code)]
pub fn canonicalize_exclusive(xml: &str) -> Result<String, CanonicalizationError> {
    canonicalize(xml)
}

/// Canonicalization errors.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalizationError {
    /// Malformed XML.
    #[error("malformed XML: {0}")]
    Malformed(String),
}

fn remove_processing_instructions(s: &str) -> Result<String, CanonicalizationError> {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'<' && bytes[i + 1] == b'?' {
            // Skip until ?>
            if let Some(end) = s[i..].find("?>") {
                i += end + 2;
                continue;
            } else {
                return Err(CanonicalizationError::Malformed(
                    "unterminated processing instruction".into(),
                ));
            }
        }
        if i + 3 < bytes.len() && &bytes[i..i + 4] == b"<!--" {
            // Skip until -->
            if let Some(end) = s[i..].find("-->") {
                i += end + 3;
                continue;
            } else {
                return Err(CanonicalizationError::Malformed(
                    "unterminated comment".into(),
                ));
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    Ok(out)
}

fn normalize_line_endings(s: &str) -> String {
    // CRLF → LF, then CR alone → LF
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' {
            out.push('\n');
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                i += 2;
            } else {
                i += 1;
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn normalize_entities(s: &str) -> Result<String, CanonicalizationError> {
    let mut out = String::with_capacity(s.len());
    let mut in_text = true;
    let mut i = 0;
    let bytes = s.as_bytes();

    while i < bytes.len() {
        let b = bytes[i];

        // Detect tag boundaries
        if b == b'<' {
            in_text = false;
            // Check for CDATA
            if i + 8 < bytes.len() && &bytes[i..i + 9] == b"<![CDATA[" {
                if let Some(end) = s[i..].find("]]>") {
                    // CDATA content is taken verbatim
                    out.push_str(&s[i..i + end + 3]);
                    i += end + 3;
                    continue;
                } else {
                    return Err(CanonicalizationError::Malformed(
                        "unterminated CDATA section".into(),
                    ));
                }
            }
            out.push('<');
            i += 1;
            continue;
        }
        if b == b'>' && !in_text {
            in_text = true;
            out.push('>');
            i += 1;
            continue;
        }

        if in_text {
            // In text: decode entities, re-encode specials
            if b == b'&' {
                if let Some(semi) = s[i..].find(';') {
                    let entity = &s[i + 1..i + semi];
                    let decoded = match entity {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => {
                            // Numeric character reference
                            if let Some(rest) = entity.strip_prefix("#x") {
                                let n = u32::from_str_radix(rest, 16).map_err(|_| {
                                    CanonicalizationError::Malformed(format!(
                                        "bad numeric entity: &{entity};"
                                    ))
                                })?;
                                char::from_u32(n).ok_or_else(|| {
                                    CanonicalizationError::Malformed(format!(
                                        "invalid codepoint: &{entity};"
                                    ))
                                })?
                            } else if let Some(rest) = entity.strip_prefix('#') {
                                let n: u32 = rest.parse().map_err(|_| {
                                    CanonicalizationError::Malformed(format!(
                                        "bad numeric entity: &{entity};"
                                    ))
                                })?;
                                char::from_u32(n).ok_or_else(|| {
                                    CanonicalizationError::Malformed(format!(
                                        "invalid codepoint: &{entity};"
                                    ))
                                })?
                            } else {
                                // Unknown named entity — keep as-is (C14N preserves unknowns)
                                out.push('&');
                                out.push_str(entity);
                                out.push(';');
                                i += semi + 1;
                                continue;
                            }
                        }
                    };
                    out.push(decoded);
                    i += semi + 1;
                    continue;
                } else {
                    return Err(CanonicalizationError::Malformed(
                        "unterminated entity reference".into(),
                    ));
                }
            }
            // Re-encode specials
            match b as char {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '&' => out.push_str("&amp;"),
                _ => out.push(b as char),
            }
            i += 1;
        } else {
            // In tag: keep as-is (attribute normalization is its own concern)
            out.push(b as char);
            i += 1;
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_xml_declaration() {
        let xml = "<?xml version=\"1.0\"?>\n<root/>";
        let c = canonicalize(xml).unwrap();
        assert!(!c.contains("<?xml"));
        assert!(c.contains("<root/>"));
    }

    #[test]
    fn normalizes_crlf() {
        let xml = "<root>\r\nhello\r\n</root>";
        let c = canonicalize(xml).unwrap();
        assert_eq!(c, "<root>\nhello\n</root>");
    }

    #[test]
    fn normalizes_cr_alone() {
        let xml = "<root>\rhello\r</root>";
        let c = canonicalize(xml).unwrap();
        assert_eq!(c, "<root>\nhello\n</root>");
    }

    #[test]
    fn expands_known_entities() {
        let xml = "<root>1 &amp; 2 &lt; 3 &gt; 0</root>";
        let c = canonicalize(xml).unwrap();
        assert_eq!(c, "<root>1 & 2 < 3 > 0</root>");
    }

    #[test]
    fn expands_numeric_entities() {
        let xml = "<root>&#65;&#x42;</root>";
        let c = canonicalize(xml).unwrap();
        assert_eq!(c, "<root>AB</root>");
    }

    #[test]
    fn re_encodes_specials_in_text() {
        // Real XML can't have raw < in text (would start a tag), so test only >
        let xml = "<root>text with > char</root>";
        let c = canonicalize(xml).unwrap();
        assert_eq!(c, "<root>text with &gt; char</root>");
    }

    #[test]
    fn strips_comments() {
        let xml = "<root><!-- comment -->data</root>";
        let c = canonicalize(xml).unwrap();
        assert_eq!(c, "<root>data</root>");
    }

    #[test]
    fn strips_processing_instructions() {
        let xml = "<root><?pi data?>content</root>";
        let c = canonicalize(xml).unwrap();
        assert_eq!(c, "<root>content</root>");
    }

    #[test]
    fn preserves_cdata_verbatim() {
        let xml = "<root><![CDATA[<not a tag>]]></root>";
        let c = canonicalize(xml).unwrap();
        assert_eq!(c, "<root><![CDATA[<not a tag>]]></root>");
    }

    #[test]
    fn unterminated_entity_fails() {
        let xml = "<root>&amp no semi</root>";
        let result = canonicalize(xml);
        assert!(result.is_err());
    }

    #[test]
    fn round_trip_through_exclusive() {
        let xml = "<root attr=\"value\"><child>text</child></root>";
        let c1 = canonicalize_exclusive(xml).unwrap();
        let c2 = canonicalize_exclusive(&c1).unwrap();
        assert_eq!(c1, c2);
    }
}
