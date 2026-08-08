//! DSL parser for predicate expressions.
//!
//! Supports a small expression language for predicates:
//!
//! ```text
//! min_count("attribute", N)
//! min_distinct("attribute", N)
//! none("attribute")
//! any("attribute")
//! all("attribute")
//! and(P1, P2, ...)
//! or(P1, P2, ...)
//! not(P)
//! ```

use crate::ast::Predicate;

/// Maximum nesting depth for recursive DSL constructs (and/or/not).
/// Limits stack-overflow DoS via adversarial inputs. 32 is generous
/// (allows `and(and(and(...)))` 32 levels deep) and small enough to
/// keep Rust stack usage bounded.
pub const MAX_DSL_DEPTH: usize = 32;

/// Parse a DSL expression into a `Predicate`.
pub fn parse(expr: &str) -> Result<Predicate, ParseError> {
    let trimmed = expr.trim();
    parse_expr(trimmed, 0).map(|(p, _)| p)
}

/// DSL parse errors.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// Unexpected end of input.
    #[error("unexpected end of input at: {0}")]
    UnexpectedEof(String),
    /// Unexpected character.
    #[error("unexpected character '{0}' at position {1}")]
    UnexpectedChar(char, usize),
    /// Unknown function.
    #[error("unknown function: {0}")]
    UnknownFunction(String),
    /// Argument count wrong.
    #[error("argument count mismatch for {0}")]
    ArgCount(String),
    /// Number parse error.
    #[error("number parse error: {0}")]
    NumberParse(String),
    /// Recursion depth exceeded (DoS guard).
    #[error("DSL recursion depth {depth} exceeds max {max}")]
    DepthExceeded { depth: usize, max: usize },
}

fn parse_expr(s: &str, depth: usize) -> Result<(Predicate, &str), ParseError> {
    if depth >= MAX_DSL_DEPTH {
        return Err(ParseError::DepthExceeded {
            depth,
            max: MAX_DSL_DEPTH,
        });
    }
    let s = s.trim();
    let (name, rest) = parse_ident(s)?;
    let rest = rest.trim_start();
    let rest = eat(rest, '(')?;
    let rest = rest.trim_start();

    match name.as_str() {
        "min_count" => {
            let (attr, rest) = parse_string(rest)?;
            let rest = eat(rest.trim_start(), ',')?;
            let (count_str, rest) = parse_number(rest.trim_start())?;
            let (_, rest) = parse_until_close(rest.trim_start())?;
            let count: usize = count_str
                .parse()
                .map_err(|_| ParseError::NumberParse(count_str))?;
            Ok((
                Predicate::MinCount {
                    attribute: attr,
                    count,
                },
                rest,
            ))
        }
        "min_distinct" => {
            let (attr, rest) = parse_string(rest)?;
            let rest = eat(rest.trim_start(), ',')?;
            let (count_str, rest) = parse_number(rest.trim_start())?;
            let (_, rest) = parse_until_close(rest.trim_start())?;
            let count: usize = count_str
                .parse()
                .map_err(|_| ParseError::NumberParse(count_str))?;
            Ok((
                Predicate::MinDistinct {
                    attribute: attr,
                    count,
                },
                rest,
            ))
        }
        "none" => {
            let (attr, rest) = parse_string(rest)?;
            let rest = parse_until_close(rest.trim_start())?.1;
            Ok((Predicate::None { attribute: attr }, rest))
        }
        "any" => {
            let (attr, rest) = parse_string(rest)?;
            let rest = parse_until_close(rest.trim_start())?.1;
            Ok((Predicate::Any { attribute: attr }, rest))
        }
        "all" => {
            let (attr, rest) = parse_string(rest)?;
            let rest = parse_until_close(rest.trim_start())?.1;
            Ok((Predicate::All { attribute: attr }, rest))
        }
        "and" | "or" => {
            let mut preds = Vec::new();
            let mut s = rest;
            loop {
                let s2 = s.trim_start();
                if s2.starts_with(')') {
                    break;
                }
                let (p, rest) = parse_expr(s2, depth + 1)?;
                preds.push(p);
                s = rest.trim_start();
                if s.starts_with(',') {
                    s = &s[1..];
                } else if s.starts_with(')') {
                    break;
                } else {
                    return Err(ParseError::UnexpectedEof(s.into()));
                }
            }
            let rest = eat(s, ')')?;
            if name == "and" {
                Ok((Predicate::And(preds), rest))
            } else {
                Ok((Predicate::Or(preds), rest))
            }
        }
        "not" => {
            let (inner, rest) = parse_expr(rest, depth + 1)?;
            let rest = eat(rest.trim_start(), ')')?;
            Ok((Predicate::Not(Box::new(inner)), rest))
        }
        other => Err(ParseError::UnknownFunction(other.into())),
    }
}

fn parse_ident(s: &str) -> Result<(String, &str), ParseError> {
    let mut chars = s.char_indices();
    let mut end = 0;
    for (i, c) in chars.by_ref() {
        if c.is_alphanumeric() || c == '_' {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        return Err(ParseError::UnexpectedEof(s.into()));
    }
    Ok((s[..end].to_string(), &s[end..]))
}

fn parse_string(s: &str) -> Result<(String, &str), ParseError> {
    let s = eat(s, '"')?;
    let end = s
        .find('"')
        .ok_or_else(|| ParseError::UnexpectedEof(s.into()))?;
    Ok((s[..end].to_string(), &s[end + 1..]))
}

fn parse_number(s: &str) -> Result<(String, &str), ParseError> {
    let end = s
        .char_indices()
        .take_while(|(_, c)| c.is_ascii_digit())
        .last()
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    if end == 0 {
        return Err(ParseError::NumberParse(s.into()));
    }
    Ok((s[..end].to_string(), &s[end..]))
}

fn eat(s: &str, ch: char) -> Result<&str, ParseError> {
    let s = s.trim_start();
    if s.starts_with(ch) {
        Ok(&s[ch.len_utf8()..])
    } else {
        Err(ParseError::UnexpectedChar(
            s.chars().next().unwrap_or(' '),
            0,
        ))
    }
}

fn parse_until_close(s: &str) -> Result<(String, &str), ParseError> {
    let s = eat(s, ')')?;
    Ok((String::new(), s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_min_count() {
        let p = parse(r#"min_count("role:director", 5)"#).unwrap();
        match p {
            Predicate::MinCount { attribute, count } => {
                assert_eq!(attribute, "role:director");
                assert_eq!(count, 5);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parses_any() {
        let p = parse(r#"any("expertise")"#).unwrap();
        assert!(matches!(p, Predicate::Any { .. }));
    }
}

#[cfg(test)]
mod depth_tests {
    use super::*;

    #[test]
    fn shallow_nesting_parses() {
        let mut expr = String::from("any(\"x\")");
        for _ in 0..5 {
            expr = format!("not({expr})");
        }
        parse(&expr).expect("5-level not() should parse");
    }

    #[test]
    fn deep_nesting_rejected() {
        // 64 levels of not(not(...)) exceeds MAX_DSL_DEPTH (32).
        let mut expr = String::from("any(\"x\")");
        for _ in 0..64 {
            expr = format!("not({expr})");
        }
        let err = parse(&expr).expect_err("64-level not() should be rejected");
        assert!(matches!(err, ParseError::DepthExceeded { .. }));
    }
}
