//! Length-prefixed JSON-RPC wire types for subprocess communication.
//!
//! Confium spawns each plugin as a child process. The host writes
//! [`Request`] frames to the plugin's stdin and reads [`Response`]
//! frames from its stdout. Every frame is prefixed with a 4-byte
//! big-endian length followed by that many bytes of UTF-8 JSON.
//!
//! The request envelope is intentionally minimal:
//!
//! ```jsonc
//! {"method": "<function>", "args": [<value>, ...]}
//! ```
//!
//! Responses carry exactly one of `result` or `error`:
//!
//! ```jsonc
//! {"result": [<value>, ...]}            // success
//! {"error": {"message": "<text>"}}      // failure
//! ```
//!
//! [`Value`] variants map to/from JSON as documented on
//! [`value_to_json`] and [`value_from_json`].

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;
use snafu::GenerateImplicitData;

use crate::Error;
use crate::Result;
use crate::sandbox::Value;

/// Length-prefix size, in bytes (u32 big-endian).
pub(crate) const LEN_PREFIX_BYTES: usize = 4;

/// Maximum frame size. Defends against a misbehaving plugin that
/// claims a multi-GB length: the host refuses to allocate that much.
pub(crate) const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// A request the host sends to the plugin subprocess.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    pub args: Vec<JsonValue>,
}

impl Request {
    pub fn new(method: impl Into<String>, args: Vec<JsonValue>) -> Self {
        Self {
            method: method.into(),
            args,
        }
    }

    /// Serialize to a length-prefixed byte frame ready for stdin.
    pub fn to_frame(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(self).map_err(|e| Error::Protocol {
            reason: format!("failed to serialize request: {e}"),
            backtrace: snafu::Backtrace::generate(),
        })?;
        encode_frame(&json)
    }
}

/// A response the plugin writes back to the host.
#[derive(Debug, Clone, Deserialize)]
pub struct Response {
    /// Present on success: the function's return values.
    #[serde(default)]
    pub result: Option<Vec<JsonValue>>,
    /// Present on failure: a human-readable message.
    #[serde(default)]
    pub error: Option<ResponseError>,
}

/// Error payload inside a [`Response`].
#[derive(Debug, Clone, Deserialize)]
pub struct ResponseError {
    pub message: String,
}

impl Response {
    /// Parse a length-prefixed frame from a raw JSON byte slice.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice::<Response>(bytes).map_err(|e| Error::Protocol {
            reason: format!("failed to parse response: {e}"),
            backtrace: snafu::Backtrace::generate(),
        })
    }

    /// Split into success values or an [`Error::PluginError`].
    pub fn into_result(self, method: &str) -> Result<Vec<Value>> {
        if let Some(err) = self.error {
            return Err(Error::PluginError {
                method: method.to_string(),
                message: err.message,
                backtrace: snafu::Backtrace::generate(),
            });
        }
        let raw = self.result.unwrap_or_default();
        raw.into_iter()
            .map(value_from_json)
            .collect::<Result<Vec<_>>>()
    }
}

/// Encode `payload` as a 4-byte big-endian length prefix + payload.
pub(crate) fn encode_frame(payload: &[u8]) -> Result<Vec<u8>> {
    let len = payload.len();
    if len > MAX_FRAME_BYTES {
        return Err(Error::Protocol {
            reason: format!("frame too large: {len} > {MAX_FRAME_BYTES} bytes"),
            backtrace: snafu::Backtrace::generate(),
        });
    }
    let mut out = Vec::with_capacity(LEN_PREFIX_BYTES + len);
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Marshal a [`Value`] to its JSON wire form.
///
/// - `I32`/`I64` -> JSON integer
/// - `F32`/`F64` -> JSON number
/// - `Bytes`     -> JSON array of unsigned byte integers
pub fn value_to_json(v: &Value) -> JsonValue {
    match v {
        Value::I32(x) => JsonValue::from(*x),
        Value::I64(x) => JsonValue::from(*x),
        Value::F32(x) => serde_json::Number::from_f64(f64::from(*x))
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Value::F64(x) => serde_json::Number::from_f64(*x)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Value::Bytes(b) => JsonValue::Array(
            b.iter()
                .map(|&byte| JsonValue::from(u32::from(byte)))
                .collect(),
        ),
    }
}

/// Inverse of [`value_to_json`].
pub fn value_from_json(v: JsonValue) -> Result<Value> {
    Ok(match v {
        JsonValue::Bool(_) | JsonValue::Null => {
            return Err(Error::Protocol {
                reason: "null/bool are not valid sandbox values".into(),
                backtrace: snafu::Backtrace::generate(),
            });
        }
        JsonValue::String(_) => {
            return Err(Error::Protocol {
                reason: "string is not a valid sandbox value".into(),
                backtrace: snafu::Backtrace::generate(),
            });
        }
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                if let Ok(small) = i32::try_from(i) {
                    Value::I32(small)
                } else {
                    Value::I64(i)
                }
            } else if let Some(u) = n.as_u64() {
                // u64 that doesn't fit in i64: represent as I64 if possible.
                if let Ok(i) = i64::try_from(u) {
                    Value::I64(i)
                } else {
                    return Err(Error::Protocol {
                        reason: format!("integer {u} overflows i64"),
                        backtrace: snafu::Backtrace::generate(),
                    });
                }
            } else if let Some(f) = n.as_f64() {
                Value::F64(f)
            } else {
                return Err(Error::Protocol {
                    reason: format!("unsupported number {n}"),
                    backtrace: snafu::Backtrace::generate(),
                });
            }
        }
        JsonValue::Array(arr) => {
            // Decode byte arrays back into Bytes. Every element must
            // be a small non-negative integer.
            let mut bytes = Vec::with_capacity(arr.len());
            for el in arr {
                let n = el.as_u64().ok_or_else(|| Error::Protocol {
                    reason: "byte array element is not a non-negative integer".into(),
                    backtrace: snafu::Backtrace::generate(),
                })?;
                let byte = u8::try_from(n).map_err(|_| Error::Protocol {
                    reason: format!("byte array element {n} out of u8 range"),
                    backtrace: snafu::Backtrace::generate(),
                })?;
                bytes.push(byte);
            }
            Value::Bytes(bytes)
        }
        JsonValue::Object(_) => {
            return Err(Error::Protocol {
                reason: "object is not a valid sandbox value".into(),
                backtrace: snafu::Backtrace::generate(),
            });
        }
    })
}

/// Read a `u32` big-endian length from a 4-byte slice.
pub(crate) fn parse_len(buf: &[u8]) -> Result<usize> {
    if buf.len() < LEN_PREFIX_BYTES {
        return Err(Error::Protocol {
            reason: format!(
                "length header truncated: got {} bytes, need {LEN_PREFIX_BYTES}",
                buf.len()
            ),
            backtrace: snafu::Backtrace::generate(),
        });
    }
    let mut arr = [0u8; LEN_PREFIX_BYTES];
    arr.copy_from_slice(&buf[..LEN_PREFIX_BYTES]);
    let len = u32::from_be_bytes(arr) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(Error::Protocol {
            reason: format!("frame too large: {len} > {MAX_FRAME_BYTES} bytes"),
            backtrace: snafu::Backtrace::generate(),
        });
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_frame_round_trips() {
        let req = Request::new("add", vec![JsonValue::from(2), JsonValue::from(3)]);
        let frame = req.to_frame().expect("frame encodes");
        // 4-byte length prefix + JSON body.
        assert!(frame.len() > LEN_PREFIX_BYTES);
        let len = parse_len(&frame[..LEN_PREFIX_BYTES]).expect("len parses");
        let body = &frame[LEN_PREFIX_BYTES..LEN_PREFIX_BYTES + len];
        let parsed: Request = serde_json::from_slice(body).expect("request parses back");
        assert_eq!(parsed.method, "add");
        assert_eq!(parsed.args.len(), 2);
    }

    #[test]
    fn encode_frame_writes_big_endian_length() {
        let payload = b"hello";
        let frame = encode_frame(payload).expect("encode");
        assert_eq!(&frame[..4], &[0, 0, 0, 5]);
        assert_eq!(&frame[4..], payload);
    }

    #[test]
    fn parse_len_rejects_truncated_header() {
        let err = parse_len(&[0, 0]).expect_err("must fail");
        // Truncated length header surfaces as a Protocol error.
        assert_eq!(err.code(), 0x2104);
    }

    #[test]
    fn value_to_json_round_trip_integers() {
        let v = Value::I32(42);
        let j = value_to_json(&v);
        let back = value_from_json(j).expect("round trips");
        assert_eq!(back, Value::I32(42));

        let v = Value::I64(5_000_000_000);
        let j = value_to_json(&v);
        let back = value_from_json(j).expect("round trips");
        assert_eq!(back, Value::I64(5_000_000_000));
    }

    #[test]
    fn value_to_json_round_trip_bytes() {
        let v = Value::Bytes(vec![0, 127, 255, 1]);
        let j = value_to_json(&v);
        let back = value_from_json(j).expect("round trips");
        assert_eq!(back, v);
    }

    #[test]
    fn value_to_json_round_trip_floats() {
        let v = Value::F64(2.5);
        let j = value_to_json(&v);
        let back = value_from_json(j).expect("round trips");
        match back {
            Value::F64(x) => assert_eq!(x, 2.5),
            other => panic!("expected F64, got {:?}", other),
        }
    }

    #[test]
    fn response_success_parses() {
        let raw = br#"{"result":[7]}"#;
        let resp = Response::from_json_bytes(raw).expect("parses");
        let out = resp.into_result("add").expect("ok");
        assert_eq!(out, vec![Value::I32(7)]);
    }

    #[test]
    fn response_error_becomes_plugin_error() {
        let raw = br#"{"error":{"message":"no such function"}}"#;
        let resp = Response::from_json_bytes(raw).expect("parses");
        let err = resp.into_result("foo").expect_err("must fail");
        match err {
            Error::PluginError {
                method, message, ..
            } => {
                assert_eq!(method, "foo");
                assert_eq!(message, "no such function");
            }
            other => panic!("expected PluginError, got {:?}", other),
        }
    }

    #[test]
    fn response_with_empty_result_is_ok_empty() {
        let raw = br#"{"result":[]}"#;
        let resp = Response::from_json_bytes(raw).expect("parses");
        let out = resp.into_result("void").expect("ok");
        assert!(out.is_empty());
    }
}
