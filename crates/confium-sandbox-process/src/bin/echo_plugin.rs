//! Test-only echo plugin binary for `confium-sandbox-process`.
//!
//! Speaks the subprocess JSON-RPC protocol: reads length-prefixed
//! request frames from stdin, writes length-prefixed response frames
//! to stdout. Recognized methods:
//!
//! - `echo`  -> returns its args verbatim as results.
//! - `add`   -> sums two integer args, returns `[sum]`.
//! - `ping`  -> returns `[1]` (no args).
//! - anything else -> returns `{"error":{"message":"unknown method: <m>"}}`.
//!
//! Not part of the public API; built only when the `test-bin` feature
//! is enabled. The integration tests spawn this binary to verify the
//! sandbox's framing and round-trip behavior end to end.

use std::io::Read;
use std::io::Write;

use serde_json::Value as JsonValue;

const LEN_PREFIX_BYTES: usize = 4;

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut stdin = stdin.lock();
    let mut stdout = stdout.lock();

    loop {
        let frame = match read_frame(&mut stdin) {
            Ok(f) => f,
            Err(_) => return, // stdin closed or truncated; exit quietly
        };
        let req: serde_json::Value = match serde_json::from_slice(&frame) {
            Ok(v) => v,
            Err(e) => {
                let _ = write_response(&mut stdout, &error_obj(&format!("bad json: {e}")));
                continue;
            }
        };
        let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let args = req
            .get("args")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let resp = match method {
            "echo" => serde_json::json!({ "result": args }),
            "ping" => serde_json::json!({ "result": [1] }),
            "add" => {
                let a = args.first().and_then(|v| v.as_i64()).unwrap_or(0);
                let b = args.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
                serde_json::json!({ "result": [a + b] })
            }
            other => error_obj(&format!("unknown method: {other}")),
        };
        if write_response(&mut stdout, &resp).is_err() {
            return;
        }
    }
}

fn error_obj(msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "message": msg } })
}

fn read_frame<R: Read>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; LEN_PREFIX_BYTES];
    reader.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

fn write_response<W: Write>(writer: &mut W, value: &JsonValue) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(value).expect("response serializes");
    let len = bytes.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}
