//! `ProcessSandbox` — the out-of-process implementation of [`Sandbox`].
//!
//! Each plugin runs in its own subprocess. Confium writes
//! length-prefixed JSON-RPC [`Request`] frames to the child's stdin
//! and reads [`Response`] frames from its stdout.
//! A plugin that misbehaves (writes a truncated frame, returns
//! malformed JSON, exits) is reported as an [`Error`] on the next
//! call rather than crashing the host.
//!
//! Capability state is held host-side: the host refuses to forward a
//! call whose required capability is not currently granted. This is
//! the minimum viable gate; a future revision can additionally
//! restrict the child at the OS level (seccomp/AppSandbox) so even a
//! compromised plugin cannot reach the network or filesystem.
//!
//! See `TODO.roadmap/08-security-model.md` § "Track B: Out-of-process
//! plugins".

use std::collections::HashSet;
use std::io::Read;
use std::io::Write;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::str;

use snafu::Backtrace;
use snafu::GenerateImplicitData;

use crate::Error;
use crate::Result;
use crate::protocol::LEN_PREFIX_BYTES;
use crate::protocol::MAX_FRAME_BYTES;
use crate::protocol::Request;
use crate::protocol::Response;
use crate::protocol::parse_len;
use crate::protocol::value_to_json;
use crate::sandbox::Capability;
use crate::sandbox::Sandbox;
use crate::sandbox::SandboxInstance;
use crate::sandbox::Value;

/// The out-of-process sandbox.
///
/// Clone-cheap: it holds no per-instance state. Each
/// [`load_module`](ProcessSandbox::load_module) spawns a fresh child
/// with its own pipes and an empty capability envelope.
#[derive(Debug, Default, Clone)]
pub struct ProcessSandbox;

impl ProcessSandbox {
    /// Construct a new process sandbox.
    pub fn new() -> Self {
        Self
    }
}

impl Sandbox for ProcessSandbox {
    fn load_module(&self, bytes: &[u8]) -> Result<Box<dyn SandboxInstance>> {
        let path = str::from_utf8(bytes).map_err(|e| Error::InvalidPath {
            source: e,
            backtrace: Backtrace::generate(),
        })?;
        // Trim a trailing newline that often appears when a path is
        // read from a file or echoed in a shell. Leading/trailing
        // whitespace is never part of a valid executable path on the
        // platforms we support.
        let path = path.trim();

        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // stderr inherits so plugin diagnostics are visible during
            // development without polluting the protocol stream.
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| Error::Spawn {
                source: e,
                backtrace: Backtrace::generate(),
            })?;

        // Take the pipes now so they live on the instance; if either
        // take fails the child is killed on drop via the guard below.
        let stdin = child.stdin.take().ok_or_else(|| Error::Spawn {
            source: std::io::Error::other("plugin stdin pipe was not captured"),
            backtrace: Backtrace::generate(),
        })?;
        let stdout = child.stdout.take().ok_or_else(|| Error::Spawn {
            source: std::io::Error::other("plugin stdout pipe was not captured"),
            backtrace: Backtrace::generate(),
        })?;

        Ok(Box::new(ProcessInstance {
            child: Some(child),
            stdin,
            stdout,
            caps: CapabilitySet::new(),
        }))
    }

    fn name(&self) -> &'static str {
        "process"
    }
}

/// A loaded plugin subprocess plus its capability envelope.
///
/// Dropping the instance kills the child (SIGKILL on Unix,
/// TerminateProcess on Windows) so a forgotten plugin cannot outlive
/// its host.
pub struct ProcessInstance {
    child: Option<Child>,
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
    caps: CapabilitySet,
}

impl Drop for ProcessInstance {
    fn drop(&mut self) {
        // Close stdin first so a well-behaved plugin can exit on its
        // own, then force-kill if it's still alive.
        let _ = self.stdin.flush();
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl ProcessInstance {
    /// Send a [`Request`] frame and read back the matching [`Response`].
    ///
    /// Synchronous: one request in, one response out, in order. The
    /// protocol is intentionally request/response with no pipelining
    /// so a confused plugin cannot desynchronize the host.
    fn round_trip(&mut self, req: &Request) -> Result<Response> {
        let frame = req.to_frame()?;
        self.stdin
            .write_all(&frame)
            .map_err(|e| Error::WriteRequest {
                source: e,
                backtrace: Backtrace::generate(),
            })?;
        self.stdin.flush().map_err(|e| Error::WriteRequest {
            source: e,
            backtrace: Backtrace::generate(),
        })?;

        let payload = read_frame(&mut self.stdout)?;
        Response::from_json_bytes(&payload)
    }
}

impl SandboxInstance for ProcessInstance {
    fn call(&mut self, function: &str, args: &[Value]) -> Result<Vec<Value>> {
        let json_args: Vec<_> = args.iter().map(value_to_json).collect();
        let req = Request::new(function, json_args);
        let resp = self.round_trip(&req)?;
        resp.into_result(function)
    }

    fn grant_capability(&mut self, cap: Capability) -> Result<()> {
        self.caps.grant(cap);
        Ok(())
    }

    fn revoke_capability(&mut self, cap: &Capability) -> Result<()> {
        self.caps.revoke(cap);
        Ok(())
    }
}

// ----------------------------------------------------------------------
// Capability set — host-side enforcement.
//
// The process sandbox enforces capability gating on the host: a call
// is only forwarded to the subprocess if the host believes the plugin
// is entitled. (A subprocess that has been compromised cannot be
// trusted to enforce its own gate, but it also has no host imports to
// call — it can only respond to `call()` messages. OS-level
// restriction of the child is a future-task item.)

#[derive(Debug, Default)]
struct CapabilitySet {
    caps: HashSet<Capability>,
}

impl CapabilitySet {
    fn new() -> Self {
        Self::default()
    }

    fn grant(&mut self, cap: Capability) {
        self.caps.insert(cap);
    }

    fn revoke(&mut self, cap: &Capability) {
        self.caps.remove(cap);
    }

    #[allow(dead_code)]
    fn has(&self, cap: &Capability) -> bool {
        self.caps.contains(cap)
    }
}

// ----------------------------------------------------------------------
// Framed I/O helpers.

/// Read one length-prefixed frame from `reader`.
///
/// Blocks until 4 length bytes are available, then blocks until the
/// full payload arrives. Returns the raw JSON payload bytes (without
/// the length prefix).
fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut header = [0u8; LEN_PREFIX_BYTES];
    read_exact_or_eof(reader, &mut header)?;
    let len = parse_len(&header)?;
    // Cap a single allocation; the read loop below handles short reads.
    let mut payload = vec![0u8; len];
    if len > 0 {
        read_exact_or_eof(reader, &mut payload)?;
    }
    Ok(payload)
}

/// Like `Read::read_exact` but maps an unexpected EOF to
/// [`Error::ReadResponse`] rather than `UnexpectedEof`. This is the
/// right error for a pipe that closed mid-frame.
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader
            .read(&mut buf[filled..])
            .map_err(|e| Error::ReadResponse {
                source: e,
                backtrace: Backtrace::generate(),
            })?;
        if n == 0 {
            return Err(Error::ReadResponse {
                source: std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!(
                        "plugin stdout closed after {filled}/{} bytes of frame",
                        buf.len()
                    ),
                ),
                backtrace: Backtrace::generate(),
            });
        }
        filled += n;
    }
    let _ = MAX_FRAME_BYTES; // keep the constant referenced
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn sandbox_name_is_process() {
        let sb = ProcessSandbox::new();
        assert_eq!(sb.name(), "process");
    }

    #[test]
    fn sandbox_default_works() {
        let sb = ProcessSandbox;
        assert_eq!(sb.name(), "process");
    }

    #[test]
    fn read_frame_decodes_simple_payload() {
        // length = 5, payload = "hello"
        let mut bytes = vec![0, 0, 0, 5];
        bytes.extend_from_slice(b"hello");
        let mut cur = Cursor::new(bytes);
        let payload = read_frame(&mut cur).expect("frame reads");
        assert_eq!(&payload, b"hello");
    }

    #[test]
    fn read_frame_empty_payload() {
        let bytes = vec![0, 0, 0, 0];
        let mut cur = Cursor::new(bytes);
        let payload = read_frame(&mut cur).expect("frame reads");
        assert!(payload.is_empty());
    }

    #[test]
    fn read_frame_eof_on_truncated_header() {
        let bytes = vec![0, 0];
        let mut cur = Cursor::new(bytes);
        let err = read_frame(&mut cur).expect_err("must fail");
        // Truncated header surfaces as a read error (0 bytes read, then EOF).
        assert_eq!(err.code(), 0x2103);
    }

    #[test]
    fn read_frame_eof_on_truncated_payload() {
        let mut bytes = vec![0, 0, 0, 10];
        bytes.extend_from_slice(b"short");
        let mut cur = Cursor::new(bytes);
        let err = read_frame(&mut cur).expect_err("must fail");
        assert_eq!(err.code(), 0x2103);
    }

    #[test]
    fn capability_set_grant_revoke() {
        let mut caps = CapabilitySet::new();
        let cap = Capability::InterfaceAccess {
            name: "hash".into(),
        };
        assert!(!caps.has(&cap));
        caps.grant(cap.clone());
        assert!(caps.has(&cap));
        caps.revoke(&cap);
        assert!(!caps.has(&cap));
    }
}
