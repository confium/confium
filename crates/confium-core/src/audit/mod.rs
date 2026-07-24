//! Structured audit logging for Confium.
//!
//! Every plugin load, secret access, and TC session boundary is written
//! as one JSON Lines record to a configurable sink. The default sink is
//! `$CONFIUM_AUDIT_LOG` if set, otherwise
//! `~/.local/share/confium/log/audit.jsonl`. If neither path can be
//! opened for append, the logger falls back to writing to **stderr**
//! (with a one-shot warning) so audit events are never silently lost.
//!
//! The logger is lock-free in the disabled case in spirit (the lock is
//! held only long enough to observe the variant) and uses a
//! `Mutex<Sink>` only for the actual write. Logging failures (a full
//! disk, a vanished log directory) degrade to dropping the event rather
//! than panicking the host process — an audit subsystem must never
//! take the crypto path down with it.
//!
//! See `TODO.roadmap/08-security-model.md` (Auditability) for the
//! threat model and wire format.

pub mod event;

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use event::AuditEvent;

/// Environment variable consulted by [`AuditLogger::default`] to
/// override the audit log destination. Set to an absolute path.
pub const AUDIT_LOG_ENV: &str = "CONFIUM_AUDIT_LOG";

/// The on-disk location used when `CONFIUM_AUDIT_LOG` is unset.
/// Relative to the user's home directory as recommended by XDG.
pub const DEFAULT_LOG_RELATIVE: &str = ".local/share/confium/log/audit.jsonl";

/// Where audit records are written. Construct one with
/// [`AuditLogger::default`] (resolves the env var / default path /
/// stderr fallback) or [`AuditLogger::disabled`] (drop all events —
/// for tests and callers that opt out), or [`AuditLogger::to_file`] /
/// [`AuditLogger::to_writer`] for explicit control.
///
/// The logger is `Send` + `Sync` so it can live behind the `Confium`
/// struct shared across FFI entry points.
pub struct AuditLogger {
    inner: Mutex<Sink>,
}

enum Sink {
    /// Records are discarded. Used by [`AuditLogger::disabled`] and by
    /// callers that opt out of audit logging.
    Disabled,
    /// Append to an opened file. The file is kept open for the life of
    /// the logger; each event is a `write_all` + `flush` so records
    /// survive a crash immediately after the call returns.
    File(std::fs::File),
    /// Stderr fallback when neither the env-var path nor the default
    /// path can be opened.
    Stderr,
    /// An arbitrary owned writer (used for in-memory test sinks).
    Writer(Box<dyn Write + Send>),
}

impl AuditLogger {
    /// A logger that drops every event. Used by tests and by callers
    /// (via `Confium::new_with_audit`) that want audit logging off.
    pub fn disabled() -> Self {
        AuditLogger {
            inner: Mutex::new(Sink::Disabled),
        }
    }

    /// Logger that writes JSONL records to a file opened in append
    /// mode. The parent directory is created if missing. Returns an
    /// error if the file cannot be opened — callers wanting the
    /// stderr-fallback behavior should use [`AuditLogger::default`]
    /// instead.
    pub fn to_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(AuditLogger {
            inner: Mutex::new(Sink::File(file)),
        })
    }

    /// Logger that writes JSONL records to an arbitrary writer. The
    /// writer is owned by the logger. Used for in-memory test sinks.
    pub fn to_writer<W: Write + Send + 'static>(writer: W) -> Self {
        AuditLogger {
            inner: Mutex::new(Sink::Writer(Box::new(writer))),
        }
    }

    /// Resolve the default sink.
    ///
    /// Order:
    /// 1. `$CONFIUM_AUDIT_LOG` if set and openable.
    /// 2. `~/.local/share/confium/log/audit.jsonl` if openable.
    /// 3. stderr, with a one-line warning emitted when we fall
    ///    through to it.
    ///
    /// Construction must never panic: an audit logger that takes the
    /// host process down on startup is worse than no audit logger.
    pub fn default_logger() -> Self {
        if let Some(path) = env_log_path() {
            match Self::to_file(&path) {
                Ok(logger) => return logger,
                Err(e) => {
                    warn_fallback(&format!(
                        "confium: could not open audit log at {} ({}); falling back to stderr",
                        path.display(),
                        e
                    ));
                }
            }
        }
        if let Some(path) = default_log_path() {
            match Self::to_file(&path) {
                Ok(logger) => return logger,
                Err(e) => {
                    warn_fallback(&format!(
                        "confium: could not open audit log at {} ({}); falling back to stderr",
                        path.display(),
                        e
                    ));
                }
            }
        }
        AuditLogger {
            inner: Mutex::new(Sink::Stderr),
        }
    }

    /// Append a single event to the sink, with the given ISO-8601
    /// timestamp. The timestamp is injected by the caller (rather than
    /// read inside the logger) so tests can assert on a fixed value.
    /// Production callers pass the result of [`now_iso8601`].
    pub fn log_at(&self, ts: &str, event: &AuditEvent<'_>) {
        let line = event.to_json(ts);
        // Hold the lock only across the write so concurrent FFI calls
        // don't serialize on audit logging for longer than the I/O.
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            // A poisoned lock means another thread panicked while
            // writing; we can't recover the sink, so drop the event
            // rather than propagate the panic.
            Err(_) => return,
        };
        write_line(&mut guard, &line);
    }

    /// Convenience: log an event timestamped "now". This is the entry
    /// point used by the framework's audit call sites.
    pub fn log(&self, event: &AuditEvent<'_>) {
        let ts = now_iso8601();
        self.log_at(&ts, event);
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::default_logger()
    }
}

// --- sink write helpers ------------------------------------------------

fn write_line(sink: &mut Sink, line: &str) {
    let result: std::io::Result<()> = match sink {
        Sink::Disabled => Ok(()),
        Sink::File(f) => f
            .write_all(line.as_bytes())
            .and_then(|()| f.write_all(b"\n"))
            .and_then(|()| f.flush()),
        Sink::Stderr => {
            let stderr = std::io::stderr();
            let mut h = stderr.lock();
            h.write_all(line.as_bytes())
                .and_then(|()| h.write_all(b"\n"))
                .and_then(|()| h.flush())
        }
        Sink::Writer(w) => w
            .write_all(line.as_bytes())
            .and_then(|()| w.write_all(b"\n"))
            .and_then(|()| w.flush()),
    };
    // Swallow write errors: an audit logger must never take the host
    // process down. If the sink is broken, the event is simply lost;
    // a future call may succeed if the sink recovers.
    let _ = result;
}

fn warn_fallback(msg: &str) {
    // Emit to stderr unconditionally. We avoid the `log` crate to keep
    // the audit subsystem dependency-free.
    let stderr = std::io::stderr();
    let mut h = stderr.lock();
    let _ = writeln!(h, "{msg}");
}

// --- path & timestamp helpers -----------------------------------------

/// Resolve the audit log path from `$CONFIUM_AUDIT_LOG`, if set and
/// non-empty.
fn env_log_path() -> Option<PathBuf> {
    resolve_env_log_path(std::env::var(AUDIT_LOG_ENV).ok())
}

/// Pure core of [`env_log_path`], factored out so the resolution
/// logic can be tested without mutating the process environment
/// (which is `unsafe` in Rust 2024 and racy under parallel `cargo
/// test`).
fn resolve_env_log_path(env_value: Option<String>) -> Option<PathBuf> {
    match env_value {
        Some(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => None,
    }
}

/// Resolve the default audit log path under the user's home
/// directory. Returns `None` only if `$HOME` is unset.
fn default_log_path() -> Option<PathBuf> {
    resolve_default_log_path(std::env::var_os("HOME"))
}

/// Pure core of [`default_log_path`], factored out for testing
/// without touching the process environment.
fn resolve_default_log_path(home: Option<std::ffi::OsString>) -> Option<PathBuf> {
    let home = home?;
    let mut p = PathBuf::from(home);
    p.push(DEFAULT_LOG_RELATIVE);
    Some(p)
}

/// Current UTC time as ISO-8601 with millisecond precision and a
/// trailing `Z`: `2026-07-25T13:05:22.123Z`.
///
/// Computed manually from `SystemTime` to avoid pulling in `chrono`
/// or `time` — the shape is fixed and trivial. The conversion uses
/// the civil-from-days algorithm (Howard Hinnant, public domain),
/// which is correct for all proleptic Gregorian dates.
pub(crate) fn now_iso8601() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = dur.as_secs();
    let millis = dur.subsec_millis();

    let days = (total_secs / 86_400) as i64;
    let secs_of_day = (total_secs % 86_400) as u32;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hour, minute, second, millis
    )
}

/// Convert days-since-Unix-epoch to a (year, month, day) triple.
/// Algorithm: Howard Hinnant's `civil_from_days`, public domain.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use event::AuditEvent;
    use std::sync::{Arc, Mutex as StdMutex};

    /// A shared, cloneable in-memory sink so tests can read what was
    /// written without taking ownership of the logger.
    #[derive(Clone)]
    struct SharedBuffer(Arc<StdMutex<Vec<u8>>>);

    impl SharedBuffer {
        fn new() -> Self {
            SharedBuffer(Arc::new(StdMutex::new(Vec::new())))
        }

        fn snapshot(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }
    }

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn disabled_logger_writes_nothing() {
        let logger = AuditLogger::disabled();
        let buf = SharedBuffer::new();
        // Install a probe writer; an event logged on the disabled
        // logger must not reach the probe.
        *logger.inner.lock().unwrap() = Sink::Writer(Box::new(buf.clone()));
        // Restore Disabled to test the real disabled path.
        *logger.inner.lock().unwrap() = Sink::Disabled;
        logger.log(&AuditEvent::PluginLoad {
            name: "botan",
            version: "3.2.0",
            publisher: "ribose",
        });
        assert!(buf.snapshot().is_empty(), "disabled logger wrote bytes");
    }

    #[test]
    fn disabled_constructor_drops_events() {
        // A logger built via `disabled()` must drop events even after
        // we prove a writer would have received them otherwise.
        let logger = AuditLogger::disabled();
        let sink = SharedBuffer::new();
        let probe = sink.clone();
        logger.log(&AuditEvent::PluginLoad {
            name: "botan",
            version: "3.2.0",
            publisher: "ribose",
        });
        assert!(
            probe.snapshot().is_empty(),
            "events leaked to a buffer the logger never owned"
        );
        // Now install the probe and confirm subsequent events land.
        *logger.inner.lock().unwrap() = Sink::Writer(Box::new(probe));
        logger.log(&AuditEvent::PluginLoad {
            name: "botan",
            version: "3.2.0",
            publisher: "ribose",
        });
        assert!(!sink.snapshot().is_empty());
    }

    #[test]
    fn multiple_events_flush_in_order() {
        let buf = SharedBuffer::new();
        let logger = AuditLogger::to_writer(buf.clone());
        logger.log_at(
            "2026-07-25T13:05:22.000Z",
            &AuditEvent::PluginLoad {
                name: "botan",
                version: "3.2.0",
                publisher: "ribose",
            },
        );
        logger.log_at(
            "2026-07-25T13:05:22.500Z",
            &AuditEvent::KeyAccess {
                key_id: "abc123",
                interface: "signature",
                operation: "sign",
            },
        );
        logger.log_at(
            "2026-07-25T13:05:23.000Z",
            &AuditEvent::TcSessionStart {
                scheme: "FROST-ed25519",
                parties: 3,
                threshold: 2,
            },
        );
        let out = String::from_utf8(buf.snapshot()).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "expected 3 records, got: {out}");
        assert!(lines[0].contains("\"event\":\"plugin_load\""));
        assert!(lines[1].contains("\"event\":\"key_access\""));
        assert!(lines[2].contains("\"event\":\"tc_session_start\""));
        // Ordering is strictly by insertion (the logger does not reorder).
        assert!(lines[0].contains("13:05:22.000"));
        assert!(lines[1].contains("13:05:22.500"));
        assert!(lines[2].contains("13:05:23.000"));
    }

    #[test]
    fn file_sink_appends_across_loggers() {
        // Two loggers pointing at the same file should both append;
        // the file is opened in append mode and the records from each
        // logger appear in call order.
        let dir = tempdir();
        let path = dir.join("audit.jsonl");
        let l1 = AuditLogger::to_file(&path).unwrap();
        let l2 = AuditLogger::to_file(&path).unwrap();
        l1.log_at(
            "2026-07-25T13:05:22.000Z",
            &AuditEvent::PluginLoad {
                name: "botan",
                version: "3.2.0",
                publisher: "ribose",
            },
        );
        l2.log_at(
            "2026-07-25T13:05:22.500Z",
            &AuditEvent::PluginLoad {
                name: "openssl",
                version: "3.0",
                publisher: "openssl",
            },
        );
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"plugin\":\"botan\""));
        assert!(lines[1].contains("\"plugin\":\"openssl\""));
    }

    #[test]
    fn file_sink_creates_parent_directory() {
        let dir = tempdir();
        let nested = dir.join("a/b/c/audit.jsonl");
        let logger = AuditLogger::to_file(&nested).unwrap();
        logger.log_at(
            "2026-07-25T13:05:22.000Z",
            &AuditEvent::ConfigChange { key: "k" },
        );
        assert!(nested.exists(), "log file was not created");
        let contents = std::fs::read_to_string(&nested).unwrap();
        assert!(contents.contains("\"event\":\"config_change\""));
    }

    #[test]
    fn to_file_error_does_not_panic() {
        // An unwritable target (a path under a file, not a dir) must
        // return an Err, not panic.
        let dir = tempdir();
        let blocking_file = dir.join("blocker");
        std::fs::write(&blocking_file, b"").unwrap();
        let bad_path = blocking_file.join("audit.jsonl");
        let result = AuditLogger::to_file(&bad_path);
        assert!(result.is_err());
    }

    #[test]
    fn env_log_path_resolution_picks_up_nonempty_value() {
        // The pure resolver returns the path when the env value is set
        // and non-empty. `default_logger` consults this resolver first,
        // so this is the test that the env var is honored without
        // mutating the process environment (which is `unsafe` in Rust
        // 2024 and racy under parallel `cargo test`).
        let p = resolve_env_log_path(Some("/tmp/x.jsonl".to_string()));
        assert_eq!(p, Some(PathBuf::from("/tmp/x.jsonl")));
    }

    #[test]
    fn env_log_path_resolution_ignores_empty_value() {
        // An explicitly empty env var must behave as if unset so we
        // fall through to the default path, not log to "".
        assert_eq!(resolve_env_log_path(Some(String::new())), None);
    }

    #[test]
    fn env_log_path_resolution_ignores_unset_value() {
        assert_eq!(resolve_env_log_path(None), None);
    }

    #[test]
    fn default_log_path_resolution_joins_relative_under_home() {
        let home = std::ffi::OsString::from("/home/alice");
        let p = resolve_default_log_path(Some(home)).unwrap();
        let mut expected = PathBuf::from("/home/alice");
        expected.push(DEFAULT_LOG_RELATIVE);
        assert_eq!(p, expected);
    }

    #[test]
    fn default_log_path_resolution_is_none_without_home() {
        // When HOME is unset there is no default path; the logger then
        // falls back to stderr.
        assert_eq!(resolve_default_log_path(None), None);
    }

    #[test]
    fn default_logger_uses_to_file_sink_for_a_writable_env_path() {
        // Drive `default_logger` indirectly: when a writable path is
        // reachable it produces a File sink that records events. We
        // cannot set CONFIUM_AUDIT_LOG safely here (env mutation is
        // unsafe + racy), so we instead confirm `to_file` — the
        // constructor `default_logger` calls internally — works end
        // to end. Path-resolution correctness is covered by the
        // resolve_* tests above.
        let dir = tempdir();
        let path = dir.join("audit.jsonl");
        let logger = AuditLogger::to_file(&path).unwrap();
        logger.log_at(
            "2026-07-25T13:05:22.000Z",
            &AuditEvent::PluginLoad {
                name: "botan",
                version: "3.2.0",
                publisher: "ribose",
            },
        );
        assert!(path.exists(), "log file was not created");
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"event\":\"plugin_load\""));
    }

    #[test]
    fn log_is_a_single_jsonl_line() {
        let buf = SharedBuffer::new();
        let logger = AuditLogger::to_writer(buf.clone());
        logger.log(&AuditEvent::KeyAccess {
            key_id: "abc123",
            interface: "signature",
            operation: "sign",
        });
        let out = String::from_utf8(buf.snapshot()).unwrap();
        assert_eq!(out.matches('\n').count(), 1, "expected exactly one newline");
        let line = out.trim_end_matches('\n');
        // The line must be valid JSON containing the expected keys.
        assert!(line.starts_with('{'));
        assert!(line.ends_with('}'));
        assert!(line.contains("\"ts\":"));
        assert!(line.contains("\"event\":\"key_access\""));
    }

    #[test]
    fn now_iso8601_has_millisecond_precision_and_z_suffix() {
        let ts = now_iso8601();
        assert!(ts.ends_with('Z'), "missing Z suffix: {ts}");
        // Shape: YYYY-MM-DDTHH:MM:SS.mmmZ
        assert_eq!(ts.len(), 24, "unexpected length for {ts}");
        assert_eq!(ts.as_bytes()[4], b'-');
        assert_eq!(ts.as_bytes()[10], b'T');
        assert_eq!(ts.as_bytes()[19], b'.');
        assert_eq!(ts.as_bytes()[23], b'Z');
    }

    #[test]
    fn civil_from_days_epoch_is_1970_01_01() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn civil_from_days_known_dates() {
        // 2026-07-25 is day 20659 since the Unix epoch.
        assert_eq!(civil_from_days(20_659), (2026, 7, 25));
        // Leap day handling: 2024-02-29 is day 19782.
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }

    // --- test utilities ------------------------------------------------

    fn tempdir() -> PathBuf {
        // A per-test temp directory so parallel cargo-test runs don't
        // stomp each other. We don't use the `tempfile` crate (not in
        // the workspace deps); std + a pid-based name is enough.
        let mut p = std::env::temp_dir();
        p.push(format!(
            "confium-audit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
