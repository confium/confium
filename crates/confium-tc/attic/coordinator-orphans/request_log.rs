//! Server request log — structured per-request logging.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::collections::VecDeque;

/// A single request log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLogEntry {
    pub timestamp: DateTime<Utc>,
    pub request_type: String,
    pub session_id: Option<String>,
    pub signer_id: Option<String>,
    pub duration_us: u64,
    pub success: bool,
    pub error: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Thread-safe request log with bounded capacity.
pub struct RequestLog {
    entries: Mutex<VecDeque<RequestLogEntry>>,
    max_entries: usize,
}

impl RequestLog {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(max_entries)),
            max_entries,
        }
    }

    pub fn log(&self, entry: RequestLogEntry) {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    pub fn entries(&self) -> Vec<RequestLogEntry> {
        self.entries.lock().unwrap().iter().cloned().collect()
    }

    pub fn count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn error_count(&self) -> usize {
        self.entries.lock().unwrap().iter().filter(|e| !e.success).count()
    }

    pub fn avg_duration_us(&self) -> f64 {
        let entries = self.entries.lock().unwrap();
        if entries.is_empty() {
            return 0.0;
        }
        entries.iter().map(|e| e.duration_us as f64).sum::<f64>() / entries.len() as f64
    }

    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

/// Helper to build and log a request.
pub struct RequestTimer {
    request_type: String,
    start: std::time::Instant,
}

impl RequestTimer {
    pub fn start(request_type: &str) -> Self {
        Self {
            request_type: request_type.into(),
            start: std::time::Instant::now(),
        }
    }

    pub fn finish(self, log: &RequestLog, success: bool, error: Option<String>) {
        log.log(RequestLogEntry {
            timestamp: Utc::now(),
            request_type: self.request_type,
            session_id: None,
            signer_id: None,
            duration_us: self.start.elapsed().as_micros() as u64,
            success,
            error,
            bytes_in: 0,
            bytes_out: 0,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_log() {
        let log = RequestLog::new(100);
        assert_eq!(log.count(), 0);
        assert_eq!(log.avg_duration_us(), 0.0);
    }

    #[test]
    fn log_and_retrieve() {
        let log = RequestLog::new(100);
        log.log(RequestLogEntry {
            timestamp: Utc::now(),
            request_type: "test".into(),
            session_id: None, signer_id: None,
            duration_us: 100, success: true,
            error: None, bytes_in: 10, bytes_out: 20,
        });
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn bounded_capacity() {
        let log = RequestLog::new(3);
        for i in 0..5 {
            log.log(RequestLogEntry {
                timestamp: Utc::now(),
                request_type: format!("req-{i}"),
                session_id: None, signer_id: None,
                duration_us: i * 100, success: true,
                error: None, bytes_in: 0, bytes_out: 0,
            });
        }
        assert_eq!(log.count(), 3);
    }

    #[test]
    fn error_count() {
        let log = RequestLog::new(100);
        log.log(RequestLogEntry {
            timestamp: Utc::now(), request_type: "a".into(),
            session_id: None, signer_id: None, duration_us: 1,
            success: true, error: None, bytes_in: 0, bytes_out: 0,
        });
        log.log(RequestLogEntry {
            timestamp: Utc::now(), request_type: "b".into(),
            session_id: None, signer_id: None, duration_us: 1,
            success: false, error: Some("fail".into()), bytes_in: 0, bytes_out: 0,
        });
        assert_eq!(log.error_count(), 1);
    }

    #[test]
    fn avg_duration() {
        let log = RequestLog::new(100);
        for d in [100u64, 200, 300] {
            log.log(RequestLogEntry {
                timestamp: Utc::now(), request_type: "x".into(),
                session_id: None, signer_id: None, duration_us: d,
                success: true, error: None, bytes_in: 0, bytes_out: 0,
            });
        }
        assert!((log.avg_duration_us() - 200.0).abs() < 0.1);
    }

    #[test]
    fn timer_finishes() {
        let log = RequestLog::new(100);
        let timer = RequestTimer::start("op");
        std::thread::sleep(std::time::Duration::from_micros(100));
        timer.finish(&log, true, None);
        assert_eq!(log.count(), 1);
        assert!(log.entries()[0].duration_us >= 50);
    }

    #[test]
    fn clear_empties() {
        let log = RequestLog::new(100);
        log.log(RequestLogEntry {
            timestamp: Utc::now(), request_type: "x".into(),
            session_id: None, signer_id: None, duration_us: 1,
            success: true, error: None, bytes_in: 0, bytes_out: 0,
        });
        log.clear();
        assert_eq!(log.count(), 0);
    }

    #[test]
    fn entry_serializes() {
        let entry = RequestLogEntry {
            timestamp: Utc::now(), request_type: "test".into(),
            session_id: Some("s1".into()), signer_id: Some("a".into()),
            duration_us: 42, success: true, error: None,
            bytes_in: 10, bytes_out: 20,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("request_type"));
        assert!(json.contains("s1"));
    }
}
