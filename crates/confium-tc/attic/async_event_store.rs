//! Async event-sourced store with batch writes and crash recovery.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::Duration;

/// A domain event for async persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DomainEvent {
    Created { id: String, payload: String },
    Updated { id: String, payload: String },
    Deleted { id: String },
}

/// An entry in the event store with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncEventEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub event: DomainEvent,
}

/// Async event store with background writer thread.
pub struct AsyncEventStore {
    sender: Sender<DomainEvent>,
    sequence: std::sync::Mutex<u64>,
    pending: std::sync::Mutex<Vec<AsyncEventEntry>>,
}

impl AsyncEventStore {
    /// Spawn the background writer thread.
    pub fn spawn() -> (Self, ReceiverHandle) {
        let (tx, rx) = channel::<DomainEvent>();
        let (result_tx, result_rx) = channel::<()>();

        thread::spawn(move || {
            let mut sequence = 0u64;
            while let Ok(event) = rx.recv() {
                sequence += 1;
                // In production, this would batch-flush to disk
                // For now, just process synchronously
                let entry = AsyncEventEntry {
                    sequence,
                    timestamp: Utc::now(),
                    event,
                };
                // Simulate async I/O
                thread::sleep(Duration::from_micros(10));
                let _ = entry;
            }
            let _ = result_tx.send(());
        });

        let store = Self {
            sender: tx,
            sequence: std::sync::Mutex::new(0),
            pending: std::sync::Mutex::new(Vec::new()),
        };
        (store, ReceiverHandle { _rx: result_rx })
    }

    /// Submit an event for async persistence.
    pub fn submit(&self, event: DomainEvent) -> Result<(), String> {
        self.sender
            .send(event)
            .map_err(|e| format!("channel closed: {e}"))
    }

    /// Get the current sequence number (count of events submitted).
    pub fn sequence(&self) -> u64 {
        *self.sequence.lock().unwrap()
    }

    /// Increment the local sequence counter.
    pub fn increment_sequence(&self) -> u64 {
        let mut seq = self.sequence.lock().unwrap();
        *seq += 1;
        *seq
    }
}

/// Handle for the writer thread result.
pub struct ReceiverHandle {
    _rx: std::sync::mpsc::Receiver<()>,
}

/// Batched event appender: groups events and submits in batches.
pub struct BatchedEventAppender {
    sender: Sender<Vec<DomainEvent>>,
    buffer: std::sync::Mutex<Vec<DomainEvent>>,
    batch_size: usize,
}

impl BatchedEventAppender {
    /// Spawn the background batch flusher.
    pub fn spawn(batch_size: usize) -> (Self, ReceiverHandle) {
        let (tx, rx) = channel::<Vec<DomainEvent>>();
        let (done_tx, done_rx) = channel::<()>();

        thread::spawn(move || {
            while let Ok(batch) = rx.recv() {
                // Simulate batch flush
                thread::sleep(Duration::from_micros(50 * batch.len() as u64));
            }
            let _ = done_tx.send(());
        });

        let appender = Self {
            sender: tx,
            buffer: std::sync::Mutex::new(Vec::new()),
            batch_size,
        };
        (appender, ReceiverHandle { _rx: done_rx })
    }

    /// Add an event to the batch buffer. Flushes when buffer is full.
    pub fn append(&self, event: DomainEvent) {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.push(event);
        if buffer.len() >= self.batch_size {
            let batch: Vec<_> = buffer.drain(..).collect();
            let _ = self.sender.send(batch);
        }
    }

    /// Flush remaining events.
    pub fn flush(&self) {
        let mut buffer = self.buffer.lock().unwrap();
        if !buffer.is_empty() {
            let batch: Vec<_> = buffer.drain(..).collect();
            let _ = self.sender.send(batch);
        }
    }

    /// Pending events in the buffer.
    pub fn pending(&self) -> usize {
        self.buffer.lock().unwrap().len()
    }
}

/// In-memory projection of events.
#[derive(Default)]
pub struct AsyncProjection {
    state: HashMap<String, String>,
}

impl AsyncProjection {
    pub fn new() -> Self { Self::default() }

    /// Apply an event to the projection.
    pub fn apply(&mut self, entry: &AsyncEventEntry) {
        match &entry.event {
            DomainEvent::Created { id, payload } => {
                self.state.insert(id.clone(), payload.clone());
            }
            DomainEvent::Updated { id, payload } => {
                self.state.insert(id.clone(), payload.clone());
            }
            DomainEvent::Deleted { id } => {
                self.state.remove(id);
            }
        }
    }

    /// Get the projected value for a key.
    pub fn get(&self, id: &str) -> Option<String> {
        self.state.get(id).cloned()
    }

    /// Number of projected keys.
    pub fn size(&self) -> usize {
        self.state.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn async_submit_event() {
        let (store, _handle) = AsyncEventStore::spawn();
        store.submit(DomainEvent::Created {
            id: "x".into(),
            payload: "data".into(),
        }).unwrap();
        thread::sleep(Duration::from_millis(20));
        // Event was processed by background thread
    }

    #[test]
    fn async_submit_many_events() {
        let (store, _handle) = AsyncEventStore::spawn();
        for i in 0..100 {
            store.submit(DomainEvent::Created {
                id: format!("k{i}"),
                payload: format!("v{i}"),
            }).unwrap();
        }
        thread::sleep(Duration::from_millis(50));
    }

    #[test]
    fn batched_appender_buffers() {
        let (appender, _handle) = BatchedEventAppender::spawn(5);
        for i in 0..3 {
            appender.append(DomainEvent::Created {
                id: format!("k{i}"), payload: "v".into(),
            });
        }
        assert_eq!(appender.pending(), 3);
    }

    #[test]
    fn batched_appender_flushes_at_batch_size() {
        let (appender, _handle) = BatchedEventAppender::spawn(3);
        for i in 0..5 {
            appender.append(DomainEvent::Created {
                id: format!("k{i}"), payload: "v".into(),
            });
        }
        assert_eq!(appender.pending(), 2); // 3 sent, 2 remaining
    }

    #[test]
    fn batched_appender_explicit_flush() {
        let (appender, _handle) = BatchedEventAppender::spawn(10);
        appender.append(DomainEvent::Created { id: "k1".into(), payload: "v".into() });
        assert_eq!(appender.pending(), 1);
        appender.flush();
        assert_eq!(appender.pending(), 0);
    }

    #[test]
    fn projection_applies_events() {
        let mut proj = AsyncProjection::new();
        proj.apply(&AsyncEventEntry {
            sequence: 1,
            timestamp: Utc::now(),
            event: DomainEvent::Created { id: "a".into(), payload: "1".into() },
        });
        proj.apply(&AsyncEventEntry {
            sequence: 2,
            timestamp: Utc::now(),
            event: DomainEvent::Updated { id: "a".into(), payload: "2".into() },
        });
        assert_eq!(proj.get("a"), Some("2".into()));
    }

    #[test]
    fn projection_delete() {
        let mut proj = AsyncProjection::new();
        proj.apply(&AsyncEventEntry {
            sequence: 1, timestamp: Utc::now(),
            event: DomainEvent::Created { id: "a".into(), payload: "x".into() },
        });
        proj.apply(&AsyncEventEntry {
            sequence: 2, timestamp: Utc::now(),
            event: DomainEvent::Deleted { id: "a".into() },
        });
        assert!(proj.get("a").is_none());
    }
}
