//! Request coalescing — merge duplicate concurrent requests.

use std::collections::HashMap;
use std::sync::Mutex;

pub struct RequestCoalescer<T: Clone + Send + Sync + 'static> {
    pending: Mutex<HashMap<String, CoalescedRequest<T>>>,
}

struct CoalescedRequest<T> {
    waiters: usize,
    result: Option<T>,
}

impl<T: Clone + Send + Sync + 'static> RequestCoalescer<T> {
    pub fn new() -> Self {
        Self { pending: Mutex::new(HashMap::new()) }
    }

    pub fn begin(&self, key: &str) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if let Some(req) = pending.get_mut(key) {
            req.waiters += 1;
            false // already in progress
        } else {
            pending.insert(key.into(), CoalescedRequest { waiters: 1, result: None });
            true // this caller should execute
        }
    }

    pub fn complete(&self, key: &str, result: T) {
        let mut pending = self.pending.lock().unwrap();
        if let Some(req) = pending.get_mut(key) {
            req.result = Some(result);
        }
    }

    pub fn collect_result(&self, key: &str) -> Option<T> {
        let mut pending = self.pending.lock().unwrap();
        if let Some(req) = pending.get_mut(key) {
            if let Some(ref result) = req.result {
                req.waiters -= 1;
                if req.waiters == 0 {
                    return pending.remove(key).and_then(|r| r.result);
                }
                return Some(result.clone());
            }
        }
        None
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    pub fn waiters_for(&self, key: &str) -> usize {
        self.pending.lock().unwrap().get(key).map(|r| r.waiters).unwrap_or(0)
    }
}

impl<T: Clone + Send + Sync + 'static> Default for RequestCoalescer<T> {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_begins() {
        let coal = RequestCoalescer::<String>::new();
        assert!(coal.begin("key1"));
    }

    #[test]
    fn second_call_coalesced() {
        let coal = RequestCoalescer::<String>::new();
        assert!(coal.begin("key1"));
        assert!(!coal.begin("key1"));
    }

    #[test]
    fn different_keys_independent() {
        let coal = RequestCoalescer::<String>::new();
        assert!(coal.begin("key1"));
        assert!(coal.begin("key2"));
        assert_eq!(coal.pending_count(), 2);
    }

    #[test]
    fn complete_and_collect() {
        let coal = RequestCoalescer::<String>::new();
        coal.begin("k1");
        coal.complete("k1", "result".into());
        let result = coal.collect_result("k1");
        assert_eq!(result, Some("result".into()));
    }

    #[test]
    fn multiple_waiters_share_result() {
        let coal = RequestCoalescer::<String>::new();
        coal.begin("k1");
        coal.begin("k1"); // waiter 2
        coal.begin("k1"); // waiter 3
        assert_eq!(coal.waiters_for("k1"), 3);
        coal.complete("k1", "shared".into());
        let r1 = coal.collect_result("k1");
        let r2 = coal.collect_result("k1");
        let r3 = coal.collect_result("k1");
        assert_eq!(r1, Some("shared".into()));
        assert_eq!(r2, Some("shared".into()));
        assert_eq!(r3, Some("shared".into()));
        assert_eq!(coal.pending_count(), 0);
    }

    #[test]
    fn collect_without_complete_returns_none() {
        let coal = RequestCoalescer::<String>::new();
        coal.begin("k1");
        assert!(coal.collect_result("k1").is_none());
    }
}
