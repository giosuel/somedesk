//! Fixed-window rate limiting for authentication attempts.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    /// Records one attempt for `key`; returns `false` if more than `limit` happened this window.
    pub fn allow(&self, key: &str, limit: u32) -> bool {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap();
        let entry = map.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= limit
    }

    pub fn cleanup(&self) {
        let now = Instant::now();
        self.buckets.lock().unwrap().retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_key() {
        let rl = RateLimiter::default();
        for _ in 0..3 {
            assert!(rl.allow("a", 3));
        }
        assert!(!rl.allow("a", 3));
        assert!(rl.allow("b", 3));
    }
}
