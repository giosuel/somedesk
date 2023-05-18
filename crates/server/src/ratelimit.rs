//! Abuse limits: fixed-window rate limits, growing waits after failed attempts, and caps on how
//! many of something one client holds at a time.
//!
//! Limits are keyed on what the client controls (its address, its connection, its device), never
//! on something public like a username or a device key alone: otherwise anyone could use up a
//! victim's allowance and lock them out.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);
/// Most keys a limit keeps track of at once, so many addresses can't grow it without end. When
/// it is full, expired keys are dropped; if none are, new keys are refused until some expire.
const MAX_KEYS: usize = 200_000;

/// The address a limit counts for. IPv6 users get a whole /64 (often more), so it counts as one.
pub fn ip_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

pub struct RateLimiter {
    buckets: Mutex<HashMap<String, (Instant, u32)>>,
    max_keys: usize,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self { buckets: Mutex::default(), max_keys: MAX_KEYS }
    }
}

impl RateLimiter {
    /// Records one attempt for `key`; returns `false` if more than `limit` happened this window.
    pub fn allow(&self, key: &str, limit: u32) -> bool {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap();
        if map.len() >= self.max_keys && !map.contains_key(key) {
            map.retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
            if map.len() >= self.max_keys {
                return false;
            }
        }
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

const FIRST_WAIT: Duration = Duration::from_secs(30);
const MAX_WAIT: Duration = Duration::from_secs(3600);
/// A key without a wrong attempt for this long starts afresh.
const FORGET_AFTER: Duration = Duration::from_secs(6 * 3600);

struct Failures {
    count: u32,
    last: Instant,
    until: Option<Instant>,
}

/// Waits that grow with every wrong attempt (a password, a code): a few are free, then 30 s,
/// doubling up to an hour. Only failures count, so a key can't be locked by attempts that
/// succeed, and nothing is spent by merely starting one.
pub struct Backoff {
    keys: Mutex<HashMap<String, Failures>>,
    max_keys: usize,
}

impl Default for Backoff {
    fn default() -> Self {
        Self { keys: Mutex::default(), max_keys: MAX_KEYS }
    }
}

impl Backoff {
    /// How long `key` still has to wait, if it does.
    pub fn wait(&self, key: &str) -> Option<Duration> {
        let now = Instant::now();
        let map = self.keys.lock().unwrap();
        map.get(key).and_then(|f| f.until).and_then(|u| u.checked_duration_since(now)).filter(|d| !d.is_zero())
    }

    /// Records a wrong attempt for `key`, which waits once more than `free` happened.
    pub fn fail(&self, key: &str, free: u32) {
        let now = Instant::now();
        let mut map = self.keys.lock().unwrap();
        if map.len() >= self.max_keys && !map.contains_key(key) {
            // Keys that aren't waiting only lose their few free attempts; waiting ones stay.
            map.retain(|_, f| f.until.is_some_and(|u| u > now));
            if map.len() >= self.max_keys {
                tracing::warn!("too many keys with wrong attempts; not counting a new one");
                return;
            }
        }
        let f = map.entry(key.to_owned()).or_insert(Failures { count: 0, last: now, until: None });
        if now.duration_since(f.last) > FORGET_AFTER {
            f.count = 0;
        }
        f.count += 1;
        f.last = now;
        if f.count > free {
            let wait = (FIRST_WAIT * 2u32.saturating_pow((f.count - free - 1).min(16))).min(MAX_WAIT);
            f.until = Some(now + wait);
        }
    }

    /// A right attempt: `key` starts afresh.
    pub fn succeed(&self, key: &str) {
        self.keys.lock().unwrap().remove(key);
    }

    pub fn cleanup(&self) {
        let now = Instant::now();
        self.keys.lock().unwrap().retain(|_, f| now.duration_since(f.last) <= FORGET_AFTER);
    }
}

/// Counts what is held at the moment (connections, relay sessions) per key.
#[derive(Default, Clone)]
pub struct Slots {
    held: Arc<Mutex<HashMap<String, u32>>>,
}

/// One held slot; dropping it gives it back.
pub struct Slot {
    held: Arc<Mutex<HashMap<String, u32>>>,
    key: String,
}

impl Slots {
    /// Takes a slot for `key` if fewer than `max` are held.
    pub fn take(&self, key: &str, max: u32) -> Option<Slot> {
        let mut held = self.held.lock().unwrap();
        let n = held.entry(key.to_owned()).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(Slot { held: self.held.clone(), key: key.to_owned() })
    }

    #[cfg(test)]
    fn count(&self, key: &str) -> u32 {
        self.held.lock().unwrap().get(key).copied().unwrap_or(0)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut held = self.held.lock().unwrap();
        if let Some(n) = held.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                held.remove(&self.key);
            }
        }
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

    #[test]
    fn the_number_of_keys_is_bounded() {
        let rl = RateLimiter { max_keys: 3, ..RateLimiter::default() };
        for k in ["a", "b", "c"] {
            assert!(rl.allow(k, 10));
        }
        assert!(!rl.allow("d", 10), "full of keys still in their window");
        assert!(rl.allow("a", 10), "known keys go on counting");
        assert_eq!(rl.buckets.lock().unwrap().len(), 3);
        rl.buckets.lock().unwrap().get_mut("b").unwrap().0 -= WINDOW;
        assert!(rl.allow("d", 10), "an expired key makes room");

        let b = Backoff { max_keys: 2, ..Backoff::default() };
        for _ in 0..6 {
            b.fail("waiting", 5);
        }
        b.fail("typo", 5);
        b.fail("new", 5);
        let keys = b.keys.lock().unwrap();
        assert!(keys.contains_key("waiting") && keys.contains_key("new") && !keys.contains_key("typo"));
    }

    #[test]
    fn ipv6_counts_per_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(ip_key(a), ip_key(b));
        assert_ne!(ip_key(a), ip_key(c));
        assert_eq!(ip_key("::ffff:192.0.2.7".parse().unwrap()), "192.0.2.7");
        assert_eq!(ip_key("192.0.2.7".parse().unwrap()), "192.0.2.7");
    }

    #[test]
    fn failures_wait_longer_and_longer() {
        let b = Backoff::default();
        for _ in 0..5 {
            b.fail("alice", 5);
        }
        assert_eq!(b.wait("alice"), None, "a few typos are free");
        b.fail("alice", 5);
        let first = b.wait("alice").unwrap();
        assert!(first <= FIRST_WAIT && first > FIRST_WAIT - Duration::from_secs(2));
        b.fail("alice", 5);
        assert!(b.wait("alice").unwrap() > FIRST_WAIT, "doubles");
        for _ in 0..40 {
            b.fail("alice", 5);
        }
        assert!(b.wait("alice").unwrap() <= MAX_WAIT);
        assert_eq!(b.wait("bob"), None, "per key");
        b.succeed("alice");
        assert_eq!(b.wait("alice"), None, "a right attempt starts afresh");
    }

    #[test]
    fn slots_are_given_back() {
        let s = Slots::default();
        let a = s.take("ip", 2).unwrap();
        let b = s.take("ip", 2).unwrap();
        assert!(s.take("ip", 2).is_none());
        drop(a);
        assert_eq!(s.count("ip"), 1);
        let _c = s.take("ip", 2).unwrap();
        drop(b);
        assert!(s.take("other", 2).is_some());
    }
}
