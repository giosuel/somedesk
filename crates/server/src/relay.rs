//! Blind relay. Pairs the two streams of a session and copies bytes between them. Everything
//! after the `RelayJoin` header is Noise ciphertext the server cannot read.

use crate::ratelimit::{ip_key, Slot};
use crate::{RelayTap, Shared};
use quinn::{RecvStream, SendStream};
use somedesk_proto::control::{RelayJoin, SessionId};
use somedesk_proto::frame::read_msg_limited;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// How long the first party waits for the second one to join.
const PENDING_TTL: Duration = Duration::from_secs(60);
/// A `RelayJoin` is a session ID; nothing near this size.
const MAX_JOIN: usize = 256;

pub struct PendingSession {
    pub viewer: u64,
    pub host: u64,
    pub created: Instant,
    /// The side that joined first: its device, address and streams.
    waiting: Option<(u64, IpAddr, SendStream, RecvStream)>,
}

impl PendingSession {
    pub fn new(viewer: u64, host: u64) -> Self {
        Self { viewer, host, created: Instant::now(), waiting: None }
    }
}

pub fn expire_pending(shared: &Shared) {
    shared.sessions.lock().unwrap().retain(|_, p| p.created.elapsed() < PENDING_TTL);
}

/// Handles a non-control stream opened by an authenticated device, from `ip`.
pub async fn handle_stream(
    shared: &Shared,
    device_id: Option<u64>,
    ip: IpAddr,
    send: SendStream,
    mut recv: RecvStream,
) {
    let Some(device_id) = device_id else { return };
    let join: RelayJoin =
        match tokio::time::timeout(Duration::from_secs(10), read_msg_limited(&mut recv, MAX_JOIN)).await {
            Ok(Ok(Some(j))) => j,
            _ => return,
        };
    let pair = {
        let mut sessions = shared.sessions.lock().unwrap();
        let Some(p) = sessions.get_mut(&join.session_id) else {
            tracing::debug!("relay join for unknown session");
            return;
        };
        if device_id != p.viewer && device_id != p.host {
            tracing::warn!(device_id, "device tried to join a session it is not part of");
            return;
        }
        match p.waiting.take() {
            None => {
                p.waiting = Some((device_id, ip, send, recv));
                return;
            }
            Some(first) if first.0 == device_id => {
                // Same side joined twice; keep the first stream.
                p.waiting = Some(first);
                return;
            }
            Some(first) => {
                let p = sessions.remove(&join.session_id).expect("present");
                tracing::info!(viewer = p.viewer, host = p.host, "relay session established");
                (first, (send, recv))
            }
        }
    };
    let ((first_device, first_ip, a_send, a_recv), (b_send, b_recv)) = pair;
    let Some(_slots) = take_slots(shared, [(first_device, first_ip), (device_id, ip)]) else {
        tracing::info!(device_id, "too many relay sessions at once; turning one away");
        return;
    };
    let tap = shared.relay_tap.clone();
    let rate = shared.limits.relay_bytes_per_sec;
    let (ab, ba) = tokio::join!(pump(a_recv, b_send, tap.clone(), rate), pump(b_recv, a_send, tap, rate));
    tracing::info!(bytes_a_to_b = ab, bytes_b_to_a = ba, "relay session ended");
}

/// The relay slots of both sides (per device and per address), or `None` if one has too many.
fn take_slots(shared: &Shared, sides: [(u64, IpAddr); 2]) -> Option<Vec<Slot>> {
    let limits = &shared.limits;
    let mut slots = Vec::new();
    for (device, _) in sides {
        slots.push(shared.relay_slots.take(&format!("device:{device}"), limits.relay_sessions_per_device)?);
    }
    let [(_, a), (_, b)] = sides.map(|(d, ip)| (d, ip_key(ip)));
    slots.push(shared.relay_slots.take(&format!("ip:{a}"), limits.relay_sessions_per_ip)?);
    if a != b {
        slots.push(shared.relay_slots.take(&format!("ip:{b}"), limits.relay_sessions_per_ip)?);
    }
    Some(slots)
}

/// Copies one direction of a session, at most `rate` bytes per second on average (with a few
/// seconds' worth of burst, so a screen change goes through at once).
async fn pump(mut from: RecvStream, mut to: SendStream, tap: Option<RelayTap>, rate: u64) -> u64 {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    let mut budget = Budget::new(rate);
    while let Ok(Some(n)) = from.read(&mut buf).await {
        if let Some(tap) = &tap {
            tap(&buf[..n]);
        }
        if to.write_all(&buf[..n]).await.is_err() {
            break;
        }
        total += n as u64;
        if let Some(wait) = budget.spend(n as u64) {
            tokio::time::sleep(wait).await;
        }
    }
    let _ = to.finish();
    total
}

/// A token bucket: `rate` bytes per second, up to [`BURST_SECS`] seconds' worth saved up.
struct Budget {
    rate: u64,
    tokens: f64,
    last: Instant,
}

const BURST_SECS: f64 = 4.0;

impl Budget {
    fn new(rate: u64) -> Self {
        Self { rate, tokens: rate as f64 * BURST_SECS, last: Instant::now() }
    }

    /// Takes `n` bytes; how long to wait before the next ones, if the budget is used up.
    fn spend(&mut self, n: u64) -> Option<Duration> {
        if self.rate == 0 {
            return None;
        }
        let now = Instant::now();
        let rate = self.rate as f64;
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * rate).min(rate * BURST_SECS);
        self.last = now;
        self.tokens -= n as f64;
        (self.tokens < 0.0).then(|| Duration::from_secs_f64(-self.tokens / rate))
    }
}

pub fn new_session_id() -> SessionId {
    use rand::RngCore;
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_allows_a_burst_then_the_rate() {
        let mut b = Budget::new(1000);
        assert_eq!(b.spend(4000), None, "a burst of a few seconds");
        let wait = b.spend(500).unwrap();
        assert!(wait > Duration::from_millis(450) && wait <= Duration::from_millis(500), "{wait:?}");
        assert_eq!(Budget::new(0).spend(u64::MAX / 2), None, "0: no limit");
    }
}
