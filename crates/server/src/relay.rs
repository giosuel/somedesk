//! Blind relay. Pairs the two streams of a session and copies bytes between them. Everything
//! after the `RelayJoin` header is Noise ciphertext the server cannot read.

use crate::{RelayTap, Shared};
use quinn::{RecvStream, SendStream};
use somedesk_proto::control::{RelayJoin, SessionId};
use somedesk_proto::frame::read_msg;
use std::time::{Duration, Instant};

/// How long the first party waits for the second one to join.
const PENDING_TTL: Duration = Duration::from_secs(60);

pub struct PendingSession {
    pub viewer: u64,
    pub host: u64,
    pub created: Instant,
    waiting: Option<(u64, SendStream, RecvStream)>,
}

impl PendingSession {
    pub fn new(viewer: u64, host: u64) -> Self {
        Self { viewer, host, created: Instant::now(), waiting: None }
    }
}

pub fn expire_pending(shared: &Shared) {
    shared.sessions.lock().unwrap().retain(|_, p| p.created.elapsed() < PENDING_TTL);
}

/// Handles a non-control stream opened by an authenticated device.
pub async fn handle_stream(shared: &Shared, device_id: Option<u64>, send: SendStream, mut recv: RecvStream) {
    let Some(device_id) = device_id else { return };
    let join: RelayJoin = match tokio::time::timeout(Duration::from_secs(10), read_msg(&mut recv)).await {
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
                p.waiting = Some((device_id, send, recv));
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
    let ((_, a_send, a_recv), (b_send, b_recv)) = pair;
    let tap = shared.relay_tap.clone();
    let (ab, ba) = tokio::join!(pump(a_recv, b_send, tap.clone()), pump(b_recv, a_send, tap));
    tracing::info!(bytes_a_to_b = ab, bytes_b_to_a = ba, "relay session ended");
}

async fn pump(mut from: RecvStream, mut to: SendStream, tap: Option<RelayTap>) -> u64 {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    while let Ok(Some(n)) = from.read(&mut buf).await {
        if let Some(tap) = &tap {
            tap(&buf[..n]);
        }
        if to.write_all(&buf[..n]).await.is_err() {
            break;
        }
        total += n as u64;
    }
    let _ = to.finish();
    total
}

pub fn new_session_id() -> SessionId {
    use rand::RngCore;
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}
