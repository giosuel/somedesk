//! Setting up the end-to-end encrypted channel to another device: directly when possible,
//! otherwise through the server's relay.
//!
//! The viewer decides the path: it tries direct connections (its own dials to the host's
//! candidates, and the host's dials to it) for a short while and falls back to the relay. The
//! host listens on every path at once and answers the Noise handshake on whichever one the
//! viewer's first message arrives on. Either way the channel is the same Noise session.

use crate::credentials::DeviceCredentials;
use crate::direct::StreamPair;
use crate::server::ServerConn;
use crate::{ClientError, Result};
use futures_util::stream::{FuturesUnordered, StreamExt};
use somedesk_crypto::channel::{self, Handshaked};
use somedesk_proto::control::{DeviceInfo, SessionId};
use std::net::SocketAddr;
use std::time::Duration;

pub type Channel = Handshaked<quinn::RecvStream, quinn::SendStream>;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the viewer tries direct paths before using the relay.
pub const DIRECT_WINDOW: Duration = Duration::from_millis(2500);

/// Which path a session's traffic takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// A QUIC connection straight between the two devices.
    Direct,
    /// Through the server's relay.
    Relay,
}

/// Ends our half of a session stream and waits (briefly) until the peer has received
/// everything. A direct connection closes as soon as its last stream is dropped, and closing
/// discards data still in flight, such as a final `Reject` or `Bye`.
pub async fn finish_stream(mut send: quinn::SendStream) {
    if send.finish().is_ok() {
        let _ = tokio::time::timeout(Duration::from_secs(2), send.stopped()).await;
    }
}

fn prologue(session_id: &SessionId) -> Vec<u8> {
    [b"somedesk session v1".as_slice(), session_id].concat()
}

/// Viewer side: asks the server for a session to `device_id` and runs the Noise handshake.
/// The returned channel's `peer` is the host's verified certificate.
pub async fn connect(conn: &ServerConn, creds: &DeviceCredentials, device_id: u64) -> Result<(Channel, DeviceInfo)> {
    connect_routed(conn, creds, device_id).await.map(|(ch, host, _)| (ch, host))
}

/// [`connect`], also reporting which path the session uses.
pub async fn connect_routed(
    conn: &ServerConn,
    creds: &DeviceCredentials,
    device_id: u64,
) -> Result<(Channel, DeviceInfo, Route)> {
    let (session_id, host, candidates) = conn.request_session(device_id).await?;
    let (prologue, key) = (prologue(&session_id), creds.device_key());

    if !candidates.is_empty() && conn.direct().allowed() {
        if let Some((send, recv)) = find_direct_path(conn, session_id, &candidates).await {
            let fut = channel::initiate(recv, send, &prologue, &key, &creds.cert, Some(&host.cert.device_pk));
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, fut).await {
                Ok(Ok(ch)) => {
                    tracing::info!(device_id, "direct connection established");
                    return Ok((ch, host, Route::Direct));
                }
                Ok(Err(e)) => tracing::warn!("handshake over the direct path failed, using the relay: {e}"),
                Err(_) => tracing::warn!("handshake over the direct path timed out, using the relay"),
            }
        }
    }

    let (send, recv) = conn.open_relay(session_id).await?;
    let fut = channel::initiate(recv, send, &prologue, &key, &creds.cert, Some(&host.cert.device_pk));
    let ch = tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| ClientError::Other("the remote device did not answer".into()))??;
    Ok((ch, host, Route::Relay))
}

/// The first direct stream for `session_id` within [`DIRECT_WINDOW`]: one we dial, or one the
/// peer dials to us.
async fn find_direct_path(conn: &ServerConn, session_id: SessionId, candidates: &[SocketAddr]) -> Option<StreamPair> {
    let mut inbound = conn.direct().wait_for(session_id);
    conn.direct().punch(candidates).await;
    let mut dials: FuturesUnordered<_> = candidates.iter().map(|a| conn.direct().dial(*a, session_id)).collect();
    let search = async {
        loop {
            tokio::select! {
                Some(pair) = inbound.next() => return pair,
                Some(result) = dials.next(), if !dials.is_empty() => {
                    if let Ok(pair) = result {
                        return pair;
                    }
                }
            }
        }
    };
    tokio::time::timeout(DIRECT_WINDOW, search).await.ok()
}

/// Host side: joins the session and runs the Noise handshake on whichever path the viewer uses.
/// `candidates` are the viewer's direct-connection addresses from the server.
pub async fn accept(
    conn: &ServerConn,
    creds: &DeviceCredentials,
    session_id: SessionId,
    from: &DeviceInfo,
    candidates: &[SocketAddr],
) -> Result<Channel> {
    accept_routed(conn, creds, session_id, from, candidates).await.map(|(ch, _)| ch)
}

/// [`accept`], also reporting which path the session uses.
pub async fn accept_routed(
    conn: &ServerConn,
    creds: &DeviceCredentials,
    session_id: SessionId,
    from: &DeviceInfo,
    candidates: &[SocketAddr],
) -> Result<(Channel, Route)> {
    let (prologue, key) = (prologue(&session_id), creds.device_key());
    let direct = !candidates.is_empty() && conn.direct().allowed();
    let mut inbound = direct.then(|| conn.direct().wait_for(session_id));
    if direct {
        conn.direct().punch(candidates).await;
    }
    // Dialling the viewer opens our side of any NAT for its dials; if one gets through, the
    // viewer may also pick that stream.
    let mut dials: FuturesUnordered<_> = if direct {
        candidates.iter().map(|a| conn.direct().dial(*a, session_id)).collect()
    } else {
        FuturesUnordered::new()
    };

    let respond = |pair: StreamPair, route: Route| {
        let (prologue, key, cert) = (prologue.clone(), key.clone(), creds.cert.clone());
        let expected = from.cert.device_pk;
        async move {
            let (send, recv) = pair;
            (route, channel::respond(recv, send, &prologue, &key, &cert, Some(&expected)).await)
        }
    };
    let mut handshakes = FuturesUnordered::new();
    handshakes.push(respond(conn.open_relay(session_id).await?, Route::Relay));

    let deadline = tokio::time::sleep(HANDSHAKE_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            Some(pair) = async { match inbound.as_mut() { Some(w) => w.next().await, None => None } } => {
                handshakes.push(respond(pair, Route::Direct));
            }
            Some(result) = dials.next(), if !dials.is_empty() => {
                if let Ok(pair) = result {
                    handshakes.push(respond(pair, Route::Direct));
                }
            }
            Some((route, result)) = handshakes.next(), if !handshakes.is_empty() => match result {
                Ok(ch) => {
                    tracing::info!(?route, "session channel established");
                    return Ok((ch, route));
                }
                Err(e) => tracing::debug!(?route, "handshake on a path failed: {e}"),
            },
            _ = &mut deadline => {
                return Err(ClientError::Other("the remote device did not complete the handshake".into()));
            }
        }
    }
}
