//! Setting up the end-to-end encrypted channel to another device through the relay.

use crate::credentials::DeviceCredentials;
use crate::server::ServerConn;
use crate::{ClientError, Result};
use somedesk_crypto::channel::{self, Handshaked};
use somedesk_proto::control::{DeviceInfo, SessionId};
use std::time::Duration;

pub type Channel = Handshaked<quinn::RecvStream, quinn::SendStream>;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

fn prologue(session_id: &SessionId) -> Vec<u8> {
    [b"somedesk session v1".as_slice(), session_id].concat()
}

/// Viewer side: asks the server for a session to `device_id` and runs the Noise handshake.
/// The returned channel's `peer` is the host's verified certificate.
pub async fn connect(conn: &ServerConn, creds: &DeviceCredentials, device_id: u64) -> Result<(Channel, DeviceInfo)> {
    let (session_id, host) = conn.request_session(device_id).await?;
    let (send, recv) = conn.open_relay(session_id).await?;
    let (prologue, key) = (prologue(&session_id), creds.device_key());
    let fut = channel::initiate(recv, send, &prologue, &key, &creds.cert, Some(&host.cert.device_pk));
    let ch = tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| ClientError::Other("the remote device did not answer".into()))??;
    Ok((ch, host))
}

/// Host side: joins the relay for an incoming session and runs the Noise handshake.
pub async fn accept(
    conn: &ServerConn,
    creds: &DeviceCredentials,
    session_id: SessionId,
    from: &DeviceInfo,
) -> Result<Channel> {
    let (send, recv) = conn.open_relay(session_id).await?;
    let (prologue, key) = (prologue(&session_id), creds.device_key());
    let fut = channel::respond(recv, send, &prologue, &key, &creds.cert, Some(&from.cert.device_pk));
    Ok(tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| ClientError::Other("the remote device did not complete the handshake".into()))??)
}
