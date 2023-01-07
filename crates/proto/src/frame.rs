//! Length-prefixed framing: `u32 big-endian length || payload`.

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound for a single frame. Protects against memory exhaustion by a malicious peer.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame of {0} bytes exceeds the limit")]
    TooLarge(usize),
    #[error("malformed message: {0}")]
    Decode(#[from] postcard::Error),
}

/// Writes one raw frame.
pub async fn write_raw<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<(), FrameError> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    w.write_all(&buf).await?;
    Ok(())
}

/// Reads one raw frame. Returns `Ok(None)` on a clean end of stream before a frame starts.
pub async fn read_raw<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Serializes `msg` with postcard and writes it as one frame.
pub async fn write_msg<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<(), FrameError> {
    let bytes = postcard::to_stdvec(msg)?;
    write_raw(w, &bytes).await
}

/// Reads one frame and deserializes it. Returns `Ok(None)` on clean end of stream.
pub async fn read_msg<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<Option<T>, FrameError> {
    match read_raw(r).await? {
        Some(bytes) => Ok(Some(postcard::from_bytes(&bytes)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{ClientFrame, Request};

    #[tokio::test]
    async fn message_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let sent = ClientFrame { id: 7, req: Request::LookupDevice { device_id: 123456789 } };
        write_msg(&mut a, &sent).await.unwrap();
        let got: ClientFrame = read_msg(&mut b).await.unwrap().unwrap();
        assert_eq!(got.id, 7);
        assert!(matches!(got.req, Request::LookupDevice { device_id: 123456789 }));
    }

    #[tokio::test]
    async fn clean_eof_is_none() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        let got: Option<ClientFrame> = read_msg(&mut b).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn oversized_length_is_rejected_without_allocating() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        assert!(matches!(read_raw(&mut b).await, Err(FrameError::TooLarge(_))));
    }

    #[tokio::test]
    async fn garbage_payload_is_a_decode_error() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_raw(&mut a, &[0xff, 0xff, 0xff, 0xff, 0xff]).await.unwrap();
        let res: Result<Option<ClientFrame>, _> = read_msg(&mut b).await;
        assert!(matches!(res, Err(FrameError::Decode(_))));
    }
}
