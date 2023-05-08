//! Length-prefixed framing: `u32 big-endian length || payload`.

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound for a single frame. Protects against memory exhaustion by a malicious peer.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// How much of a frame's announced length is reserved before its bytes arrive.
const READ_CHUNK: usize = 64 * 1024;

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
    read_raw_limited(r, MAX_FRAME_LEN).await
}

/// [`read_raw`] for frames of at most `max` bytes, for streams where nothing larger is expected
/// (a relay's join header, a connection that hasn't signed in yet). The buffer grows as the
/// bytes arrive, so a length alone reserves no memory.
pub async fn read_raw_limited<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < len.len() {
        match r.read(&mut len[got..]).await? {
            0 if got == 0 => return Ok(None),
            // The stream ended inside a header: cut off, not closed.
            0 => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()),
            n => got += n,
        }
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > max.min(MAX_FRAME_LEN) {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = Vec::with_capacity(len.min(READ_CHUNK));
    r.take(len as u64).read_to_end(&mut buf).await?;
    if buf.len() != len {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }
    Ok(Some(buf))
}

/// Serializes `msg` with postcard and writes it as one frame.
pub async fn write_msg<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<(), FrameError> {
    let bytes = postcard::to_stdvec(msg)?;
    write_raw(w, &bytes).await
}

/// Reads one frame and deserializes it. Returns `Ok(None)` on clean end of stream.
pub async fn read_msg<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<Option<T>, FrameError> {
    read_msg_limited(r, MAX_FRAME_LEN).await
}

/// [`read_msg`] for frames of at most `max` bytes.
pub async fn read_msg_limited<R: AsyncRead + Unpin, T: DeserializeOwned>(
    r: &mut R,
    max: usize,
) -> Result<Option<T>, FrameError> {
    match read_raw_limited(r, max).await? {
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
    async fn a_cut_off_header_is_an_error_not_a_clean_end() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0, 0]).await.unwrap();
        drop(a);
        assert!(matches!(read_raw(&mut b).await, Err(FrameError::Io(_))));
    }

    #[tokio::test]
    async fn a_cut_off_payload_is_an_error() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&10u32.to_be_bytes()).await.unwrap();
        a.write_all(&[1, 2, 3]).await.unwrap();
        drop(a);
        assert!(matches!(read_raw(&mut b).await, Err(FrameError::Io(_))));
    }

    #[tokio::test]
    async fn limited_reads_reject_larger_frames() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_raw(&mut a, &[7; 100]).await.unwrap();
        write_raw(&mut a, &[7; 10]).await.unwrap();
        assert!(matches!(read_raw_limited(&mut b, 64).await, Err(FrameError::TooLarge(100))));
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_raw(&mut a, &[7; 10]).await.unwrap();
        assert_eq!(read_raw_limited(&mut b, 64).await.unwrap().unwrap(), vec![7; 10]);
    }

    #[tokio::test]
    async fn large_frames_arrive_in_pieces() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let payload: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
        let sent = payload.clone();
        let writer = tokio::spawn(async move { write_raw(&mut a, &sent).await.unwrap() });
        assert_eq!(read_raw(&mut b).await.unwrap().unwrap(), payload);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn garbage_payload_is_a_decode_error() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_raw(&mut a, &[0xff, 0xff, 0xff, 0xff, 0xff]).await.unwrap();
        let res: Result<Option<ClientFrame>, _> = read_msg(&mut b).await;
        assert!(matches!(res, Err(FrameError::Decode(_))));
    }
}
