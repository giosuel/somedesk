//! End-to-end encrypted channel between two devices (Noise XX).
//!
//! Handshake (`Noise_XX_25519_ChaChaPoly_BLAKE2s`):
//!
//! ```text
//!   -> e
//!   <- e, ee, s, es   + responder's DeviceCert (encrypted)
//!   -> s, se          + initiator's DeviceCert (encrypted)
//! ```
//!
//! Each side checks that the peer's certificate is validly signed and certifies exactly the
//! static key the peer proved possession of. Ephemeral keys give forward secrecy. The relay
//! between the two sides only ever sees handshake messages and ciphertext.
//!
//! Application messages are serialized with postcard and split into chunks that fit a Noise
//! message (≤ 65535 bytes). The first plaintext byte of every chunk is 1 if more chunks of the
//! same message follow, 0 otherwise.

use crate::keys::{verify_device_cert, DeviceKey};
use serde::{de::DeserializeOwned, Serialize};
use snow::{Builder, StatelessTransportState};
use somedesk_proto::control::DeviceCert;
use somedesk_proto::frame::{read_raw, write_raw, FrameError};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const NOISE_MAX: usize = 65535;
const TAG_LEN: usize = 16;
const CHUNK_PAYLOAD: usize = NOISE_MAX - TAG_LEN - 1;
/// Maximum size of one reassembled application message.
pub const MAX_MESSAGE: usize = 32 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("peer closed the channel during the handshake")]
    HandshakeEof,
    #[error("peer certificate rejected: {0}")]
    BadPeer(String),
    #[error("malformed message")]
    Malformed,
    #[error("message too large")]
    TooLarge,
}

pub struct Handshaked<R, W> {
    pub sender: SecureSender<W>,
    pub receiver: SecureReceiver<R>,
    /// The verified certificate of the peer.
    pub peer: DeviceCert,
}

fn builder<'a>(key: &'a DeviceKey, prologue: &'a [u8]) -> Builder<'a> {
    Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
        .local_private_key(key.secret_bytes())
        .prologue(prologue)
}

fn check_peer(
    cert_bytes: &[u8],
    remote_static: Option<&[u8]>,
    expected: Option<&[u8; 32]>,
) -> Result<DeviceCert, ChannelError> {
    let cert: DeviceCert =
        postcard::from_bytes(cert_bytes).map_err(|_| ChannelError::BadPeer("unreadable certificate".into()))?;
    verify_device_cert(&cert).map_err(|e| ChannelError::BadPeer(e.to_string()))?;
    if remote_static != Some(cert.device_pk.as_slice()) {
        return Err(ChannelError::BadPeer("certificate does not match the handshake key".into()));
    }
    if let Some(expected) = expected {
        if expected != &cert.device_pk {
            return Err(ChannelError::BadPeer("peer is not the expected device".into()));
        }
    }
    Ok(cert)
}

async fn read_hs<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, ChannelError> {
    read_raw(r).await?.ok_or(ChannelError::HandshakeEof)
}

/// Runs the handshake as the connecting side (viewer).
///
/// `prologue` must be identical on both sides (we use the session id) and binds the handshake to
/// this session. If `expected_peer` is given, the peer must present that device key.
pub async fn initiate<R, W>(
    mut r: R,
    mut w: W,
    prologue: &[u8],
    key: &DeviceKey,
    cert: &DeviceCert,
    expected_peer: Option<&[u8; 32]>,
) -> Result<Handshaked<R, W>, ChannelError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut hs = builder(key, prologue).build_initiator()?;
    let mut buf = vec![0u8; NOISE_MAX];
    let mut payload = vec![0u8; NOISE_MAX];

    let n = hs.write_message(&[], &mut buf)?;
    write_raw(&mut w, &buf[..n]).await?;

    let msg = read_hs(&mut r).await?;
    let n = hs.read_message(&msg, &mut payload)?;
    let peer = check_peer(&payload[..n], hs.get_remote_static(), expected_peer)?;

    let own = postcard::to_stdvec(cert).map_err(|_| ChannelError::Malformed)?;
    let n = hs.write_message(&own, &mut buf)?;
    write_raw(&mut w, &buf[..n]).await?;

    let t = Arc::new(hs.into_stateless_transport_mode()?);
    Ok(Handshaked { sender: SecureSender::new(w, t.clone()), receiver: SecureReceiver::new(r, t), peer })
}

/// Runs the handshake as the accepting side (host).
pub async fn respond<R, W>(
    mut r: R,
    mut w: W,
    prologue: &[u8],
    key: &DeviceKey,
    cert: &DeviceCert,
    expected_peer: Option<&[u8; 32]>,
) -> Result<Handshaked<R, W>, ChannelError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut hs = builder(key, prologue).build_responder()?;
    let mut buf = vec![0u8; NOISE_MAX];
    let mut payload = vec![0u8; NOISE_MAX];

    let msg = read_hs(&mut r).await?;
    hs.read_message(&msg, &mut payload)?;

    let own = postcard::to_stdvec(cert).map_err(|_| ChannelError::Malformed)?;
    let n = hs.write_message(&own, &mut buf)?;
    write_raw(&mut w, &buf[..n]).await?;

    let msg = read_hs(&mut r).await?;
    let n = hs.read_message(&msg, &mut payload)?;
    let peer = check_peer(&payload[..n], hs.get_remote_static(), expected_peer)?;

    let t = Arc::new(hs.into_stateless_transport_mode()?);
    Ok(Handshaked { sender: SecureSender::new(w, t.clone()), receiver: SecureReceiver::new(r, t), peer })
}

/// Sending half of an established channel.
pub struct SecureSender<W> {
    w: W,
    t: Arc<StatelessTransportState>,
    nonce: u64,
    plain: Vec<u8>,
    cipher: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> SecureSender<W> {
    fn new(w: W, t: Arc<StatelessTransportState>) -> Self {
        Self { w, t, nonce: 0, plain: Vec::with_capacity(NOISE_MAX), cipher: vec![0u8; NOISE_MAX] }
    }

    pub async fn send<T: Serialize>(&mut self, msg: &T) -> Result<(), ChannelError> {
        let bytes = postcard::to_stdvec(msg).map_err(|_| ChannelError::Malformed)?;
        self.send_bytes(&bytes).await
    }

    pub async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), ChannelError> {
        if bytes.len() > MAX_MESSAGE {
            return Err(ChannelError::TooLarge);
        }
        let mut chunks = bytes.chunks(CHUNK_PAYLOAD).peekable();
        if chunks.peek().is_none() {
            return self.send_chunk(&[], false).await;
        }
        while let Some(chunk) = chunks.next() {
            self.send_chunk(chunk, chunks.peek().is_some()).await?;
        }
        Ok(())
    }

    async fn send_chunk(&mut self, chunk: &[u8], more: bool) -> Result<(), ChannelError> {
        self.plain.clear();
        self.plain.push(more as u8);
        self.plain.extend_from_slice(chunk);
        let n = self.t.write_message(self.nonce, &self.plain, &mut self.cipher)?;
        self.nonce += 1;
        write_raw(&mut self.w, &self.cipher[..n]).await?;
        Ok(())
    }

    pub fn into_inner(self) -> W {
        self.w
    }
}

/// Receiving half of an established channel.
pub struct SecureReceiver<R> {
    r: R,
    t: Arc<StatelessTransportState>,
    nonce: u64,
    plain: Vec<u8>,
}

impl<R: AsyncRead + Unpin> SecureReceiver<R> {
    fn new(r: R, t: Arc<StatelessTransportState>) -> Self {
        Self { r, t, nonce: 0, plain: vec![0u8; NOISE_MAX] }
    }

    /// Receives the next message. `Ok(None)` means the peer closed the channel cleanly.
    pub async fn recv<T: DeserializeOwned>(&mut self) -> Result<Option<T>, ChannelError> {
        match self.recv_bytes().await? {
            Some(bytes) => postcard::from_bytes(&bytes).map(Some).map_err(|_| ChannelError::Malformed),
            None => Ok(None),
        }
    }

    pub async fn recv_bytes(&mut self) -> Result<Option<Vec<u8>>, ChannelError> {
        let mut message = Vec::new();
        loop {
            let Some(frame) = read_raw(&mut self.r).await? else {
                return if message.is_empty() { Ok(None) } else { Err(ChannelError::Malformed) };
            };
            let n = self.t.read_message(self.nonce, &frame, &mut self.plain)?;
            self.nonce += 1;
            if n == 0 {
                return Err(ChannelError::Malformed);
            }
            if message.len() + n - 1 > MAX_MESSAGE {
                return Err(ChannelError::TooLarge);
            }
            message.extend_from_slice(&self.plain[1..n]);
            match self.plain[0] {
                0 => return Ok(Some(message)),
                1 => continue,
                _ => return Err(ChannelError::Malformed),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKey;
    use somedesk_proto::session::SessionMsg;
    use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

    struct Party {
        key: DeviceKey,
        cert: DeviceCert,
    }

    fn party(user: &str) -> Party {
        let id = IdentityKey::generate();
        let key = DeviceKey::generate();
        let cert = id.certify_device(user, key.public(), "pc", 0);
        Party { key, cert }
    }

    type Hs = Handshaked<ReadHalf<DuplexStream>, WriteHalf<DuplexStream>>;

    async fn connect(a: &Party, b: &Party) -> (Hs, Hs) {
        let (x, y) = duplex(1 << 20);
        let (xr, xw) = split(x);
        let (yr, yw) = split(y);
        let (i, r) = tokio::join!(
            initiate(xr, xw, b"session-1", &a.key, &a.cert, Some(&b.cert.device_pk)),
            respond(yr, yw, b"session-1", &b.key, &b.cert, None),
        );
        (i.unwrap(), r.unwrap())
    }

    #[tokio::test]
    async fn handshake_authenticates_both_sides() {
        let (alice, bob) = (party("alice"), party("bob"));
        let (i, r) = connect(&alice, &bob).await;
        assert_eq!(i.peer, bob.cert);
        assert_eq!(r.peer, alice.cert);
    }

    #[tokio::test]
    async fn messages_flow_both_ways() {
        let (alice, bob) = (party("alice"), party("bob"));
        let (mut i, mut r) = connect(&alice, &bob).await;
        i.sender.send(&SessionMsg::Key { keysym: 0x61, down: true }).await.unwrap();
        r.sender.send(&SessionMsg::Accept).await.unwrap();
        assert_eq!(r.receiver.recv::<SessionMsg>().await.unwrap(), Some(SessionMsg::Key { keysym: 0x61, down: true }));
        assert_eq!(i.receiver.recv::<SessionMsg>().await.unwrap(), Some(SessionMsg::Accept));
    }

    #[tokio::test]
    async fn large_messages_are_chunked_and_reassembled() {
        let (alice, bob) = (party("alice"), party("bob"));
        let (mut i, mut r) = connect(&alice, &bob).await;
        for size in [0usize, 1, CHUNK_PAYLOAD - 1, CHUNK_PAYLOAD, CHUNK_PAYLOAD + 1, 3 * CHUNK_PAYLOAD, 1_000_000] {
            let data: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
            let msg = SessionMsg::Video { seq: size as u64, keyframe: true, width: 1, height: 1, data };
            let (_, got) = tokio::join!(async { r.sender.send(&msg).await.unwrap() }, async {
                i.receiver.recv::<SessionMsg>().await.unwrap().unwrap()
            });
            assert_eq!(got, msg, "size {size}");
        }
    }

    #[tokio::test]
    async fn wrong_expected_peer_is_rejected() {
        let (alice, bob, carol) = (party("alice"), party("bob"), party("carol"));
        let (x, y) = duplex(1 << 16);
        let (xr, xw) = split(x);
        let (yr, yw) = split(y);
        // Alice expects carol, but bob answers (e.g. a malicious relay redirected the session).
        let (i, _r) = tokio::join!(
            initiate(xr, xw, b"s", &alice.key, &alice.cert, Some(&carol.cert.device_pk)),
            respond(yr, yw, b"s", &bob.key, &bob.cert, None),
        );
        assert!(matches!(i, Err(ChannelError::BadPeer(_))));
    }

    #[tokio::test]
    async fn stolen_certificate_without_key_is_rejected() {
        let (alice, bob) = (party("alice"), party("bob"));
        // Mallory presents bob's certificate but only has her own static key.
        let mallory = Party { key: DeviceKey::generate(), cert: bob.cert.clone() };
        let (x, y) = duplex(1 << 16);
        let (xr, xw) = split(x);
        let (yr, yw) = split(y);
        let (i, _r) = tokio::join!(
            initiate(xr, xw, b"s", &alice.key, &alice.cert, None),
            respond(yr, yw, b"s", &mallory.key, &mallory.cert, None),
        );
        assert!(matches!(i, Err(ChannelError::BadPeer(_))));
    }

    #[tokio::test]
    async fn mismatched_prologue_fails() {
        let (alice, bob) = (party("alice"), party("bob"));
        let (x, y) = duplex(1 << 16);
        let (xr, xw) = split(x);
        let (yr, yw) = split(y);
        let (i, r) = tokio::join!(
            initiate(xr, xw, b"session-A", &alice.key, &alice.cert, None),
            respond(yr, yw, b"session-B", &bob.key, &bob.cert, None),
        );
        assert!(i.is_err() || r.is_err());
    }

    #[tokio::test]
    async fn wire_bytes_are_ciphertext() {
        // Put a tap between the two parties and check the plaintext never appears on the wire.
        let (alice, bob) = (party("alice"), party("bob"));
        let (a_side, mut tap_a) = duplex(1 << 20);
        let (b_side, mut tap_b) = duplex(1 << 20);
        let captured = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let cap = captured.clone();
        let relay = tokio::spawn(async move {
            let mut ab = [0u8; 8192];
            let mut ba = [0u8; 8192];
            loop {
                tokio::select! {
                    n = tap_a.read(&mut ab) => { let n = n.unwrap(); if n == 0 { break } cap.lock().unwrap().extend_from_slice(&ab[..n]); tap_b.write_all(&ab[..n]).await.unwrap(); }
                    n = tap_b.read(&mut ba) => { let n = n.unwrap(); if n == 0 { break } cap.lock().unwrap().extend_from_slice(&ba[..n]); tap_a.write_all(&ba[..n]).await.unwrap(); }
                }
            }
        });
        let (ar, aw) = split(a_side);
        let (br, bw) = split(b_side);
        let (i, r) = tokio::join!(
            initiate(ar, aw, b"s", &alice.key, &alice.cert, None),
            respond(br, bw, b"s", &bob.key, &bob.cert, None),
        );
        let (mut i, mut r) = (i.unwrap(), r.unwrap());
        let secret = b"TOP-SECRET-CLIPBOARD-CONTENT-0123456789".to_vec();
        i.sender.send_bytes(&secret).await.unwrap();
        assert_eq!(r.receiver.recv_bytes().await.unwrap().unwrap(), secret);
        drop(i);
        drop(r);
        relay.await.unwrap();
        let wire = captured.lock().unwrap().clone();
        assert!(!wire.is_empty());
        assert!(!wire.windows(secret.len()).any(|w| w == secret.as_slice()));
        // Device names travel inside the encrypted handshake payload, never in clear.
        assert!(!wire.windows(5).any(|w| w == b"alice"));
    }

    #[tokio::test]
    async fn tampered_ciphertext_is_rejected() {
        let (alice, bob) = (party("alice"), party("bob"));
        let (a_side, mut tap_a) = duplex(1 << 20);
        let (b_side, mut tap_b) = duplex(1 << 20);
        let flip = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f = flip.clone();
        tokio::spawn(async move {
            let mut ab = [0u8; 8192];
            let mut ba = [0u8; 8192];
            loop {
                tokio::select! {
                    n = tap_a.read(&mut ab) => { let n = n.unwrap(); if n == 0 { break }
                        if f.load(std::sync::atomic::Ordering::SeqCst) && n > 8 { ab[n - 1] ^= 0x80; }
                        tap_b.write_all(&ab[..n]).await.unwrap(); }
                    n = tap_b.read(&mut ba) => { let n = n.unwrap(); if n == 0 { break } tap_a.write_all(&ba[..n]).await.unwrap(); }
                }
            }
        });
        let (ar, aw) = split(a_side);
        let (br, bw) = split(b_side);
        let (i, r) = tokio::join!(
            initiate(ar, aw, b"s", &alice.key, &alice.cert, None),
            respond(br, bw, b"s", &bob.key, &bob.cert, None),
        );
        let (mut i, mut r) = (i.unwrap(), r.unwrap());
        flip.store(true, std::sync::atomic::Ordering::SeqCst);
        i.sender.send_bytes(b"hello world, this is a message").await.unwrap();
        assert!(matches!(r.receiver.recv_bytes().await, Err(ChannelError::Noise(_))));
    }
}
