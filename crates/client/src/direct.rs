//! Direct (peer-to-peer) QUIC connections between two devices.
//!
//! The QUIC endpoint a device uses to talk to the server also accepts connections from peers.
//! Both sides learn each other's candidate addresses from the server when a session starts and
//! dial them at the same time: the outgoing packets open each side's NAT or firewall for the
//! other ("hole punching"). Every direct stream starts with a [`DirectHello`] naming its session,
//! and the session's Noise handshake then runs over it exactly as over the relay, so a direct
//! path changes nothing about authentication or encryption. The QUIC layer's own certificates are
//! throwaway ones and are not checked.
//!
//! Before dialling, each side sends a few tiny datagrams with a low TTL towards the peer. They
//! open a mapping in our own NAT but expire before they reach the peer's NAT. Without them, the
//! peer's first packet can arrive at our NAT before we have sent anything, and many NATs (Linux
//! conntrack among them) then remember that stray packet and pick a different port for our own
//! traffic, which breaks the hole.

use crate::tls::PinningVerifier;
use crate::{ClientError, Result};
use somedesk_proto::control::{DirectHello, SessionId};
use somedesk_proto::frame::{read_msg_limited, write_msg};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// How long a dial to one candidate address may take.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(3);
/// TTLs of the hole-punching datagrams: enough to leave our own NAT (and an ISP-level NAT behind
/// it), too little to reach the peer's.
const PUNCH_TTLS: [u32; 2] = [2, 3];
/// Pause between punching and dialling, so the mappings exist before the real packets arrive.
const PUNCH_LEAD: Duration = Duration::from_millis(150);
/// Concurrent incoming direct connections that have not yet named a session.
const MAX_PENDING_INCOMING: usize = 32;
/// A [`DirectHello`] is a session ID; nothing larger is read before one.
const MAX_HELLO: usize = 64;
/// How long an incoming connection has to name a session we wait for before it is closed.
const NAME_SESSION_WITHIN: Duration = Duration::from_secs(15);

pub type StreamPair = (quinn::SendStream, quinn::RecvStream);

/// Direct-connection state of one server connection's endpoint.
pub struct DirectHub {
    endpoint: quinn::Endpoint,
    /// A second handle to the endpoint's UDP socket, for hole-punching datagrams.
    punch_socket: std::net::UdpSocket,
    client_config: quinn::ClientConfig,
    waiters: Mutex<HashMap<SessionId, mpsc::UnboundedSender<StreamPair>>>,
    allow: AtomicBool,
    accept_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    // Keeps NAT mappings open while a session is idle.
    t.keep_alive_interval(Some(Duration::from_secs(5)));
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().expect("valid timeout")));
    Arc::new(t)
}

impl DirectHub {
    /// Makes `endpoint` accept direct connections and returns the hub that routes them.
    pub fn install(endpoint: &quinn::Endpoint, punch_socket: std::net::UdpSocket) -> Result<Arc<Self>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = rcgen::generate_simple_self_signed(vec!["somedesk-peer".into()])
            .map_err(|e| ClientError::Other(format!("cannot create a peer certificate: {e}")))?;
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
        let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(transport_err)?
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .map_err(transport_err)?;
        server_tls.alpn_protocols = vec![somedesk_proto::P2P_ALPN.to_vec()];
        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).map_err(transport_err)?,
        ));
        server_cfg.transport_config(transport());
        endpoint.set_server_config(Some(server_cfg));

        // Peers are authenticated by the Noise handshake, not by TLS: accept any certificate.
        let verifier = Arc::new(PinningVerifier::new(None, provider.clone()));
        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(transport_err)?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![somedesk_proto::P2P_ALPN.to_vec()];
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).map_err(transport_err)?,
        ));
        client_config.transport_config(transport());

        let hub = Arc::new(Self {
            endpoint: endpoint.clone(),
            punch_socket,
            client_config,
            waiters: Mutex::default(),
            allow: AtomicBool::new(true),
            accept_task: Mutex::new(None),
        });
        let task = tokio::spawn(accept_loop(Arc::downgrade(&hub), endpoint.clone()));
        *hub.accept_task.lock().unwrap() = Some(task);
        Ok(hub)
    }

    pub fn allowed(&self) -> bool {
        self.allow.load(Ordering::Relaxed)
    }

    pub fn set_allowed(&self, allow: bool) {
        self.allow.store(allow, Ordering::Relaxed);
    }

    /// Addresses on this machine where the endpoint can be reached (not loopback or link-local).
    pub fn local_candidates(&self) -> Vec<SocketAddr> {
        let Ok(local) = self.endpoint.local_addr() else { return Vec::new() };
        let port = local.port();
        let mut out: Vec<SocketAddr> = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .map(|i| i.ip())
            .filter(|ip| !ip.is_loopback() && !ip.is_unspecified() && !is_link_local(ip))
            .filter(|ip| ip.is_ipv4() == local.is_ipv4())
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Receives the direct streams peers open for `session_id` until the returned guard is
    /// dropped.
    pub fn wait_for(self: &Arc<Self>, session_id: SessionId) -> Waiter {
        let (tx, rx) = mpsc::unbounded_channel();
        self.waiters.lock().unwrap().insert(session_id, tx);
        Waiter { hub: self.clone(), session_id, rx }
    }

    /// Sends low-TTL datagrams to each address (see the module docs), then waits a moment.
    pub async fn punch(&self, addrs: &[SocketAddr]) {
        let s = &self.punch_socket;
        let Ok(normal_ttl) = s.ttl() else { return };
        for &ttl in &PUNCH_TTLS {
            if s.set_ttl(ttl).is_err() {
                break;
            }
            for addr in addrs.iter().filter(|a| a.is_ipv4()) {
                // A single zero byte: not a valid QUIC packet, so a receiver just drops it.
                let _ = s.send_to(&[0], addr);
            }
        }
        let _ = s.set_ttl(normal_ttl);
        tokio::time::sleep(PUNCH_LEAD).await;
    }

    /// Connects to a peer at `addr` and opens a stream for `session_id`.
    pub async fn dial(&self, addr: SocketAddr, session_id: SessionId) -> Result<StreamPair> {
        let attempt = async {
            let conn = self
                .endpoint
                .connect_with(self.client_config.clone(), addr, "somedesk-peer")
                .map_err(transport_err)?
                .await
                .map_err(transport_err)?;
            let (mut send, recv) = conn.open_bi().await.map_err(transport_err)?;
            write_msg(&mut send, &DirectHello { session_id }).await?;
            Ok::<_, ClientError>((send, recv))
        };
        tokio::time::timeout(DIAL_TIMEOUT, attempt)
            .await
            .map_err(|_| ClientError::Transport(format!("no direct answer from {addr}")))?
    }
}

impl Drop for DirectHub {
    fn drop(&mut self) {
        if let Some(t) = self.accept_task.lock().unwrap().take() {
            t.abort();
        }
    }
}

/// Direct streams for one session; stops routing them when dropped.
pub struct Waiter {
    hub: Arc<DirectHub>,
    session_id: SessionId,
    rx: mpsc::UnboundedReceiver<StreamPair>,
}

impl Waiter {
    pub async fn next(&mut self) -> Option<StreamPair> {
        self.rx.recv().await
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        self.hub.waiters.lock().unwrap().remove(&self.session_id);
    }
}

fn transport_err(e: impl std::fmt::Display) -> ClientError {
    ClientError::Transport(e.to_string())
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

async fn accept_loop(hub: std::sync::Weak<DirectHub>, endpoint: quinn::Endpoint) {
    let pending = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_INCOMING));
    while let Some(incoming) = endpoint.accept().await {
        let Some(h) = hub.upgrade() else { return };
        if !h.allowed() {
            incoming.refuse();
            continue;
        }
        let Ok(permit) = pending.clone().try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        let hub = hub.clone();
        tokio::spawn(async move {
            // The permit only covers the time until the connection names a session we wait for;
            // one that doesn't within `NAME_SESSION_WITHIN` is closed.
            let mut permit = Some(permit);
            let named_by = tokio::time::Instant::now() + NAME_SESSION_WITHIN;
            let limit = |permit: &Option<_>, d: Duration| match permit {
                Some(_) => d.min(named_by.saturating_duration_since(tokio::time::Instant::now())),
                None => d,
            };
            let conn = match tokio::time::timeout(limit(&permit, Duration::from_secs(5)), incoming).await {
                Ok(Ok(c)) => c,
                _ => return,
            };
            // A peer opens one stream per session attempt; route each by its hello.
            loop {
                let wait = limit(&permit, Duration::from_secs(10));
                let Ok(Ok((send, mut recv))) = tokio::time::timeout(wait, conn.accept_bi()).await else {
                    break;
                };
                let wait = limit(&permit, Duration::from_secs(5));
                let hello: DirectHello = match tokio::time::timeout(wait, read_msg_limited(&mut recv, MAX_HELLO)).await
                {
                    Ok(Ok(Some(h))) => h,
                    _ => break,
                };
                let Some(hub) = hub.upgrade() else { break };
                let waiter = hub.waiters.lock().unwrap().get(&hello.session_id).cloned();
                match waiter {
                    Some(tx) => {
                        let _ = tx.send((send, recv));
                        permit = None;
                    }
                    None => tracing::debug!("direct stream for an unknown session"),
                }
            }
        });
    }
}
