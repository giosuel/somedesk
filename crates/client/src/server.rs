//! Connection to the SomeDesk server.

use crate::credentials::DeviceCredentials;
use crate::tls::PinningVerifier;
use crate::{ClientError, Result};
use somedesk_crypto::keys::{DeviceKey, IdentityKey};
use somedesk_crypto::opaque;
use somedesk_proto::control::*;
use somedesk_proto::frame::{read_msg, write_msg};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

type Pending = Arc<Mutex<HashMap<u32, oneshot::Sender<Result<Response, ErrorInfo>>>>>;

pub struct ServerConn {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    control: tokio::sync::Mutex<quinn::SendStream>,
    pending: Pending,
    next_id: AtomicU32,
    fingerprint: [u8; 32],
}

/// The result of a password login: the decrypted identity key.
pub struct LoggedIn {
    pub username: String,
    pub identity: IdentityKey,
}

async fn resolve(server: &str) -> Result<SocketAddr> {
    let with_port = if server.rsplit_once(':').is_some_and(|(_, p)| p.parse::<u16>().is_ok()) && !server.ends_with(']')
    {
        server.to_owned()
    } else {
        format!("{server}:{}", somedesk_proto::DEFAULT_PORT)
    };
    let mut addrs = tokio::net::lookup_host(&with_port)
        .await
        .map_err(|e| ClientError::Transport(format!("cannot resolve {server}: {e}")))?;
    addrs.next().ok_or_else(|| ClientError::Transport(format!("cannot resolve {server}")))
}

fn transport_err(e: impl std::fmt::Display) -> ClientError {
    ClientError::Transport(e.to_string())
}

fn unexpected() -> ClientError {
    ClientError::Protocol("unexpected response from server")
}

impl ServerConn {
    /// Connects to `server` (`host` or `host:port`). If `pin` is `None` the certificate is
    /// trusted on first use; read it back with [`ServerConn::fingerprint`] and store it.
    pub async fn connect(server: &str, pin: Option<[u8; 32]>) -> Result<(Arc<Self>, mpsc::UnboundedReceiver<Event>)> {
        let addr = resolve(server).await?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(PinningVerifier::new(pin, provider.clone()));
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(transport_err)?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        tls.alpn_protocols = vec![somedesk_proto::ALPN.to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(transport_err)?;
        let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().expect("valid timeout")));
        cfg.transport_config(Arc::new(transport));

        let bind: SocketAddr = if addr.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
        let mut endpoint = quinn::Endpoint::client(bind).map_err(transport_err)?;
        endpoint.set_default_client_config(cfg);
        let conn =
            tokio::time::timeout(Duration::from_secs(10), endpoint.connect(addr, "somedesk").map_err(transport_err)?)
                .await
                .map_err(|_| ClientError::Transport(format!("timed out connecting to {server}")))?
                .map_err(transport_err)?;
        let fingerprint = verifier.seen().ok_or(ClientError::Protocol("no server certificate"))?;

        let (send, mut recv) = conn.open_bi().await.map_err(transport_err)?;
        let pending: Pending = Arc::default();
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let p = pending.clone();
        tokio::spawn(async move {
            loop {
                match read_msg::<_, ServerFrame>(&mut recv).await {
                    Ok(Some(ServerFrame::Response { id, result })) => {
                        if let Some(tx) = p.lock().unwrap().remove(&id) {
                            let _ = tx.send(result);
                        }
                    }
                    Ok(Some(ServerFrame::Event(ev))) => {
                        let _ = events_tx.send(ev);
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            // Fail all outstanding requests.
            p.lock().unwrap().clear();
        });

        let this = Arc::new(Self {
            endpoint,
            conn,
            control: tokio::sync::Mutex::new(send),
            pending,
            next_id: AtomicU32::new(1),
            fingerprint,
        });
        match this.request(Request::Hello { version: somedesk_proto::PROTOCOL_VERSION }).await? {
            Response::Hello { .. } => Ok((this, events_rx)),
            _ => Err(unexpected()),
        }
    }

    /// SHA-256 fingerprint of the server's TLS certificate.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Resolves when the connection to the server is lost.
    pub async fn closed(&self) -> String {
        self.conn.closed().await.to_string()
    }

    pub fn close(&self) {
        self.conn.close(0u32.into(), b"bye");
        self.endpoint.close(0u32.into(), b"bye");
    }

    pub async fn request(&self, req: Request) -> Result<Response> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        {
            let mut send = self.control.lock().await;
            if let Err(e) = write_msg(&mut *send, &ClientFrame { id, req }).await {
                self.pending.lock().unwrap().remove(&id);
                return Err(e.into());
            }
        }
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(Ok(resp))) => Ok(resp),
            Ok(Ok(Err(e))) => Err(ClientError::Server(e)),
            Ok(Err(_)) => Err(ClientError::Transport("connection to server lost".into())),
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err(ClientError::Transport("server did not answer in time".into()))
            }
        }
    }

    fn normalize(username: &str) -> Result<String> {
        somedesk_proto::normalize_username(username).ok_or_else(|| {
            ClientError::Server(ErrorInfo::new(
                ErrorCode::BadRequest,
                "username must be 3-32 characters: a-z, 0-9, '.', '_' or '-'",
            ))
        })
    }

    /// Creates an account. Generates the user's identity key and stores it on the server
    /// encrypted under the password-derived key.
    pub async fn register(&self, username: &str, password: &str) -> Result<()> {
        let username = Self::normalize(username)?;
        if password.chars().count() < 8 {
            return Err(ClientError::Server(ErrorInfo::new(
                ErrorCode::BadRequest,
                "password must have at least 8 characters",
            )));
        }
        let (m1, st) = opaque::client_register_start(&username, password)?;
        let Response::RegisterStart { message } =
            self.request(Request::RegisterStart { username: username.clone(), message: m1 }).await?
        else {
            return Err(unexpected());
        };
        let (upload, export_key) = opaque::client_register_finish(st, password, &message)?;
        let identity = IdentityKey::generate();
        let key_bundle = identity.seal(&export_key, &username);
        match self
            .request(Request::RegisterFinish { message: upload, identity_pk: identity.public(), key_bundle })
            .await?
        {
            Response::Ok => Ok(()),
            _ => Err(unexpected()),
        }
    }

    /// Password login. Decrypts the identity key locally.
    pub async fn login(&self, username: &str, password: &str) -> Result<LoggedIn> {
        let username = Self::normalize(username)?;
        let (m1, st) = opaque::client_login_start(&username, password)?;
        let Response::LoginStart { message } =
            self.request(Request::LoginStart { username: username.clone(), message: m1 }).await?
        else {
            return Err(unexpected());
        };
        let (fin, export_key) = match opaque::client_login_finish(st, password, &message) {
            Ok(v) => v,
            Err(somedesk_crypto::CryptoError::AuthFailed) => {
                return Err(ClientError::Server(ErrorInfo::new(ErrorCode::AuthFailed, "wrong username or password")))
            }
            Err(e) => return Err(e.into()),
        };
        let Response::LoginFinish { identity_pk, key_bundle } =
            self.request(Request::LoginFinish { message: fin }).await?
        else {
            return Err(unexpected());
        };
        let identity = IdentityKey::open(&key_bundle, &export_key, &username, &identity_pk)?;
        Ok(LoggedIn { username, identity })
    }

    /// Enrolls this machine under the logged-in account.
    pub async fn enroll_device(&self, server: &str, login: &LoggedIn, device_name: &str) -> Result<DeviceCredentials> {
        let key = DeviceKey::generate();
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let cert = login.identity.certify_device(&login.username, key.public(), device_name.trim(), now);
        let Response::DeviceRegistered { device_id, token } =
            self.request(Request::RegisterDevice { cert: cert.clone() }).await?
        else {
            return Err(unexpected());
        };
        Ok(DeviceCredentials {
            server: server.to_owned(),
            server_fingerprint: self.fingerprint,
            username: login.username.clone(),
            identity_pk: login.identity.public(),
            device_id,
            device_secret: *key.secret_bytes(),
            cert,
            token,
        })
    }

    /// Authenticates as an enrolled device; the device is online while this connection lives.
    pub async fn authenticate(&self, creds: &DeviceCredentials) -> Result<DeviceInfo> {
        match self.request(Request::TokenAuth { device_id: creds.device_id, token: creds.token }).await? {
            Response::Authenticated { device, .. } => Ok(device),
            _ => Err(unexpected()),
        }
    }

    pub async fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        match self.request(Request::ListDevices).await? {
            Response::Devices(d) => Ok(d),
            _ => Err(unexpected()),
        }
    }

    pub async fn lookup_device(&self, device_id: u64) -> Result<DeviceInfo> {
        match self.request(Request::LookupDevice { device_id }).await? {
            Response::Device(d) => Ok(d),
            _ => Err(unexpected()),
        }
    }

    pub async fn remove_device(&self, device_id: u64) -> Result<()> {
        match self.request(Request::RemoveDevice { device_id }).await? {
            Response::Ok => Ok(()),
            _ => Err(unexpected()),
        }
    }

    /// Asks the server to set up a relayed session to `device_id`.
    pub async fn request_session(&self, device_id: u64) -> Result<(SessionId, DeviceInfo)> {
        match self.request(Request::Connect { device_id }).await? {
            Response::Connect { session_id, host } => Ok((session_id, host)),
            _ => Err(unexpected()),
        }
    }

    /// Opens a relay stream for `session_id`.
    pub async fn open_relay(&self, session_id: SessionId) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let (mut send, recv) = self.conn.open_bi().await.map_err(transport_err)?;
        write_msg(&mut send, &RelayJoin { session_id }).await?;
        Ok((send, recv))
    }
}

impl Drop for ServerConn {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"bye");
    }
}
