//! Connection to the SomeDesk server.

use crate::credentials::{AccountCredentials, DeviceCredentials};
use crate::direct::DirectHub;
use crate::tls::PinningVerifier;
use crate::{ClientError, Result};
use somedesk_crypto::keys::{DeviceKey, IdentityKey};
use somedesk_crypto::opaque;
use somedesk_crypto::recovery::RecoveryKey;
use somedesk_crypto::totp::TotpSecret;
use somedesk_crypto::vault::VaultKey;
use somedesk_proto::control::*;
use somedesk_proto::frame::{read_msg, write_msg};
use somedesk_proto::org::{OrgDeviceCert, SignedPolicy};
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
    direct: Arc<DirectHub>,
}

/// The result of a password login: the decrypted identity key.
pub struct LoggedIn {
    pub username: String,
    pub identity: IdentityKey,
    /// Whether the account has a recovery key. If not, offer to create one with
    /// [`ServerConn::set_up_recovery`].
    pub has_recovery: bool,
}

/// The result of a password reset with the recovery key.
pub struct Recovered {
    pub login: LoggedIn,
    /// The replacement recovery key. The one used for the reset no longer works.
    pub new_recovery_key: RecoveryKey,
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
        // We own the socket so the direct-connection code can also send hole-punching packets
        // from it (see `direct`).
        let socket = std::net::UdpSocket::bind(bind).map_err(transport_err)?;
        let punch_socket = socket.try_clone().map_err(transport_err)?;
        let runtime = quinn::default_runtime().ok_or_else(|| ClientError::Transport("no async runtime".into()))?;
        let mut endpoint =
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime).map_err(transport_err)?;
        endpoint.set_default_client_config(cfg);
        let conn =
            tokio::time::timeout(Duration::from_secs(10), endpoint.connect(addr, "somedesk").map_err(transport_err)?)
                .await
                .map_err(|_| ClientError::Transport(format!("timed out connecting to {server}")))?
                .map_err(transport_err)?;
        let fingerprint = verifier.seen().ok_or(ClientError::Protocol("no server certificate"))?;
        // The same UDP socket accepts direct connections from peers, so its NAT mapping (opened
        // by talking to the server) can be reused for them.
        let direct = DirectHub::install(&endpoint, punch_socket)?;

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
            direct,
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

    fn check_password(password: &str) -> Result<()> {
        if password.chars().count() < 8 {
            return Err(ClientError::Server(ErrorInfo::new(
                ErrorCode::BadRequest,
                "password must have at least 8 characters",
            )));
        }
        Ok(())
    }

    /// Creates an account. Generates the user's identity key and stores it on the server twice:
    /// encrypted under the password-derived key, and under the returned recovery key, which the
    /// user must keep safe.
    pub async fn register(&self, username: &str, password: &str) -> Result<RecoveryKey> {
        let username = Self::normalize(username)?;
        Self::check_password(password)?;
        let (m1, st) = opaque::client_register_start(&username, password)?;
        let Response::RegisterStart { message } =
            self.request(Request::RegisterStart { username: username.clone(), message: m1 }).await?
        else {
            return Err(unexpected());
        };
        let (upload, export_key) = opaque::client_register_finish(st, password, &message)?;
        let identity = IdentityKey::generate();
        let key_bundle = identity.seal(&export_key, &username);
        let recovery_key = RecoveryKey::generate();
        let recovery = recovery_setup(&recovery_key, &identity, &username);
        match self
            .request(Request::RegisterFinish { message: upload, identity_pk: identity.public(), key_bundle, recovery })
            .await?
        {
            Response::Ok => Ok(recovery_key),
            _ => Err(unexpected()),
        }
    }

    /// Creates a new recovery key for the logged-in account, replacing any previous one.
    pub async fn set_up_recovery(&self, login: &LoggedIn) -> Result<RecoveryKey> {
        let recovery_key = RecoveryKey::generate();
        let recovery = recovery_setup(&recovery_key, &login.identity, &login.username);
        match self.request(Request::SetRecovery { recovery }).await? {
            Response::Ok => Ok(recovery_key),
            _ => Err(unexpected()),
        }
    }

    /// Sets a new password using the recovery key. On success this connection is logged in, as
    /// after [`ServerConn::login`], and the recovery key is replaced by a new one.
    pub async fn recover(&self, username: &str, recovery_key: &RecoveryKey, new_password: &str) -> Result<Recovered> {
        let username = Self::normalize(username)?;
        Self::check_password(new_password)?;
        let Response::RecoveryChallenge { challenge } =
            self.request(Request::RecoveryStart { username: username.clone() }).await?
        else {
            return Err(unexpected());
        };
        let proof = recovery_key.prove(&username, &challenge).to_vec();
        let (m1, st) = opaque::client_register_start(&username, new_password)?;
        let Response::RecoveryProve { identity_pk, recovery_bundle, message } =
            self.request(Request::RecoveryProve { proof, message: m1 }).await?
        else {
            return Err(unexpected());
        };
        // Only proceed if the recovery copy really opens to the account's identity key; otherwise
        // the server would end up with a password bundle we cannot vouch for.
        let identity = recovery_key.open(&recovery_bundle, &username, &identity_pk)?;
        let (upload, export_key) = opaque::client_register_finish(st, new_password, &message)?;
        let key_bundle = identity.seal(&export_key, &username);
        let new_recovery_key = RecoveryKey::generate();
        let recovery = recovery_setup(&new_recovery_key, &identity, &username);
        match self.request(Request::RecoveryFinish { message: upload, key_bundle, recovery }).await? {
            Response::Ok => {
                Ok(Recovered { login: LoggedIn { username, identity, has_recovery: true }, new_recovery_key })
            }
            _ => Err(unexpected()),
        }
    }

    /// Password login. Decrypts the identity key locally. On an account with two-factor
    /// authentication this fails with [`ClientError::TotpRequired`]; log in again with the code
    /// ([`ServerConn::login_with_code`]).
    pub async fn login(&self, username: &str, password: &str) -> Result<LoggedIn> {
        self.login_with_code(username, password, None).await
    }

    /// Password login with the code from the authenticator app, for accounts that have one.
    pub async fn login_with_code(&self, username: &str, password: &str, code: Option<&str>) -> Result<LoggedIn> {
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
        let finish = match self.request(Request::LoginFinish { message: fin }).await? {
            Response::TotpRequired => match code {
                Some(code) => self.request(Request::LoginTotp { code: code.to_owned() }).await?,
                None => return Err(ClientError::TotpRequired),
            },
            other => other,
        };
        let Response::LoginFinish { identity_pk, key_bundle, has_recovery } = finish else {
            return Err(unexpected());
        };
        let identity = IdentityKey::open(&key_bundle, &export_key, &username, &identity_pk)?;
        Ok(LoggedIn { username, identity, has_recovery })
    }

    /// Brings the device with `key` online under the name `name`: proves to the server that this
    /// connection holds the key. A key the server doesn't know yet gets a new ID.
    pub async fn come_online(&self, key: &DeviceKey, name: &str) -> Result<DeviceInfo> {
        self.come_online_as(key, name, None).await
    }

    /// [`ServerConn::come_online`] for a device enrolled into an organisation, with its
    /// certificate from the service worker.
    pub async fn come_online_as(&self, key: &DeviceKey, name: &str, org: Option<OrgDeviceCert>) -> Result<DeviceInfo> {
        let Response::DeviceChallenge { server_pk, nonce } =
            self.request(Request::DeviceChallenge { device_pk: key.public() }).await?
        else {
            return Err(unexpected());
        };
        let proof = key.prove(&server_pk, &nonce);
        match self.request(Request::DeviceAuth { name: name.trim().to_owned(), proof, org }).await? {
            Response::Authenticated { device } => Ok(device),
            _ => Err(unexpected()),
        }
    }

    /// Sets up this installation: creates its device key and brings it online, which gives it
    /// its ID. No account is needed (unless the server only lets in its accounts' devices; then
    /// log in on this connection first and [`ServerConn::attach`] right after).
    pub async fn create_device(&self, server: &str, name: &str) -> Result<DeviceCredentials> {
        let key = DeviceKey::generate();
        let device = self.come_online(&key, name).await?;
        self.announce_candidates().await?;
        Ok(DeviceCredentials {
            server: server.to_owned(),
            server_fingerprint: self.fingerprint,
            device_id: device.device_id,
            device_secret: *key.secret_bytes(),
            device_name: device.identity.name,
            account: None,
            org: None,
        })
    }

    /// Brings an existing device online; it is online while this connection lives. Also tells
    /// the server where the device can be reached directly (see
    /// [`ServerConn::set_allow_direct`]). Updates `creds` if the server knows the device
    /// differently: under another ID (e.g. after the server lost its data) or off its account.
    pub async fn authenticate(&self, creds: &mut DeviceCredentials) -> Result<DeviceInfo> {
        let device = self.come_online_as(&creds.device_key(), &creds.device_name, creds.org.clone()).await?;
        if device.device_id != creds.device_id {
            tracing::warn!(old = creds.device_id, new = device.device_id, "the server gave this device a new ID");
            creds.device_id = device.device_id;
        }
        if device.identity.account.is_none() && creds.account.is_some() {
            tracing::info!("this device was signed out of its account elsewhere");
            creds.account = None;
        }
        self.announce_candidates().await?;
        Ok(device)
    }

    /// Enrolls this installation into an organisation with a service worker's enrollment key:
    /// creates the device key, has the worker certify it and brings the device online.
    pub async fn enroll_device(
        &self,
        server: &str,
        key: &somedesk_crypto::org::EnrollmentKey,
        name: &str,
    ) -> Result<DeviceCredentials> {
        let device_key = DeviceKey::generate();
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let cert = key.certify_device(device_key.public(), name.trim(), now);
        let device = self.come_online_as(&device_key, name, Some(cert.clone())).await?;
        self.announce_candidates().await?;
        Ok(DeviceCredentials {
            server: server.to_owned(),
            server_fingerprint: self.fingerprint,
            device_id: device.device_id,
            device_secret: *device_key.secret_bytes(),
            device_name: device.identity.name,
            account: None,
            org: Some(cert),
        })
    }

    /// Signs this (online) device in to the logged-in account. The device keeps its ID.
    pub async fn attach(&self, login: &LoggedIn, creds: &mut DeviceCredentials) -> Result<()> {
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let cert =
            login.identity.certify_device(&login.username, creds.device_key().public(), creds.device_name.trim(), now);
        match self.request(Request::AttachDevice { cert: cert.clone() }).await? {
            Response::Ok => {
                creds.account = Some(AccountCredentials {
                    username: login.username.clone(),
                    identity_pk: login.identity.public(),
                    cert,
                    vault_key: Some(VaultKey::derive(&login.identity).to_bytes()),
                });
                Ok(())
            }
            _ => Err(unexpected()),
        }
    }

    /// Signs this device out of its account. It keeps its ID.
    pub async fn detach(&self, creds: &mut DeviceCredentials) -> Result<()> {
        match self.request(Request::DetachDevice).await? {
            Response::Ok => {
                creds.account = None;
                Ok(())
            }
            _ => Err(unexpected()),
        }
    }

    /// Whether sessions may use direct connections (default: yes). Without, this device's
    /// addresses are never shared with peers. Takes effect with the next announcement.
    pub fn set_allow_direct(&self, allow: bool) {
        self.direct.set_allowed(allow);
    }

    /// Tells the server this device's direct-connection addresses (or that it wants none).
    pub async fn announce_candidates(&self) -> Result<()> {
        let allow_direct = self.direct.allowed();
        let local = if allow_direct { self.direct.local_candidates() } else { Vec::new() };
        match self.request(Request::SetCandidates { local, allow_direct }).await? {
            Response::Ok => Ok(()),
            _ => Err(unexpected()),
        }
    }

    pub(crate) fn direct(&self) -> &Arc<DirectHub> {
        &self.direct
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

    /// The account of this connection: its name and whether it has two-factor authentication.
    pub async fn account_info(&self) -> Result<(String, bool)> {
        match self.request(Request::AccountInfo).await? {
            Response::Account { username, totp_enabled } => Ok((username, totp_enabled)),
            _ => Err(unexpected()),
        }
    }

    /// Starts turning on two-factor authentication (after a password login): returns the secret
    /// for the authenticator app. [`ServerConn::totp_enable`] with a code turns it on.
    pub async fn totp_begin(&self) -> Result<TotpSecret> {
        match self.request(Request::TotpBegin).await? {
            Response::TotpSecret { secret } => Ok(TotpSecret::from_bytes(&secret)),
            _ => Err(unexpected()),
        }
    }

    pub async fn totp_enable(&self, code: &str) -> Result<()> {
        match self.request(Request::TotpEnable { code: code.to_owned() }).await? {
            Response::Ok => Ok(()),
            _ => Err(unexpected()),
        }
    }

    pub async fn totp_disable(&self, code: &str) -> Result<()> {
        match self.request(Request::TotpDisable { code: code.to_owned() }).await? {
            Response::Ok => Ok(()),
            _ => Err(unexpected()),
        }
    }

    /// The account's encrypted vault: (version, blob); (0, empty) if there is none yet.
    pub async fn get_vault(&self) -> Result<(u64, Vec<u8>)> {
        match self.request(Request::GetVault).await? {
            Response::Vault { version, blob } => Ok((version, blob)),
            _ => Err(unexpected()),
        }
    }

    /// Stores the vault if it is still at `base_version`; fails with a `Conflict` otherwise.
    pub async fn put_vault(&self, base_version: u64, blob: Vec<u8>) -> Result<u64> {
        match self.request(Request::PutVault { base_version, blob }).await? {
            Response::VaultSaved { version } => Ok(version),
            _ => Err(unexpected()),
        }
    }

    /// An account's identity key, as the server knows it.
    pub async fn lookup_user(&self, username: &str) -> Result<[u8; 32]> {
        match self.request(Request::LookupUser { username: username.to_owned() }).await? {
            Response::User { identity_pk, .. } => Ok(identity_pk),
            _ => Err(unexpected()),
        }
    }

    pub async fn create_org(&self, name: &str, org_pk: [u8; 32], sealed_key: Vec<u8>) -> Result<u64> {
        match self.request(Request::CreateOrg { name: name.to_owned(), org_pk, sealed_key }).await? {
            Response::OrgCreated { org_id } => Ok(org_id),
            _ => Err(unexpected()),
        }
    }

    pub async fn list_orgs(&self) -> Result<Vec<OrgInfo>> {
        match self.request(Request::ListOrgs).await? {
            Response::Orgs(orgs) => Ok(orgs),
            _ => Err(unexpected()),
        }
    }

    pub async fn put_org_policy(&self, org_id: u64, policy: SignedPolicy) -> Result<()> {
        match self.request(Request::PutOrgPolicy { org_id, policy }).await? {
            Response::Ok => Ok(()),
            _ => Err(unexpected()),
        }
    }

    pub async fn share_org_key(&self, org_id: u64, username: &str, sealed_key: Vec<u8>) -> Result<()> {
        match self.request(Request::ShareOrgKey { org_id, username: username.to_owned(), sealed_key }).await? {
            Response::Ok => Ok(()),
            _ => Err(unexpected()),
        }
    }

    pub async fn get_org_policy(&self, org_id: u64) -> Result<Option<SignedPolicy>> {
        match self.request(Request::GetOrgPolicy { org_id }).await? {
            Response::OrgPolicy(p) => Ok(p),
            _ => Err(unexpected()),
        }
    }

    pub async fn list_org_devices(&self, org_id: u64) -> Result<Vec<DeviceInfo>> {
        match self.request(Request::ListOrgDevices { org_id }).await? {
            Response::Devices(d) => Ok(d),
            _ => Err(unexpected()),
        }
    }

    /// Takes one of the account's devices off the account (it keeps its ID).
    pub async fn remove_device(&self, device_id: u64) -> Result<()> {
        match self.request(Request::RemoveDevice { device_id }).await? {
            Response::Ok => Ok(()),
            _ => Err(unexpected()),
        }
    }

    /// Asks the server to set up a session to `device_id`. Returns the host's direct-connection
    /// candidates too (empty: relay only).
    pub async fn request_session(&self, device_id: u64) -> Result<(SessionId, DeviceInfo, Vec<SocketAddr>)> {
        match self.request(Request::Connect { device_id }).await? {
            Response::Connect { session_id, host, candidates } => Ok((session_id, host, candidates)),
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

fn recovery_setup(recovery_key: &RecoveryKey, identity: &IdentityKey, username: &str) -> RecoverySetup {
    RecoverySetup { recovery_pk: recovery_key.public(), key_bundle: recovery_key.seal(identity, username) }
}

impl Drop for ServerConn {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"bye");
    }
}
