//! One client connection: the control stream plus any relay streams.

use crate::{db, relay, Online, Shared};
use somedesk_crypto::keys::{verify_device_cert, DeviceChallenge};
use somedesk_crypto::opaque::{self, ServerLoginState};
use somedesk_crypto::recovery;
use somedesk_crypto::totp::{self, TotpSecret};
use somedesk_proto::control::*;
use somedesk_proto::frame::{read_msg, write_msg};
use somedesk_proto::org::{policy_hash, OrgDeviceCert, OrgPolicy, PolicyBundle, SignedPolicy};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// Login/registration attempts per minute, per IP and per username.
const AUTH_LIMIT: u32 = 20;
const MAX_DEVICE_NAME: usize = 64;
/// Local addresses a device may announce for direct connections.
const MAX_CANDIDATES: usize = 8;
/// Largest encrypted vault (address book and saved passwords).
const MAX_VAULT: usize = 1 << 20;
/// Largest organisation policy.
const MAX_POLICY: usize = 256 * 1024;
/// How many organisations one account can create.
const MAX_ORGS_PER_ACCOUNT: i64 = 20;
/// How long after logging in with a code turning two-factor authentication off needs no other.
const TOTP_FRESH: Duration = Duration::from_secs(600);

/// Password-login progress on this connection.
enum Login {
    None,
    Registering {
        username: String,
    },
    LoggingIn {
        username: String,
        user: Option<Box<db::UserRow>>,
        st: Box<ServerLoginState>,
    },
    /// Password reset: challenge sent, waiting for the recovery-key proof.
    Recovering {
        username: String,
        user: Option<Box<db::UserRow>>,
        challenge: [u8; 32],
    },
    /// Password reset: recovery key proven, waiting for the new password record.
    RecoveryProven {
        user_id: i64,
        username: String,
        identity_pk: [u8; 32],
    },
    /// Password right; waiting for the code from the authenticator app.
    TotpPending {
        user: Box<db::UserRow>,
    },
    User {
        user_id: i64,
        username: String,
        identity_pk: [u8; 32],
    },
}

struct Ctx {
    shared: Arc<Shared>,
    conn_id: u64,
    ip: IpAddr,
    /// The client's address as seen from here (its public address behind NAT).
    remote: SocketAddr,
    tx: mpsc::UnboundedSender<ServerFrame>,
    login: Login,
    /// The challenge of a device that is coming online.
    challenge: Option<DeviceChallenge>,
    /// The device online on this connection.
    device: Option<u64>,
    /// A two-factor secret being set up, until it is confirmed with a code.
    totp_pending: Option<TotpSecret>,
    /// When this connection's login last checked a code from the authenticator app: turning
    /// two-factor authentication off right after needs no second code.
    totp_verified: Option<std::time::Instant>,
    /// The same, read by the relay stream acceptor.
    device_slot: Arc<Mutex<Option<u64>>>,
}

pub async fn handle(shared: Arc<Shared>, incoming: quinn::Incoming) {
    let conn = match incoming.await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("handshake failed: {e}");
            return;
        }
    };
    let remote = conn.remote_address();
    let ip = remote.ip();
    let (mut send, mut recv) = match tokio::time::timeout(Duration::from_secs(10), conn.accept_bi()).await {
        Ok(Ok(s)) => s,
        _ => return,
    };

    let conn_id = shared.next_conn_id.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerFrame>();
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if write_msg(&mut send, &frame).await.is_err() {
                break;
            }
        }
    });

    let device_slot = Arc::new(Mutex::new(None));
    let streams = {
        let (conn, shared, slot) = (conn.clone(), shared.clone(), device_slot.clone());
        tokio::spawn(async move {
            while let Ok((s, r)) = conn.accept_bi().await {
                let device = *slot.lock().unwrap();
                let shared = shared.clone();
                tokio::spawn(async move { relay::handle_stream(&shared, device, s, r).await });
            }
        })
    };

    let mut ctx = Ctx {
        shared,
        conn_id,
        ip,
        remote,
        tx,
        login: Login::None,
        challenge: None,
        device: None,
        totp_pending: None,
        totp_verified: None,
        device_slot,
    };
    loop {
        let frame: ClientFrame = match read_msg(&mut recv).await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                tracing::debug!("control stream error: {e}");
                break;
            }
        };
        let result = ctx.dispatch(frame.req).await;
        if ctx.tx.send(ServerFrame::Response { id: frame.id, result }).is_err() {
            break;
        }
    }

    ctx.go_offline().await;
    streams.abort();
    drop(ctx);
    let _ = writer.await;
}

fn err(code: ErrorCode, msg: &str) -> ErrorInfo {
    ErrorInfo::new(code, msg)
}

fn internal(e: impl std::fmt::Display) -> ErrorInfo {
    tracing::error!("internal error: {e}");
    err(ErrorCode::Internal, "internal server error")
}

fn normalize_username(name: &str) -> Result<String, ErrorInfo> {
    somedesk_proto::normalize_username(name)
        .ok_or_else(|| err(ErrorCode::BadRequest, "username must be 3-32 characters: a-z, 0-9, '.', '_' or '-'"))
}

/// Rejects implausibly large key bundles (a sealed Ed25519 key is 48 bytes).
fn check_bundle(bundle: &EncryptedKeyBundle) -> Result<(), ErrorInfo> {
    if bundle.ciphertext.len() > 256 {
        return Err(err(ErrorCode::BadRequest, "key bundle too large"));
    }
    Ok(())
}

fn check_device_name(name: &str) -> Result<(), ErrorInfo> {
    if name.trim().is_empty() || name.len() > MAX_DEVICE_NAME {
        return Err(err(ErrorCode::BadRequest, "invalid device name"));
    }
    Ok(())
}

impl Ctx {
    fn limit(&self, what: &str, key: &str) -> Result<(), ErrorInfo> {
        let ok = self.shared.limiter.allow(&format!("{what}:ip:{}", self.ip), AUTH_LIMIT)
            && self.shared.limiter.allow(&format!("{what}:key:{key}"), AUTH_LIMIT);
        if ok {
            Ok(())
        } else {
            Err(err(ErrorCode::RateLimited, "too many attempts, try again in a minute"))
        }
    }

    fn device_info(&self, d: &db::DeviceRow) -> DeviceInfo {
        DeviceInfo {
            device_id: d.id,
            online: self.shared.online.contains_key(&d.id),
            identity: DeviceIdentity {
                device_pk: d.device_pk,
                name: d.name.clone(),
                account: d.account.as_ref().map(|a| a.cert.clone()),
                org: d.org.as_ref().map(|(_, cert)| cert.clone()),
            },
        }
    }

    fn require_device(&self) -> Result<u64, ErrorInfo> {
        self.device.ok_or_else(|| err(ErrorCode::NotAuthenticated, "bring the device online first"))
    }

    /// The account of this connection: the password login, or the account the device is signed
    /// in to.
    async fn account(&self) -> Result<i64, ErrorInfo> {
        if let Login::User { user_id, .. } = &self.login {
            return Ok(*user_id);
        }
        if let Some(device_id) = self.device {
            if let Some(a) = db::get_device(&self.shared.db, device_id).await.map_err(internal)?.and_then(|d| d.account)
            {
                return Ok(a.user_id);
            }
        }
        Err(err(ErrorCode::NotAuthenticated, "sign in to an account first"))
    }

    /// Updates which account an online device counts for, telling the account's other devices.
    fn set_online_account(&self, device_id: u64, user_id: Option<i64>) {
        let previous = self.shared.online.get_mut(&device_id).map(|mut o| std::mem::replace(&mut o.user_id, user_id));
        if let Some(Some(old)) = previous {
            self.broadcast_presence(old, device_id, false);
        }
        if let Some(new) = user_id {
            if self.shared.online.contains_key(&device_id) {
                self.broadcast_presence(new, device_id, true);
            }
        }
    }

    async fn dispatch(&mut self, req: Request) -> Result<Response, ErrorInfo> {
        let db = self.shared.db.clone();
        match req {
            Request::Hello { version } => {
                if version != somedesk_proto::PROTOCOL_VERSION {
                    return Err(err(ErrorCode::VersionMismatch, "unsupported protocol version"));
                }
                Ok(Response::Hello { version: somedesk_proto::PROTOCOL_VERSION })
            }

            Request::RegisterStart { username, message } => {
                let username = normalize_username(&username)?;
                self.limit("register", &username)?;
                if db::user_exists(&db, &username).await.map_err(internal)? {
                    return Err(err(ErrorCode::UsernameTaken, "username is already taken"));
                }
                let reply = opaque::server_register_start(&self.shared.opaque, &username, &message)
                    .map_err(|_| err(ErrorCode::BadRequest, "malformed registration request"))?;
                self.login = Login::Registering { username };
                Ok(Response::RegisterStart { message: reply })
            }

            Request::RegisterFinish { message, identity_pk, key_bundle, recovery } => {
                let Login::Registering { username } = std::mem::replace(&mut self.login, Login::None) else {
                    return Err(err(ErrorCode::BadRequest, "registration not started"));
                };
                check_bundle(&key_bundle)?;
                check_bundle(&recovery.key_bundle)?;
                let file = opaque::server_register_finish(&message)
                    .map_err(|_| err(ErrorCode::BadRequest, "malformed registration upload"))?;
                match db::create_user(&db, &username, &file, &identity_pk, &key_bundle, &recovery)
                    .await
                    .map_err(internal)?
                {
                    Some(user_id) => {
                        db::audit(&db, Some(user_id), None, "register", None).await;
                        Ok(Response::Ok)
                    }
                    None => Err(err(ErrorCode::UsernameTaken, "username is already taken")),
                }
            }

            Request::LoginStart { username, message } => {
                let username = normalize_username(&username).map_err(|_| err(ErrorCode::AuthFailed, "login failed"))?;
                self.limit("login", &username)?;
                let user = db::get_user(&db, &username).await.map_err(internal)?;
                let (reply, st) = opaque::server_login_start(
                    &self.shared.opaque,
                    user.as_ref().map(|u| u.password_file.as_slice()),
                    &username,
                    &message,
                )
                .map_err(|_| err(ErrorCode::BadRequest, "malformed login request"))?;
                self.login = Login::LoggingIn { username, user: user.map(Box::new), st: Box::new(st) };
                Ok(Response::LoginStart { message: reply })
            }

            Request::LoginFinish { message } => {
                let Login::LoggingIn { username, user, st } = std::mem::replace(&mut self.login, Login::None) else {
                    return Err(err(ErrorCode::BadRequest, "login not started"));
                };
                let verified = opaque::server_login_finish(*st, &message).is_ok();
                let Some(user) = user.filter(|_| verified) else {
                    tracing::info!(%username, ip = %self.ip, "failed login");
                    return Err(err(ErrorCode::AuthFailed, "wrong username or password"));
                };
                if user.totp_secret.is_some() {
                    self.login = Login::TotpPending { user };
                    return Ok(Response::TotpRequired);
                }
                Ok(self.logged_in(*user).await)
            }

            Request::LoginTotp { code } => {
                let Login::TotpPending { user } = std::mem::replace(&mut self.login, Login::None) else {
                    return Err(err(ErrorCode::BadRequest, "login not started"));
                };
                self.limit("totp", &user.username)?;
                if !self.check_totp(&user, &code).await? {
                    tracing::info!(username = %user.username, ip = %self.ip, "wrong two-factor code");
                    return Err(err(ErrorCode::AuthFailed, "wrong code"));
                }
                self.totp_verified = Some(std::time::Instant::now());
                Ok(self.logged_in(*user).await)
            }

            Request::SetRecovery { recovery } => {
                let Login::User { user_id, .. } = &self.login else {
                    return Err(err(ErrorCode::NotAuthenticated, "log in with your password first"));
                };
                check_bundle(&recovery.key_bundle)?;
                db::set_recovery(&db, *user_id, &recovery).await.map_err(internal)?;
                db::audit(&db, Some(*user_id), None, "recovery_key_set", None).await;
                Ok(Response::Ok)
            }

            Request::RecoveryStart { username } => {
                // Unknown users get a challenge too and fail at the next step exactly like a wrong
                // recovery key, so this does not reveal which usernames exist.
                let username = normalize_username(&username).unwrap_or_default();
                self.limit("recover", &username)?;
                let user =
                    if username.is_empty() { None } else { db::get_user(&db, &username).await.map_err(internal)? };
                let mut challenge = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut challenge);
                self.login = Login::Recovering { username, user: user.map(Box::new), challenge };
                Ok(Response::RecoveryChallenge { challenge })
            }

            Request::RecoveryProve { proof, message } => {
                let Login::Recovering { username, user, challenge } = std::mem::replace(&mut self.login, Login::None)
                else {
                    return Err(err(ErrorCode::BadRequest, "recovery not started"));
                };
                let proven = user.filter(|u| {
                    u.recovery
                        .as_ref()
                        .is_some_and(|r| recovery::verify_proof(&r.recovery_pk, &username, &challenge, &proof).is_ok())
                });
                let Some(user) = proven else {
                    tracing::info!(%username, ip = %self.ip, "failed recovery attempt");
                    return Err(err(ErrorCode::AuthFailed, "wrong username or recovery key"));
                };
                let reply = opaque::server_register_start(&self.shared.opaque, &username, &message)
                    .map_err(|_| err(ErrorCode::BadRequest, "malformed registration request"))?;
                let recovery_bundle = user.recovery.expect("checked above").key_bundle;
                self.login = Login::RecoveryProven { user_id: user.id, username, identity_pk: user.identity_pk };
                Ok(Response::RecoveryProve { identity_pk: user.identity_pk, recovery_bundle, message: reply })
            }

            Request::RecoveryFinish { message, key_bundle, recovery } => {
                let Login::RecoveryProven { user_id, username, identity_pk } =
                    std::mem::replace(&mut self.login, Login::None)
                else {
                    return Err(err(ErrorCode::BadRequest, "recovery not proven"));
                };
                check_bundle(&key_bundle)?;
                check_bundle(&recovery.key_bundle)?;
                let file = opaque::server_register_finish(&message)
                    .map_err(|_| err(ErrorCode::BadRequest, "malformed registration upload"))?;
                db::reset_password(&db, user_id, &file, &key_bundle, &recovery).await.map_err(internal)?;
                db::audit(&db, Some(user_id), None, "password_reset", Some(&self.ip.to_string())).await;
                tracing::info!(%username, "password reset with recovery key");
                self.login = Login::User { user_id, username, identity_pk };
                Ok(Response::Ok)
            }

            Request::DeviceChallenge { device_pk } => {
                self.limit("device", &hex::encode(device_pk))?;
                let challenge = DeviceChallenge::new(device_pk);
                let (server_pk, nonce) = (challenge.server_pk, challenge.nonce);
                self.challenge = Some(challenge);
                Ok(Response::DeviceChallenge { server_pk, nonce })
            }

            Request::DeviceAuth { name, proof, org } => {
                let Some(challenge) = self.challenge.take() else {
                    return Err(err(ErrorCode::BadRequest, "ask for a challenge first"));
                };
                if !challenge.verify(&proof) {
                    return Err(err(ErrorCode::AuthFailed, "the device could not prove its key"));
                }
                let name = match &org {
                    Some(cert) => cert.device_name.trim().to_owned(),
                    None => name.trim().to_owned(),
                };
                check_device_name(&name)?;
                let existing = db::get_device_by_key(&db, &challenge.device_pk).await.map_err(internal)?;
                if let Some(cert) = &org {
                    let enrolled = existing.as_ref().and_then(|d| d.org.as_ref()).is_some_and(|(_, c)| c == cert);
                    self.check_org_cert(cert, &challenge.device_pk, !enrolled).await?;
                }
                let signed_in = matches!(self.login, Login::User { .. }) || org.is_some();
                let device = match existing {
                    Some(d) => {
                        if !self.shared.open && d.account.is_none() && d.org.is_none() && !signed_in {
                            return Err(closed_server());
                        }
                        // Devices on an account are named by their certificate.
                        if d.account.is_none() && d.name != name {
                            db::set_device_name(&db, d.id, &name).await.map_err(internal)?;
                        }
                        db::get_device(&db, d.id).await.map_err(internal)?.ok_or_else(|| internal("device vanished"))?
                    }
                    None => {
                        if !self.shared.open && !signed_in {
                            return Err(closed_server());
                        }
                        let id = db::insert_device(&db, &challenge.device_pk, &name).await.map_err(internal)?;
                        db::audit(&db, None, Some(id), "device_registered", Some(&name)).await;
                        db::get_device(&db, id).await.map_err(internal)?.ok_or_else(|| internal("device vanished"))?
                    }
                };
                let device = match &org {
                    Some(cert) if device.org.as_ref().is_none_or(|(_, c)| c != cert) => {
                        db::set_device_org(&db, device.id, cert).await.map_err(internal)?;
                        db::audit(&db, None, Some(device.id), "device_enrolled", Some(&cert.org_id.to_string())).await;
                        db::get_device(&db, device.id)
                            .await
                            .map_err(internal)?
                            .ok_or_else(|| internal("device vanished"))?
                    }
                    _ => device,
                };
                self.go_offline().await;
                let user_id = device.account.as_ref().map(|a| a.user_id);
                self.device = Some(device.id);
                *self.device_slot.lock().unwrap() = Some(device.id);
                self.shared.online.insert(
                    device.id,
                    Online { conn_id: self.conn_id, user_id, tx: self.tx.clone(), candidates: Vec::new() },
                );
                if let Some(user_id) = user_id {
                    self.broadcast_presence(user_id, device.id, true);
                }
                let _ = db::touch_device(&db, device.id).await;
                tracing::info!(device_id = device.id, account = ?device.account.as_ref().map(|a| &a.username), "device online");
                Ok(Response::Authenticated { device: self.device_info(&device) })
            }

            Request::AttachDevice { cert } => {
                let device_id = self.require_device()?;
                let Login::User { user_id, username, identity_pk } = &self.login else {
                    return Err(err(ErrorCode::NotAuthenticated, "log in with your password first"));
                };
                let (user_id, username, identity_pk) = (*user_id, username.clone(), *identity_pk);
                if cert.username != username || cert.identity_pk != identity_pk {
                    return Err(err(ErrorCode::BadRequest, "certificate is not for this account"));
                }
                let device = db::get_device(&db, device_id)
                    .await
                    .map_err(internal)?
                    .ok_or_else(|| internal("device vanished"))?;
                if cert.device_pk != device.device_pk {
                    return Err(err(ErrorCode::BadRequest, "certificate is not for this device"));
                }
                check_device_name(&cert.device_name)?;
                verify_device_cert(&cert).map_err(|_| err(ErrorCode::BadRequest, "certificate signature invalid"))?;
                db::attach_device(&db, device_id, user_id, &cert).await.map_err(internal)?;
                db::audit(&db, Some(user_id), Some(device_id), "device_attached", Some(&cert.device_name)).await;
                self.set_online_account(device_id, Some(user_id));
                Ok(Response::Ok)
            }

            Request::DetachDevice => {
                let device_id = self.require_device()?;
                let user_id =
                    db::get_device(&db, device_id).await.map_err(internal)?.and_then(|d| d.account).map(|a| a.user_id);
                if db::detach_device(&db, device_id, None).await.map_err(internal)? {
                    db::audit(&db, user_id, Some(device_id), "device_detached", None).await;
                }
                self.set_online_account(device_id, None);
                Ok(Response::Ok)
            }

            Request::SetCandidates { local, allow_direct } => {
                let device_id = self.require_device()?;
                let mut candidates = Vec::new();
                if allow_direct {
                    // The address we see first: it works across NAT if the peer's packets open it.
                    candidates.push(self.remote);
                    candidates.extend(local.into_iter().filter(|a| *a != self.remote).take(MAX_CANDIDATES));
                }
                if let Some(mut o) = self.shared.online.get_mut(&device_id) {
                    if o.conn_id == self.conn_id {
                        o.candidates = candidates;
                    }
                }
                Ok(Response::Ok)
            }

            Request::ListDevices => {
                let user_id = self.account().await?;
                let devices = db::list_devices(&db, user_id).await.map_err(internal)?;
                Ok(Response::Devices(devices.iter().map(|d| self.device_info(d)).collect()))
            }

            Request::LookupDevice { device_id } => {
                self.require_device()?;
                match db::get_device(&db, device_id).await.map_err(internal)? {
                    Some(d) => Ok(Response::Device(self.device_info(&d))),
                    None => Err(err(ErrorCode::NotFound, "no device with this id")),
                }
            }

            Request::Connect { device_id } => {
                let my_device = self.require_device()?;
                if device_id == my_device {
                    return Err(err(ErrorCode::BadRequest, "cannot connect to yourself"));
                }
                let Some(target) = db::get_device(&db, device_id).await.map_err(internal)? else {
                    return Err(err(ErrorCode::NotFound, "no device with this id"));
                };
                let Some(me) = db::get_device(&db, my_device).await.map_err(internal)? else {
                    return Err(err(ErrorCode::NotAuthenticated, "this device is unknown"));
                };
                if me.org.is_some() {
                    return Err(err(ErrorCode::Forbidden, "devices enrolled by an organisation don't start sessions"));
                }
                let session_id = relay::new_session_id();
                let host = self.shared.online.get(&device_id).map(|o| (o.tx.clone(), o.candidates.clone()));
                let Some((host_tx, host_candidates)) = host else {
                    return Err(err(ErrorCode::Offline, "the device is offline"));
                };
                self.shared
                    .sessions
                    .lock()
                    .unwrap()
                    .insert(session_id, relay::PendingSession::new(my_device, device_id));
                let from = self.device_info(&me);
                // Direct connections only if both sides want them; otherwise neither learns the
                // other's addresses.
                let my_candidates =
                    self.shared.online.get(&my_device).map(|o| o.candidates.clone()).unwrap_or_default();
                let (my_candidates, host_candidates) = if my_candidates.is_empty() || host_candidates.is_empty() {
                    (Vec::new(), Vec::new())
                } else {
                    (my_candidates, host_candidates)
                };
                let event = Event::IncomingSession { session_id, from, candidates: my_candidates };
                if host_tx.send(ServerFrame::Event(event)).is_err() {
                    self.shared.sessions.lock().unwrap().remove(&session_id);
                    return Err(err(ErrorCode::Offline, "the device is offline"));
                }
                let user_id = me.account.as_ref().map(|a| a.user_id);
                db::audit(&db, user_id, Some(my_device), "connect", Some(&device_id.to_string())).await;
                Ok(Response::Connect { session_id, host: self.device_info(&target), candidates: host_candidates })
            }

            Request::RemoveDevice { device_id } => {
                let user_id = self.account().await?;
                if !db::detach_device(&db, device_id, Some(user_id)).await.map_err(internal)? {
                    return Err(err(ErrorCode::NotFound, "no such device on your account"));
                }
                self.set_online_account(device_id, None);
                if let Some(o) = self.shared.online.get(&device_id) {
                    let _ = o.tx.send(ServerFrame::Event(Event::SignedOut));
                }
                db::audit(&db, Some(user_id), Some(device_id), "device_removed", None).await;
                Ok(Response::Ok)
            }

            Request::GetVault => {
                let user_id = self.account().await?;
                let (version, blob) = db::get_vault(&db, user_id).await.map_err(internal)?;
                Ok(Response::Vault { version, blob })
            }

            Request::PutVault { base_version, blob } => {
                let user_id = self.account().await?;
                if blob.len() > MAX_VAULT {
                    return Err(err(ErrorCode::BadRequest, "the vault is too large"));
                }
                match db::put_vault(&db, user_id, base_version, &blob).await.map_err(internal)? {
                    Some(version) => Ok(Response::VaultSaved { version }),
                    None => Err(err(ErrorCode::Conflict, "the vault changed in the meantime")),
                }
            }

            Request::AccountInfo => {
                let user = self.account_user().await?;
                Ok(Response::Account { username: user.username, totp_enabled: user.totp_secret.is_some() })
            }

            Request::TotpBegin => {
                let Login::User { .. } = &self.login else {
                    return Err(err(ErrorCode::NotAuthenticated, "log in with your password first"));
                };
                let secret = TotpSecret::generate();
                let bytes = secret.as_bytes().to_vec();
                self.totp_pending = Some(secret);
                Ok(Response::TotpSecret { secret: bytes })
            }

            Request::TotpEnable { code } => {
                let Login::User { user_id, username, .. } = &self.login else {
                    return Err(err(ErrorCode::NotAuthenticated, "log in with your password first"));
                };
                let (user_id, username) = (*user_id, username.clone());
                self.limit("totp", &username)?;
                let Some(secret) = self.totp_pending.as_ref() else {
                    return Err(err(ErrorCode::BadRequest, "start setting up two-factor authentication first"));
                };
                let Some(step) = secret.verify(&code, totp::now(), None) else {
                    return Err(err(ErrorCode::AuthFailed, "wrong code"));
                };
                db::set_totp(&db, user_id, Some(secret.as_bytes()), Some(step)).await.map_err(internal)?;
                self.totp_pending = None;
                db::audit(&db, Some(user_id), None, "totp_enabled", None).await;
                self.broadcast_account_changed(user_id);
                Ok(Response::Ok)
            }

            Request::TotpDisable { code } => {
                let Login::User { user_id, .. } = &self.login else {
                    return Err(err(ErrorCode::NotAuthenticated, "log in with your password first"));
                };
                let user_id = *user_id;
                let user = db::get_user_by_id(&db, user_id)
                    .await
                    .map_err(internal)?
                    .ok_or_else(|| internal("user vanished"))?;
                self.limit("totp", &user.username)?;
                if user.totp_secret.is_none() {
                    return Ok(Response::Ok);
                }
                let fresh = self.totp_verified.is_some_and(|t| t.elapsed() < TOTP_FRESH);
                if !(fresh && code.is_empty()) && !self.check_totp(&user, &code).await? {
                    return Err(err(ErrorCode::AuthFailed, "wrong code"));
                }
                db::set_totp(&db, user_id, None, None).await.map_err(internal)?;
                db::audit(&db, Some(user_id), None, "totp_disabled", None).await;
                self.broadcast_account_changed(user_id);
                Ok(Response::Ok)
            }

            Request::LookupUser { username } => {
                if self.device.is_none() && !matches!(self.login, Login::User { .. }) {
                    return Err(err(ErrorCode::NotAuthenticated, "bring the device online first"));
                }
                let username = normalize_username(&username)?;
                self.limit("lookup_user", &username)?;
                match db::get_user(&db, &username).await.map_err(internal)? {
                    Some(u) => Ok(Response::User { username: u.username, identity_pk: u.identity_pk }),
                    None => Err(err(ErrorCode::NotFound, "no account with this name")),
                }
            }

            Request::CreateOrg { name, org_pk, sealed_key } => {
                let Login::User { user_id, .. } = &self.login else {
                    return Err(err(ErrorCode::NotAuthenticated, "log in with your password first"));
                };
                let user_id = *user_id;
                let name = name.trim().to_owned();
                if name.is_empty() || name.len() > MAX_DEVICE_NAME || sealed_key.len() > 256 {
                    return Err(err(ErrorCode::BadRequest, "invalid organisation"));
                }
                if db::count_orgs_created_by(&db, user_id).await.map_err(internal)? >= MAX_ORGS_PER_ACCOUNT {
                    return Err(err(ErrorCode::Forbidden, "this account has created as many organisations as it can"));
                }
                let org_id = db::create_org(&db, &name, &org_pk, user_id, &sealed_key).await.map_err(internal)?;
                db::audit(&db, Some(user_id), None, "org_created", Some(&org_id.to_string())).await;
                Ok(Response::OrgCreated { org_id })
            }

            Request::ListOrgs => {
                let user = self.account_user().await?;
                let mut orgs = Vec::new();
                for (org, joined) in db::list_member_orgs(&db, user.id).await.map_err(internal)? {
                    if org_role(&org, &user).is_none() {
                        continue;
                    }
                    let sealed_key =
                        if joined { db::get_org_key(&db, org.id, user.id).await.map_err(internal)? } else { None };
                    let rotations = db::org_rotations(&db, org.id).await.map_err(internal)?;
                    orgs.push(OrgInfo {
                        org_id: org.id,
                        name: org.name,
                        org_pk: org.org_pk,
                        sealed_key,
                        policy: org.policy,
                        rotations,
                        joined,
                    });
                }
                Ok(Response::Orgs(orgs))
            }

            Request::PutOrgPolicy { org_id, policy } => {
                let user = self.account_user().await?;
                let org = self.org(org_id).await?;
                if self.member_role(&org, &user).await? != Some(true) {
                    return Err(err(ErrorCode::Forbidden, "only the organisation's admins can change its policy"));
                }
                let decoded = self.check_next_policy(&org, &org.org_pk, &policy)?;
                let members = self.member_ids(&decoded).await?;
                if !db::put_org_policy(&db, org_id, decoded.version, &policy, &members).await.map_err(internal)? {
                    return Err(err(ErrorCode::Conflict, "a newer policy exists"));
                }
                let detail = format!("{org_id} v{}", decoded.version);
                db::audit(&db, Some(user.id), None, "org_policy", Some(&detail)).await;
                self.broadcast_org_changed(org_id, &decoded).await;
                Ok(Response::Ok)
            }

            Request::RotateOrgKey { org_id, rotation, policy, sealed_keys } => {
                let user = self.account_user().await?;
                let org = self.org(org_id).await?;
                if self.member_role(&org, &user).await? != Some(true) {
                    return Err(err(ErrorCode::Forbidden, "only the organisation's admins can replace its key"));
                }
                let bad = |m: &str| err(ErrorCode::BadRequest, m);
                let (to_pk, since) =
                    somedesk_crypto::org::follow_rotations(org_id, &org.org_pk, std::slice::from_ref(&rotation))
                        .map_err(|_| bad("the key rotation is not signed with the organisation's key"))?;
                if since == 0 || to_pk == org.org_pk {
                    return Err(bad("the key rotation doesn't start at the organisation's key"));
                }
                let decoded = self.check_next_policy(&org, &to_pk, &policy)?;
                if decoded.version != rotation.version {
                    return Err(bad("the key rotation is for another policy"));
                }
                // Every admin of the new policy gets the new key, nobody else.
                let mut keys = Vec::new();
                for m in decoded.members.iter().filter(|m| m.admin) {
                    let sealed = sealed_keys.iter().find(|(u, _)| u == &m.username).map(|(_, k)| k);
                    let target = db::get_user(&db, &m.username).await.map_err(internal)?;
                    match (sealed, target) {
                        (Some(k), Some(t)) if k.len() <= 256 && t.identity_pk == m.identity_pk => {
                            keys.push((t.id, k.clone()))
                        }
                        _ => return Err(bad("the new key isn't sealed to every admin")),
                    }
                }
                let members = self.member_ids(&decoded).await?;
                if !db::rotate_org_key(&db, org_id, &rotation, &policy, &members, &keys).await.map_err(internal)? {
                    return Err(err(ErrorCode::Conflict, "a newer policy exists"));
                }
                let detail = format!("{org_id} v{}", decoded.version);
                db::audit(&db, Some(user.id), None, "org_key_rotated", Some(&detail)).await;
                self.broadcast_org_changed(org_id, &decoded).await;
                Ok(Response::Ok)
            }

            Request::AnswerOrgInvite { org_id, join } => {
                let user = self.account_user().await?;
                if !db::answer_org_invite(&db, org_id, user.id, join).await.map_err(internal)? {
                    return Err(err(ErrorCode::NotFound, "no invitation to this organisation"));
                }
                let detail = format!("{org_id} {}", if join { "joined" } else { "declined" });
                db::audit(&db, Some(user.id), None, "org_invite", Some(&detail)).await;
                Ok(Response::Ok)
            }

            Request::ShareOrgKey { org_id, username, sealed_key } => {
                let user = self.account_user().await?;
                let org = self.org(org_id).await?;
                if self.member_role(&org, &user).await? != Some(true) {
                    return Err(err(ErrorCode::Forbidden, "only the organisation's admins can share its key"));
                }
                let username = normalize_username(&username)?;
                let Some(target) = db::get_user(&db, &username).await.map_err(internal)? else {
                    return Err(err(ErrorCode::NotFound, "no account with this name"));
                };
                if sealed_key.len() > 256 {
                    return Err(err(ErrorCode::BadRequest, "invalid key"));
                }
                db::put_org_key(&db, org_id, target.id, &sealed_key).await.map_err(internal)?;
                Ok(Response::Ok)
            }

            Request::GetOrgPolicy { org_id } => {
                let org = self.org(org_id).await?;
                if !self.may_read_org(&org).await? {
                    return Err(err(ErrorCode::Forbidden, "not part of this organisation"));
                }
                let rotations = db::org_rotations(&db, org_id).await.map_err(internal)?;
                Ok(Response::OrgPolicy(org.policy.map(|policy| PolicyBundle { policy, rotations })))
            }

            Request::ListOrgDevices { org_id } => {
                let user = self.account_user().await?;
                let org = self.org(org_id).await?;
                if self.member_role(&org, &user).await?.is_none() {
                    return Err(err(ErrorCode::Forbidden, "not part of this organisation"));
                }
                let devices = db::list_org_devices(&db, org_id).await.map_err(internal)?;
                Ok(Response::Devices(devices.iter().map(|d| self.device_info(d)).collect()))
            }

            Request::Ping => Ok(Response::Pong),
        }
    }

    /// Finishes a password login (after the two-factor code, if the account has one).
    async fn logged_in(&mut self, user: db::UserRow) -> Response {
        db::audit(&self.shared.db, Some(user.id), None, "login", Some(&self.ip.to_string())).await;
        self.login = Login::User { user_id: user.id, username: user.username.clone(), identity_pk: user.identity_pk };
        Response::LoginFinish {
            identity_pk: user.identity_pk,
            has_recovery: user.recovery.is_some(),
            key_bundle: user.key_bundle,
        }
    }

    /// Checks a code from the account's authenticator app, each code only once.
    async fn check_totp(&self, user: &db::UserRow, code: &str) -> Result<bool, ErrorInfo> {
        let Some(secret) = user.totp_secret.as_deref() else { return Ok(false) };
        let last = user.totp_last_step.map(|s| s as u64);
        match TotpSecret::from_bytes(secret).verify(code, totp::now(), last) {
            Some(step) => db::use_totp_step(&self.shared.db, user.id, step).await.map_err(internal),
            None => Ok(false),
        }
    }

    /// The account of this connection, read fresh.
    async fn account_user(&self) -> Result<db::UserRow, ErrorInfo> {
        let user_id = self.account().await?;
        db::get_user_by_id(&self.shared.db, user_id).await.map_err(internal)?.ok_or_else(|| internal("user vanished"))
    }

    async fn org(&self, org_id: u64) -> Result<db::OrgRow, ErrorInfo> {
        db::get_org(&self.shared.db, org_id)
            .await
            .map_err(internal)?
            .ok_or_else(|| err(ErrorCode::NotFound, "no such organisation"))
    }

    /// Checks an enrolled device's certificate: signed by a service worker of an organisation
    /// with that key; for a new enrollment, also that the worker may still enroll devices.
    async fn check_org_cert(
        &self,
        cert: &OrgDeviceCert,
        device_pk: &[u8; 32],
        enrolling: bool,
    ) -> Result<(), ErrorInfo> {
        let bad = || err(ErrorCode::Forbidden, "the enrollment key is not valid for this organisation");
        somedesk_crypto::org::verify_device_cert(cert).map_err(|_| bad())?;
        if &cert.device_pk != device_pk {
            return Err(bad());
        }
        let org = db::get_org(&self.shared.db, cert.org_id).await.map_err(internal)?.ok_or_else(bad)?;
        // Enrollment keys carry the organisation key of when they were made; it may have been
        // replaced since.
        if org.org_pk != cert.org_pk {
            let rotations = db::org_rotations(&self.shared.db, org.id).await.map_err(internal)?;
            if !rotations.iter().any(|r| r.from_pk == cert.org_pk) {
                return Err(bad());
            }
        }
        if enrolling {
            let policy = org
                .policy
                .as_ref()
                .and_then(|p| somedesk_crypto::org::verify_policy(p, &org.org_pk).ok())
                .ok_or_else(bad)?;
            if !policy.worker_can_enroll(&cert.worker_pk, totp::now() as i64) {
                return Err(err(ErrorCode::Forbidden, "this enrollment key was revoked or has expired"));
            }
        }
        Ok(())
    }

    /// Members read their organisation's policy, and so do its own devices.
    async fn may_read_org(&self, org: &db::OrgRow) -> Result<bool, ErrorInfo> {
        if let Some(device_id) = self.device {
            let device = db::get_device(&self.shared.db, device_id).await.map_err(internal)?;
            if device.is_some_and(|d| d.org.is_some_and(|(id, _)| id == org.id)) {
                return Ok(true);
            }
        }
        match self.account_user().await {
            Ok(user) => Ok(self.member_role(org, &user).await?.is_some()),
            Err(_) => Ok(false),
        }
    }

    /// [`org_role`], for an account that joined the organisation (not just invited to it).
    async fn member_role(&self, org: &db::OrgRow, user: &db::UserRow) -> Result<Option<bool>, ErrorInfo> {
        let Some(role) = org_role(org, user) else { return Ok(None) };
        let joined = db::org_joined(&self.shared.db, org.id, user.id).await.map_err(internal)?;
        Ok((joined == Some(true)).then_some(role))
    }

    /// Checks a policy an admin wants to publish next: signed with `org_pk`, for this
    /// organisation, made from the current one, and not too large.
    fn check_next_policy(
        &self,
        org: &db::OrgRow,
        org_pk: &[u8; 32],
        policy: &SignedPolicy,
    ) -> Result<OrgPolicy, ErrorInfo> {
        if policy.policy.len() > MAX_POLICY {
            return Err(err(ErrorCode::BadRequest, "the policy is too large"));
        }
        let decoded = somedesk_crypto::org::verify_policy(policy, org_pk)
            .map_err(|_| err(ErrorCode::BadRequest, "the policy is not signed with the organisation's key"))?;
        if decoded.org_id != org.id || i64::try_from(decoded.version).is_err() {
            return Err(err(ErrorCode::BadRequest, "invalid policy"));
        }
        // Two admins changing it at once: the second has to start from the first one's.
        if decoded.prev_hash != org.policy.as_ref().map_or([0; 32], policy_hash) {
            return Err(err(ErrorCode::Conflict, "a newer policy exists"));
        }
        Ok(decoded)
    }

    /// The accounts a policy lists (those whose identity key it has right).
    async fn member_ids(&self, policy: &OrgPolicy) -> Result<Vec<i64>, ErrorInfo> {
        let mut ids = Vec::new();
        for m in &policy.members {
            if let Some(u) = db::get_user(&self.shared.db, &m.username).await.map_err(internal)? {
                if u.identity_pk == m.identity_pk {
                    ids.push(u.id);
                }
            }
        }
        Ok(ids)
    }

    fn broadcast_account_changed(&self, user_id: i64) {
        for entry in self.shared.online.iter() {
            if entry.user_id == Some(user_id) {
                let _ = entry.tx.send(ServerFrame::Event(Event::AccountChanged));
            }
        }
    }

    /// Tells the organisation's online devices and members about a new policy.
    async fn broadcast_org_changed(&self, org_id: u64, policy: &OrgPolicy) {
        let devices = db::list_org_devices(&self.shared.db, org_id).await.unwrap_or_default();
        let mut members = Vec::new();
        for m in &policy.members {
            if let Ok(Some(u)) = db::get_user(&self.shared.db, &m.username).await {
                members.push(u.id);
            }
        }
        for entry in self.shared.online.iter() {
            let is_device = devices.iter().any(|d| d.id == *entry.key());
            let is_member = entry.user_id.is_some_and(|u| members.contains(&u));
            if is_device || is_member {
                let _ = entry.tx.send(ServerFrame::Event(Event::OrgPolicyChanged { org_id }));
            }
        }
    }

    fn broadcast_presence(&self, user_id: i64, device_id: u64, online: bool) {
        for entry in self.shared.online.iter() {
            if entry.user_id == Some(user_id) && *entry.key() != device_id {
                let _ = entry.tx.send(ServerFrame::Event(Event::DevicePresence { device_id, online }));
            }
        }
    }

    async fn go_offline(&mut self) {
        let Some(device_id) = self.device.take() else { return };
        *self.device_slot.lock().unwrap() = None;
        if let Some((_, o)) = self.shared.online.remove_if(&device_id, |_, o| o.conn_id == self.conn_id) {
            if let Some(user_id) = o.user_id {
                self.broadcast_presence(user_id, device_id, false);
            }
            let _ = db::touch_device(&self.shared.db, device_id).await;
            tracing::info!(device_id, "device offline");
        }
    }
}

/// The account's role in an organisation: `Some(true)` for admins, `Some(false)` for other
/// members. Membership is what the organisation's signed policy says; before the first policy,
/// its creator is its admin.
fn org_role(org: &db::OrgRow, user: &db::UserRow) -> Option<bool> {
    match &org.policy {
        Some(signed) => {
            let policy = somedesk_crypto::org::verify_policy(signed, &org.org_pk).ok()?;
            let m = policy.member(&user.username).filter(|m| m.identity_pk == user.identity_pk)?;
            Some(m.admin)
        }
        None => (org.created_by == Some(user.id)).then_some(true),
    }
}

fn closed_server() -> ErrorInfo {
    err(ErrorCode::Forbidden, "this server only lets in devices signed in to one of its accounts")
}
