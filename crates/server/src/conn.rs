//! One client connection: the control stream plus any relay streams.

use crate::{db, relay, Online, Shared};
use somedesk_crypto::keys::{verify_device_cert, DeviceChallenge};
use somedesk_crypto::opaque::{self, ServerLoginState};
use somedesk_crypto::recovery;
use somedesk_proto::control::*;
use somedesk_proto::frame::{read_msg, write_msg};
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

    let mut ctx =
        Ctx { shared, conn_id, ip, remote, tx, login: Login::None, challenge: None, device: None, device_slot };
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
                db::audit(&db, Some(user.id), None, "login", Some(&self.ip.to_string())).await;
                self.login = Login::User { user_id: user.id, username, identity_pk: user.identity_pk };
                Ok(Response::LoginFinish {
                    identity_pk: user.identity_pk,
                    has_recovery: user.recovery.is_some(),
                    key_bundle: user.key_bundle,
                })
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

            Request::DeviceAuth { name, proof } => {
                let Some(challenge) = self.challenge.take() else {
                    return Err(err(ErrorCode::BadRequest, "ask for a challenge first"));
                };
                if !challenge.verify(&proof) {
                    return Err(err(ErrorCode::AuthFailed, "the device could not prove its key"));
                }
                let name = name.trim().to_owned();
                check_device_name(&name)?;
                let signed_in = matches!(self.login, Login::User { .. });
                let device = match db::get_device_by_key(&db, &challenge.device_pk).await.map_err(internal)? {
                    Some(d) => {
                        if !self.shared.open && d.account.is_none() && !signed_in {
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

            Request::Ping => Ok(Response::Pong),
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

fn closed_server() -> ErrorInfo {
    err(ErrorCode::Forbidden, "this server only lets in devices signed in to one of its accounts")
}
