//! One client connection: the control stream plus any relay streams.

use crate::{db, relay, Online, Shared};
use sha2::{Digest, Sha256};
use somedesk_crypto::keys::verify_device_cert;
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

enum AuthState {
    Anonymous,
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
    Device {
        user_id: i64,
        username: String,
        device_id: u64,
    },
}

struct Ctx {
    shared: Arc<Shared>,
    conn_id: u64,
    ip: IpAddr,
    /// The client's address as seen from here (its public address behind NAT).
    remote: SocketAddr,
    tx: mpsc::UnboundedSender<ServerFrame>,
    state: AuthState,
    /// Device id once authenticated, read by the relay stream acceptor.
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

    let mut ctx = Ctx { shared, conn_id, ip, remote, tx, state: AuthState::Anonymous, device_slot };
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

fn token_hash(token: &[u8; 32]) -> Vec<u8> {
    Sha256::digest(token).to_vec()
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
            username: d.username.clone(),
            name: d.name.clone(),
            online: self.shared.online.contains_key(&d.id),
            cert: d.cert.clone(),
        }
    }

    fn require_device(&self) -> Result<(i64, String, u64), ErrorInfo> {
        match &self.state {
            AuthState::Device { user_id, username, device_id } => Ok((*user_id, username.clone(), *device_id)),
            _ => Err(err(ErrorCode::NotAuthenticated, "authenticate as a device first")),
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
                self.state = AuthState::Registering { username };
                Ok(Response::RegisterStart { message: reply })
            }

            Request::RegisterFinish { message, identity_pk, key_bundle, recovery } => {
                let AuthState::Registering { username } = std::mem::replace(&mut self.state, AuthState::Anonymous)
                else {
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
                self.state = AuthState::LoggingIn { username, user: user.map(Box::new), st: Box::new(st) };
                Ok(Response::LoginStart { message: reply })
            }

            Request::LoginFinish { message } => {
                let AuthState::LoggingIn { username, user, st } =
                    std::mem::replace(&mut self.state, AuthState::Anonymous)
                else {
                    return Err(err(ErrorCode::BadRequest, "login not started"));
                };
                let verified = opaque::server_login_finish(*st, &message).is_ok();
                let Some(user) = user.filter(|_| verified) else {
                    tracing::info!(%username, ip = %self.ip, "failed login");
                    return Err(err(ErrorCode::AuthFailed, "wrong username or password"));
                };
                db::audit(&db, Some(user.id), None, "login", Some(&self.ip.to_string())).await;
                self.state = AuthState::User { user_id: user.id, username, identity_pk: user.identity_pk };
                Ok(Response::LoginFinish {
                    identity_pk: user.identity_pk,
                    has_recovery: user.recovery.is_some(),
                    key_bundle: user.key_bundle,
                })
            }

            Request::SetRecovery { recovery } => {
                let AuthState::User { user_id, .. } = &self.state else {
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
                self.state = AuthState::Recovering { username, user: user.map(Box::new), challenge };
                Ok(Response::RecoveryChallenge { challenge })
            }

            Request::RecoveryProve { proof, message } => {
                let AuthState::Recovering { username, user, challenge } =
                    std::mem::replace(&mut self.state, AuthState::Anonymous)
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
                self.state = AuthState::RecoveryProven { user_id: user.id, username, identity_pk: user.identity_pk };
                Ok(Response::RecoveryProve { identity_pk: user.identity_pk, recovery_bundle, message: reply })
            }

            Request::RecoveryFinish { message, key_bundle, recovery } => {
                let AuthState::RecoveryProven { user_id, username, identity_pk } =
                    std::mem::replace(&mut self.state, AuthState::Anonymous)
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
                self.state = AuthState::User { user_id, username, identity_pk };
                Ok(Response::Ok)
            }

            Request::RegisterDevice { cert } => {
                let AuthState::User { user_id, username, identity_pk } = &self.state else {
                    return Err(err(ErrorCode::NotAuthenticated, "log in with your password first"));
                };
                if cert.username != *username || cert.identity_pk != *identity_pk {
                    return Err(err(ErrorCode::BadRequest, "certificate is not for this account"));
                }
                if cert.device_name.trim().is_empty() || cert.device_name.len() > MAX_DEVICE_NAME {
                    return Err(err(ErrorCode::BadRequest, "invalid device name"));
                }
                verify_device_cert(&cert).map_err(|_| err(ErrorCode::BadRequest, "certificate signature invalid"))?;
                let mut token = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);
                let device_id = db::insert_device(&db, *user_id, &cert, &token_hash(&token)).await.map_err(internal)?;
                db::audit(&db, Some(*user_id), Some(device_id), "device_registered", Some(&cert.device_name)).await;
                Ok(Response::DeviceRegistered { device_id, token })
            }

            Request::TokenAuth { device_id, token } => {
                self.limit("token", &device_id.to_string())?;
                let device = db::get_device(&db, device_id).await.map_err(internal)?;
                let Some(device) = device.filter(|d| d.token_hash == token_hash(&token)) else {
                    return Err(err(ErrorCode::AuthFailed, "unknown device or invalid token"));
                };
                self.go_offline().await;
                self.state =
                    AuthState::Device { user_id: device.user_id, username: device.username.clone(), device_id };
                *self.device_slot.lock().unwrap() = Some(device_id);
                self.shared.online.insert(
                    device_id,
                    Online {
                        conn_id: self.conn_id,
                        user_id: device.user_id,
                        tx: self.tx.clone(),
                        candidates: Vec::new(),
                    },
                );
                self.broadcast_presence(device.user_id, device_id, true);
                let _ = db::touch_device(&db, device_id).await;
                tracing::info!(device_id, user = %device.username, "device online");
                Ok(Response::Authenticated { username: device.username.clone(), device: self.device_info(&device) })
            }

            Request::SetCandidates { local, allow_direct } => {
                let (_, _, device_id) = self.require_device()?;
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
                let (user_id, _, _) = self.require_device()?;
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
                let (user_id, _, my_device) = self.require_device()?;
                if device_id == my_device {
                    return Err(err(ErrorCode::BadRequest, "cannot connect to yourself"));
                }
                let Some(target) = db::get_device(&db, device_id).await.map_err(internal)? else {
                    return Err(err(ErrorCode::NotFound, "no device with this id"));
                };
                let Some(me) = db::get_device(&db, my_device).await.map_err(internal)? else {
                    return Err(err(ErrorCode::NotAuthenticated, "this device was removed"));
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
                db::audit(&db, Some(user_id), Some(my_device), "connect", Some(&device_id.to_string())).await;
                Ok(Response::Connect { session_id, host: self.device_info(&target), candidates: host_candidates })
            }

            Request::RemoveDevice { device_id } => {
                let user_id = match &self.state {
                    AuthState::User { user_id, .. } | AuthState::Device { user_id, .. } => *user_id,
                    _ => return Err(err(ErrorCode::NotAuthenticated, "not logged in")),
                };
                if !db::delete_device(&db, user_id, device_id).await.map_err(internal)? {
                    return Err(err(ErrorCode::NotFound, "no such device on your account"));
                }
                self.shared.online.remove(&device_id);
                db::audit(&db, Some(user_id), Some(device_id), "device_removed", None).await;
                Ok(Response::Ok)
            }

            Request::Ping => Ok(Response::Pong),
        }
    }

    fn broadcast_presence(&self, user_id: i64, device_id: u64, online: bool) {
        for entry in self.shared.online.iter() {
            if entry.user_id == user_id && *entry.key() != device_id {
                let _ = entry.tx.send(ServerFrame::Event(Event::DevicePresence { device_id, online }));
            }
        }
    }

    async fn go_offline(&mut self) {
        if let AuthState::Device { user_id, device_id, .. } = self.state {
            let removed = self.shared.online.remove_if(&device_id, |_, o| o.conn_id == self.conn_id).is_some();
            if removed {
                self.broadcast_presence(user_id, device_id, false);
                let _ = db::touch_device(&self.shared.db, device_id).await;
                tracing::info!(device_id, "device offline");
            }
        }
    }
}
