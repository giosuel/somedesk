//! Who may get in. A viewer reaches a host in one of four ways:
//!
//! 1. **By ID** — the person at the host accepts or declines, every time.
//! 2. **Unattended, with the host's password and authenticator code** — set up on the host
//!    itself. The password is checked end to end inside the session with OPAQUE, bound to the
//!    session ([`somedesk_crypto::unattended`]); the server never sees it, and neither would a
//!    fake host. Codes work once, and wrong attempts lock the host for a growing while.
//! 3. **Unattended, from the same account** — only if the host turned it on, and only while the
//!    account has two-factor authentication.
//! 4. **Unattended, by an organisation's policy** — for devices a service worker enrolled.
//!
//! The viewer's first message in the session says whether it brings a password; the host
//! decides the rest from the viewer's verified identity.

use crate::session::Channel;
use crate::{ClientError, Result};
use serde::{Deserialize, Serialize};
use somedesk_crypto::totp::{self, TotpSecret};
use somedesk_crypto::unattended::{self as opaque, HostRecord};
use somedesk_proto::control::DeviceIdentity;
use somedesk_proto::session::SessionMsg;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Wrong attempts allowed before the host makes the next one wait.
const FREE_ATTEMPTS: u32 = 3;
/// The first wait, doubling with every further wrong attempt, up to [`MAX_LOCK`].
const FIRST_LOCK: i64 = 30;
const MAX_LOCK: i64 = 3600;
/// How long a viewer has to finish the password exchange.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// The host's unattended-access setup.
#[derive(Clone, Serialize, Deserialize)]
struct Config {
    opaque_setup: Vec<u8>,
    password_file: Vec<u8>,
    totp_secret: Vec<u8>,
    #[serde(default)]
    last_step: Option<u64>,
    #[serde(default)]
    failures: u32,
    #[serde(default)]
    locked_until: i64,
}

/// Unattended access (password and authenticator code) of this host, kept in a file that only
/// the user can read. It holds no password: an OPAQUE password file and the authenticator
/// secret.
pub struct Unattended {
    path: PathBuf,
    config: Option<Config>,
}

/// A setup that waits for its first code: the authenticator app has to be set up before
/// unattended access goes on.
pub struct PendingSetup {
    record: HostRecord,
    pub secret: TotpSecret,
}

/// The outcome of a password attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Rejected(String),
}

fn now() -> i64 {
    totp::now() as i64
}

impl Unattended {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let config = match std::fs::read(path) {
            Ok(bytes) => Some(serde_json::from_slice(&bytes).map_err(std::io::Error::other)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        Ok(Self { path: path.to_owned(), config })
    }

    fn save(&self) -> std::io::Result<()> {
        use std::io::Write;
        let Some(config) = &self.config else {
            return match std::fs::remove_file(&self.path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            };
        };
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&tmp)?;
        f.write_all(&serde_json::to_vec(config).expect("serializable"))?;
        f.sync_all()?;
        std::fs::rename(tmp, &self.path)
    }

    /// Whether unattended access with a password is set up.
    pub fn enabled(&self) -> bool {
        self.config.is_some()
    }

    /// Starts setting up (or replacing) the password. Nothing changes until
    /// [`Unattended::confirm`] gets a code from the authenticator app.
    pub fn begin(host_pk: &[u8; 32], password: &str) -> Result<PendingSetup> {
        if password.chars().count() < 10 {
            return Err(ClientError::Other("use at least 10 characters for unattended access".into()));
        }
        Ok(PendingSetup { record: opaque::create_record(host_pk, password)?, secret: TotpSecret::generate() })
    }

    /// Turns unattended access on, once a code shows the authenticator app is set up.
    pub fn confirm(&mut self, pending: PendingSetup, code: &str) -> Result<()> {
        let Some(step) = pending.secret.verify(code, totp::now(), None) else {
            return Err(ClientError::Other("wrong code: check the time on both devices and try again".into()));
        };
        self.config = Some(Config {
            opaque_setup: pending.record.setup,
            password_file: pending.record.password_file,
            totp_secret: pending.secret.as_bytes().to_vec(),
            last_step: Some(step),
            failures: 0,
            locked_until: 0,
        });
        self.save().map_err(|e| ClientError::Other(e.to_string()))
    }

    /// Turns unattended access off.
    pub fn disable(&mut self) -> Result<()> {
        self.config = None;
        self.save().map_err(|e| ClientError::Other(e.to_string()))
    }

    /// Seconds until the next attempt is allowed, after too many wrong ones.
    pub fn locked_for(&self) -> i64 {
        self.config.as_ref().map_or(0, |c| (c.locked_until - now()).max(0))
    }

    fn record_failure(&mut self) {
        if let Some(c) = &mut self.config {
            c.failures += 1;
            if c.failures >= FREE_ATTEMPTS {
                let wait = (FIRST_LOCK << (c.failures - FREE_ATTEMPTS).min(10)).min(MAX_LOCK);
                c.locked_until = now() + wait;
            }
        }
        if let Err(e) = self.save() {
            tracing::warn!("cannot record the failed attempt: {e}");
        }
    }

    /// Host: answers a viewer's [`SessionMsg::UnattendedStart`] (its OPAQUE `request`) and checks
    /// the password and code it sends back.
    pub async fn check(&mut self, ch: &mut Channel, host_pk: &[u8; 32], request: &[u8]) -> Result<Verdict> {
        let Some(config) = self.config.clone() else {
            return Ok(Verdict::Rejected("This computer doesn't allow unattended access.".into()));
        };
        let wait = self.locked_for();
        if wait > 0 {
            return Ok(Verdict::Rejected(format!(
                "Too many wrong attempts. Try again in {}.",
                if wait < 90 { format!("{wait} seconds") } else { format!("{} minutes", (wait + 59) / 60) }
            )));
        }
        let record = HostRecord { setup: config.opaque_setup.clone(), password_file: config.password_file.clone() };
        let (response, state) = opaque::host_start(&record, host_pk, &ch.handshake_hash, request)?;
        ch.sender.send(&SessionMsg::UnattendedChallenge { response }).await?;
        let reply = tokio::time::timeout(EXCHANGE_TIMEOUT, ch.receiver.recv::<SessionMsg>())
            .await
            .map_err(|_| ClientError::Other("the viewer did not finish signing in".into()))??;
        let Some(SessionMsg::UnattendedFinish { finalization, code }) = reply else {
            return Err(ClientError::Protocol("expected the unattended-access finalization"));
        };
        let password_ok = opaque::host_finish(state, &finalization).is_ok();
        let step = TotpSecret::from_bytes(&config.totp_secret).verify(&code, totp::now(), config.last_step);
        match (password_ok, step) {
            (true, Some(step)) => {
                if let Some(c) = &mut self.config {
                    c.last_step = Some(step);
                    c.failures = 0;
                    c.locked_until = 0;
                }
                self.save().map_err(|e| ClientError::Other(e.to_string()))?;
                Ok(Verdict::Accepted)
            }
            _ => {
                tracing::warn!("wrong unattended-access password or code");
                self.record_failure();
                Ok(Verdict::Rejected("Wrong password or code.".into()))
            }
        }
    }
}

/// What a viewer's first message asks for.
pub enum Asked {
    /// To be let in by the person at the host (or by account or organisation).
    Access,
    /// Unattended access with the host's password; the OPAQUE request.
    Password(Vec<u8>),
}

/// Host: reads the viewer's first message.
pub async fn read_request(ch: &mut Channel) -> Result<Asked> {
    let first = tokio::time::timeout(EXCHANGE_TIMEOUT, ch.receiver.recv::<SessionMsg>())
        .await
        .map_err(|_| ClientError::Other("the viewer did not say what it wants".into()))??;
    match first {
        Some(SessionMsg::AccessRequest) => Ok(Asked::Access),
        Some(SessionMsg::UnattendedStart { request }) => Ok(Asked::Password(request)),
        _ => Err(ClientError::Protocol("expected an access request")),
    }
}

/// Viewer: asks to be let in (the person at the host decides, unless an account or organisation
/// rule lets this device in).
pub async fn request_access(ch: &mut Channel) -> Result<()> {
    ch.sender.send(&SessionMsg::AccessRequest).await?;
    Ok(())
}

/// Viewer: unattended access with the host's password and authenticator code. Afterwards the
/// host answers like for any session (accept or reject); a wrong password shows up as
/// [`ClientError::Rejected`] right here when this side can already tell.
pub async fn sign_in_unattended(ch: &mut Channel, password: &str, code: &str) -> Result<()> {
    let host_pk = ch.peer.device_pk;
    let (request, state) = opaque::viewer_start(password)?;
    ch.sender.send(&SessionMsg::UnattendedStart { request }).await?;
    let reply = tokio::time::timeout(EXCHANGE_TIMEOUT, ch.receiver.recv::<SessionMsg>())
        .await
        .map_err(|_| ClientError::Other("the remote device did not answer".into()))??;
    let response = match reply {
        Some(SessionMsg::UnattendedChallenge { response }) => response,
        Some(SessionMsg::Reject { reason }) => return Err(ClientError::Rejected(reason)),
        _ => return Err(ClientError::Protocol("expected the host's answer")),
    };
    // A wrong password fails here already; the host still gets a finalization (and counts the
    // attempt), so a guesser learns nothing from timing.
    let finalization =
        opaque::viewer_finish(state, password, &host_pk, &ch.handshake_hash, &response).unwrap_or_else(|_| vec![0; 64]);
    ch.sender.send(&SessionMsg::UnattendedFinish { finalization, code: code.to_owned() }).await?;
    Ok(())
}

/// Whether `peer` is a device of the same account as `own_identity_pk` (its certificate is
/// signed by that account's identity key, checked in the handshake).
pub fn same_account(own_identity_pk: Option<&[u8; 32]>, peer: &DeviceIdentity) -> bool {
    match (own_identity_pk, &peer.account) {
        (Some(own), Some(cert)) => &cert.identity_pk == own,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Unattended {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        Unattended::load(&std::env::temp_dir().join(format!("somedesk-unattended-{}-{n}.json", std::process::id())))
            .unwrap()
    }

    #[test]
    fn setup_needs_a_code_from_the_app() {
        let mut s = store();
        assert!(Unattended::begin(&[1; 32], "short").is_err(), "too short");
        let pending = Unattended::begin(&[1; 32], "a long unattended password").unwrap();
        let code = pending.secret.code_at(totp::now() / 30);
        let pending2 = Unattended::begin(&[1; 32], "a long unattended password").unwrap();
        assert!(s.confirm(pending2, "000000").is_err() || !s.enabled());
        s.confirm(pending, &code).unwrap();
        assert!(s.enabled());
        let again = Unattended::load(&s.path).unwrap();
        assert!(again.enabled());
        s.disable().unwrap();
        assert!(!Unattended::load(&s.path).unwrap().enabled());
    }

    #[test]
    fn wrong_attempts_lock_for_longer_and_longer() {
        let mut s = store();
        let pending = Unattended::begin(&[1; 32], "a long unattended password").unwrap();
        let code = pending.secret.code_at(totp::now() / 30);
        s.confirm(pending, &code).unwrap();
        s.record_failure();
        s.record_failure();
        assert_eq!(s.locked_for(), 0, "a typo or two is fine");
        s.record_failure();
        assert!((25..=30).contains(&s.locked_for()));
        s.record_failure();
        assert!((55..=60).contains(&s.locked_for()), "doubles");
        for _ in 0..20 {
            s.record_failure();
        }
        assert!(s.locked_for() <= MAX_LOCK);
        s.disable().unwrap();
    }
}
