//! SomeDesk server: accounts, device registry, presence and a blind relay.
//!
//! The server authenticates users with OPAQUE (it never learns passwords), stores each user's
//! identity key only in password-encrypted form, and relays sessions whose content is end-to-end
//! encrypted between the two devices. It does see metadata: which device connects to which, when,
//! and how many bytes flow.

mod conn;
pub mod db;
mod ratelimit;
mod relay;
pub mod tls;

use dashmap::DashMap;
use somedesk_crypto::opaque::ServerSetup;
use somedesk_proto::control::{ServerFrame, SessionId};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// Observes every byte the relay forwards. Used by tests to prove the relay only sees ciphertext.
pub type RelayTap = Arc<dyn Fn(&[u8]) + Send + Sync>;

pub struct ServerConfig {
    pub listen: SocketAddr,
    pub database_url: String,
    pub data_dir: PathBuf,
    /// Let devices without an account come online (and get an ID). Otherwise only devices
    /// signed in to one of this server's accounts can.
    pub open: bool,
    /// Who may create an account.
    pub registration: Registration,
    pub limits: Limits,
    pub relay_tap: Option<RelayTap>,
}

/// Who may create an account on the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Registration {
    /// Anyone.
    Open,
    /// Only with an invite code (`somedesk-server invite`).
    Invite,
    /// Nobody: the accounts there are all there will be.
    Closed,
}

/// How much one client may use. The defaults leave room for normal use, including remote
/// desktop sessions over the relay.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Open connections per address (an IPv6 /64 counts as one).
    pub connections_per_ip: u32,
    pub connections_total: u32,
    /// Relay sessions a device takes part in at the same time.
    pub relay_sessions_per_device: u32,
    /// Relay sessions at the same time per address.
    pub relay_sessions_per_ip: u32,
    /// Bytes per second each direction of a relay session may carry, on average.
    pub relay_bytes_per_sec: u64,
    /// Audit log entries are deleted after this many days (0: kept).
    pub audit_retention_days: u32,
    /// Devices without an account or organisation are forgotten when unseen for this many days
    /// (0: kept). They get a new ID if they come back.
    pub device_retention_days: u32,
    /// How long a connection has to bring a device online or log in.
    pub sign_in_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connections_per_ip: 64,
            connections_total: 20_000,
            relay_sessions_per_device: 4,
            relay_sessions_per_ip: 16,
            relay_bytes_per_sec: 16 * 1024 * 1024,
            audit_retention_days: 90,
            device_retention_days: 180,
            sign_in_timeout: Duration::from_secs(30),
        }
    }
}

/// Queued frames per connection (responses and events). A client that doesn't read them makes
/// the server stop reading its requests, then drop its events.
pub(crate) const QUEUE_LEN: usize = 16;

pub(crate) struct Online {
    pub conn_id: u64,
    /// The account the device is signed in to.
    pub user_id: Option<i64>,
    pub tx: mpsc::Sender<ServerFrame>,
    /// To close the connection of a device that doesn't keep up with its events.
    pub conn: quinn::Connection,
    /// Addresses peers may try for a direct connection; empty if the device only wants the relay.
    pub candidates: Vec<SocketAddr>,
}

impl Online {
    /// Queues an event for the device; one that has fallen this far behind is disconnected
    /// (it reconnects and reads the current state).
    pub fn push(&self, frame: ServerFrame) -> bool {
        match self.tx.try_send(frame) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(conn_id = self.conn_id, "a device is not reading its events; disconnecting it");
                self.conn.close(0u32.into(), b"too slow");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

pub(crate) struct Shared {
    pub db: PgPool,
    pub opaque: ServerSetup,
    pub open: bool,
    pub registration: Registration,
    pub limits: Limits,
    pub online: DashMap<u64, Online>,
    pub sessions: Mutex<HashMap<SessionId, relay::PendingSession>>,
    pub limiter: ratelimit::RateLimiter,
    /// Waits after wrong passwords, codes and recovery keys.
    pub backoff: ratelimit::Backoff,
    pub connections: ratelimit::Slots,
    pub relay_slots: ratelimit::Slots,
    /// Bumped when an account's password is reset or two-factor authentication is turned on:
    /// password logins from before then end.
    pub account_epochs: DashMap<i64, u64>,
    pub relay_tap: Option<RelayTap>,
    pub next_conn_id: AtomicU64,
}

impl Shared {
    pub fn account_epoch(&self, user_id: i64) -> u64 {
        self.account_epochs.get(&user_id).map_or(0, |e| *e)
    }
}

/// How often old audit entries and forgotten devices are deleted.
const PRUNE_EVERY: Duration = Duration::from_secs(3600);

async fn prune(shared: &Shared) {
    let limits = &shared.limits;
    if limits.audit_retention_days > 0 {
        match db::prune_audit_log(&shared.db, limits.audit_retention_days).await {
            Ok(0) => {}
            Ok(n) => tracing::info!("deleted {n} old audit log entries"),
            Err(e) => tracing::warn!("cannot prune the audit log: {e}"),
        }
    }
    if limits.device_retention_days > 0 {
        let online: Vec<i64> = shared.online.iter().map(|o| *o.key() as i64).collect();
        match db::prune_devices(&shared.db, limits.device_retention_days, &online).await {
            Ok(0) => {}
            Ok(n) => tracing::info!("forgot {n} devices without an account that weren't seen in a long time"),
            Err(e) => tracing::warn!("cannot prune devices: {e}"),
        }
    }
}

pub struct RunningServer {
    pub local_addr: SocketAddr,
    /// SHA-256 of the server's TLS certificate (what clients pin).
    pub cert_fingerprint: [u8; 32],
    endpoint: quinn::Endpoint,
    task: tokio::task::JoinHandle<()>,
}

impl RunningServer {
    pub async fn shutdown(self) {
        self.endpoint.close(0u32.into(), b"shutdown");
        self.task.abort();
        self.endpoint.wait_idle().await;
    }

    pub async fn wait(self) {
        let _ = self.task.await;
    }
}

/// Creates an invite code in the server's database (`somedesk-server invite`).
pub async fn create_invite(database_url: &str, uses: u32, expires_in_days: Option<u32>) -> anyhow::Result<String> {
    let db = PgPoolOptions::new().max_connections(1).connect(database_url).await?;
    db::migrate(&db).await?;
    db::create_invite(&db, uses, expires_in_days).await
}

pub async fn start(config: ServerConfig) -> anyhow::Result<RunningServer> {
    let db = PgPoolOptions::new().max_connections(20).connect(&config.database_url).await?;
    db::migrate(&db).await?;
    let opaque = db::load_or_create_opaque_setup(&db).await?;
    let tls = tls::load_or_create(&config.data_dir)?;
    let endpoint = quinn::Endpoint::server(tls::quinn_server_config(&tls)?, config.listen)?;
    let local_addr = endpoint.local_addr()?;

    let shared = Arc::new(Shared {
        db,
        opaque,
        open: config.open,
        registration: config.registration,
        limits: config.limits,
        online: DashMap::new(),
        sessions: Mutex::new(HashMap::new()),
        limiter: ratelimit::RateLimiter::default(),
        backoff: ratelimit::Backoff::default(),
        connections: ratelimit::Slots::default(),
        relay_slots: ratelimit::Slots::default(),
        account_epochs: DashMap::new(),
        relay_tap: config.relay_tap,
        next_conn_id: AtomicU64::new(1),
    });

    let janitor = shared.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        let mut last_prune: Option<std::time::Instant> = None;
        loop {
            tick.tick().await;
            relay::expire_pending(&janitor);
            janitor.limiter.cleanup();
            janitor.backoff.cleanup();
            if last_prune.is_none_or(|t| t.elapsed() >= PRUNE_EVERY) {
                last_prune = Some(std::time::Instant::now());
                prune(&janitor).await;
            }
        }
    });

    let ep = endpoint.clone();
    let task = tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let ip = ratelimit::ip_key(incoming.remote_address().ip());
            let limits = &shared.limits;
            let slots = shared
                .connections
                .take("total", limits.connections_total)
                .and_then(|total| Some((total, shared.connections.take(&ip, limits.connections_per_ip)?)));
            match slots {
                Some(slots) => {
                    tokio::spawn(conn::handle(shared.clone(), incoming, slots));
                }
                None => {
                    tracing::debug!(%ip, "too many connections; refusing one");
                    incoming.refuse();
                }
            }
        }
    });

    Ok(RunningServer { local_addr, cert_fingerprint: tls.fingerprint(), endpoint, task })
}
