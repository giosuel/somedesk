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
    pub relay_tap: Option<RelayTap>,
}

pub(crate) struct Online {
    pub conn_id: u64,
    /// The account the device is signed in to.
    pub user_id: Option<i64>,
    pub tx: mpsc::UnboundedSender<ServerFrame>,
    /// Addresses peers may try for a direct connection; empty if the device only wants the relay.
    pub candidates: Vec<SocketAddr>,
}

pub(crate) struct Shared {
    pub db: PgPool,
    pub opaque: ServerSetup,
    pub open: bool,
    pub online: DashMap<u64, Online>,
    pub sessions: Mutex<HashMap<SessionId, relay::PendingSession>>,
    pub limiter: ratelimit::RateLimiter,
    pub relay_tap: Option<RelayTap>,
    pub next_conn_id: AtomicU64,
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
        online: DashMap::new(),
        sessions: Mutex::new(HashMap::new()),
        limiter: ratelimit::RateLimiter::default(),
        relay_tap: config.relay_tap,
        next_conn_id: AtomicU64::new(1),
    });

    let janitor = shared.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            relay::expire_pending(&janitor);
            janitor.limiter.cleanup();
        }
    });

    let ep = endpoint.clone();
    let task = tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            tokio::spawn(conn::handle(shared.clone(), incoming));
        }
    });

    Ok(RunningServer { local_addr, cert_fingerprint: tls.fingerprint(), endpoint, task })
}
