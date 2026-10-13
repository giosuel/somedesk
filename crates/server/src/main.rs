use clap::{Parser, Subcommand};
use somedesk_server::{Limits, Registration};
use std::net::SocketAddr;
use std::path::PathBuf;

/// SomeDesk server: accounts, presence and end-to-end-encrypted relay.
#[derive(Parser)]
#[command(version = env!("SOMEDESK_VERSION"), args_conflicts_with_subcommands = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// UDP address to listen on (QUIC).
    #[arg(long, env = "SOMEDESK_LISTEN", default_value = "0.0.0.0:21116")]
    listen: SocketAddr,
    /// PostgreSQL connection string.
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,
    /// Directory for the TLS certificate and key.
    #[arg(long, env = "SOMEDESK_DATA_DIR", default_value = "./data")]
    data_dir: PathBuf,
    /// Only let in devices signed in to one of this server's accounts. By default any device
    /// can come online and get an ID, with or without an account.
    #[arg(long, env = "SOMEDESK_ACCOUNTS_ONLY")]
    accounts_only: bool,
    /// Who may create an account: anyone, only with an invite code (`somedesk-server invite`),
    /// or nobody. Default: open, or invite with --accounts-only.
    #[arg(long, env = "SOMEDESK_REGISTRATION", value_enum)]
    registration: Option<Registration>,
    /// Open connections per address (an IPv6 /64 counts as one).
    #[arg(long, env = "SOMEDESK_CONNECTIONS_PER_IP", default_value_t = Limits::default().connections_per_ip)]
    connections_per_ip: u32,
    /// Open connections in total.
    #[arg(long, env = "SOMEDESK_MAX_CONNECTIONS", default_value_t = Limits::default().connections_total)]
    max_connections: u32,
    /// Relay sessions a device takes part in at the same time.
    #[arg(long, env = "SOMEDESK_RELAY_SESSIONS_PER_DEVICE", default_value_t = Limits::default().relay_sessions_per_device)]
    relay_sessions_per_device: u32,
    /// Relay sessions at the same time per address.
    #[arg(long, env = "SOMEDESK_RELAY_SESSIONS_PER_IP", default_value_t = Limits::default().relay_sessions_per_ip)]
    relay_sessions_per_ip: u32,
    /// Average megabytes per second each direction of a relay session may carry (0: no limit).
    #[arg(long, env = "SOMEDESK_RELAY_MBPS", default_value_t = Limits::default().relay_bytes_per_sec / (1024 * 1024))]
    relay_mbps: u64,
    /// Days after which audit log entries are deleted (0: keep them).
    #[arg(long, env = "SOMEDESK_AUDIT_RETENTION_DAYS", default_value_t = Limits::default().audit_retention_days)]
    audit_retention_days: u32,
    /// Days after which devices without an account or organisation that weren't seen are
    /// forgotten (0: keep them). They get a new ID if they come back.
    #[arg(long, env = "SOMEDESK_DEVICE_RETENTION_DAYS", default_value_t = Limits::default().device_retention_days)]
    device_retention_days: u32,
}

#[derive(Subcommand)]
enum Command {
    /// Prints a new invite code, for creating an account on a server with `--registration invite`.
    Invite {
        /// PostgreSQL connection string.
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        /// How many accounts it creates.
        #[arg(long, default_value_t = 1)]
        uses: u32,
        /// Days until it expires (default: never).
        #[arg(long)]
        expires_in: Option<u32>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logs go to stderr, so what a command prints (an invite code) is all there is on stdout.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    if let Some(Command::Invite { database_url, uses, expires_in }) = args.command {
        let code = somedesk_server::create_invite(&database_url, uses.max(1), expires_in).await?;
        println!("{code}");
        return Ok(());
    }
    let Some(database_url) = args.database_url else {
        anyhow::bail!("set the PostgreSQL connection string with --database-url or DATABASE_URL");
    };
    let registration =
        args.registration.unwrap_or(if args.accounts_only { Registration::Invite } else { Registration::Open });
    let server = somedesk_server::start(somedesk_server::ServerConfig {
        listen: args.listen,
        database_url,
        data_dir: args.data_dir,
        open: !args.accounts_only,
        registration,
        limits: Limits {
            connections_per_ip: args.connections_per_ip,
            connections_total: args.max_connections,
            relay_sessions_per_device: args.relay_sessions_per_device,
            relay_sessions_per_ip: args.relay_sessions_per_ip,
            relay_bytes_per_sec: args.relay_mbps.saturating_mul(1024 * 1024),
            audit_retention_days: args.audit_retention_days,
            device_retention_days: args.device_retention_days,
            ..Limits::default()
        },
        relay_tap: None,
    })
    .await?;
    tracing::info!(?registration, "accounts");
    tracing::info!(
        "listening on {} — certificate fingerprint {}",
        server.local_addr,
        hex::encode_upper(server.cert_fingerprint)
    );
    tokio::select! {
        _ = shutdown_signal() => tracing::info!("shutting down"),
        _ = server.wait() => {}
    }
    Ok(())
}

/// Ctrl+C, or SIGTERM from systemd / container runtimes.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
