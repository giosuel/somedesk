use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

/// SomeDesk server: accounts, presence and end-to-end-encrypted relay.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// UDP address to listen on (QUIC).
    #[arg(long, env = "SOMEDESK_LISTEN", default_value = "0.0.0.0:21116")]
    listen: SocketAddr,
    /// PostgreSQL connection string.
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    /// Directory for the TLS certificate and key.
    #[arg(long, env = "SOMEDESK_DATA_DIR", default_value = "./data")]
    data_dir: PathBuf,
    /// Only let in devices signed in to one of this server's accounts. By default any device
    /// can come online and get an ID, with or without an account.
    #[arg(long, env = "SOMEDESK_ACCOUNTS_ONLY")]
    accounts_only: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    let server = somedesk_server::start(somedesk_server::ServerConfig {
        listen: args.listen,
        database_url: args.database_url,
        data_dir: args.data_dir,
        open: !args.accounts_only,
        relay_tap: None,
    })
    .await?;
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
