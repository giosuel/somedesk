//! SomeDesk desktop client.

mod controller;
mod keymap;

use clap::Parser;
use std::path::PathBuf;

slint::include_modules!();

#[derive(Parser)]
#[command(version, about = "SomeDesk remote desktop client")]
struct Args {
    /// Profile name; lets several independent instances run under one user account.
    #[arg(long, env = "SOMEDESK_PROFILE", default_value = "default")]
    profile: String,
    /// Pre-fill the server address on the sign-in screen.
    #[arg(long)]
    server: Option<String>,
}

fn data_dir(profile: &str) -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("somedesk").join(profile)
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let ui = AppWindow::new()?;
    let controller = controller::Controller::new(&ui, runtime.handle().clone(), data_dir(&args.profile), args.server);
    controller.start();
    ui.run()?;
    controller.shutdown();
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    Ok(())
}
