//! SomeDesk desktop client.

// No console window next to the app in Windows release builds.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "somedesk", version, about = "SomeDesk remote desktop client")]
struct Args {
    /// Profile name; lets several independent instances run under one user account.
    #[arg(long, env = "SOMEDESK_PROFILE", default_value = "default")]
    profile: String,
    /// Pre-fill the server address on the sign-in screen.
    #[arg(long)]
    server: Option<String>,
    /// Use the phone layout (as on Android), for trying it out on a desktop.
    #[arg(long, env = "SOMEDESK_MOBILE_UI")]
    mobile_ui: bool,
}

/// Where credentials and settings live: `$XDG_DATA_HOME/somedesk` on Linux, `%APPDATA%\somedesk`
/// on Windows, `~/Library/Application Support/somedesk` on macOS.
fn data_dir(profile: &str) -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(dirs::data_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("somedesk").join(profile)
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,zbus=warn,zbus::proxy=error".into()),
        )
        .init();
    let args = Args::parse();
    somedesk_app::run(somedesk_app::Options {
        data_dir: data_dir(&args.profile),
        server: args.server,
        mobile: args.mobile_ui,
    })
}
