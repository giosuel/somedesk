//! SomeDesk agent: for machines an organisation manages (see `somedesk_app::agent`).

// No console window in Windows release builds.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,zbus=warn,zbus::proxy=error".into()),
        )
        .init();
    somedesk_app::agent::main()
}
