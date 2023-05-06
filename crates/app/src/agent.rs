//! `somedesk-agent`: a machine enrolled into an organisation by a service worker.
//!
//! It has no window of its own except the banner shown while someone controls it. It never
//! starts a session, can't be reached by ID or password, and lets in only members its
//! organisation's signed policy allows. It checks that policy itself, against the organisation key
//! from its enrollment key, so the server can't add anyone.

use crate::AgentBanner;
use clap::{Parser, Subcommand};
use slint::ComponentHandle;
use somedesk_client::access::{self, Asked};
use somedesk_client::credentials::DeviceCredentials;
use somedesk_client::host::{self, HostSettings};
use somedesk_client::org::PolicyStore;
use somedesk_client::server::ServerConn;
use somedesk_client::session;
use somedesk_crypto::org::EnrollmentKey;
use somedesk_proto::control::{DeviceInfo, Event, SessionId};
use somedesk_proto::format_device_id;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

#[derive(Parser)]
#[command(name = "somedesk-agent", version, about = "SomeDesk for machines an organisation manages")]
struct Args {
    /// Where the enrollment is kept (default: the user's data directory).
    #[arg(long, env = "SOMEDESK_AGENT_DIR")]
    dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enrolls this machine with a service worker's key (from the organisation's admin).
    Enroll {
        /// The SomeDesk server.
        #[arg(long)]
        server: String,
        /// The service worker's enrollment key (sdw1-…). Or set SOMEDESK_ENROLLMENT_KEY.
        #[arg(long, env = "SOMEDESK_ENROLLMENT_KEY", hide_env_values = true)]
        key: String,
        /// The machine's name (default: its hostname).
        #[arg(long)]
        name: Option<String>,
    },
    /// Keeps the machine online and lets the organisation's members in (with a banner).
    Run,
    /// Shows the machine's ID and organisation.
    Status,
    /// Starts `run` when the user logs in (a systemd user unit, a Windows Run key or a macOS
    /// LaunchAgent).
    InstallService,
}

fn default_dir() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(dirs::data_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("somedesk-agent")
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "machine".into())
}

/// The agent's entry point (the `somedesk-agent` binary).
pub fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let dir = args.dir.unwrap_or_else(default_dir);
    let creds_path = dir.join("device.json");
    match args.command {
        Command::Enroll { server, key, name } => {
            let key =
                EnrollmentKey::decode(&key).map_err(|_| anyhow::anyhow!("that is not an enrollment key (sdw1-…)"))?;
            let name = name.unwrap_or_else(hostname);
            let rt = tokio::runtime::Runtime::new()?;
            let creds = rt.block_on(async {
                let (conn, _) = ServerConn::connect(&server, None).await?;
                let creds = conn.enroll_device(&server, &key, &name).await?;
                let policy = conn.get_org_policy(key.org_id).await?;
                conn.close();
                Ok::<_, somedesk_client::ClientError>((creds, policy))
            })?;
            let (creds, policy) = creds;
            creds.save(&creds_path)?;
            if let Some(policy) = policy {
                PolicyStore::load(&dir.join("policy.json"), key.org_pk).update(policy)?;
            }
            println!("Enrolled into {} as {} (ID {}).", key.org_name, name, format_device_id(creds.device_id));
            println!("Start it with `somedesk-agent run`, or `somedesk-agent install-service` to start it at login.");
            Ok(())
        }
        Command::Status => {
            let creds = load(&creds_path)?;
            let org = creds.org.as_ref().expect("checked by load");
            let store = PolicyStore::load(&dir.join("policy.json"), org.org_pk);
            println!("{} · ID {} · {}", creds.device_name, format_device_id(creds.device_id), org.org_name);
            match store.current() {
                Some(p) => println!("Policy version {}, {} members", p.version, p.members.len()),
                None => println!("No valid policy yet: nobody can connect until the organisation publishes one."),
            }
            Ok(())
        }
        Command::InstallService => install_service(&dir),
        Command::Run => run(dir, creds_path),
    }
}

fn load(path: &Path) -> anyhow::Result<DeviceCredentials> {
    let creds = DeviceCredentials::load(path)?
        .ok_or_else(|| anyhow::anyhow!("not enrolled yet: run `somedesk-agent enroll --server … --key …`"))?;
    if creds.org.is_none() {
        anyhow::bail!("{} is not an organisation's enrollment", path.display());
    }
    Ok(creds)
}

struct Agent {
    dir: PathBuf,
    creds: Mutex<DeviceCredentials>,
    policy: Mutex<PolicyStore>,
    banner: slint::Weak<AgentBanner>,
    busy: std::sync::atomic::AtomicBool,
    stop: Mutex<Option<watch::Sender<bool>>>,
}

fn run(dir: PathBuf, creds_path: PathBuf) -> anyhow::Result<()> {
    let creds = load(&creds_path)?;
    let org_pk = creds.org.as_ref().expect("checked by load").org_pk;
    let policy = PolicyStore::load(&dir.join("policy.json"), org_pk);
    let rt = tokio::runtime::Runtime::new()?;
    // The banner needs the UI event loop on this thread; the network runs on the runtime.
    let banner = AgentBanner::new()?;
    let agent = Arc::new(Agent {
        dir,
        creds: Mutex::new(creds),
        policy: Mutex::new(policy),
        banner: banner.as_weak(),
        busy: std::sync::atomic::AtomicBool::new(false),
        stop: Mutex::new(None),
    });
    {
        let agent = agent.clone();
        banner.on_disconnect(move || {
            if let Some(stop) = agent.stop.lock().unwrap().take() {
                let _ = stop.send(true);
            }
        });
    }
    let a = agent.clone();
    rt.spawn(async move { a.online(creds_path).await });
    slint::run_event_loop_until_quit()?;
    Ok(())
}

impl Agent {
    async fn online(self: Arc<Self>, creds_path: PathBuf) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let mut creds = self.creds.lock().unwrap().clone();
            match ServerConn::connect(&creds.server, Some(creds.server_fingerprint)).await {
                Ok((conn, mut events)) => match conn.authenticate(&mut creds).await {
                    Ok(_) => {
                        backoff = Duration::from_secs(1);
                        if let Err(e) = creds.save(&creds_path) {
                            tracing::warn!("cannot store the enrollment: {e}");
                        }
                        *self.creds.lock().unwrap() = creds.clone();
                        tracing::info!(id = %format_device_id(creds.device_id), "online");
                        self.refresh_policy(&conn).await;
                        loop {
                            tokio::select! {
                                ev = events.recv() => match ev {
                                    Some(Event::IncomingSession { session_id, from, candidates }) => {
                                        let (this, conn) = (self.clone(), conn.clone());
                                        tokio::spawn(async move { this.incoming(conn, session_id, from, candidates).await });
                                    }
                                    Some(Event::OrgPolicyChanged { .. }) => self.refresh_policy(&conn).await,
                                    Some(_) => {}
                                    None => break,
                                },
                                reason = conn.closed() => {
                                    tracing::warn!("lost the connection to the server: {reason}");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => tracing::warn!("cannot come online: {e}"),
                },
                Err(e) => tracing::warn!("cannot reach the server: {e}"),
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }

    /// Takes the newest policy from the server, if the organisation signed it.
    async fn refresh_policy(&self, conn: &ServerConn) {
        let org_id = self.creds.lock().unwrap().org.as_ref().map(|o| o.org_id).unwrap_or_default();
        match conn.get_org_policy(org_id).await {
            Ok(Some(signed)) => match self.policy.lock().unwrap().update(signed) {
                Ok(true) => tracing::info!("new organisation policy"),
                Ok(false) => {}
                Err(e) => tracing::warn!("rejected a policy that isn't the organisation's: {e}"),
            },
            Ok(None) => {}
            Err(e) => tracing::warn!("cannot read the organisation's policy: {e}"),
        }
        let _ = &self.dir;
    }

    async fn incoming(
        self: Arc<Self>,
        conn: Arc<ServerConn>,
        session_id: SessionId,
        from: DeviceInfo,
        candidates: Vec<std::net::SocketAddr>,
    ) {
        let creds = self.creds.lock().unwrap().clone();
        let mut ch = match session::accept(&conn, &creds, session_id, &from, &candidates).await {
            Ok(ch) => ch,
            Err(e) => return tracing::warn!("incoming session handshake failed: {e}"),
        };
        let peer = ch.peer.clone();
        let org_name = creds.org.as_ref().map(|o| o.org_name.clone()).unwrap_or_default();
        let allowed = match access::read_request(&mut ch).await {
            Ok(Asked::Access) => self.policy.lock().unwrap().allows(&peer, creds.device_id),
            Ok(Asked::Password(_)) | Err(_) => false,
        };
        if !allowed {
            tracing::info!(peer = %peer.name, account = ?peer.username(), "turned away: not allowed by the policy");
            host::reject(ch, &format!("This computer is managed by {org_name}; only its members can connect.")).await;
            return;
        }
        if self.busy.swap(true, std::sync::atomic::Ordering::SeqCst) {
            host::reject(ch, "The computer is busy with another session.").await;
            return;
        }
        let who = format!("{} ({})", peer.username().unwrap_or("?"), peer.name);
        tracing::info!(%who, "session from a member");
        let screen = tokio::task::spawn_blocking(|| somedesk_platform::open_screen(None))
            .await
            .unwrap_or_else(|e| Err(anyhow::anyhow!("{e}")));
        let screen = match screen {
            Ok(s) => s,
            Err(e) => {
                host::reject(ch, &format!("Screen sharing is not available on this computer: {e}")).await;
                self.busy.store(false, std::sync::atomic::Ordering::SeqCst);
                return;
            }
        };
        let (stop_tx, stop_rx) = watch::channel(false);
        *self.stop.lock().unwrap() = Some(stop_tx);
        // The banner always shows while someone is connected.
        let (w, o) = (who.clone(), org_name.clone());
        let _ = self.banner.upgrade_in_event_loop(move |b| {
            b.set_who(w.into());
            b.set_org(o.into());
            let _ = b.show();
            place_at_top(&b);
        });
        let clipboard = somedesk_platform::default_clipboard().ok();
        let extras = somedesk_client::SessionExtras { clipboard, files: None };
        let settings = HostSettings { view_only: !screen.can_control, ..Default::default() };
        let result = host::serve(ch, screen.capturer, screen.injector, extras, settings, stop_rx).await;
        let _ = self.banner.upgrade_in_event_loop(|b| {
            let _ = b.hide();
        });
        *self.stop.lock().unwrap() = None;
        self.busy.store(false, std::sync::atomic::Ordering::SeqCst);
        match result {
            Ok(_) => tracing::info!(%who, "session ended"),
            Err(e) => tracing::info!(%who, "session ended: {e}"),
        }
    }
}

/// Puts the banner at the top of the screen, centred, where it doesn't cover much.
fn place_at_top(banner: &AgentBanner) {
    use slint::winit_030::WinitWindowAccessor;
    let width = banner.window().size().width as i32;
    let x = banner
        .window()
        .with_winit_window(|w| w.current_monitor().map(|m| (m.position().x, m.size().width as i32)))
        .flatten()
        .map_or(0, |(left, screen)| left + (screen - width) / 2);
    banner.window().set_position(slint::PhysicalPosition::new(x.max(0), 16));
}

fn install_service(dir: &Path) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let units = dirs::config_dir().ok_or_else(|| anyhow::anyhow!("no config directory"))?.join("systemd/user");
        std::fs::create_dir_all(&units)?;
        std::fs::write(
            units.join("somedesk-agent.service"),
            format!(
                "[Unit]\nDescription=SomeDesk agent (organisation-managed remote access)\nPartOf=graphical-session.target\nAfter=graphical-session.target\n\n\
                 [Service]\nExecStart=\"{}\" --dir \"{}\" run\nRestart=on-failure\nRestartSec=5\n\n\
                 [Install]\nWantedBy=graphical-session.target\n",
                exe.display(),
                dir.display()
            ),
        )?;
        let status = std::process::Command::new("systemctl")
            .args(["--user", "enable", "--now", "somedesk-agent.service"])
            .status()?;
        if !status.success() {
            anyhow::bail!("systemctl --user enable failed");
        }
        println!("Installed and started somedesk-agent.service (systemctl --user status somedesk-agent).");
        Ok(())
    }
    #[cfg(windows)]
    {
        let value = format!("\"{}\" --dir \"{}\" run", exe.display(), dir.display());
        let status = std::process::Command::new("reg")
            .args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "SomeDeskAgent",
                "/t",
                "REG_SZ",
                "/d",
                &value,
                "/f",
            ])
            .status()?;
        if !status.success() {
            anyhow::bail!("the registry refused the change");
        }
        println!("somedesk-agent now starts when you log in.");
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let agents = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home directory"))?.join("Library/LaunchAgents");
        std::fs::create_dir_all(&agents)?;
        let plist = agents.join("ch.giosuel.SomeDesk.agent.plist");
        std::fs::write(
            &plist,
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>ch.giosuel.SomeDesk.agent</string>
  <key>ProgramArguments</key><array><string>{}</string><string>--dir</string><string>{}</string><string>run</string></array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
"#,
                exe.display(),
                dir.display()
            ),
        )?;
        std::process::Command::new("launchctl").arg("load").arg(&plist).status()?;
        println!("somedesk-agent now starts when you log in.");
        Ok(())
    }
}
