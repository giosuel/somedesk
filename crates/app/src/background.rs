//! Running in the background: starting when the user logs in, staying up when the window is
//! closed (see [`crate::tray`]), and one instance at a time (a second start shows the first
//! one's window instead).

use std::path::{Path, PathBuf};

/// The command that starts this app in the background.
fn command() -> anyhow::Result<PathBuf> {
    // An AppImage runs from a temporary mount; start the AppImage itself.
    if let Some(appimage) = std::env::var_os("APPIMAGE") {
        return Ok(PathBuf::from(appimage));
    }
    Ok(std::env::current_exe()?)
}

/// Starts the app (in the background) when the user logs in, or stops doing so.
pub fn set_autostart(on: bool) -> anyhow::Result<()> {
    #[cfg(all(unix, not(target_os = "macos"), not(target_os = "android")))]
    {
        let dir = dirs::config_dir().ok_or_else(|| anyhow::anyhow!("no config directory"))?.join("autostart");
        let file = dir.join("ch.giosuel.SomeDesk.desktop");
        if !on {
            return remove(&file);
        }
        std::fs::create_dir_all(&dir)?;
        let exec = match std::env::var_os("FLATPAK_ID") {
            Some(id) => format!("flatpak run {} --background", id.to_string_lossy()),
            None => format!("\"{}\" --background", command()?.display()),
        };
        std::fs::write(
            &file,
            format!(
                "[Desktop Entry]\nType=Application\nName=SomeDesk\nExec={exec}\nIcon=ch.giosuel.SomeDesk\n\
                 X-GNOME-Autostart-enabled=true\nNoDisplay=true\n"
            ),
        )?;
        Ok(())
    }
    #[cfg(windows)]
    {
        let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        let status = if on {
            let value = format!("\"{}\" --background", command()?.display());
            std::process::Command::new("reg")
                .args(["add", key, "/v", "SomeDesk", "/t", "REG_SZ", "/d", &value, "/f"])
                .status()?
        } else {
            std::process::Command::new("reg").args(["delete", key, "/v", "SomeDesk", "/f"]).status()?
        };
        if !status.success() && on {
            anyhow::bail!("the registry refused the change");
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let dir = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home directory"))?.join("Library/LaunchAgents");
        let file = dir.join("ch.giosuel.SomeDesk.plist");
        if !on {
            return remove(&file);
        }
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            &file,
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>ch.giosuel.SomeDesk</string>
  <key>ProgramArguments</key><array><string>{}</string><string>--background</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
"#,
                command()?.display()
            ),
        )?;
        Ok(())
    }
    #[cfg(target_os = "android")]
    {
        let _ = on;
        anyhow::bail!("not on a phone")
    }
}

#[allow(dead_code)]
fn remove(file: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(file) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// One instance per profile: the first one listens on a socket in its data directory; a second
/// start asks it to show its window and exits.
pub enum Instance {
    /// This is the only instance; `wait_for_show` calls back when another start knocks.
    First(InstanceListener),
    /// Another instance runs and was asked to show itself.
    Other,
}

pub struct InstanceListener {
    #[cfg(unix)]
    listener: std::os::unix::net::UnixListener,
    #[cfg(not(unix))]
    listener: std::net::TcpListener,
}

/// Claims `dir` for this process, or asks the instance that has it to show its window.
pub fn claim(dir: &Path) -> Instance {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::net::{UnixListener, UnixStream};
        let path = dir.join("instance.sock");
        if let Ok(mut other) = UnixStream::connect(&path) {
            let _ = other.write_all(b"show\n");
            return Instance::Other;
        }
        // Nobody answered: a stale socket from a crash, or none.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::create_dir_all(dir);
        match UnixListener::bind(&path) {
            Ok(listener) => Instance::First(InstanceListener { listener }),
            Err(e) => {
                tracing::warn!("cannot listen for other starts: {e}");
                Instance::First(InstanceListener {
                    listener: UnixListener::bind(dir.join(format!("instance-{}.sock", std::process::id())))
                        .expect("a fresh socket"),
                })
            }
        }
    }
    // No Unix sockets: a port on localhost, written to a file in the directory.
    #[cfg(not(unix))]
    {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        let port_file = dir.join("instance.port");
        if let Some(port) = std::fs::read_to_string(&port_file).ok().and_then(|p| p.trim().parse::<u16>().ok()) {
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            if let Ok(mut other) = TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(300)) {
                let _ = other.write_all(b"show\n");
                return Instance::Other;
            }
        }
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a port on localhost");
        let _ = std::fs::create_dir_all(dir);
        if let Ok(addr) = listener.local_addr() {
            let _ = std::fs::write(&port_file, addr.port().to_string());
        }
        Instance::First(InstanceListener { listener })
    }
}

impl InstanceListener {
    /// Calls `show` (on a background thread) whenever another start asks this instance to show
    /// its window.
    pub fn on_show(self, show: impl Fn() + Send + 'static) {
        #[cfg(unix)]
        std::thread::Builder::new()
            .name("somedesk-instance".into())
            .spawn(move || {
                for stream in self.listener.incoming().flatten() {
                    drop(stream);
                    show();
                }
            })
            .expect("spawning a thread");
        #[cfg(not(unix))]
        std::thread::Builder::new()
            .name("somedesk-instance".into())
            .spawn(move || {
                for stream in self.listener.incoming().flatten() {
                    drop(stream);
                    show();
                }
            })
            .expect("spawning a thread");
    }
}
