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
    /// None when no socket could be had: then every start runs on its own.
    #[cfg(unix)]
    listener: Option<std::os::unix::net::UnixListener>,
    #[cfg(not(unix))]
    listener: std::net::TcpListener,
    /// What a knock has to bring (from the port file), so other programs can't knock.
    #[cfg(not(unix))]
    token: String,
}

/// Claims `dir` for this process, or asks the instance that has it to show its window.
pub fn claim(dir: &Path) -> Instance {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::net::{UnixListener, UnixStream};
        let path = socket_path(dir);
        if let Ok(mut other) = UnixStream::connect(&path) {
            let _ = other.write_all(b"show\n");
            return Instance::Other;
        }
        // Nobody answered: a stale socket from a crash, or none.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::create_dir_all(dir);
        let listener = UnixListener::bind(&path)
            .inspect_err(|e| tracing::warn!("cannot listen for other starts at {}: {e}", path.display()))
            .ok();
        Instance::First(InstanceListener { listener })
    }
    // No Unix sockets: a named mutex says whether another instance runs (the system releases
    // it when a process ends, also after a crash), and a port on localhost, written to a file
    // in the directory with a token, takes its knocks.
    #[cfg(not(unix))]
    {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        let port_file = dir.join("instance.port");
        #[cfg(windows)]
        if !claim_mutex(dir) {
            let knock =
                std::fs::read_to_string(&port_file).ok().and_then(|t| parse_port_file(&t)).and_then(|(port, token)| {
                    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                    let mut other = TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(300)).ok()?;
                    other.write_all(knock_line(&token).as_bytes()).ok()
                });
            if knock.is_none() {
                tracing::warn!("SomeDesk runs already, but its window couldn't be shown");
            }
            return Instance::Other;
        }
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a port on localhost");
        let token = hex::encode(rand::random::<[u8; 16]>());
        let _ = std::fs::create_dir_all(dir);
        if let Ok(addr) = listener.local_addr() {
            let _ = std::fs::write(&port_file, format!("{} {token}", addr.port()));
        }
        Instance::First(InstanceListener { listener, token })
    }
}

/// Takes the named mutex for `dir` for the rest of this process; false if another process has
/// it. If there's no mutex to be had, this start runs on its own.
#[cfg(windows)]
fn claim_mutex(dir: &Path) -> bool {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    let name: Vec<u16> = format!("Local\\SomeDesk-{:016x}", dir_hash(dir)).encode_utf16().chain([0]).collect();
    // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the call; no security
    // attributes. The handle is never closed: the mutex is held until the process ends.
    let (handle, error) = unsafe { (CreateMutexW(std::ptr::null(), 0, name.as_ptr()), GetLastError()) };
    if handle.is_null() {
        tracing::warn!("cannot check for other instances (error {error})");
        return true;
    }
    error != ERROR_ALREADY_EXISTS
}

/// The port and token in an `instance.port` file.
#[cfg(any(not(unix), test))]
fn parse_port_file(text: &str) -> Option<(u16, String)> {
    let (port, token) = text.trim().split_once(' ')?;
    Some((port.parse().ok()?, token.to_owned())).filter(|(_, t)| !t.is_empty())
}

/// What a second start sends to the first one.
#[cfg(any(not(unix), test))]
fn knock_line(token: &str) -> String {
    format!("show {token}\n")
}

/// Whether `line` is a knock with the right token.
#[cfg(any(not(unix), test))]
fn is_knock(line: &str, token: &str) -> bool {
    line.trim_end().strip_prefix("show ") == Some(token)
}

/// The same for `dir` from every build, so a new version finds the running one (FNV-1a).
fn dir_hash(dir: &Path) -> u64 {
    dir.as_os_str()
        .as_encoded_bytes()
        .iter()
        .fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3))
}

/// The socket in `dir`, or, where that path would be too long for a socket (deep home
/// directories), one named after `dir` in the user's runtime directory.
#[cfg(unix)]
fn socket_path(dir: &Path) -> std::path::PathBuf {
    // sockaddr_un holds 108 bytes on Linux and 104 on macOS, with the terminating zero.
    const MAX: usize = 100;
    let path = dir.join("instance.sock");
    if path.as_os_str().len() < MAX {
        return path;
    }
    let hash = dir_hash(dir);
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
    runtime.join(format!("somedesk-{hash:016x}.sock"))
}

impl InstanceListener {
    /// Calls `show` (on a background thread) whenever another start asks this instance to show
    /// its window.
    pub fn on_show(self, show: impl Fn() + Send + 'static) {
        #[cfg(unix)]
        let Some(listener) = self.listener
        else {
            return;
        };
        #[cfg(unix)]
        std::thread::Builder::new()
            .name("somedesk-instance".into())
            .spawn(move || {
                for stream in listener.incoming().flatten() {
                    drop(stream);
                    show();
                }
            })
            .expect("spawning a thread");
        #[cfg(not(unix))]
        std::thread::Builder::new()
            .name("somedesk-instance".into())
            .spawn(move || {
                use std::io::{BufRead, Read};
                for stream in self.listener.incoming().flatten() {
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
                    let mut line = String::new();
                    let _ = std::io::BufReader::new(stream.take(128)).read_line(&mut line);
                    if is_knock(&line, &self.token) {
                        show();
                    }
                }
            })
            .expect("spawning a thread");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knocks_need_the_token_from_the_port_file() {
        let (port, token) = parse_port_file("50123 0a1b2c\r\n").unwrap();
        assert_eq!(port, 50123);
        assert!(is_knock(&knock_line(&token), &token));
        assert!(!is_knock("show\n", &token));
        assert!(!is_knock("show 0a1b2d\n", &token));
        // An old-style file without a token isn't trusted.
        assert_eq!(parse_port_file("50123"), None);
        assert_eq!(parse_port_file("x 0a1b2c"), None);
    }
}
