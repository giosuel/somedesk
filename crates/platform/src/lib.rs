//! Platform backends: screen capture, input injection and the clipboard.
//!
//! Backends implement [`Capturer`], [`Injector`] and [`Clipboard`]: Linux X11, Linux Wayland (via
//! the xdg-desktop-portal), Windows (GDI + SendInput) and macOS (CoreGraphics). Android only
//! has a clipboard: the app there views other computers but does not share its own screen.

#[cfg(target_os = "android")]
pub mod android;
#[cfg(not(target_os = "android"))]
pub mod clipboard;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod mac;
#[cfg(windows)]
pub mod win;

/// One captured frame, 32-bit BGRX/BGRA.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    /// Bytes per row.
    pub stride: usize,
    pub data: Vec<u8>,
    /// The area the frame shows, in the injector's coordinates (x, y, width, height), when that
    /// is not simply the whole screen at one pixel per unit: one monitor, or a HiDPI screen whose
    /// pointer coordinates are in points. `None`: the frame is the whole screen.
    pub view: Option<(i32, i32, u32, u32)>,
}

/// A monitor that can be shown on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Monitor {
    /// Stable while the monitor exists.
    pub id: u32,
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
}

pub trait Capturer: Send {
    /// Captures the whole screen, or the selected monitor.
    fn capture(&mut self) -> anyhow::Result<Frame>;

    /// The monitors that can be selected. Fewer than two means there is nothing to choose.
    fn monitors(&mut self) -> anyhow::Result<Vec<Monitor>> {
        Ok(Vec::new())
    }

    /// Shows only monitor `id` from now on, or everything with `None`.
    fn select_monitor(&mut self, id: Option<u32>) -> anyhow::Result<()> {
        match id {
            None => Ok(()),
            Some(_) => anyhow::bail!("this screen cannot be split into monitors"),
        }
    }
}

pub trait Injector: Send {
    /// Current screen size, used to map normalized pointer coordinates.
    fn screen_size(&mut self) -> anyhow::Result<(u32, u32)>;
    fn pointer_move(&mut self, x: u32, y: u32) -> anyhow::Result<()>;
    /// 1 = left, 2 = middle, 3 = right.
    fn button(&mut self, button: u8, down: bool) -> anyhow::Result<()>;
    /// Wheel steps, positive = down / right.
    fn scroll(&mut self, dx: i32, dy: i32) -> anyhow::Result<()>;
    /// Presses or releases the key producing X11 keysym `keysym`.
    fn key(&mut self, keysym: u32, down: bool) -> anyhow::Result<()>;
}

/// The character an X11 keysym types: Latin-1 keysyms are their code point, Unicode keysyms
/// carry it in the low 24 bits. Used by backends that type text rather than press keys.
pub fn keysym_char(keysym: u32) -> Option<char> {
    match keysym {
        0x20..=0x7e | 0xa0..=0xff => char::from_u32(keysym),
        0x0100_0000..=0x0110_ffff => char::from_u32(keysym - 0x0100_0000),
        _ => None,
    }
}

pub trait Clipboard: Send {
    /// Current clipboard text, or `None` if the clipboard is empty or holds something else.
    fn get_text(&mut self) -> anyhow::Result<Option<String>>;
    fn set_text(&mut self, text: &str) -> anyhow::Result<()>;
}

/// Opens the system clipboard.
pub fn default_clipboard() -> anyhow::Result<Box<dyn Clipboard>> {
    #[cfg(target_os = "android")]
    return Ok(Box::new(android::AndroidClipboard::open()?));
    #[cfg(not(target_os = "android"))]
    Ok(Box::new(clipboard::SystemClipboard::open()?))
}

/// Whether [`open_screen`] is implemented here, i.e. whether others can connect to this device.
pub const fn can_share_screen() -> bool {
    cfg!(any(target_os = "linux", windows, target_os = "macos"))
}

/// The screen of this machine: a capturer and an injector that belong together.
pub struct Screen {
    pub capturer: Box<dyn Capturer>,
    pub injector: Box<dyn Injector>,
    /// False if the person at the computer allowed viewing but not remote input.
    pub can_control: bool,
    /// Human-readable backend name, for logs.
    pub backend: &'static str,
}

/// Which backend [`open_screen`] uses on Linux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxBackend {
    X11,
    /// xdg-desktop-portal (Wayland sessions).
    Portal,
}

/// Picks the backend for the current session: the portal on Wayland, X11 otherwise.
/// `SOMEDESK_BACKEND=x11|portal` overrides the choice.
pub fn detect_linux_backend() -> LinuxBackend {
    match std::env::var("SOMEDESK_BACKEND").as_deref() {
        Ok("x11") => return LinuxBackend::X11,
        Ok("portal") | Ok("wayland") => return LinuxBackend::Portal,
        _ => {}
    }
    // Under Wayland, DISPLAY usually points at XWayland, which only shows X11 apps.
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some()
        || std::env::var("XDG_SESSION_TYPE").is_ok_and(|t| t == "wayland");
    if wayland {
        LinuxBackend::Portal
    } else {
        LinuxBackend::X11
    }
}

const RESTORE_TOKEN_FILE: &str = "portal-restore-token";

/// Whether [`open_screen`] will make the desktop ask the user for permission (Wayland, and not
/// yet allowed before).
pub fn will_ask_permission(state_dir: Option<&std::path::Path>) -> bool {
    cfg!(target_os = "linux")
        && detect_linux_backend() == LinuxBackend::Portal
        && !state_dir.is_some_and(|d| d.join(RESTORE_TOKEN_FILE).exists())
}

/// Opens the screen for a session.
///
/// On Wayland this asks the person at the computer for permission through the desktop portal
/// (and may block until they answer). `state_dir` is where the portal's restore token is kept,
/// so the question is only asked once.
pub fn open_screen(state_dir: Option<&std::path::Path>) -> anyhow::Result<Screen> {
    #[cfg(target_os = "linux")]
    {
        match detect_linux_backend() {
            LinuxBackend::X11 => Ok(Screen {
                capturer: Box::new(linux::x11::X11Capturer::open(None)?),
                injector: Box::new(linux::x11::X11Injector::open(None)?),
                can_control: true,
                backend: "x11",
            }),
            LinuxBackend::Portal => {
                let token_path = state_dir.map(|d| d.join(RESTORE_TOKEN_FILE));
                let token = token_path
                    .as_ref()
                    .and_then(|p| std::fs::read_to_string(p).ok())
                    .map(|t| t.trim().to_owned())
                    .filter(|t| !t.is_empty());
                let session = linux::portal::open(token)?;
                if let (Some(path), Some(token)) = (&token_path, session.restore_token()) {
                    if let Err(e) = std::fs::write(path, token) {
                        tracing::warn!("cannot store the portal restore token: {e}");
                    }
                }
                let can_control = session.can_control();
                let (capturer, injector) = session.split();
                Ok(Screen {
                    capturer: Box::new(capturer),
                    injector: Box::new(injector),
                    can_control,
                    backend: "portal",
                })
            }
        }
    }
    #[cfg(windows)]
    {
        let _ = state_dir;
        Ok(Screen {
            capturer: Box::new(win::GdiCapturer::open()?),
            injector: Box::new(win::SendInputInjector::open()?),
            can_control: true,
            backend: "windows-gdi",
        })
    }
    #[cfg(target_os = "macos")]
    {
        let _ = state_dir;
        mac::open_screen()
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        let _ = state_dir;
        anyhow::bail!("screen sharing is not implemented on this platform yet")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn keysyms_to_characters() {
        assert_eq!(super::keysym_char(0x61), Some('a'));
        assert_eq!(super::keysym_char(0xe4), Some('ä'));
        assert_eq!(super::keysym_char(0x0100_263a), Some('☺'));
        assert_eq!(super::keysym_char(0xff0d), None);
    }
}
