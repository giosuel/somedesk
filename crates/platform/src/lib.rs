//! Platform backends: screen capture and input injection.
//!
//! Backends implement [`Capturer`] and [`Injector`]. Currently: Linux/X11. Wayland (via the
//! xdg-desktop-portal), Windows and macOS plug in behind the same traits later.

#[cfg(target_os = "linux")]
pub mod linux;

/// One captured frame, 32-bit BGRX/BGRA.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    /// Bytes per row.
    pub stride: usize,
    pub data: Vec<u8>,
}

pub trait Capturer: Send {
    /// Captures the whole screen.
    fn capture(&mut self) -> anyhow::Result<Frame>;
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

/// Opens the default capturer for this machine.
pub fn default_capturer() -> anyhow::Result<Box<dyn Capturer>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::x11::X11Capturer::open(None)?))
    }
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("screen capture is not implemented on this platform yet")
}

/// Opens the default input injector for this machine.
pub fn default_injector() -> anyhow::Result<Box<dyn Injector>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::x11::X11Injector::open(None)?))
    }
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("input injection is not implemented on this platform yet")
}
