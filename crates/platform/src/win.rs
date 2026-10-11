//! Windows backend: GDI capture and `SendInput` injection.
//!
//! Coordinates are relative to the top-left corner of the virtual desktop (all monitors), so
//! the same numbers work for capture and input. Runs as a normal desktop application; the secure
//! desktop (UAC prompts, the login screen) needs a system service and is not covered.

use crate::{Capturer, Frame, Injector, Monitor};
use anyhow::{anyhow, bail};
use std::mem::size_of;
use windows::core::BOOL;
use windows::Win32::Foundation::{LPARAM, RECT};
use windows::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, EnumDisplayMonitors, GetDC, GetMonitorInfoW,
    ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, CAPTUREBLT, DIB_RGB_COLORS, HDC, HMONITOR,
    MONITORINFO, MONITORINFOEXW, SRCCOPY,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_EXTENDEDKEY,
    KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
    MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEINPUT, MOUSE_EVENT_FLAGS, VIRTUAL_KEY,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, MONITORINFOF_PRIMARY, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
    SM_YVIRTUALSCREEN, WHEEL_DELTA,
};

/// The virtual desktop: (x, y, width, height) in screen coordinates.
fn virtual_screen() -> (i32, i32, i32, i32) {
    unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1),
            GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1),
        )
    }
}

/// Stable id for a monitor from its device name (FNV-1a).
fn monitor_id(name: &str) -> u32 {
    name.bytes().fold(0x811c_9dc5u32, |h, b| (h ^ b as u32).wrapping_mul(0x0100_0193)).max(1)
}

fn list_monitors() -> Vec<Monitor> {
    unsafe extern "system" fn each(m: HMONITOR, _: HDC, _: *mut RECT, data: LPARAM) -> BOOL {
        let out = &mut *(data.0 as *mut Vec<Monitor>);
        let mut info = MONITORINFOEXW::default();
        info.monitorInfo.cbSize = size_of::<MONITORINFOEXW>() as u32;
        if GetMonitorInfoW(m, &mut info as *mut MONITORINFOEXW as *mut MONITORINFO).as_bool() {
            let r = info.monitorInfo.rcMonitor;
            let len = info.szDevice.iter().position(|&c| c == 0).unwrap_or(info.szDevice.len());
            let name = String::from_utf16_lossy(&info.szDevice[..len]);
            out.push(Monitor {
                id: monitor_id(&name),
                name: name.trim_start_matches(r"\\.\").to_owned(),
                x: r.left,
                y: r.top,
                width: (r.right - r.left).max(0) as u32,
                height: (r.bottom - r.top).max(0) as u32,
                primary: info.monitorInfo.dwFlags & MONITORINFOF_PRIMARY != 0,
            });
        }
        true.into()
    }
    let mut out: Vec<Monitor> = Vec::new();
    unsafe {
        let _ = EnumDisplayMonitors(None, None, Some(each), LPARAM(&mut out as *mut Vec<Monitor> as isize));
    }
    out
}

#[derive(Default)]
pub struct GdiCapturer {
    selected: Option<u32>,
}

impl GdiCapturer {
    pub fn open() -> anyhow::Result<Self> {
        Ok(Self::default())
    }
}

impl Capturer for GdiCapturer {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        let (vx, vy, vw, vh) = virtual_screen();
        let monitor = self.selected.and_then(|id| list_monitors().into_iter().find(|m| m.id == id));
        let (x, y, w, h) = match &monitor {
            Some(m) => (m.x, m.y, m.width as i32, m.height as i32),
            None => (vx, vy, vw, vh),
        };
        if w <= 0 || h <= 0 {
            bail!("empty screen area");
        }
        let data = unsafe { grab(x, y, w, h)? };
        let view = monitor.map(|m| (m.x - vx, m.y - vy, m.width, m.height));
        Ok(Frame { width: w as u32, height: h as u32, stride: w as usize * 4, data, view })
    }

    fn monitors(&mut self) -> anyhow::Result<Vec<Monitor>> {
        Ok(list_monitors())
    }

    fn select_monitor(&mut self, id: Option<u32>) -> anyhow::Result<()> {
        if let Some(id) = id {
            if !list_monitors().iter().any(|m| m.id == id) {
                bail!("no such monitor");
            }
        }
        self.selected = id;
        Ok(())
    }
}

/// Copies a screen rectangle into a top-down BGRA buffer.
unsafe fn grab(x: i32, y: i32, w: i32, h: i32) -> anyhow::Result<Vec<u8>> {
    let screen = GetDC(None);
    if screen.is_invalid() {
        bail!("GetDC failed");
    }
    let mem = CreateCompatibleDC(Some(screen));
    let info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w,
            biHeight: -h, // negative: top-down rows
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut bits = std::ptr::null_mut();
    let result = (|| {
        let bitmap = CreateDIBSection(Some(mem), &info, DIB_RGB_COLORS, &mut bits, None, 0)
            .map_err(|e| anyhow!("CreateDIBSection: {e}"))?;
        let old = SelectObject(mem, bitmap.into());
        let copied = BitBlt(mem, 0, 0, w, h, Some(screen), x, y, SRCCOPY | CAPTUREBLT);
        let data = if copied.is_ok() && !bits.is_null() {
            Ok(std::slice::from_raw_parts(bits as *const u8, (w * h * 4) as usize).to_vec())
        } else {
            Err(anyhow!("BitBlt failed"))
        };
        SelectObject(mem, old);
        let _ = DeleteObject(bitmap.into());
        data
    })();
    let _ = DeleteDC(mem);
    ReleaseDC(None, screen);
    result
}

pub struct SendInputInjector;

impl SendInputInjector {
    pub fn open() -> anyhow::Result<Self> {
        Ok(Self)
    }
}

fn mouse(flags: MOUSE_EVENT_FLAGS, dx: i32, dy: i32, data: i32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT { dx, dy, mouseData: data as u32, dwFlags: flags, time: 0, dwExtraInfo: 0 },
        },
    }
}

fn keyboard(vk: u16, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT { wVk: VIRTUAL_KEY(vk), wScan: scan, dwFlags: flags, time: 0, dwExtraInfo: 0 },
        },
    }
}

fn send(inputs: &[INPUT]) -> anyhow::Result<()> {
    let sent = unsafe { SendInput(inputs, size_of::<INPUT>() as i32) };
    if sent as usize != inputs.len() {
        bail!("SendInput injected {sent} of {} events", inputs.len());
    }
    Ok(())
}

impl Injector for SendInputInjector {
    fn screen_size(&mut self) -> anyhow::Result<(u32, u32)> {
        let (_, _, w, h) = virtual_screen();
        Ok((w as u32, h as u32))
    }

    fn pointer_move(&mut self, x: u32, y: u32) -> anyhow::Result<()> {
        let (_, _, w, h) = virtual_screen();
        // Absolute coordinates on the virtual desktop are normalized to 0..=65535.
        let nx = (x as i64 * 65535 / (w - 1).max(1) as i64) as i32;
        let ny = (y as i64 * 65535 / (h - 1).max(1) as i64) as i32;
        send(&[mouse(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK, nx, ny, 0)])
    }

    fn button(&mut self, button: u8, down: bool) -> anyhow::Result<()> {
        let flags = match (button, down) {
            (1, true) => MOUSEEVENTF_LEFTDOWN,
            (1, false) => MOUSEEVENTF_LEFTUP,
            (2, true) => MOUSEEVENTF_MIDDLEDOWN,
            (2, false) => MOUSEEVENTF_MIDDLEUP,
            (3, true) => MOUSEEVENTF_RIGHTDOWN,
            (3, false) => MOUSEEVENTF_RIGHTUP,
            _ => bail!("unsupported mouse button {button}"),
        };
        send(&[mouse(flags, 0, 0, 0)])
    }

    fn scroll(&mut self, dx: i32, dy: i32) -> anyhow::Result<()> {
        let mut inputs = Vec::new();
        if dy != 0 {
            // Positive dy means down; Windows' positive wheel delta means up.
            inputs.push(mouse(MOUSEEVENTF_WHEEL, 0, 0, -dy * WHEEL_DELTA as i32));
        }
        if dx != 0 {
            inputs.push(mouse(MOUSEEVENTF_HWHEEL, 0, 0, dx * WHEEL_DELTA as i32));
        }
        if inputs.is_empty() {
            return Ok(());
        }
        send(&inputs)
    }

    fn key(&mut self, keysym: u32, down: bool) -> anyhow::Result<()> {
        let up = if down { KEYBD_EVENT_FLAGS(0) } else { KEYEVENTF_KEYUP };
        if let Some((vk, extended)) = vk_for_keysym(keysym) {
            let flags = if extended { up | KEYEVENTF_EXTENDEDKEY } else { up };
            return send(&[keyboard(vk, 0, flags)]);
        }
        // Anything else is typed as the Unicode character it stands for.
        let Some(ch) = crate::keysym_char(keysym) else { bail!("no key for keysym {keysym:#x}") };
        let mut units = [0u16; 2];
        let inputs: Vec<INPUT> =
            ch.encode_utf16(&mut units).iter().map(|&u| keyboard(0, u, KEYEVENTF_UNICODE | up)).collect();
        send(&inputs)
    }
}

/// Windows virtual-key code for an X11 keysym, and whether it is an "extended" key.
pub fn vk_for_keysym(keysym: u32) -> Option<(u16, bool)> {
    Some(match keysym {
        // Letters and digits as keys, so shortcuts like Ctrl+C work.
        0x61..=0x7a => ((keysym - 0x61 + 0x41) as u16, false),
        0x41..=0x5a => (keysym as u16, false),
        0x30..=0x39 => (keysym as u16, false),
        0x20 => (0x20, false),
        0xff08 => (0x08, false),                                     // BackSpace
        0xff09 => (0x09, false),                                     // Tab
        0xff0d => (0x0d, false),                                     // Return
        0xff13 => (0x13, false),                                     // Pause
        0xff14 => (0x91, false),                                     // Scroll_Lock
        0xff1b => (0x1b, false),                                     // Escape
        0xff50 => (0x24, true),                                      // Home
        0xff51 => (0x25, true),                                      // Left
        0xff52 => (0x26, true),                                      // Up
        0xff53 => (0x27, true),                                      // Right
        0xff54 => (0x28, true),                                      // Down
        0xff55 => (0x21, true),                                      // Prior
        0xff56 => (0x22, true),                                      // Next
        0xff57 => (0x23, true),                                      // End
        0xff61 => (0x2c, false),                                     // Print
        0xff63 => (0x2d, true),                                      // Insert
        0xff67 => (0x5d, true),                                      // Menu
        0xff7f => (0x90, false),                                     // Num_Lock
        0xffbe..=0xffc9 => ((keysym - 0xffbe + 0x70) as u16, false), // F1..F12
        0xffe1 => (0xa0, false),                                     // Shift_L
        0xffe2 => (0xa1, false),                                     // Shift_R
        0xffe3 => (0xa2, false),                                     // Control_L
        0xffe4 => (0xa3, true),                                      // Control_R
        0xffe5 => (0x14, false),                                     // Caps_Lock
        0xffe9 => (0xa4, false),                                     // Alt_L
        0xffea => (0xa5, true),                                      // Alt_R
        0xffeb => (0x5b, true),                                      // Super_L
        0xffec => (0x5c, true),                                      // Super_R
        0xffff => (0x2e, true),                                      // Delete
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keysyms_map_to_virtual_keys() {
        assert_eq!(vk_for_keysym(0x63), Some((0x43, false))); // c → 'C'
        assert_eq!(vk_for_keysym(0x43), Some((0x43, false)));
        assert_eq!(vk_for_keysym(0xff0d), Some((0x0d, false)));
        assert_eq!(vk_for_keysym(0xff51), Some((0x25, true)));
        assert_eq!(vk_for_keysym(0xffc9), Some((0x7b, false))); // F12
        assert_eq!(vk_for_keysym(0x0100_263a), None);
    }

    /// Runs against the real desktop (or Wine): capture something and move the pointer.
    #[test]
    fn capture_and_pointer_on_the_desktop() {
        if std::env::var_os("SOMEDESK_TEST_WINDOWS_DESKTOP").is_none() {
            eprintln!("SOMEDESK_TEST_WINDOWS_DESKTOP not set, skipping");
            return;
        }
        let mut cap = GdiCapturer::open().unwrap();
        let f = cap.capture().unwrap();
        let (_, _, w, h) = virtual_screen();
        assert_eq!((f.width, f.height), (w as u32, h as u32));
        assert_eq!(f.data.len(), f.stride * f.height as usize);
        let monitors = cap.monitors().unwrap();
        assert!(!monitors.is_empty());
        cap.select_monitor(Some(monitors[0].id)).unwrap();
        let f = cap.capture().unwrap();
        assert_eq!((f.width, f.height), (monitors[0].width, monitors[0].height));

        let mut inj = SendInputInjector::open().unwrap();
        inj.pointer_move(w as u32 / 4, h as u32 / 2).unwrap();
        let mut p = windows::Win32::Foundation::POINT::default();
        unsafe { windows::Win32::UI::WindowsAndMessaging::GetCursorPos(&mut p).unwrap() };
        assert!((p.x - w / 4).abs() <= 1 && (p.y - h / 2).abs() <= 1, "cursor at {},{}", p.x, p.y);
        inj.key(0x61, true).unwrap();
        inj.key(0x61, false).unwrap();
        inj.key(0x0100_263a, true).unwrap();
        inj.key(0x0100_263a, false).unwrap();
        inj.scroll(0, 1).unwrap();
    }
}
