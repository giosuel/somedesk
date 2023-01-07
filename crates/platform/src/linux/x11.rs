//! X11 backend: `GetImage` capture and XTest input injection.

use crate::{Capturer, Frame, Injector};
use anyhow::{bail, Context};
use std::collections::HashMap;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    ConnectionExt as _, ImageFormat, Keycode, Keysym, Window, BUTTON_PRESS_EVENT, BUTTON_RELEASE_EVENT,
    KEY_PRESS_EVENT, KEY_RELEASE_EVENT, MOTION_NOTIFY_EVENT,
};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;

fn connect(display: Option<&str>) -> anyhow::Result<(RustConnection, Window)> {
    if display.is_none() && std::env::var_os("DISPLAY").is_none() {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            bail!("Wayland sessions are not supported yet; please log in with an X11 session");
        }
        bail!("no X11 display found (DISPLAY is not set)");
    }
    let (conn, screen) = RustConnection::connect(display).context("connecting to the X server")?;
    let root = conn.setup().roots[screen].root;
    Ok((conn, root))
}

pub struct X11Capturer {
    conn: RustConnection,
    root: Window,
}

impl X11Capturer {
    pub fn open(display: Option<&str>) -> anyhow::Result<Self> {
        let (conn, root) = connect(display)?;
        let depth = conn.setup().roots.iter().find(|s| s.root == root).map(|s| s.root_depth).unwrap_or(0);
        let bpp = conn.setup().pixmap_formats.iter().find(|f| f.depth == depth).map(|f| f.bits_per_pixel);
        if bpp != Some(32) {
            bail!("unsupported X11 pixel format (depth {depth}, {bpp:?} bits per pixel)");
        }
        Ok(Self { conn, root })
    }
}

impl Capturer for X11Capturer {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        let geo = self.conn.get_geometry(self.root)?.reply()?;
        let (w, h) = (geo.width, geo.height);
        let img = self.conn.get_image(ImageFormat::Z_PIXMAP, self.root, 0, 0, w, h, !0)?.reply().context("GetImage")?;
        let stride = img.data.len() / h.max(1) as usize;
        Ok(Frame { width: w as u32, height: h as u32, stride, data: img.data })
    }
}

pub struct X11Injector {
    conn: RustConnection,
    root: Window,
    min_keycode: Keycode,
    per_keycode: usize,
    /// Keysyms of every keycode, `per_keycode` entries each, starting at `min_keycode`.
    keysyms: Vec<Keysym>,
    /// Keycodes with no keysyms, which we can temporarily remap for characters the layout lacks.
    spare: Vec<Keycode>,
    next_spare: usize,
    remapped: HashMap<Keysym, Keycode>,
}

impl X11Injector {
    pub fn open(display: Option<&str>) -> anyhow::Result<Self> {
        let (conn, root) = connect(display)?;
        conn.xtest_get_version(2, 2)?.reply().context("the XTEST extension is not available")?;
        let (min, max) = (conn.setup().min_keycode, conn.setup().max_keycode);
        let map = conn.get_keyboard_mapping(min, max - min + 1)?.reply()?;
        let per = map.keysyms_per_keycode as usize;
        let spare = (min..=max)
            .filter(|kc| {
                let i = (kc - min) as usize * per;
                map.keysyms[i..i + per].iter().all(|&k| k == 0)
            })
            .collect();
        Ok(Self {
            conn,
            root,
            min_keycode: min,
            per_keycode: per,
            keysyms: map.keysyms,
            spare,
            next_spare: 0,
            remapped: HashMap::new(),
        })
    }

    fn keycode_for(&mut self, keysym: Keysym) -> anyhow::Result<Keycode> {
        if let Some(pos) = self.keysyms.iter().position(|&k| k == keysym) {
            return Ok(self.min_keycode + (pos / self.per_keycode) as u8);
        }
        if let Some(&kc) = self.remapped.get(&keysym) {
            return Ok(kc);
        }
        // Not on the current layout: borrow a spare keycode (the same trick xdotool uses).
        if self.spare.is_empty() {
            bail!("no spare keycode available for keysym {keysym:#x}");
        }
        let kc = self.spare[self.next_spare % self.spare.len()];
        self.next_spare += 1;
        self.remapped.retain(|_, v| *v != kc);
        let syms = vec![keysym; self.per_keycode];
        self.conn.change_keyboard_mapping(1, kc, self.per_keycode as u8, &syms)?;
        self.conn.sync()?;
        self.remapped.insert(keysym, kc);
        Ok(kc)
    }

    fn fake(&self, kind: u8, detail: u8, x: i16, y: i16) -> anyhow::Result<()> {
        self.conn.xtest_fake_input(kind, detail, x11rb::CURRENT_TIME, self.root, x, y, 0)?;
        self.conn.flush()?;
        Ok(())
    }
}

impl Injector for X11Injector {
    fn screen_size(&mut self) -> anyhow::Result<(u32, u32)> {
        let geo = self.conn.get_geometry(self.root)?.reply()?;
        Ok((geo.width as u32, geo.height as u32))
    }

    fn pointer_move(&mut self, x: u32, y: u32) -> anyhow::Result<()> {
        self.fake(MOTION_NOTIFY_EVENT, 0, x.min(i16::MAX as u32) as i16, y.min(i16::MAX as u32) as i16)
    }

    fn button(&mut self, button: u8, down: bool) -> anyhow::Result<()> {
        if !(1..=3).contains(&button) {
            bail!("unsupported mouse button {button}");
        }
        self.fake(if down { BUTTON_PRESS_EVENT } else { BUTTON_RELEASE_EVENT }, button, 0, 0)
    }

    fn scroll(&mut self, dx: i32, dy: i32) -> anyhow::Result<()> {
        // X11 wheel buttons: 4 up, 5 down, 6 left, 7 right.
        for (steps, neg, pos) in [(dy, 4u8, 5u8), (dx, 6, 7)] {
            let b = if steps < 0 { neg } else { pos };
            for _ in 0..steps.unsigned_abs().min(20) {
                self.fake(BUTTON_PRESS_EVENT, b, 0, 0)?;
                self.fake(BUTTON_RELEASE_EVENT, b, 0, 0)?;
            }
        }
        Ok(())
    }

    fn key(&mut self, keysym: u32, down: bool) -> anyhow::Result<()> {
        let kc = self.keycode_for(keysym)?;
        self.fake(if down { KEY_PRESS_EVENT } else { KEY_RELEASE_EVENT }, kc, 0, 0)
    }
}

#[cfg(test)]
mod tests {
    //! These tests need an X server. They run against `SOMEDESK_TEST_DISPLAY` (e.g. a Xvfb
    //! started by `scripts/test.sh`) and are skipped when it is not set.

    use super::*;
    use x11rb::protocol::xproto::{ChangeWindowAttributesAux, ConnectionExt};

    fn display() -> Option<String> {
        let d = std::env::var("SOMEDESK_TEST_DISPLAY").ok();
        if d.is_none() {
            eprintln!("SOMEDESK_TEST_DISPLAY not set, skipping X11 test");
        }
        d
    }

    fn keycode_is_down(conn: &RustConnection, kc: u8) -> bool {
        let keys = conn.query_keymap().unwrap().reply().unwrap().keys;
        keys[kc as usize / 8] & (1 << (kc % 8)) != 0
    }

    #[test]
    fn capture_reads_root_window_color() {
        let Some(d) = display() else { return };
        let (conn, root) = connect(Some(&d)).unwrap();
        // Paint the root background a known color (0x00RRGGBB on TrueColor visuals).
        conn.change_window_attributes(root, &ChangeWindowAttributesAux::new().background_pixel(0x0030_80C0)).unwrap();
        conn.clear_area(false, root, 0, 0, 0, 0).unwrap();
        conn.sync().unwrap();

        let mut cap = X11Capturer::open(Some(&d)).unwrap();
        let f = cap.capture().unwrap();
        assert!(f.width >= 640 && f.height >= 480);
        assert_eq!(f.stride, f.width as usize * 4);
        let px = &f.data[(10 * f.stride + 10 * 4)..][..3];
        assert_eq!(px, &[0xC0, 0x80, 0x30], "BGR of the root background");
    }

    #[test]
    fn pointer_injection_moves_pointer() {
        let Some(d) = display() else { return };
        let mut inj = X11Injector::open(Some(&d)).unwrap();
        inj.pointer_move(123, 234).unwrap();
        inj.conn.sync().unwrap();
        let (conn, root) = connect(Some(&d)).unwrap();
        let p = conn.query_pointer(root).unwrap().reply().unwrap();
        assert_eq!((p.root_x, p.root_y), (123, 234));
    }

    #[test]
    fn key_injection_presses_and_releases() {
        let Some(d) = display() else { return };
        let mut inj = X11Injector::open(Some(&d)).unwrap();
        let (conn, _) = connect(Some(&d)).unwrap();
        let kc = inj.keycode_for(0x61 /* 'a' */).unwrap();
        inj.key(0x61, true).unwrap();
        inj.conn.sync().unwrap();
        assert!(keycode_is_down(&conn, kc));
        inj.key(0x61, false).unwrap();
        inj.conn.sync().unwrap();
        assert!(!keycode_is_down(&conn, kc));
    }

    #[test]
    fn keysyms_missing_from_layout_are_remapped() {
        let Some(d) = display() else { return };
        let mut inj = X11Injector::open(Some(&d)).unwrap();
        let smiley = 0x0100_263A; // U+263A as a Unicode keysym
        inj.key(smiley, true).unwrap();
        inj.conn.sync().unwrap();
        let kc = inj.remapped[&smiley];
        let (conn, _) = connect(Some(&d)).unwrap();
        assert!(keycode_is_down(&conn, kc));
        let map = conn.get_keyboard_mapping(kc, 1).unwrap().reply().unwrap();
        assert_eq!(map.keysyms[0], smiley);
        inj.key(smiley, false).unwrap();
        inj.conn.sync().unwrap();
        assert!(!keycode_is_down(&conn, kc));
    }

    #[test]
    fn mouse_buttons_and_wheel() {
        let Some(d) = display() else { return };
        let mut inj = X11Injector::open(Some(&d)).unwrap();
        let (conn, root) = connect(Some(&d)).unwrap();
        inj.button(1, true).unwrap();
        inj.conn.sync().unwrap();
        let mask = u16::from(conn.query_pointer(root).unwrap().reply().unwrap().mask);
        inj.button(1, false).unwrap();
        inj.conn.sync().unwrap();
        assert!(mask & 0x100 != 0, "Button1Mask should be set while pressed");
        let mask = u16::from(conn.query_pointer(root).unwrap().reply().unwrap().mask);
        assert_eq!(mask & 0x100, 0);
        inj.scroll(0, 3).unwrap();
        inj.conn.sync().unwrap();
        assert!(inj.button(9, true).is_err());
    }
}
