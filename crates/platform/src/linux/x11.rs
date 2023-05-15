//! X11 backend: `GetImage` capture and XTest input injection.

use crate::{Capturer, Frame, Injector, Monitor};
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
            bail!("this is a Wayland session without X11; use the portal backend (SOMEDESK_BACKEND=portal)");
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
    /// Selected monitor (RandR monitor name atom), or `None` for the whole screen.
    selected: Option<u32>,
}

impl X11Capturer {
    pub fn open(display: Option<&str>) -> anyhow::Result<Self> {
        let (conn, root) = connect(display)?;
        let depth = conn.setup().roots.iter().find(|s| s.root == root).map(|s| s.root_depth).unwrap_or(0);
        let bpp = conn.setup().pixmap_formats.iter().find(|f| f.depth == depth).map(|f| f.bits_per_pixel);
        if bpp != Some(32) {
            bail!("unsupported X11 pixel format (depth {depth}, {bpp:?} bits per pixel)");
        }
        Ok(Self { conn, root, selected: None })
    }

    fn monitor(&mut self, id: u32) -> anyhow::Result<Option<Monitor>> {
        Ok(self.monitors()?.into_iter().find(|m| m.id == id))
    }
}

impl Capturer for X11Capturer {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        let geo = self.conn.get_geometry(self.root)?.reply()?;
        // The selected monitor, clipped to the screen; the whole screen if it went away.
        let area = match self.selected {
            Some(id) => self.monitor(id)?.map(|m| {
                let x = m.x.clamp(0, geo.width as i32);
                let y = m.y.clamp(0, geo.height as i32);
                let w = (m.width as i32).min(geo.width as i32 - x).max(1);
                let h = (m.height as i32).min(geo.height as i32 - y).max(1);
                (x as i16, y as i16, w as u16, h as u16)
            }),
            None => None,
        };
        let (x, y, w, h) = area.unwrap_or((0, 0, geo.width, geo.height));
        let img = self.conn.get_image(ImageFormat::Z_PIXMAP, self.root, x, y, w, h, !0)?.reply().context("GetImage")?;
        let stride = img.data.len() / h.max(1) as usize;
        let view = area.map(|_| (x as i32, y as i32, w as u32, h as u32));
        Ok(Frame { width: w as u32, height: h as u32, stride, data: img.data, view })
    }

    fn monitors(&mut self) -> anyhow::Result<Vec<Monitor>> {
        use x11rb::protocol::randr::ConnectionExt as _;
        let Ok(cookie) = self.conn.randr_get_monitors(self.root, true) else { return Ok(Vec::new()) };
        let Ok(reply) = cookie.reply() else { return Ok(Vec::new()) };
        let mut out = Vec::new();
        for m in reply.monitors {
            let name = self
                .conn
                .get_atom_name(m.name)?
                .reply()
                .map(|r| String::from_utf8_lossy(&r.name).into_owned())
                .unwrap_or_default();
            out.push(Monitor {
                id: m.name,
                name,
                x: m.x as i32,
                y: m.y as i32,
                width: m.width as u32,
                height: m.height as u32,
                primary: m.primary,
            });
        }
        Ok(out)
    }

    fn select_monitor(&mut self, id: Option<u32>) -> anyhow::Result<()> {
        if let Some(id) = id {
            if self.monitor(id)?.is_none() {
                bail!("no such monitor");
            }
        }
        self.selected = id;
        Ok(())
    }
}

pub struct X11Injector {
    conn: RustConnection,
    root: Window,
    min_keycode: Keycode,
    max_keycode: Keycode,
    per_keycode: usize,
    /// Keysyms of every keycode, `per_keycode` entries each, starting at `min_keycode`.
    keysyms: Vec<Keysym>,
    /// The modifier bit that selects the third level (the one `ISO_Level3_Shift`, AltGr, sets).
    level3_mask: u16,
    /// Keycodes with no keysyms, which we can temporarily remap for characters the layout lacks.
    spare: Vec<Keycode>,
    next_spare: usize,
    remapped: HashMap<Keysym, Keycode>,
    /// Keys held down and the keycode each one went down on, so it is released on that keycode
    /// even if the mapping changed in between.
    held: HashMap<Keysym, Keycode>,
}

const SHIFT_MASK: u16 = 1;
const LOCK_MASK: u16 = 2;
const ISO_LEVEL3_SHIFT: Keysym = 0xfe03;

impl X11Injector {
    pub fn open(display: Option<&str>) -> anyhow::Result<Self> {
        let (conn, root) = connect(display)?;
        conn.xtest_get_version(2, 2)?.reply().context("the XTEST extension is not available")?;
        let (min, max) = (conn.setup().min_keycode, conn.setup().max_keycode);
        let mut injector = Self {
            conn,
            root,
            min_keycode: min,
            max_keycode: max,
            per_keycode: 0,
            keysyms: Vec::new(),
            level3_mask: 0x80,
            spare: Vec::new(),
            next_spare: 0,
            remapped: HashMap::new(),
            held: HashMap::new(),
        };
        injector.load_mapping()?;
        Ok(injector)
    }

    /// Reads the keyboard and modifier mapping, at the start and whenever it changes.
    fn load_mapping(&mut self) -> anyhow::Result<()> {
        let (min, max) = (self.min_keycode, self.max_keycode);
        let map = self.conn.get_keyboard_mapping(min, max - min + 1)?.reply()?;
        self.per_keycode = (map.keysyms_per_keycode as usize).max(1);
        self.keysyms = map.keysyms;
        // Our remaps survive changes made by others only if the keycode still has our keysym
        // (a new layout replaces the whole map).
        let remapped = std::mem::take(&mut self.remapped);
        self.remapped = remapped.into_iter().filter(|&(k, kc)| self.syms(kc).contains(&k)).collect();
        self.spare = (min..=max)
            .filter(|&kc| self.syms(kc).iter().all(|&k| k == 0) || self.remapped.values().any(|&r| r == kc))
            .collect();
        let mods = self.conn.get_modifier_mapping()?.reply()?;
        let per_mod = (mods.keycodes.len() / 8).max(1);
        self.level3_mask = mods
            .keycodes
            .chunks(per_mod)
            .position(|kcs| kcs.iter().any(|&kc| kc != 0 && self.syms(kc).contains(&ISO_LEVEL3_SHIFT)))
            .map_or(0x80, |i| 1 << i);
        Ok(())
    }

    /// The keysyms of `kc`.
    fn syms(&self, kc: Keycode) -> &[Keysym] {
        let i = kc.wrapping_sub(self.min_keycode) as usize * self.per_keycode;
        self.keysyms.get(i..i + self.per_keycode).unwrap_or(&[])
    }

    fn keycodes(&self) -> impl Iterator<Item = Keycode> {
        self.min_keycode..=self.max_keycode
    }

    /// Picks up a keyboard mapping change (another layout, or our own remap) reported by the
    /// X server since the last call.
    fn handle_events(&mut self) -> anyhow::Result<()> {
        let mut changed = false;
        while let Some(event) = self.conn.poll_for_event()? {
            if let x11rb::protocol::Event::MappingNotify(e) = event {
                changed |= e.request != x11rb::protocol::xproto::Mapping::POINTER;
            }
        }
        if changed {
            self.load_mapping()?;
        }
        Ok(())
    }

    /// The keycode to press for `keysym`: one that types it with the modifiers held right now
    /// (Shift, AltGr, Caps Lock), or else a spare keycode remapped to it.
    fn keycode_for(&mut self, keysym: Keysym) -> anyhow::Result<Keycode> {
        let state = u16::from(self.conn.query_pointer(self.root)?.reply()?.mask);
        self.handle_events()?;
        let level = usize::from(state & SHIFT_MASK != 0) + if state & self.level3_mask != 0 { 2 } else { 0 };
        let (group, lock) = (usize::from((state >> 13) & 3), state & LOCK_MASK != 0);
        let borrowed = |kc: &Keycode| self.remapped.values().any(|r| r == kc);
        if let Some(kc) =
            self.keycodes().find(|kc| !borrowed(kc) && level_keysym(self.syms(*kc), group, level, lock) == keysym)
        {
            return Ok(kc);
        }
        if let Some(&kc) = self.remapped.get(&keysym) {
            return Ok(kc);
        }
        // Keys that don't type a character (Tab, arrows, modifiers) keep their own key on any
        // level: Shift+Tab has to be Shift plus the Tab key.
        if crate::keysym_char(keysym).is_none() {
            if let Some(kc) = self.any_keycode(keysym) {
                return Ok(kc);
            }
        }
        // Not on the current layout at this level: borrow a spare keycode (the same trick
        // xdotool uses), but never one a held key is still down on.
        let n = self.spare.len();
        let Some(kc) =
            (0..n).map(|i| self.spare[(self.next_spare + i) % n]).find(|kc| !self.held.values().any(|h| h == kc))
        else {
            bail!("no spare keycode available for keysym {keysym:#x}");
        };
        self.next_spare = self.spare.iter().position(|&s| s == kc).unwrap_or(0) + 1;
        self.remapped.retain(|_, v| *v != kc);
        let syms = vec![keysym; self.per_keycode];
        self.conn.change_keyboard_mapping(1, kc, self.per_keycode as u8, &syms)?;
        self.conn.sync()?;
        let i = (kc - self.min_keycode) as usize * self.per_keycode;
        self.keysyms[i..i + self.per_keycode].copy_from_slice(&syms);
        self.remapped.insert(keysym, kc);
        Ok(kc)
    }

    /// A keycode with `keysym` on any level, or remapped to it.
    fn any_keycode(&self, keysym: Keysym) -> Option<Keycode> {
        self.keycodes().find(|&kc| self.syms(kc).contains(&keysym)).or_else(|| self.remapped.get(&keysym).copied())
    }

    fn fake(&self, kind: u8, detail: u8, x: i16, y: i16) -> anyhow::Result<()> {
        self.conn.xtest_fake_input(kind, detail, x11rb::CURRENT_TIME, self.root, x, y, 0)?;
        self.conn.flush()?;
        Ok(())
    }
}

impl Drop for X11Injector {
    fn drop(&mut self) {
        // Let go of anything still held, and give the borrowed keycodes back: the keyboard
        // mapping belongs to the whole X server and would otherwise keep our remaps.
        for (_, kc) in std::mem::take(&mut self.held) {
            let _ = self.fake(KEY_RELEASE_EVENT, kc, 0, 0);
        }
        let _ = self.handle_events();
        let none = vec![0; self.per_keycode];
        for (&keysym, &kc) in &self.remapped {
            if self.syms(kc).contains(&keysym) {
                let _ = self.conn.change_keyboard_mapping(1, kc, self.per_keycode as u8, &none);
            }
        }
        let _ = self.conn.sync();
    }
}

/// The lower- and uppercase form of a Latin-1 letter keysym, or the keysym twice.
fn case_pair(k: Keysym) -> (Keysym, Keysym) {
    match k {
        0x41..=0x5a | 0xc0..=0xd6 | 0xd8..=0xde => (k + 0x20, k),
        0x61..=0x7a | 0xe0..=0xf6 | 0xf8..=0xfe => (k, k - 0x20),
        _ => (k, k),
    }
}

/// The keysym a key with the core keysym list `syms` types in `group` at `level` (Shift adds
/// one, the level-3 modifier two), with Caps Lock `lock` on. Follows the core protocol's rules
/// for the first two columns of a group, and XKB's layout of the core map, which puts the third
/// and fourth level of the first group in columns 4 and 5. Returns NoSymbol (0) where it can't
/// tell, so a spare keycode is used instead.
fn level_keysym(syms: &[Keysym], group: usize, level: usize, lock: bool) -> Keysym {
    let at = |i: usize| syms.get(i).copied().unwrap_or(0);
    let mut level = level;
    if level >= 2 {
        if group != 0 {
            return 0;
        }
        if at(4) != 0 || at(5) != 0 {
            return match at(4 + level - 2) {
                0 => at(4),
                k => k,
            };
        }
        // A key without a third level ignores the level-3 modifier.
        level -= 2;
    }
    let base = match group {
        0 => 0,
        // A key without a second group uses its first one.
        1 if at(2) != 0 || at(3) != 0 => 2,
        1 => 0,
        _ => return 0,
    };
    let (lower, upper) = match (at(base), at(base + 1)) {
        (a, 0) => case_pair(a),
        (a, b) => (a, b),
    };
    let alphabetic = lower != upper && case_pair(lower) == (lower, upper);
    if (level == 1) ^ (lock && alphabetic) {
        upper
    } else {
        lower
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
        if !down {
            let Some(kc) = self.held.remove(&keysym).or_else(|| self.any_keycode(keysym)) else {
                return Ok(());
            };
            return self.fake(KEY_RELEASE_EVENT, kc, 0, 0);
        }
        // Auto-repeat goes to the key that is already down.
        let kc = match self.held.get(&keysym) {
            Some(&kc) => kc,
            None => self.keycode_for(keysym)?,
        };
        self.held.insert(keysym, kc);
        self.fake(KEY_PRESS_EVENT, kc, 0, 0)
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
    fn levels_follow_the_core_rules() {
        let de_q = [0x71, 0x51, 0x71, 0x51, 0x40, 0x7d9]; // q Q q Q at Greek_OMEGA
        assert_eq!(level_keysym(&de_q, 0, 0, false), 0x71);
        assert_eq!(level_keysym(&de_q, 0, 1, false), 0x51);
        assert_eq!(level_keysym(&de_q, 0, 0, true), 0x51, "Caps Lock shifts letters");
        assert_eq!(level_keysym(&de_q, 0, 1, true), 0x71);
        assert_eq!(level_keysym(&de_q, 0, 2, false), 0x40, "AltGr");
        let two = [0x32, 0x40]; // 2 at
        assert_eq!(level_keysym(&two, 0, 0, true), 0x32, "Caps Lock leaves digits alone");
        assert_eq!(level_keysym(&two, 0, 2, false), 0x32, "no third level: AltGr is ignored");
        assert_eq!(level_keysym(&two, 1, 1, false), 0x40, "no second group: the first one");
        let one = [0xff53]; // Right
        assert_eq!(level_keysym(&one, 0, 1, false), 0xff53);
        let lone_letter = [0x61];
        assert_eq!(level_keysym(&lone_letter, 0, 1, false), 0x41, "a lone letter has both cases");
    }

    /// Runs `f` with the test display switched to keyboard layout `layout`, then back to "us".
    fn with_layout(d: &str, layout: &str, f: impl FnOnce()) {
        let setxkbmap = |l: &str| std::process::Command::new("setxkbmap").arg("-display").arg(d).arg(l).status();
        match setxkbmap(layout) {
            Ok(s) if s.success() => {}
            _ => {
                eprintln!("setxkbmap {layout} failed, skipping");
                return;
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        let _ = setxkbmap("us");
        result.unwrap();
    }

    #[test]
    fn characters_on_other_levels_of_a_german_layout() {
        let Some(d) = display() else { return };
        let (conn, _) = connect(Some(&d)).unwrap();
        // Opened on the US layout: the layout switch below must be picked up.
        let _ = std::process::Command::new("setxkbmap").arg("-display").arg(&d).arg("us").status();
        let mut inj = X11Injector::open(Some(&d)).unwrap();
        let mapping = |kc: u8| conn.get_keyboard_mapping(kc, 1).unwrap().reply().unwrap().keysyms;
        with_layout(&d, "de", || {
            const AT: u32 = 0x40;
            // A US viewer types '@' as Shift+2. On a German host Shift+2 is '"' and '@' is
            // AltGr+Q (Shift+Q would be 'Q'), so a borrowed key has to type it.
            inj.key(0xffe1, true).unwrap();
            inj.key(AT, true).unwrap();
            inj.conn.sync().unwrap();
            let kc = inj.held[&AT];
            assert!(keycode_is_down(&conn, kc));
            assert_eq!(mapping(kc)[1], AT, "the key types '@' with Shift held");
            inj.key(AT, false).unwrap();
            inj.key(0xffe1, false).unwrap();
            inj.conn.sync().unwrap();
            assert!(!keycode_is_down(&conn, kc));

            // A German viewer types it as AltGr+Q: that is the host's own key.
            inj.key(ISO_LEVEL3_SHIFT, true).unwrap();
            inj.key(AT, true).unwrap();
            let kc = inj.held[&AT];
            inj.key(AT, false).unwrap();
            inj.key(ISO_LEVEL3_SHIFT, false).unwrap();
            inj.conn.sync().unwrap();
            assert_eq!(mapping(kc)[0], 0x71, "AltGr+@ goes to the Q key");
            assert_eq!(mapping(kc)[4], AT);

            // Without modifiers (the phone's keyboard sends just the character) it's no Q either.
            inj.key(AT, true).unwrap();
            let kc = inj.held[&AT];
            inj.key(AT, false).unwrap();
            assert_eq!(mapping(kc)[0], AT);
        });
    }

    #[test]
    fn held_keys_keep_their_spare_keycode() {
        let Some(d) = display() else { return };
        let mut inj = X11Injector::open(Some(&d)).unwrap();
        let (conn, _) = connect(Some(&d)).unwrap();
        inj.spare.truncate(2);
        let held = 0x0100_2600;
        inj.key(held, true).unwrap();
        let kc = inj.held[&held];
        // More unusual keysyms than spare keycodes while the first one is still down.
        for k in 0x0100_2601..0x0100_2605 {
            inj.key(k, true).unwrap();
            inj.key(k, false).unwrap();
            assert_ne!(inj.held.get(&k), Some(&kc));
        }
        inj.conn.sync().unwrap();
        assert!(keycode_is_down(&conn, kc));
        assert_eq!(conn.get_keyboard_mapping(kc, 1).unwrap().reply().unwrap().keysyms[0], held);
        inj.key(held, false).unwrap();
        inj.conn.sync().unwrap();
        assert!(!keycode_is_down(&conn, kc));
    }

    #[test]
    fn remaps_are_undone_on_drop() {
        let Some(d) = display() else { return };
        let mut inj = X11Injector::open(Some(&d)).unwrap();
        let smiley = 0x0100_263B;
        inj.key(smiley, true).unwrap();
        let kc = inj.remapped[&smiley];
        drop(inj);
        let (conn, _) = connect(Some(&d)).unwrap();
        assert!(!keycode_is_down(&conn, kc), "released on drop");
        let map = conn.get_keyboard_mapping(kc, 1).unwrap().reply().unwrap();
        assert!(map.keysyms.iter().all(|&k| k == 0), "{:x?}", map.keysyms);
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

    #[test]
    fn randr_monitors_can_be_captured_separately() {
        let Some(d) = display() else { return };
        let xrandr = |args: &[&str]| std::process::Command::new("xrandr").arg("-display").arg(&d).args(args).status();
        if xrandr(&["--version"]).is_err() {
            eprintln!("xrandr not installed, skipping");
            return;
        }
        let mut cap = X11Capturer::open(Some(&d)).unwrap();
        let full = cap.capture().unwrap();
        let (w, h) = (full.width, full.height);
        let left = format!("{}/1x{}/1+0+0", w / 2, h);
        let right = format!("{}/1x{}/1+{}+0", w - w / 2, h, w / 2);
        xrandr(&["--setmonitor", "SD-LEFT", &left, "none"]).unwrap();
        xrandr(&["--setmonitor", "SD-RIGHT", &right, "none"]).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let monitors = cap.monitors().unwrap();
            let right = monitors.iter().find(|m| m.name == "SD-RIGHT").expect("right monitor listed");
            assert_eq!((right.x, right.width, right.height), ((w / 2) as i32, w - w / 2, h));
            cap.select_monitor(Some(right.id)).unwrap();
            let f = cap.capture().unwrap();
            assert_eq!((f.width, f.height, f.view), (w - w / 2, h, Some(((w / 2) as i32, 0, w - w / 2, h))));
            cap.select_monitor(None).unwrap();
            let f = cap.capture().unwrap();
            assert_eq!((f.width, f.height, f.view), (w, h, None));
            assert!(cap.select_monitor(Some(0xDEAD)).is_err());
        }));
        let _ = xrandr(&["--delmonitor", "SD-LEFT"]);
        let _ = xrandr(&["--delmonitor", "SD-RIGHT"]);
        result.unwrap();
    }
}
