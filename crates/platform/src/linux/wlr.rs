//! Remote input on wlroots-style compositors (Hyprland, Sway, river, ...) through the virtual
//! pointer and virtual keyboard protocols.
//!
//! Their desktop portals share the screen but have no `RemoteDesktop` interface, so the portal
//! alone gives a view-only session. These compositors instead let clients create a virtual
//! pointer (`zwlr_virtual_pointer_v1`) and keyboard (`zwp_virtual_keyboard_v1`), which is how
//! wayvnc controls them too.
//!
//! The virtual keyboard brings its own keymap. Like `wtype`, it is built on the fly: every
//! keysym the viewer presses gets a keycode of its own, so any character can be typed whatever
//! the layout of the computer. The usual keys are there from the start; the keymap is uploaded
//! again when another keysym comes along.

use crate::Injector;
use anyhow::{anyhow, bail, Context};
use rustix::fs::{memfd_create, MemfdFlags};
use std::io::Write;
use std::os::fd::AsFd;
use std::time::Instant;
use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::{wl_output, wl_pointer, wl_registry, wl_seat};
use wayland_client::{delegate_noop, Connection, Dispatch, EventQueue, Proxy, QueueHandle};
use wayland_protocols::xdg::xdg_output::zv1::client::{zxdg_output_manager_v1, zxdg_output_v1};
use wayland_protocols_misc::zwp_virtual_keyboard_v1::client::{
    zwp_virtual_keyboard_manager_v1::ZwpVirtualKeyboardManagerV1, zwp_virtual_keyboard_v1::ZwpVirtualKeyboardV1,
};
use wayland_protocols_wlr::virtual_pointer::v1::client::{
    zwlr_virtual_pointer_manager_v1::ZwlrVirtualPointerManagerV1, zwlr_virtual_pointer_v1::ZwlrVirtualPointerV1,
};

// Linux evdev button codes (linux/input-event-codes.h).
const BTN_LEFT: u32 = 0x110;
const BTN_RIGHT: u32 = 0x111;
const BTN_MIDDLE: u32 = 0x112;
/// One wheel step, in the pointer axis unit (as libinput reports a wheel click).
const SCROLL_STEP: f64 = 15.0;
/// `wl_keyboard.keymap_format.xkb_v1`.
const KEYMAP_FORMAT_XKB_V1: u32 = 1;

/// Input through the virtual pointer and keyboard protocols, for the monitor shared by the
/// portal.
pub struct WlrInjector {
    conn: Connection,
    queue: EventQueue<State>,
    state: State,
    pointer: ZwlrVirtualPointerV1,
    keyboard: ZwpVirtualKeyboardV1,
    /// The coordinate space of [`Injector::pointer_move`]: the shared monitor's logical size.
    size: (u32, u32),
    /// Where that monitor is, when the pointer covers the whole desktop rather than just it:
    /// its offset in the pointer's space and the size of that space.
    layout: Option<((i32, i32), (u32, u32))>,
    keymap: Keymap,
    started: Instant,
}

impl WlrInjector {
    /// Connects to the compositor and creates the virtual devices. `position` and `size` are
    /// the logical position and size of the monitor the portal shares, if it reported them.
    pub fn open(position: Option<(i32, i32)>, size: Option<(u32, u32)>) -> anyhow::Result<Self> {
        let conn = Connection::connect_to_env().context("connecting to the Wayland compositor")?;
        let (globals, mut queue) = registry_queue_init::<State>(&conn).context("listing the compositor's globals")?;
        let qh = queue.handle();

        let pointers: ZwlrVirtualPointerManagerV1 =
            globals.bind(&qh, 1..=2, ()).map_err(|_| anyhow!("the compositor has no virtual pointer protocol"))?;
        let keyboards: ZwpVirtualKeyboardManagerV1 =
            globals.bind(&qh, 1..=1, ()).map_err(|_| anyhow!("the compositor has no virtual keyboard protocol"))?;
        let seat: wl_seat::WlSeat = globals.bind(&qh, 1..=1, ()).map_err(|_| anyhow!("the compositor has no seat"))?;

        // The outputs and, through xdg-output, their place on the desktop.
        let mut state = State::default();
        let output_globals: Vec<(u32, u32)> = globals.contents().with_list(|list| {
            list.iter()
                .filter(|g| g.interface == wl_output::WlOutput::interface().name)
                .map(|g| (g.name, g.version))
                .collect()
        });
        let registry = globals.registry();
        for (i, (name, version)) in output_globals.into_iter().enumerate() {
            let output: wl_output::WlOutput = registry.bind(name, version.min(4), &qh, i);
            state.outputs.push(Output { output, position: None, size: None, name: None });
        }
        if let Ok(xdg) = globals.bind::<zxdg_output_manager_v1::ZxdgOutputManagerV1, _, _>(&qh, 1..=3, ()) {
            for (i, o) in state.outputs.iter().enumerate() {
                xdg.get_xdg_output(&o.output, &qh, i);
            }
        }
        queue.roundtrip(&mut state).context("reading the outputs")?;

        let target = pick_output(&state.outputs, position, size);
        let size = size
            .or_else(|| target.and_then(|o| o.size))
            .ok_or_else(|| anyhow!("the size of the shared monitor is unknown"))?;
        let (pointer, layout) = match target {
            // Version 2 can tie the pointer to one output, which is exactly the shared monitor.
            Some(o) if pointers.version() >= 2 => {
                (pointers.create_virtual_pointer_with_output(Some(&seat), Some(&o.output), &qh, ()), None)
            }
            _ => {
                let pointer = pointers.create_virtual_pointer(Some(&seat), &qh, ());
                let layout = desktop_bounds(&state.outputs).map(|(min, extent)| {
                    let at = target.and_then(|o| o.position).unwrap_or(min);
                    ((at.0 - min.0, at.1 - min.1), extent)
                });
                (pointer, layout)
            }
        };
        tracing::debug!(output = ?target.and_then(|o| o.name.clone()), ?size, ?layout, "virtual pointer created");

        let keyboard = keyboards.create_virtual_keyboard(&seat, &qh, ());
        let mut injector = Self {
            conn,
            queue,
            state,
            pointer,
            keyboard,
            size,
            layout,
            keymap: Keymap::default(),
            started: Instant::now(),
        };
        // A virtual keyboard needs a keymap before its first key.
        injector.upload_keymap()?;
        injector.queue.roundtrip(&mut injector.state).context("creating the virtual input devices")?;
        Ok(injector)
    }

    fn time(&self) -> u32 {
        self.started.elapsed().as_millis() as u32
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        self.conn.flush().context("sending input to the compositor")?;
        self.queue.dispatch_pending(&mut self.state).context("the compositor rejected the input")?;
        Ok(())
    }

    fn upload_keymap(&mut self) -> anyhow::Result<()> {
        let mut text = self.keymap.to_xkb().into_bytes();
        text.push(0);
        let fd = memfd_create("somedesk-keymap", MemfdFlags::CLOEXEC).context("creating the keymap file")?;
        std::fs::File::from(fd.try_clone()?).write_all(&text).context("writing the keymap")?;
        self.keyboard.keymap(KEYMAP_FORMAT_XKB_V1, fd.as_fd(), text.len() as u32);
        self.conn.flush().context("sending the keymap")?;
        Ok(())
    }
}

impl Injector for WlrInjector {
    fn screen_size(&mut self) -> anyhow::Result<(u32, u32)> {
        Ok(self.size)
    }

    fn pointer_move(&mut self, x: u32, y: u32) -> anyhow::Result<()> {
        let x = x.min(self.size.0.saturating_sub(1));
        let y = y.min(self.size.1.saturating_sub(1));
        let (x, y, extent) = match self.layout {
            None => (x, y, self.size),
            Some(((ox, oy), extent)) => ((x as i32 + ox).max(0) as u32, (y as i32 + oy).max(0) as u32, extent),
        };
        let t = self.time();
        self.pointer.motion_absolute(t, x, y, extent.0, extent.1);
        self.pointer.frame();
        self.flush()
    }

    fn button(&mut self, button: u8, down: bool) -> anyhow::Result<()> {
        let code = match button {
            1 => BTN_LEFT,
            2 => BTN_MIDDLE,
            3 => BTN_RIGHT,
            _ => bail!("unsupported mouse button {button}"),
        };
        let state = if down { wl_pointer::ButtonState::Pressed } else { wl_pointer::ButtonState::Released };
        let t = self.time();
        self.pointer.button(t, code, state);
        self.pointer.frame();
        self.flush()
    }

    fn scroll(&mut self, dx: i32, dy: i32) -> anyhow::Result<()> {
        let t = self.time();
        self.pointer.axis_source(wl_pointer::AxisSource::Wheel);
        for (axis, steps) in [(wl_pointer::Axis::VerticalScroll, dy), (wl_pointer::Axis::HorizontalScroll, dx)] {
            if steps != 0 {
                self.pointer.axis_discrete(t, axis, steps as f64 * SCROLL_STEP, steps);
            }
        }
        self.pointer.frame();
        self.flush()
    }

    fn key(&mut self, keysym: u32, down: bool) -> anyhow::Result<()> {
        let (code, new) = if down {
            self.keymap.press(keysym)
        } else {
            match self.keymap.code(keysym) {
                Some(code) => (code, false),
                // Pressed before the keymap was rebuilt; its key is gone already.
                None => return Ok(()),
            }
        };
        if new {
            self.upload_keymap()?;
            // Clients start over with a new keymap, modifiers included, but the compositor only
            // passes modifiers on when they change: clear them and set them again, or
            // Ctrl+<a new key> would arrive without the Ctrl.
            if self.keymap.depressed != 0 || self.keymap.locked != 0 {
                self.keyboard.modifiers(0, 0, 0, 0);
                self.keyboard.modifiers(self.keymap.depressed, 0, self.keymap.locked, 0);
            }
        }
        let t = self.time();
        self.keyboard.key(t, code, if down { 1 } else { 0 });
        if let Some(mods) = self.keymap.update_modifiers(keysym, down) {
            self.keyboard.modifiers(mods.depressed, 0, mods.locked, 0);
        }
        self.flush()
    }
}

impl Drop for WlrInjector {
    fn drop(&mut self) {
        // Let go of anything still held, so no key or button stays stuck on the computer.
        if self.keymap.depressed != 0 || self.keymap.locked != 0 {
            self.keyboard.modifiers(0, 0, 0, 0);
        }
        self.pointer.destroy();
        self.keyboard.destroy();
        let _ = self.conn.flush();
    }
}

/// The monitor the portal shares: by position, then by size, and the only one if there is one.
fn pick_output(outputs: &[Output], position: Option<(i32, i32)>, size: Option<(u32, u32)>) -> Option<&Output> {
    if let Some(p) = position {
        if let Some(o) = outputs.iter().find(|o| o.position == Some(p)) {
            return Some(o);
        }
    }
    if let Some(s) = size {
        let same_size: Vec<_> = outputs.iter().filter(|o| o.size == Some(s)).collect();
        if same_size.len() == 1 {
            return Some(same_size[0]);
        }
    }
    if outputs.len() > 1 {
        tracing::warn!("cannot tell which monitor is shared; the pointer may land on another one");
    }
    outputs.first()
}

/// The top-left corner and size of the box around all outputs.
fn desktop_bounds(outputs: &[Output]) -> Option<((i32, i32), (u32, u32))> {
    let boxes: Vec<_> = outputs.iter().filter_map(|o| Some((o.position?, o.size?))).collect();
    let min_x = boxes.iter().map(|((x, _), _)| *x).min()?;
    let min_y = boxes.iter().map(|((_, y), _)| *y).min()?;
    let max_x = boxes.iter().map(|((x, _), (w, _))| x + *w as i32).max()?;
    let max_y = boxes.iter().map(|((_, y), (_, h))| y + *h as i32).max()?;
    Some(((min_x, min_y), ((max_x - min_x) as u32, (max_y - min_y) as u32)))
}

#[derive(Default)]
struct State {
    outputs: Vec<Output>,
}

struct Output {
    output: wl_output::WlOutput,
    /// Logical position and size on the desktop (xdg-output).
    position: Option<(i32, i32)>,
    size: Option<(u32, u32)>,
    name: Option<String>,
}

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for State {
    fn event(
        _: &mut Self,
        _: &wl_registry::WlRegistry,
        _: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wl_output::WlOutput, usize> for State {
    fn event(
        s: &mut Self,
        _: &wl_output::WlOutput,
        event: wl_output::Event,
        i: &usize,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let wl_output::Event::Name { name } = event {
            s.outputs[*i].name.get_or_insert(name);
        }
    }
}

impl Dispatch<zxdg_output_v1::ZxdgOutputV1, usize> for State {
    fn event(
        s: &mut Self,
        _: &zxdg_output_v1::ZxdgOutputV1,
        event: zxdg_output_v1::Event,
        i: &usize,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let o = &mut s.outputs[*i];
        match event {
            zxdg_output_v1::Event::LogicalPosition { x, y } => o.position = Some((x, y)),
            zxdg_output_v1::Event::LogicalSize { width, height } => {
                o.size = Some((width.max(0) as u32, height.max(0) as u32))
            }
            zxdg_output_v1::Event::Name { name } => o.name = Some(name),
            _ => {}
        }
    }
}

delegate_noop!(State: ignore wl_seat::WlSeat);
delegate_noop!(State: zxdg_output_manager_v1::ZxdgOutputManagerV1);
delegate_noop!(State: ZwlrVirtualPointerManagerV1);
delegate_noop!(State: ZwlrVirtualPointerV1);
delegate_noop!(State: ZwpVirtualKeyboardManagerV1);
delegate_noop!(State: ZwpVirtualKeyboardV1);

/// Modifier keys and their bit in the keymap's modifier mask: Shift, Lock, Control, Mod1 (Alt),
/// Mod4 (Super), Mod5 (AltGr).
const MODIFIERS: [(u32, u32); 13] = [
    (0xffe1, 1),   // Shift_L
    (0xffe2, 1),   // Shift_R
    (0xffe5, 2),   // Caps_Lock
    (0xffe3, 4),   // Control_L
    (0xffe4, 4),   // Control_R
    (0xffe9, 8),   // Alt_L
    (0xffea, 8),   // Alt_R
    (0xffe7, 8),   // Meta_L
    (0xffe8, 8),   // Meta_R
    (0xffeb, 64),  // Super_L
    (0xffec, 64),  // Super_R
    (0xffed, 64),  // Hyper_L
    (0xfe03, 128), // ISO_Level3_Shift
];
const CAPS_LOCK: u32 = 0xffe5;
/// Keys in the keymap from the start, besides the modifiers: printable ASCII and the usual
/// editing, navigation and function keys.
fn common_keysyms() -> impl Iterator<Item = u32> {
    (0x20..=0x7e)
        .chain([
            0xff08, 0xff09, 0xff0d, 0xff1b, 0xffff, // BackSpace, Tab, Return, Escape, Delete
            0xff50, 0xff51, 0xff52, 0xff53, 0xff54, 0xff55, 0xff56, 0xff57, // Home, arrows, Prior, Next, End
            0xff63, 0xff61, 0xff67, // Insert, Print, Menu
        ])
        .chain(0xffbe..=0xffc9) // F1..F12
}
/// xkb keycodes run from 8 to 255; ours start at 9 (evdev code 1).
const MAX_KEYS: usize = 255 - 8;

/// The virtual keyboard's keymap: one key per keysym, modifiers first.
struct Keymap {
    keysyms: Vec<u32>,
    /// Modifier keys held, and the modifiers that are locked (Caps Lock).
    pressed_mods: Vec<u32>,
    depressed: u32,
    locked: u32,
}

impl Default for Keymap {
    fn default() -> Self {
        let keysyms = MODIFIERS.iter().map(|(k, _)| *k).chain(common_keysyms()).collect();
        Self { keysyms, pressed_mods: Vec::new(), depressed: 0, locked: 0 }
    }
}

struct Mods {
    depressed: u32,
    locked: u32,
}

impl Keymap {
    /// The evdev code of the key for `keysym`, if it has one.
    fn code(&self, keysym: u32) -> Option<u32> {
        self.keysyms.iter().position(|k| *k == keysym).map(|i| i as u32 + 1)
    }

    /// The evdev code for pressing `keysym`, and whether the keymap changed to make room for it.
    fn press(&mut self, keysym: u32) -> (u32, bool) {
        if let Some(code) = self.code(keysym) {
            return (code, false);
        }
        if self.keysyms.len() >= MAX_KEYS {
            // Full: start over with the keys there from the start.
            self.keysyms = Self::default().keysyms;
        }
        self.keysyms.push(keysym);
        (self.keysyms.len() as u32, true)
    }

    /// Tracks modifier keys; returns the new modifier state if `keysym` changed it.
    fn update_modifiers(&mut self, keysym: u32, down: bool) -> Option<Mods> {
        let bit = MODIFIERS.iter().find(|(k, _)| *k == keysym)?.1;
        if keysym == CAPS_LOCK {
            if down {
                self.locked ^= bit;
            }
        } else if down {
            self.pressed_mods.push(keysym);
        } else {
            self.pressed_mods.retain(|k| *k != keysym);
        }
        self.depressed = self
            .pressed_mods
            .iter()
            .filter_map(|k| MODIFIERS.iter().find(|(m, _)| m == k).map(|(_, b)| *b))
            .fold(0, |a, b| a | b);
        Some(Mods { depressed: self.depressed, locked: self.locked })
    }

    /// The keymap in xkb's text format.
    fn to_xkb(&self) -> String {
        let mut keycodes = String::new();
        let mut symbols = String::new();
        for (i, keysym) in self.keysyms.iter().enumerate() {
            let code = i + 9;
            keycodes += &format!("    <K{code}> = {code};\n");
            symbols += &format!("    key <K{code}> {{ [ 0x{keysym:08x} ] }};\n");
        }
        for (name, bit) in [("Shift", 1), ("Lock", 2), ("Control", 4), ("Mod1", 8), ("Mod4", 64), ("Mod5", 128)] {
            let keys: Vec<String> = MODIFIERS
                .iter()
                .filter(|(_, b)| *b == bit)
                .filter_map(|(k, _)| self.code(*k))
                .map(|c| format!("<K{}>", c + 8))
                .collect();
            symbols += &format!("    modifier_map {name} {{ {} }};\n", keys.join(", "));
        }
        format!(
            "xkb_keymap {{\n\
             xkb_keycodes \"somedesk\" {{\n    minimum = 8;\n    maximum = 255;\n{keycodes}}};\n\
             xkb_types \"somedesk\" {{ include \"complete\" }};\n\
             xkb_compatibility \"somedesk\" {{ include \"complete\" }};\n\
             xkb_symbols \"somedesk\" {{\n{symbols}}};\n\
             }};\n"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_get_codes_on_demand() {
        let mut map = Keymap::default();
        let (a, new) = map.press(0x61);
        assert!(!new, "letters are there from the start");
        let (smiley, new) = map.press(0x0100_263a);
        assert!(new, "a new keysym changes the keymap");
        assert_eq!(map.press(0x0100_263a), (smiley, false), "the same keysym keeps its key");
        assert_eq!(map.code(0xffe1), Some(1), "Shift_L comes first");
        let xkb = map.to_xkb();
        assert!(xkb.contains(&format!("key <K{}> {{ [ 0x00000061 ] }};", a + 8)), "{xkb}");
        assert!(xkb.contains(&format!("key <K{}> {{ [ 0x0100263a ] }};", smiley + 8)), "{xkb}");
        assert!(xkb.contains("modifier_map Shift { <K9>, <K10> };"), "{xkb}");
    }

    #[test]
    fn a_full_keymap_starts_over() {
        let mut map = Keymap::default();
        let base = map.keysyms.len();
        for k in 0..(MAX_KEYS - base) as u32 {
            map.press(0x0100_1000 + k);
        }
        assert_eq!(map.keysyms.len(), MAX_KEYS);
        let (code, new) = map.press(0x0100_263a);
        assert!(new);
        assert_eq!(code as usize, base + 1, "back to the keys there from the start, plus this one");
    }

    #[test]
    fn modifiers_are_tracked() {
        let mut map = Keymap::default();
        assert_eq!(map.update_modifiers(0xffe3, true).unwrap().depressed, 4);
        assert_eq!(map.update_modifiers(0xffe1, true).unwrap().depressed, 5);
        assert_eq!(map.update_modifiers(0xffe3, false).unwrap().depressed, 1);
        assert!(map.update_modifiers(0x61, true).is_none(), "letters aren't modifiers");
        let caps = map.update_modifiers(CAPS_LOCK, true).unwrap();
        assert_eq!((caps.depressed, caps.locked), (1, 2));
        map.update_modifiers(CAPS_LOCK, false);
        assert_eq!(map.update_modifiers(CAPS_LOCK, true).unwrap().locked, 0, "Caps Lock toggles");
    }
}
