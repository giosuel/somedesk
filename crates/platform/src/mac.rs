//! macOS backend: CoreGraphics display capture and `CGEvent` input.
//!
//! macOS asks the user for two permissions: *Screen Recording* (without it, captures show only
//! the wallpaper) and *Accessibility* (without it, injected input is ignored). Capture is
//! refused until the first is granted; without the second the screen is shared view-only.
//!
//! Pointer coordinates are in points (global display coordinates); captured frames are in
//! pixels, which on Retina displays are twice as many. Each frame says which area it covers in
//! points, so the host maps the viewer's pointer correctly either way.

use crate::{Capturer, Frame, Injector, Monitor, Screen};
use anyhow::{anyhow, bail};
use core_graphics::display::{CGDirectDisplayID, CGDisplay};
use core_graphics::event::{
    CGEvent, CGEventFlags, CGEventTapLocation, CGEventType, CGKeyCode, CGMouseButton, ScrollEventUnit,
};
use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
use core_graphics::geometry::CGPoint;
use std::collections::HashMap;
use std::ffi::c_void;

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGPreflightScreenCaptureAccess() -> bool;
    fn CGRequestScreenCaptureAccess() -> bool;
}

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXIsProcessTrusted() -> bool;
}

// The keyboard layout, from the Text Input Sources API (HIToolbox, in Carbon).
#[link(name = "Carbon", kind = "framework")]
extern "C" {
    fn TISCopyCurrentKeyboardLayoutInputSource() -> *const c_void;
    fn TISGetInputSourceProperty(source: *const c_void, key: core_foundation::string::CFStringRef) -> *const c_void;
    static kTISPropertyUnicodeKeyLayoutData: core_foundation::string::CFStringRef;
    fn LMGetKbdType() -> u8;
    #[allow(clippy::too_many_arguments)]
    fn UCKeyTranslate(
        layout: *const u8,
        virtual_key_code: u16,
        key_action: u16,
        modifier_key_state: u32,
        keyboard_type: u32,
        key_translate_options: u32,
        dead_key_state: *mut u32,
        max_string_length: usize,
        actual_string_length: *mut usize,
        unicode_string: *mut u16,
    ) -> i32;
}

// libdispatch and pthread, in libSystem.
extern "C" {
    static _dispatch_main_q: c_void;
    fn dispatch_async_f(queue: *const c_void, context: *mut c_void, work: extern "C" fn(*mut c_void));
    fn pthread_main_np() -> i32;
}

/// Opens the screen, asking for permissions where needed.
pub fn open_screen() -> anyhow::Result<Screen> {
    if !unsafe { CGPreflightScreenCaptureAccess() } {
        unsafe { CGRequestScreenCaptureAccess() };
        bail!(
            "SomeDesk needs permission to record the screen. Allow it under System Settings › Privacy & \
             Security › Screen Recording, then try again"
        );
    }
    let can_control = unsafe { AXIsProcessTrusted() };
    if !can_control {
        tracing::warn!("no Accessibility permission: sharing view-only");
    }
    Ok(Screen {
        capturer: Box::new(DisplayCapturer::default()),
        injector: Box::new(EventInjector { layout: layout_keys(), ..Default::default() }),
        can_control,
        view_only_reason: (!can_control)
            .then_some("SomeDesk may not control this Mac (System Settings › Privacy & Security › Accessibility)"),
        backend: "macos-coregraphics",
    })
}

fn displays() -> Vec<CGDisplay> {
    CGDisplay::active_displays()
        .map(|ids| ids.into_iter().map(CGDisplay::new).collect())
        .unwrap_or_else(|_| vec![CGDisplay::main()])
}

fn monitor(d: &CGDisplay, index: usize) -> Monitor {
    let b = d.bounds();
    Monitor {
        id: d.id,
        name: format!("Display {}", index + 1),
        x: b.origin.x as i32,
        y: b.origin.y as i32,
        width: b.size.width as u32,
        height: b.size.height as u32,
        primary: d.is_main(),
    }
}

/// Shows one display at a time: the main display unless another is selected.
#[derive(Default)]
pub struct DisplayCapturer {
    selected: Option<CGDirectDisplayID>,
}

impl Capturer for DisplayCapturer {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        let display =
            self.selected.and_then(|id| displays().into_iter().find(|d| d.id == id)).unwrap_or_else(CGDisplay::main);
        let image = display.image().ok_or_else(|| anyhow!("could not capture the display"))?;
        if image.bits_per_pixel() != 32 {
            bail!("unsupported pixel format ({} bits per pixel)", image.bits_per_pixel());
        }
        let b = display.bounds();
        Ok(Frame {
            width: image.width() as u32,
            height: image.height() as u32,
            stride: image.bytes_per_row(),
            // 32-bit little-endian with alpha first: BGRA/BGRX in memory.
            data: image.data().bytes().to_vec(),
            view: Some((b.origin.x as i32, b.origin.y as i32, b.size.width as u32, b.size.height as u32)),
        })
    }

    fn monitors(&mut self) -> anyhow::Result<Vec<Monitor>> {
        Ok(displays().iter().enumerate().map(|(i, d)| monitor(d, i)).collect())
    }

    fn select_monitor(&mut self, id: Option<u32>) -> anyhow::Result<()> {
        if let Some(id) = id {
            if !displays().iter().any(|d| d.id == id) {
                bail!("no such display");
            }
        }
        self.selected = id;
        Ok(())
    }
}

#[derive(Default)]
pub struct EventInjector {
    position: (f64, f64),
    /// Mouse buttons currently held (1 left, 2 middle, 3 right): moves become drags.
    buttons: u8,
    flags: CGEventFlags,
    /// The keys of the keyboard layout, if it could be read: characters are pressed where the
    /// layout has them (AZERTY's A is not where the US layout has it).
    layout: Option<HashMap<char, LayoutKey>>,
    /// Keys held down and the keycode each went down on (`None`: typed as text).
    held: HashMap<u32, Option<CGKeyCode>>,
}

/// Where a character is on the keyboard layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LayoutKey {
    code: CGKeyCode,
    shift: bool,
    option: bool,
}

/// Reads the current keyboard layout on the main thread (the Text Input Sources API traps when
/// called from others on recent macOS). `None` if that fails or the main thread doesn't answer
/// within a second; the US positions are used then.
fn layout_keys() -> Option<HashMap<char, LayoutKey>> {
    type Reply = std::sync::mpsc::SyncSender<Option<HashMap<char, LayoutKey>>>;
    extern "C" fn work(ctx: *mut c_void) {
        let reply = unsafe { Box::from_raw(ctx as *mut Reply) };
        let _ = reply.send(read_layout());
    }
    if unsafe { pthread_main_np() } != 0 {
        return read_layout();
    }
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let ctx = Box::into_raw(Box::new(tx)) as *mut c_void;
    unsafe { dispatch_async_f(std::ptr::addr_of!(_dispatch_main_q), ctx, work) };
    let layout = rx.recv_timeout(std::time::Duration::from_secs(1)).ok().flatten();
    if layout.is_none() {
        tracing::warn!("cannot read the keyboard layout; using US key positions");
    }
    layout
}

fn read_layout() -> Option<HashMap<char, LayoutKey>> {
    unsafe {
        let source = TISCopyCurrentKeyboardLayoutInputSource();
        if source.is_null() {
            return None;
        }
        let data =
            TISGetInputSourceProperty(source, kTISPropertyUnicodeKeyLayoutData) as core_foundation::data::CFDataRef;
        let keys = (!data.is_null()).then(|| translate_layout(core_foundation::data::CFDataGetBytePtr(data)));
        core_foundation::base::CFRelease(source);
        keys
    }
}

/// The character every key of `layout` (a `UCKeyboardLayout`) types, plain and with Shift
/// and/or Option, keeping the simplest way to type each one. Dead keys are left out.
unsafe fn translate_layout(layout: *const u8) -> HashMap<char, LayoutKey> {
    const KEY_ACTION_DOWN: u16 = 0;
    // Carbon's shiftKey (0x200) and optionKey (0x800), shifted right by 8 as UCKeyTranslate wants.
    const SHIFT: u32 = 0x02;
    const OPTION: u32 = 0x08;
    let kbd = LMGetKbdType() as u32;
    let mut keys = HashMap::new();
    for (state, shift, option) in
        [(0, false, false), (SHIFT, true, false), (OPTION, false, true), (SHIFT | OPTION, true, true)]
    {
        // The character keys: 0x00-0x32 and the two extra JIS keys (the rest are keypad,
        // function and control keys).
        for code in (0x00..=0x32).chain([0x5D, 0x5E]) {
            let (mut dead, mut len, mut buf) = (0u32, 0usize, [0u16; 4]);
            let status = UCKeyTranslate(
                layout,
                code,
                KEY_ACTION_DOWN,
                state,
                kbd,
                0,
                &mut dead,
                buf.len(),
                &mut len,
                buf.as_mut_ptr(),
            );
            if status != 0 || dead != 0 || len == 0 {
                continue;
            }
            let mut chars = char::decode_utf16(buf[..len.min(buf.len())].iter().copied());
            if let (Some(Ok(c)), None) = (chars.next(), chars.next()) {
                if !c.is_control() {
                    keys.entry(c).or_insert(LayoutKey { code, shift, option });
                }
            }
        }
    }
    keys
}

/// The key of `layout` to press for `ch` with modifiers `flags`: one that types it with them,
/// or for a shortcut (Command or Control held) the key it is on regardless of Shift. Letters go
/// by their key whatever the case, as Shift and Caps Lock make the case.
fn layout_code(layout: &HashMap<char, LayoutKey>, ch: char, flags: CGEventFlags) -> Option<CGKeyCode> {
    let mut lower = ch.to_lowercase();
    if let (Some(l), None) = (lower.next(), lower.next()) {
        if l != ch || ch.is_lowercase() {
            if let Some(k) = layout.get(&l).filter(|k| !k.shift && !k.option) {
                return Some(k.code);
            }
        }
    }
    let k = layout.get(&ch)?;
    let shortcut = flags.intersects(CGEventFlags::CGEventFlagCommand | CGEventFlags::CGEventFlagControl);
    let shift = flags.contains(CGEventFlags::CGEventFlagShift);
    let option = flags.contains(CGEventFlags::CGEventFlagAlternate);
    ((k.shift == shift || shortcut) && (!k.option || option)).then_some(k.code)
}

fn source() -> anyhow::Result<CGEventSource> {
    CGEventSource::new(CGEventSourceStateID::HIDSystemState).map_err(|_| anyhow!("no event source"))
}

impl EventInjector {
    fn post_mouse(&self, kind: CGEventType, button: CGMouseButton) -> anyhow::Result<()> {
        let point = CGPoint::new(self.position.0, self.position.1);
        let event = CGEvent::new_mouse_event(source()?, kind, point, button).map_err(|_| anyhow!("mouse event"))?;
        event.set_flags(self.flags);
        event.post(CGEventTapLocation::HID);
        Ok(())
    }
}

impl Injector for EventInjector {
    fn screen_size(&mut self) -> anyhow::Result<(u32, u32)> {
        let b = CGDisplay::main().bounds();
        Ok((b.size.width as u32, b.size.height as u32))
    }

    fn pointer_move(&mut self, x: u32, y: u32) -> anyhow::Result<()> {
        self.position = (x as f64, y as f64);
        let (kind, button) = if self.buttons & 1 != 0 {
            (CGEventType::LeftMouseDragged, CGMouseButton::Left)
        } else if self.buttons & 4 != 0 {
            (CGEventType::RightMouseDragged, CGMouseButton::Right)
        } else if self.buttons & 2 != 0 {
            (CGEventType::OtherMouseDragged, CGMouseButton::Center)
        } else {
            (CGEventType::MouseMoved, CGMouseButton::Left)
        };
        self.post_mouse(kind, button)
    }

    fn button(&mut self, button: u8, down: bool) -> anyhow::Result<()> {
        let (kind, cg_button, bit) = match (button, down) {
            (1, true) => (CGEventType::LeftMouseDown, CGMouseButton::Left, 1),
            (1, false) => (CGEventType::LeftMouseUp, CGMouseButton::Left, 1),
            (2, true) => (CGEventType::OtherMouseDown, CGMouseButton::Center, 2),
            (2, false) => (CGEventType::OtherMouseUp, CGMouseButton::Center, 2),
            (3, true) => (CGEventType::RightMouseDown, CGMouseButton::Right, 4),
            (3, false) => (CGEventType::RightMouseUp, CGMouseButton::Right, 4),
            _ => bail!("unsupported mouse button {button}"),
        };
        if down {
            self.buttons |= bit;
        } else {
            self.buttons &= !bit;
        }
        self.post_mouse(kind, cg_button)
    }

    fn scroll(&mut self, dx: i32, dy: i32) -> anyhow::Result<()> {
        // Positive dy means down; macOS lines are positive upwards.
        let event = CGEvent::new_scroll_event(source()?, ScrollEventUnit::LINE, 2, -dy, -dx, 0)
            .map_err(|_| anyhow!("scroll event"))?;
        event.post(CGEventTapLocation::HID);
        Ok(())
    }

    fn key(&mut self, keysym: u32, down: bool) -> anyhow::Result<()> {
        if let Some(flag) = modifier_flag(keysym) {
            if down {
                self.flags.insert(flag);
            } else {
                self.flags.remove(flag);
            }
        }
        let ch = crate::keysym_char(keysym);
        let held = if down { self.held.get(&keysym).copied() } else { self.held.remove(&keysym) };
        let key = match held {
            Some(key) => key,
            // Letters and digits by the layout, if it could be read; keys that don't type a
            // character are in the same place on every layout.
            None => match (&self.layout, ch) {
                (Some(layout), Some(c)) if c != ' ' => layout_code(layout, c, self.flags),
                _ => keycode_for_keysym(keysym),
            },
        };
        if down {
            self.held.insert(keysym, key);
        }
        let (code, text) = match key {
            Some(code) => (code, None),
            None => (0, Some(ch.ok_or_else(|| anyhow!("no key for keysym {keysym:#x}"))?)),
        };
        let event = CGEvent::new_keyboard_event(source()?, code, down).map_err(|_| anyhow!("keyboard event"))?;
        if let Some(ch) = text {
            // Characters without a key on the layout are typed as text.
            event.set_string(&ch.to_string());
        }
        event.set_flags(self.flags);
        event.post(CGEventTapLocation::HID);
        Ok(())
    }
}

fn modifier_flag(keysym: u32) -> Option<CGEventFlags> {
    Some(match keysym {
        0xffe1 | 0xffe2 => CGEventFlags::CGEventFlagShift,
        0xffe3 | 0xffe4 => CGEventFlags::CGEventFlagControl,
        0xffe9 | 0xffea => CGEventFlags::CGEventFlagAlternate,
        0xffeb | 0xffec => CGEventFlags::CGEventFlagCommand,
        _ => return None,
    })
}

/// macOS virtual key code (US ANSI positions) for an X11 keysym.
pub fn keycode_for_keysym(keysym: u32) -> Option<CGKeyCode> {
    const LETTERS: [CGKeyCode; 26] = [
        0x00, 0x0B, 0x08, 0x02, 0x0E, 0x03, 0x05, 0x04, 0x22, 0x26, 0x28, 0x25, 0x2E, // a..m
        0x2D, 0x1F, 0x23, 0x0C, 0x0F, 0x01, 0x11, 0x20, 0x09, 0x0D, 0x07, 0x10, 0x06, // n..z
    ];
    const DIGITS: [CGKeyCode; 10] = [0x1D, 0x12, 0x13, 0x14, 0x15, 0x17, 0x16, 0x1A, 0x1C, 0x19];
    const F_KEYS: [CGKeyCode; 12] = [0x7A, 0x78, 0x63, 0x76, 0x60, 0x61, 0x62, 0x64, 0x65, 0x6D, 0x67, 0x6F];
    Some(match keysym {
        0x61..=0x7a => LETTERS[(keysym - 0x61) as usize],
        0x41..=0x5a => LETTERS[(keysym - 0x41) as usize],
        0x30..=0x39 => DIGITS[(keysym - 0x30) as usize],
        0x20 => 0x31,
        0xff08 => 0x33, // BackSpace
        0xff09 => 0x30, // Tab
        0xff0d => 0x24, // Return
        0xff1b => 0x35, // Escape
        0xff50 => 0x73, // Home
        0xff51 => 0x7B, // Left
        0xff52 => 0x7E, // Up
        0xff53 => 0x7C, // Right
        0xff54 => 0x7D, // Down
        0xff55 => 0x74, // Prior
        0xff56 => 0x79, // Next
        0xff57 => 0x77, // End
        0xffbe..=0xffc9 => F_KEYS[(keysym - 0xffbe) as usize],
        0xffe1 => 0x38, // Shift_L
        0xffe2 => 0x3C, // Shift_R
        0xffe3 => 0x3B, // Control_L
        0xffe4 => 0x3E, // Control_R
        0xffe5 => 0x39, // Caps_Lock
        0xffe9 => 0x3A, // Alt_L → Option
        0xffea => 0x3D, // Alt_R → right Option
        0xffeb => 0x37, // Super_L → Command
        0xffec => 0x36, // Super_R → right Command
        0xffff => 0x75, // Delete (forward)
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn characters_go_by_the_layout() {
        // A few keys of French AZERTY: A where US has Q, and & / 1 on one key.
        let key = |code, shift, option| LayoutKey { code, shift, option };
        let layout: HashMap<char, LayoutKey> = [
            ('a', key(0x0C, false, false)),
            ('A', key(0x0C, true, false)),
            ('&', key(0x12, false, false)),
            ('1', key(0x12, true, false)),
            ('@', key(0x32, false, false)),
            ('#', key(0x32, true, false)),
            ('ë', key(0x0E, false, true)),
        ]
        .into();
        let none = CGEventFlags::empty();
        let shift = CGEventFlags::CGEventFlagShift;
        assert_eq!(layout_code(&layout, 'a', none), Some(0x0C));
        assert_eq!(layout_code(&layout, 'A', shift), Some(0x0C));
        assert_eq!(layout_code(&layout, 'A', none), Some(0x0C), "letters whatever the case");
        assert_eq!(layout_code(&layout, '1', shift), Some(0x12));
        assert_eq!(layout_code(&layout, '1', none), None, "the key would type '&': typed as text");
        assert_eq!(layout_code(&layout, '1', CGEventFlags::CGEventFlagCommand), Some(0x12), "Cmd+1");
        assert_eq!(layout_code(&layout, '#', none), None);
        assert_eq!(layout_code(&layout, 'ë', none), None, "needs Option");
        assert_eq!(layout_code(&layout, 'ë', CGEventFlags::CGEventFlagAlternate), Some(0x0E));
        assert_eq!(layout_code(&layout, '☺', none), None);
    }
}
