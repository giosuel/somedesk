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

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGPreflightScreenCaptureAccess() -> bool;
    fn CGRequestScreenCaptureAccess() -> bool;
}

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXIsProcessTrusted() -> bool;
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
        injector: Box::new(EventInjector::default()),
        can_control,
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
        let (code, text) = match keycode_for_keysym(keysym) {
            Some(code) => (code, None),
            None => (0, Some(crate::keysym_char(keysym).ok_or_else(|| anyhow!("no key for keysym {keysym:#x}"))?)),
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
