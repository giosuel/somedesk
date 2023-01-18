//! End-to-end session messages. Only ever transmitted inside the Noise channel.

use serde::{Deserialize, Serialize};

/// Maximum value of a normalized pointer coordinate.
pub const POINTER_MAX: u16 = u16::MAX;

/// Clipboard text larger than this (in bytes) is not shared.
pub const MAX_CLIPBOARD_TEXT: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SessionMsg {
    /// Host → viewer: the user at the host accepted the connection.
    Accept,
    /// Host → viewer: the connection was refused.
    Reject {
        reason: String,
    },
    /// Host → viewer: the screen is shared, but remote input is not allowed on the host.
    ViewOnly,
    /// Host → viewer: current screen geometry.
    ScreenInfo {
        width: u32,
        height: u32,
    },
    /// Host → viewer: one encoded H.264 access unit.
    Video {
        seq: u64,
        keyframe: bool,
        width: u32,
        height: u32,
        data: Vec<u8>,
    },
    /// Viewer → host: pointer position, normalized to `0..=POINTER_MAX` on both axes.
    PointerMove {
        x: u16,
        y: u16,
    },
    /// Viewer → host: 1 = left, 2 = middle, 3 = right.
    PointerButton {
        button: u8,
        down: bool,
    },
    /// Viewer → host: scroll in wheel steps (positive = down / right).
    Scroll {
        dx: i16,
        dy: i16,
    },
    /// Viewer → host: an X11 keysym.
    Key {
        keysym: u32,
        down: bool,
    },
    /// Either side: the local clipboard now holds this text (at most [`MAX_CLIPBOARD_TEXT`]
    /// bytes).
    Clipboard {
        text: String,
    },
    /// Viewer → host: the decoder lost sync, please send an IDR frame.
    RequestKeyframe,
    Ping {
        t: u64,
    },
    Pong {
        t: u64,
    },
    /// Either side: orderly shutdown.
    Bye,
}
