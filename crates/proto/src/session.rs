//! End-to-end session messages. Only ever transmitted inside the Noise channel.

use serde::{Deserialize, Serialize};

/// Maximum value of a normalized pointer coordinate.
pub const POINTER_MAX: u16 = u16::MAX;

/// Clipboard text larger than this (in bytes) is not shared.
pub const MAX_CLIPBOARD_TEXT: usize = 1 << 20;

/// Size of the pieces files are sent in. Small enough not to hold up video for long.
pub const FILE_CHUNK: usize = 64 * 1024;

/// A monitor of the host that the viewer can choose to show on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorInfo {
    pub id: u32,
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
}

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
    /// Host → viewer: the host's monitors (only sent if there are several) and which one is shown
    /// (`None`: all of them).
    Monitors {
        list: Vec<MonitorInfo>,
        selected: Option<u32>,
    },
    /// Viewer → host: show only this monitor, or all with `None`.
    SelectMonitor {
        id: Option<u32>,
    },
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
    /// Either side: offers to send a file. `id` is chosen by the sender and names the transfer
    /// in all following messages.
    FileOffer {
        id: u32,
        name: String,
        size: u64,
    },
    /// Receiver → sender: go ahead.
    FileAccept {
        id: u32,
    },
    /// Receiver → sender: not wanted.
    FileReject {
        id: u32,
        reason: String,
    },
    /// Sender → receiver: the next piece of the file, starting at `offset`.
    FileChunk {
        id: u32,
        offset: u64,
        data: Vec<u8>,
    },
    /// Sender → receiver: all data sent; SHA-256 of the whole file.
    FileDone {
        id: u32,
        sha256: [u8; 32],
    },
    /// Receiver → sender: the file was checked and saved (or not).
    FileResult {
        id: u32,
        ok: bool,
        message: String,
    },
    /// Either side aborts a transfer. `by_sender` says whose id namespace `id` is in.
    FileCancel {
        id: u32,
        by_sender: bool,
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
