//! Clipboard sharing: text copied on one side of a session becomes pasteable on the other.
//!
//! Each side polls its local clipboard and sends changes as [`SessionMsg::Clipboard`]; text from
//! the peer is written to the local clipboard. Both sides remember the last text they sent or
//! received, so applying the peer's text never echoes it back.

use somedesk_platform::Clipboard;
use somedesk_proto::session::{SessionMsg, MAX_CLIPBOARD_TEXT};
use std::sync::mpsc::RecvTimeoutError;
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc;

/// How often the local clipboard is checked for changes.
pub const POLL_INTERVAL: Duration = Duration::from_millis(300);

pub struct ClipboardSync {
    incoming: std::sync::mpsc::Sender<String>,
    thread: JoinHandle<()>,
}

impl ClipboardSync {
    /// Starts mirroring `clipboard`. Local changes are sent through `outgoing` (waiting while it
    /// is full; the session must close it before joining the thread). With
    /// `send_initial`, whatever the clipboard already holds is sent right away too.
    pub fn start(mut clipboard: Box<dyn Clipboard>, outgoing: mpsc::Sender<SessionMsg>, send_initial: bool) -> Self {
        let (incoming, rx) = std::sync::mpsc::channel::<String>();
        let thread = std::thread::Builder::new()
            .name("somedesk-clipboard".into())
            .spawn(move || {
                let mut last = read(&mut *clipboard);
                if send_initial {
                    if let Some(text) = last.clone() {
                        if outgoing.blocking_send(SessionMsg::Clipboard { text }).is_err() {
                            return;
                        }
                    }
                }
                loop {
                    match rx.recv_timeout(POLL_INTERVAL) {
                        Ok(text) => {
                            if last.as_ref() == Some(&text) {
                                continue;
                            }
                            match clipboard.set_text(&text) {
                                Ok(()) => last = Some(text),
                                Err(e) => tracing::warn!("cannot set clipboard: {e:#}"),
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => match read(&mut *clipboard) {
                            Some(text) if last.as_ref() != Some(&text) => {
                                last = Some(text.clone());
                                if outgoing.blocking_send(SessionMsg::Clipboard { text }).is_err() {
                                    return;
                                }
                            }
                            _ => {}
                        },
                        Err(RecvTimeoutError::Disconnected) => return,
                    }
                }
            })
            .expect("spawn clipboard thread");
        Self { incoming, thread }
    }

    /// Writes text received from the peer to the local clipboard.
    pub fn apply(&self, text: String) {
        if text.len() <= MAX_CLIPBOARD_TEXT {
            let _ = self.incoming.send(text);
        }
    }

    /// Stops mirroring. Returns the worker thread so the caller can join it off the async runtime.
    pub fn stop(self) -> JoinHandle<()> {
        drop(self.incoming);
        self.thread
    }
}

/// Reads the clipboard text, treating errors and oversized text as "nothing to share".
fn read(clipboard: &mut dyn Clipboard) -> Option<String> {
    match clipboard.get_text() {
        Ok(Some(t)) if t.len() <= MAX_CLIPBOARD_TEXT => Some(t),
        Ok(_) => None,
        Err(e) => {
            tracing::debug!("cannot read clipboard: {e:#}");
            None
        }
    }
}
