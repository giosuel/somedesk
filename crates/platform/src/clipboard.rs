//! System clipboard access (text only for now).

use crate::Clipboard;
use anyhow::Context;

/// The real system clipboard, via `arboard` (X11 selections, Wayland data-control, Windows,
/// macOS).
pub struct SystemClipboard {
    inner: arboard::Clipboard,
}

impl SystemClipboard {
    pub fn open() -> anyhow::Result<Self> {
        Ok(Self { inner: arboard::Clipboard::new().context("opening the system clipboard")? })
    }
}

impl Clipboard for SystemClipboard {
    fn get_text(&mut self) -> anyhow::Result<Option<String>> {
        match self.inner.get_text() {
            Ok(t) => Ok(Some(t)),
            // Empty, or holding something that is not text (an image, files, ...).
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set_text(&mut self, text: &str) -> anyhow::Result<()> {
        // On X11 the selection is served by a background thread owned by `inner`, so the text
        // stays pasteable for as long as this clipboard object lives.
        self.inner.set_text(text).map_err(Into::into)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    /// Runs against the X server in `SOMEDESK_TEST_DISPLAY` and uses `xsel` as an independent
    /// clipboard client.
    fn display() -> Option<String> {
        let d = std::env::var("SOMEDESK_TEST_DISPLAY").ok()?;
        if Command::new("xsel").arg("--version").output().is_err() {
            eprintln!("xsel not installed, skipping");
            return None;
        }
        std::env::set_var("DISPLAY", &d);
        std::env::remove_var("WAYLAND_DISPLAY");
        Some(d)
    }

    fn xsel_get() -> String {
        let out = Command::new("xsel").args(["--clipboard", "--output"]).output().unwrap();
        String::from_utf8(out.stdout).unwrap()
    }

    fn xsel_set(text: &str) {
        let mut child = Command::new("xsel").args(["--clipboard", "--input"]).stdin(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn clipboard_round_trips_with_other_x11_clients() {
        let Some(_) = display() else { return };
        let mut clip = SystemClipboard::open().unwrap();

        let ours = "hello from SomeDesk ✓ äöü\nsecond line";
        clip.set_text(ours).unwrap();
        assert_eq!(xsel_get(), ours);

        let theirs = "copied in another app 🚀";
        xsel_set(theirs);
        // Losing ownership of the selection is noticed asynchronously.
        let mut got = None;
        for _ in 0..40 {
            got = clip.get_text().unwrap();
            if got.as_deref() == Some(theirs) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(got.as_deref(), Some(theirs));
    }
}
