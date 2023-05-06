//! File transfers, remote frames and input during a session (unchanged by who got in how).

use super::*;

/// "1.4 MB" etc.
fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut unit = 0;
    while v >= 1000.0 && unit < UNITS.len() - 1 {
        v /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

static DOWNLOAD_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Overrides where received files go (Android, which has no home directory).
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn set_download_dir(dir: PathBuf) {
    let _ = DOWNLOAD_DIR.set(dir);
}

/// Where received files go: `~/Downloads/SomeDesk`.
fn download_dir() -> PathBuf {
    if let Some(dir) = DOWNLOAD_DIR.get() {
        return dir.clone();
    }
    dirs::download_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join("Downloads")))
        .unwrap_or_else(std::env::temp_dir)
        .join("SomeDesk")
}

impl Controller {
    // ------------------------------------------------------------------ files

    pub(super) fn start_transfers(&self, policy: AcceptPolicy, peer: &str) -> FileTransfers {
        let this = self.clone();
        let peer = peer.to_owned();
        let files = FileTransfers::new(download_dir(), policy, Arc::new(move |ev| this.on_transfer(ev, &peer)));
        let mut st = self.0.state.lock().unwrap();
        st.files = Some(files.clone());
        st.transfers.clear();
        st.file_offers.clear();
        drop(st);
        self.publish_transfers();
        files
    }

    pub(super) fn end_transfers(&self) {
        let mut st = self.0.state.lock().unwrap();
        st.files = None;
        st.file_offers.clear();
        // Finished transfers stay visible until cleared; nothing is running any more.
        st.transfers.retain(|t| t.state >= 2);
        drop(st);
        self.publish_transfers();
        self.ui(|ui| ui.set_file_offer_visible(false));
    }

    pub(super) fn pick_and_send_files(&self) {
        let Some(files) = self.0.state.lock().unwrap().files.clone() else {
            return;
        };
        #[cfg(not(target_os = "android"))]
        {
            let this = self.clone();
            self.0.rt.spawn(async move {
                let picked = rfd::AsyncFileDialog::new().set_title("Send files").pick_files().await;
                for f in picked.unwrap_or_default() {
                    if let Err(e) = files.send_file(f.path()) {
                        this.toast(format!("Cannot send {}: {e}", f.file_name()), true);
                    }
                }
            });
        }
        #[cfg(target_os = "android")]
        {
            let _ = files;
            self.toast("Sending files from the phone is not supported yet", true);
        }
    }

    pub(super) fn on_transfer(&self, ev: TransferEvent, peer: &str) {
        let mut st = self.0.state.lock().unwrap();
        let mut show_offer = false;
        let mut toast = None;
        match ev {
            TransferEvent::Offered { id, name, size } => {
                st.file_offers.push_back((id, name, size));
                show_offer = st.file_offers.len() == 1;
            }
            TransferEvent::Started { id, direction, name, size } => {
                let upload = direction == Direction::Upload;
                st.transfers.retain(|t| !(t.id == id && t.upload == upload));
                let detail = if upload { "Waiting for the other side…".to_string() } else { format_size(size) };
                st.transfers.push(TransferRow { id, upload, name, size, done: 0, state: i32::from(!upload), detail });
            }
            TransferEvent::Progress { id, direction, done, total } => {
                let upload = direction == Direction::Upload;
                if let Some(t) = st.transfers.iter_mut().find(|t| t.id == id && t.upload == upload) {
                    t.state = 1;
                    t.done = done;
                    t.detail = format!("{} of {}", format_size(done), format_size(total));
                }
            }
            TransferEvent::Completed { id, direction, name, path } => {
                let upload = direction == Direction::Upload;
                if let Some(t) = st.transfers.iter_mut().find(|t| t.id == id && t.upload == upload) {
                    t.state = 2;
                    t.done = t.size;
                    t.detail = if upload {
                        format!("Sent · {}", format_size(t.size))
                    } else {
                        format!(
                            "Saved to {}",
                            path.as_ref().and_then(|p| p.parent()).map(|p| p.display().to_string()).unwrap_or_default()
                        )
                    };
                }
                if !upload {
                    toast = Some((format!("Received {name} from {peer}"), false));
                }
            }
            TransferEvent::Failed { id, direction, name, reason } => {
                let upload = direction == Direction::Upload;
                match st.transfers.iter_mut().find(|t| t.id == id && t.upload == upload) {
                    Some(t) => {
                        t.state = 3;
                        t.detail = reason;
                    }
                    None => {
                        st.transfers.push(TransferRow { id, upload, name, size: 0, done: 0, state: 3, detail: reason })
                    }
                }
                // An offer we never answered disappears with the transfer.
                if !upload {
                    let before = st.file_offers.front().map(|o| o.0);
                    st.file_offers.retain(|o| o.0 != id);
                    show_offer = before != st.file_offers.front().map(|o| o.0);
                }
            }
        }
        drop(st);
        self.publish_transfers();
        if show_offer {
            self.show_file_offer(peer);
        }
        if let Some((text, error)) = toast {
            self.toast(text, error);
        }
    }

    pub(super) fn show_file_offer(&self, peer: &str) {
        let next = self.0.state.lock().unwrap().file_offers.front().cloned();
        let peer = peer.to_owned();
        self.ui(move |ui| match next {
            Some((_, name, size)) => {
                ui.set_file_offer_peer(peer.into());
                ui.set_file_offer_name(name.into());
                ui.set_file_offer_size(format_size(size).into());
                ui.set_file_offer_visible(true);
                bring_to_front(ui);
            }
            None => ui.set_file_offer_visible(false),
        });
    }

    pub(super) fn answer_file_offer(&self, accept: bool) {
        let (offer, files, peer) = {
            let mut st = self.0.state.lock().unwrap();
            let peer = self.0.ui.upgrade().map(|ui| ui.get_file_offer_peer().to_string()).unwrap_or_default();
            (st.file_offers.pop_front(), st.files.clone(), peer)
        };
        if let (Some((id, ..)), Some(files)) = (offer, files) {
            files.respond(id, accept);
        }
        self.show_file_offer(&peer);
    }

    pub(super) fn publish_transfers(&self) {
        let items: Vec<TransferItem> = self
            .0
            .state
            .lock()
            .unwrap()
            .transfers
            .iter()
            .map(|t| TransferItem {
                id: t.id as i32,
                upload: t.upload,
                name: t.name.clone().into(),
                detail: t.detail.clone().into(),
                progress: if t.size == 0 { 0.0 } else { (t.done as f64 / t.size as f64) as f32 },
                state: t.state,
            })
            .collect();
        self.ui(move |ui| ui.set_transfers(ModelRc::new(VecModel::from(items))));
    }

    /// The system clipboard, if clipboard sharing is enabled and the clipboard is available.
    pub(super) fn clipboard(&self) -> Option<Box<dyn somedesk_platform::Clipboard>> {
        if !self.0.state.lock().unwrap().settings.share_clipboard {
            return None;
        }
        somedesk_platform::default_clipboard()
            .inspect_err(|e| tracing::warn!("clipboard sharing unavailable: {e:#}"))
            .ok()
    }

    pub(super) fn show_frame(&self, frame: RgbFrame) {
        self.0.frame_w.store(frame.width, Ordering::Relaxed);
        self.0.frame_h.store(frame.height, Ordering::Relaxed);
        *self.0.frame.pending.lock().unwrap() = Some(frame);
        if self.0.frame.scheduled.swap(true, Ordering::AcqRel) {
            return;
        }
        let inner = self.0.clone();
        let _ = self.0.ui.upgrade_in_event_loop(move |ui| {
            inner.frame.scheduled.store(false, Ordering::Release);
            if let Some(f) = inner.frame.pending.lock().unwrap().take() {
                let buf = SharedPixelBuffer::<Rgb8Pixel>::clone_from_slice(&f.data, f.width, f.height);
                ui.set_remote_frame(Image::from_rgb8(buf));
                ui.set_has_frame(true);
            }
        });
    }

    /// The phone's keyboard changed the hidden input from what it was to `text`: sends a
    /// Backspace for every character that went away and types the new ones.
    pub(super) fn soft_input(&self, text: &str, ctrl: bool, alt: bool) {
        let previous = {
            let mut st = self.0.state.lock().unwrap();
            let previous = std::mem::replace(&mut st.soft_text, text.to_owned());
            if previous.is_empty() {
                SOFT_PAD.to_owned()
            } else {
                previous
            }
        };
        let (removed, added) = text_diff(&previous, text);
        self.type_keys(&"\u{8}".repeat(removed), false, false);
        self.type_keys(&added, ctrl, alt);
        // Refill the padding before it runs out, and don't let the text grow forever.
        let len = text.chars().count();
        if !(4..=200).contains(&len) {
            self.0.state.lock().unwrap().soft_text = SOFT_PAD.to_owned();
            self.ui(|ui| ui.set_session_soft_text(SOFT_PAD.into()));
        }
    }

    /// Presses and releases the key for each character of `text` (Slint key text), with Ctrl
    /// and/or Alt held down around each one.
    pub(super) fn type_keys(&self, text: &str, ctrl: bool, alt: bool) {
        const CONTROL_L: u32 = 0xffe3;
        const ALT_L: u32 = 0xffe9;
        let mods: Vec<u32> = [(ctrl, CONTROL_L), (alt, ALT_L)].into_iter().filter(|m| m.0).map(|m| m.1).collect();
        for c in text.chars() {
            let Some(keysym) = keysym_for(c.encode_utf8(&mut [0; 4])) else {
                continue;
            };
            for &m in &mods {
                self.send_input(SessionMsg::Key { keysym: m, down: true });
            }
            self.send_input(SessionMsg::Key { keysym, down: true });
            self.send_input(SessionMsg::Key { keysym, down: false });
            for &m in mods.iter().rev() {
                self.send_input(SessionMsg::Key { keysym: m, down: false });
            }
        }
    }

    pub(super) fn send_input(&self, msg: SessionMsg) {
        if let Some(tx) = &self.0.state.lock().unwrap().viewer_input {
            let _ = tx.send(msg);
        }
    }

    /// Maps a position in the viewport to normalized remote coordinates, accounting for the
    /// letterboxing of `image-fit: contain`.
    pub(super) fn pointer_moved(&self, x: f32, y: f32, w: f32, h: f32) {
        let (fw, fh) = (self.0.frame_w.load(Ordering::Relaxed) as f32, self.0.frame_h.load(Ordering::Relaxed) as f32);
        if let Some((nx, ny)) = map_pointer(x, y, w, h, fw, fh) {
            self.send_input(SessionMsg::PointerMove { x: nx, y: ny });
        }
    }

    pub(super) fn scroll(&self, dx: f32, dy: f32) {
        let steps = {
            let mut st = self.0.state.lock().unwrap();
            st.scroll_acc.0 += dx;
            st.scroll_acc.1 += dy;
            let sx = (st.scroll_acc.0 / WHEEL_STEP).trunc();
            let sy = (st.scroll_acc.1 / WHEEL_STEP).trunc();
            st.scroll_acc.0 -= sx * WHEEL_STEP;
            st.scroll_acc.1 -= sy * WHEEL_STEP;
            (sx as i16, sy as i16)
        };
        if steps != (0, 0) {
            // Slint: positive = wheel up / left. Protocol: positive = down / right.
            self.send_input(SessionMsg::Scroll { dx: -steps.0, dy: -steps.1 });
        }
    }
}

/// How `new` differs from `old` at the end: the number of characters removed from `old` after
/// their common beginning, and what `new` has there instead.
fn text_diff(old: &str, new: &str) -> (usize, String) {
    let common = old.chars().zip(new.chars()).take_while(|(a, b)| a == b).count();
    (old.chars().count() - common, new.chars().skip(common).collect())
}

/// Maps viewport coordinates to `0..=POINTER_MAX`, or `None` outside the displayed image.
fn map_pointer(x: f32, y: f32, view_w: f32, view_h: f32, frame_w: f32, frame_h: f32) -> Option<(u16, u16)> {
    if frame_w <= 0.0 || frame_h <= 0.0 || view_w <= 0.0 || view_h <= 0.0 {
        return None;
    }
    let scale = (view_w / frame_w).min(view_h / frame_h);
    let (dw, dh) = (frame_w * scale, frame_h * scale);
    let (ox, oy) = ((view_w - dw) / 2.0, (view_h - dh) / 2.0);
    let (nx, ny) = ((x - ox) / dw, (y - oy) / dh);
    if !(0.0..=1.0).contains(&nx) || !(0.0..=1.0).contains(&ny) {
        return None;
    }
    let max = POINTER_MAX as f32;
    Some(((nx * max).round() as u16, (ny * max).round() as u16))
}

#[cfg(test)]
mod tests {
    use super::{map_pointer, text_diff};

    #[test]
    pub(super) fn soft_keyboard_edits() {
        assert_eq!(text_diff("  ", "  a"), (0, "a".into()));
        assert_eq!(text_diff("  ab", "  a"), (1, "".into()));
        // Autocorrect replaces a word.
        assert_eq!(text_diff("  teh", "  the "), (2, "he ".into()));
        assert_eq!(text_diff("  ä", "  äö"), (0, "ö".into()));
    }

    #[test]
    pub(super) fn pointer_mapping_handles_letterboxing() {
        // 1600x900 viewport showing a 1024x768 frame: 1200x900 image with 200px bars left/right.
        assert_eq!(map_pointer(200.0, 0.0, 1600.0, 900.0, 1024.0, 768.0), Some((0, 0)));
        assert_eq!(map_pointer(1400.0, 900.0, 1600.0, 900.0, 1024.0, 768.0), Some((65535, 65535)));
        assert_eq!(map_pointer(800.0, 450.0, 1600.0, 900.0, 1024.0, 768.0), Some((32768, 32768)));
        assert_eq!(map_pointer(100.0, 450.0, 1600.0, 900.0, 1024.0, 768.0), None);
        assert_eq!(map_pointer(10.0, 10.0, 100.0, 100.0, 0.0, 0.0), None);
    }
}
