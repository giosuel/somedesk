//! Connecting to another computer: asking the person there, or with its unattended-access
//! password and the current code from its authenticator app.

use super::*;
use crate::SaveIn;
use somedesk_client::access;
use somedesk_client::session;
use somedesk_client::trust::{Changed, PeerStatus};
use somedesk_client::viewer::{self, SessionEnd, ViewerEvent};
use somedesk_client::ClientError;

/// How the viewer asks to get in.
#[derive(Clone)]
enum Ask {
    /// The person at the other computer decides.
    Person,
    /// Unattended access with this password and code; a newly typed password is kept where
    /// the user chose once it worked.
    Password { password: String, code: String, save: Option<SaveIn> },
}

/// Whether the user has to decide about a host whose identity changed before connecting: not
/// for the account's own devices, nor for the exact key the user just approved (`approved`).
fn must_ask_about(
    status: Option<&PeerStatus>,
    own_account: bool,
    approved: Option<&[u8; 32]>,
    peer_pk: &[u8; 32],
) -> bool {
    matches!(status, Some(PeerStatus::Changed(_))) && !own_account && approved != Some(peer_pk)
}

impl Controller {
    pub(super) fn install_viewing_callbacks(&self, ui: &AppWindow) {
        let c = self.clone();
        ui.on_connect(move |id| c.connect(id.to_string()));
        let c = self.clone();
        ui.on_connect_with_password(move |id| c.open_password_dialog(id.to_string()));
        let c = self.clone();
        ui.on_pw_submit(move || c.password_submit());
        let c = self.clone();
        ui.on_pw_cancel(move || {
            c.0.state.lock().unwrap().pw_target = None;
            c.cancel_viewer();
            c.ui(|ui| {
                ui.set_pw_visible(false);
                ui.set_pw_password("".into());
                ui.set_pw_code("".into());
            });
        });
        let c = self.clone();
        ui.on_pw_use_other(move || {
            // The saved password didn't work (the other computer changed it, say): type one.
            if let Some((_, saved)) = c.0.state.lock().unwrap().pw_target.as_mut() {
                *saved = None;
            }
            c.ui(|ui| {
                ui.set_pw_saved(false);
                ui.set_pw_error("".into());
            });
        });
        let c = self.clone();
        ui.on_identity_changed_answer(move |trust| c.identity_changed_answer(trust));
        let c = self.clone();
        ui.on_outgoing_cancel(move || c.cancel_viewer());
        let c = self.clone();
        ui.on_disconnect(move || {
            // Dropping the input sender ends the viewer session gracefully.
            c.0.state.lock().unwrap().viewer_input = None;
        });
        let c = self.clone();
        ui.on_remove_device(move |id| {
            let (Ok(id), Some(conn)) = (id.parse::<u64>(), c.conn()) else { return };
            let this = c.clone();
            c.0.rt.spawn(async move {
                match conn.remove_device(id).await {
                    Ok(()) => {
                        this.toast("Taken off your account. It keeps its ID.", false);
                        this.refresh_devices();
                    }
                    Err(e) => this.toast(format!("Could not remove it: {e}"), true),
                }
            });
        });
    }

    /// Stops the connection being set up. Its task cleans up (and frees the session) itself.
    fn cancel_viewer(&self) {
        if let Some(cancel) = self.0.state.lock().unwrap().viewer_cancel.take() {
            let _ = cancel.send(());
        }
        self.ui(|ui| {
            ui.set_outgoing_visible(false);
            ui.set_pw_busy(false);
        });
    }

    /// Checks an ID typed by the user; `None` (after telling them why) if there's nothing to
    /// connect to.
    fn target(&self, input: &str) -> Option<u64> {
        let Some(device_id) = parse_device_id(input) else {
            self.toast("Enter a valid 9-digit ID.", true);
            return None;
        };
        if self.0.state.lock().unwrap().creds.as_ref().is_some_and(|c| c.device_id == device_id) {
            self.toast("That is this computer's own ID.", true);
            return None;
        }
        Some(device_id)
    }

    pub(super) fn connect(&self, input: String) {
        if let Some(device_id) = self.target(&input) {
            self.start_viewer(device_id, Ask::Person, None);
        }
    }

    fn open_password_dialog(&self, input: String) {
        let Some(device_id) = self.target(&input) else { return };
        let label = self
            .0
            .state
            .lock()
            .unwrap()
            .book
            .as_ref()
            .and_then(|b| b.get(device_id).map(|e| format!("{} ({})", e.label, format_device_id(device_id))))
            .unwrap_or_else(|| format_device_id(device_id));
        let this = self.clone();
        self.0.rt.spawn_blocking(move || {
            let saved = this.saved_password(device_id);
            let keychain = this.0.state.lock().unwrap().keychain;
            let signed_in = this.0.state.lock().unwrap().creds.as_ref().is_some_and(|c| c.account.is_some());
            let default = if keychain {
                SaveIn::Device
            } else if signed_in {
                SaveIn::Account
            } else {
                SaveIn::Nowhere
            };
            let has_saved = saved.is_some();
            this.0.state.lock().unwrap().pw_target = Some((device_id, saved.map(|(p, _)| p)));
            this.ui(move |ui| {
                ui.set_pw_target(label.into());
                ui.set_pw_password("".into());
                ui.set_pw_code("".into());
                ui.set_pw_saved(has_saved);
                ui.set_pw_save(default);
                ui.set_pw_error("".into());
                ui.set_pw_busy(false);
                ui.set_pw_visible(true);
            });
        });
    }

    fn password_submit(&self) {
        let Some(ui) = self.0.ui.upgrade() else { return };
        let Some((device_id, saved)) = self.0.state.lock().unwrap().pw_target.clone() else { return };
        let code: String = ui.get_pw_code().chars().filter(|c| !c.is_whitespace()).collect();
        let typed = ui.get_pw_password().to_string();
        let password = saved.clone().unwrap_or_else(|| typed.clone());
        if password.is_empty() || code.len() != 6 {
            ui.set_pw_error("Enter the password and the 6-digit code.".into());
            return;
        }
        // Where to keep a newly typed password, once it turns out to be right.
        let save = Some(ui.get_pw_save()).filter(|s| saved.is_none() && *s != SaveIn::Nowhere);
        ui.set_pw_error("".into());
        ui.set_pw_busy(true);
        self.start_viewer(device_id, Ask::Password { password, code, save }, None);
    }

    /// Connects to `device_id`. `approved` is a changed host key the user just decided to trust.
    fn start_viewer(&self, device_id: u64, ask: Ask, approved: Option<[u8; 32]>) {
        let (conn, creds) = {
            let st = self.0.state.lock().unwrap();
            (st.conn.clone(), st.creds.clone())
        };
        let (Some(conn), Some(creds)) = (conn, creds) else {
            self.toast("Not connected to the server.", true);
            self.ui(|ui| ui.set_pw_busy(false));
            return;
        };
        if self.0.busy.swap(true, Ordering::SeqCst) {
            self.toast("Another session is already in progress.", true);
            self.ui(|ui| ui.set_pw_busy(false));
            return;
        }
        let with_password = matches!(ask, Ask::Password { .. });
        let target = format_device_id(device_id);
        self.ui(move |ui| {
            ui.set_connect_busy(true);
            if !with_password {
                ui.set_outgoing_target(target.into());
                ui.set_outgoing_visible(true);
            }
        });
        let (cancel_tx, cancel_rx) = oneshot::channel();
        self.0.state.lock().unwrap().viewer_cancel = Some(cancel_tx);
        let this = self.clone();
        self.0.rt.spawn(async move {
            // Cancelling stops the connection here, so the cleanup below always runs.
            let result = tokio::select! {
                r = this.run_viewer(conn, creds, device_id, ask, approved) => r,
                Ok(()) = cancel_rx => Ok(None),
            };
            this.end_transfers();
            {
                let mut st = this.0.state.lock().unwrap();
                st.viewer_input = None;
                st.viewer_cancel = None;
            }
            this.0.busy.store(false, Ordering::SeqCst);
            this.ui(|ui| {
                ui.set_outgoing_visible(false);
                ui.set_connect_busy(false);
                ui.set_pw_busy(false);
                ui.set_has_frame(false);
                ui.set_remote_frame(Image::default());
                ui.set_page(Page::Home);
            });
            match result {
                Ok(Some(SessionEnd::Closed)) => this.toast("Session ended", false),
                Ok(Some(SessionEnd::Rejected(reason))) if with_password => {
                    this.ui(move |ui| ui.set_pw_error(reason.into()));
                }
                Ok(Some(SessionEnd::Rejected(reason))) => this.toast(reason, true),
                Ok(None) => {}
                Err(ClientError::Rejected(reason)) if with_password => {
                    this.ui(move |ui| ui.set_pw_error(reason.into()))
                }
                Err(e) if with_password => {
                    let msg = e.to_string();
                    this.ui(move |ui| ui.set_pw_error(msg.into()));
                }
                Err(e) => this.toast(e.to_string(), true),
            }
        });
    }

    async fn run_viewer(
        &self,
        conn: Arc<ServerConn>,
        creds: DeviceCredentials,
        device_id: u64,
        ask: Ask,
        approved: Option<[u8; 32]>,
    ) -> somedesk_client::Result<Option<SessionEnd>> {
        let (mut ch, host_info, route) = session::connect_routed(&conn, &creds, device_id).await?;
        let route_label = match route {
            session::Route::Direct => "Encrypted · direct",
            session::Route::Relay => "Encrypted · relayed",
        };
        let peer = access::verified_identity(&ch.peer, &host_info.identity);
        let own_account = access::same_account(creds.account.as_ref().map(|a| &a.identity_pk), &peer);
        let status = {
            let st = self.0.state.lock().unwrap();
            let status = st.trust.as_ref().map(|t| t.status(device_id, &peer));
            // The address book pins the key too, for all of the account's devices: a new one
            // that never saw this device is warned just the same.
            let pinned = st.book.as_ref().and_then(|b| b.get(device_id)).and_then(|e| e.device_pk);
            match (status, pinned) {
                (Some(PeerStatus::Changed(c)), _) => Some(PeerStatus::Changed(c)),
                (_, Some(pk)) if pk != peer.device_pk => Some(PeerStatus::Changed(Changed::Device { previous_pk: pk })),
                (status, _) => status,
            }
        };
        if let Some(PeerStatus::Changed(changed)) =
            status.as_ref().filter(|s| must_ask_about(Some(s), own_account, approved.as_ref(), &peer.device_pk))
        {
            // Stop before the host sees anything from us; let the user decide.
            drop(ch);
            let device = matches!(changed, Changed::Device { .. });
            let (user, now, before) =
                (device_label(device_id, &peer), fingerprint(&peer.device_pk), fingerprint(changed.previous_key()));
            let with_password = matches!(ask, Ask::Password { .. });
            self.0.state.lock().unwrap().identity_changed = Some((device_id, peer, with_password));
            self.ui(move |ui| {
                ui.set_outgoing_visible(false);
                ui.set_pw_visible(false);
                ui.set_identity_changed_user(user.into());
                ui.set_identity_changed_device(device);
                ui.set_identity_changed_fingerprint(now.into());
                ui.set_identity_changed_previous(before.into());
                ui.set_identity_changed_visible(true);
            });
            return Ok(None);
        }
        let password_to_save = match &ask {
            Ask::Person => {
                access::request_access(&mut ch).await?;
                None
            }
            Ask::Password { password, code, save } => {
                access::sign_in_unattended(&mut ch, password, code).await?;
                save.map(|s| (password.clone(), s))
            }
        };
        let password_to_save = Mutex::new(password_to_save);
        let peer_fp = fingerprint(&peer.device_pk);
        let name = peer.name.clone();
        self.ui(move |ui| ui.set_outgoing_target(name.into()));

        let (input_tx, input_rx) = mpsc::unbounded_channel();
        self.0.state.lock().unwrap().viewer_input = Some(input_tx);

        let this = self.clone();
        let peer_label = device_label(device_id, &peer);
        let peer_id = format_device_id(device_id);
        let fps = Arc::new(Mutex::new((Instant::now(), 0u32)));
        let remembered = peer.clone();
        let sink: viewer::EventSink = Arc::new(move |ev| match ev {
            ViewerEvent::Accepted => {
                this.with_trust(|t| t.remember(device_id, &remembered));
                this.with_book(|b| b.pin(device_id, remembered.device_pk, remembered.username()));
                this.remember_recent(device_id, peer_label.clone());
                // A password that worked goes where the user wanted it.
                if let Some((password, save)) = password_to_save.lock().unwrap().take() {
                    let this = this.clone();
                    this.0.rt.clone().spawn_blocking(move || this.store_password(device_id, Some(&password), save));
                }
                this.0.state.lock().unwrap().soft_text = SOFT_PAD.to_owned();
                let (label, id, fp) = (peer_label.clone(), peer_id.clone(), peer_fp.clone());
                let peer_letter = letter(remembered.username().unwrap_or(&remembered.name));
                this.ui(move |ui| {
                    ui.set_session_peer(label.into());
                    ui.set_session_peer_letter(peer_letter.into());
                    ui.set_session_route(route_label.into());
                    ui.set_session_peer_id(id.into());
                    ui.set_session_peer_fingerprint(fp.into());
                    ui.set_has_frame(false);
                    ui.set_session_view_only(false);
                    ui.set_session_monitors(ModelRc::default());
                    ui.set_session_monitor_selected(-1);
                    ui.set_latency("–".into());
                    ui.set_fps("–".into());
                    ui.set_session_soft_text(SOFT_PAD.into());
                    ui.set_outgoing_visible(false);
                    ui.set_pw_visible(false);
                    ui.set_pw_password("".into());
                    ui.set_pw_code("".into());
                    ui.set_page(Page::Session);
                });
            }
            ViewerEvent::Monitors { list, selected } => {
                let mut choices = vec![MonitorChoice { id: -1, label: "All".into() }];
                for (i, m) in list.iter().enumerate() {
                    // Numbered like the host's display settings; the primary one is marked.
                    let label = if m.primary { format!("{} ★", i + 1) } else { format!("{}", i + 1) };
                    choices.push(MonitorChoice { id: m.id as i32, label: label.into() });
                }
                let selected = selected.map_or(-1, |id| id as i32);
                this.ui(move |ui| {
                    ui.set_session_monitors(ModelRc::new(VecModel::from(choices)));
                    ui.set_session_monitor_selected(selected);
                });
            }
            ViewerEvent::ViewOnly => {
                this.ui(|ui| ui.set_session_view_only(true));
                this.toast("The other computer only allows viewing, not control", false);
            }
            ViewerEvent::ScreenInfo { width, height } => {
                this.ui(move |ui| ui.set_resolution(format!("{width}×{height}").into()));
            }
            ViewerEvent::Latency(rtt) => {
                let ms = rtt.as_millis();
                let text = if ms == 0 { "<1 ms".to_string() } else { format!("{ms} ms") };
                this.ui(move |ui| ui.set_latency(text.into()));
            }
            ViewerEvent::Frame(frame) => {
                let mut f = fps.lock().unwrap();
                f.1 += 1;
                if f.0.elapsed() >= Duration::from_secs(1) {
                    let rate = f.1 as f64 / f.0.elapsed().as_secs_f64();
                    *f = (Instant::now(), 0);
                    this.ui(move |ui| ui.set_fps(format!("{rate:.0}").into()));
                }
                drop(f);
                this.show_frame(frame);
            }
        });
        // Files from the host could be anything, so the user decides about each one.
        let files = self.start_transfers(AcceptPolicy::Ask, &device_label(device_id, &peer));
        let extras = somedesk_client::SessionExtras { clipboard: self.clipboard(), files: Some(files) };
        viewer::run(ch, sink, input_rx, extras).await.map(Some)
    }

    fn identity_changed_answer(&self, trust: bool) {
        let pending = self.0.state.lock().unwrap().identity_changed.take();
        self.ui(|ui| ui.set_identity_changed_visible(false));
        let Some((device_id, identity, with_password)) = pending else { return };
        if !trust {
            return;
        }
        self.with_trust(|t| t.remember(device_id, &identity));
        self.with_book(|b| b.pin(device_id, identity.device_pk, identity.username()));
        if with_password {
            self.open_password_dialog(device_id.to_string());
        } else {
            self.start_viewer(device_id, Ask::Person, Some(identity.device_pk));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changed_identity_is_asked_about_unless_it_is_the_approved_key() {
        let changed = PeerStatus::Changed(Changed::Device { previous_pk: [1; 32] });
        let (x, y) = ([2u8; 32], [3u8; 32]);
        assert!(must_ask_about(Some(&changed), false, None, &x));
        // The user approved X: connecting again with X goes ahead.
        assert!(!must_ask_about(Some(&changed), false, Some(&x), &x));
        // But a different key Y on that connection is asked about again.
        assert!(must_ask_about(Some(&changed), false, Some(&x), &y));
        assert!(!must_ask_about(Some(&changed), true, None, &y));
        assert!(!must_ask_about(Some(&PeerStatus::Known), false, None, &y));
        assert!(!must_ask_about(None, false, None, &y));
    }
}
