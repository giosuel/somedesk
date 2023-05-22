//! Who gets into this computer: the person here accepts, or the viewer brings this computer's
//! unattended-access password and authenticator code, or it is one of the account's own devices
//! (when turned on, and only with two-factor authentication). And setting unattended access up.

use super::*;
use crate::TrustLevel;
use somedesk_client::access::{self, Asked, Verdict};
use somedesk_client::host::{self, HostSettings};
use somedesk_client::session;
use somedesk_client::trust::PeerStatus;
use somedesk_proto::control::{DeviceInfo, SessionId};

/// Accept works only this long after the prompt appeared, so a click or key press meant for
/// something else doesn't let anyone in.
pub(super) const ACCEPT_DELAY: Duration = Duration::from_secs(1);
/// How long a caller who was declined (or not answered) is turned away without asking again.
const DECLINE_COOLDOWN: Duration = Duration::from_secs(60);

/// The incoming-connection prompt on screen.
pub(super) struct Prompt {
    id: u64,
    shown: Instant,
    answer: oneshot::Sender<bool>,
}

/// Whether an answer from the UI counts: it is for the prompt on screen (`pending`, shown at
/// `shown`), and an Accept comes only after [`ACCEPT_DELAY`].
fn answer_counts(pending: u64, shown: Instant, id: u64, accept: bool, now: Instant) -> bool {
    pending == id && (!accept || now.saturating_duration_since(shown) >= ACCEPT_DELAY)
}

/// Whether `device_id` was declined within [`DECLINE_COOLDOWN`] of `now` (forgetting older ones).
fn recently_declined(declined: &mut std::collections::HashMap<u64, Instant>, device_id: u64, now: Instant) -> bool {
    declined.retain(|_, at| now.saturating_duration_since(*at) < DECLINE_COOLDOWN);
    declined.contains_key(&device_id)
}

/// How a viewer got in.
enum Admitted {
    Accepted,
    Password,
    OwnDevice,
}

impl Controller {
    pub(super) fn install_hosting_callbacks(&self, ui: &AppWindow) {
        let c = self.clone();
        ui.on_incoming_answer(move |id, ok| {
            let mut st = c.0.state.lock().unwrap();
            let counts =
                st.incoming.as_ref().is_some_and(|p| answer_counts(p.id, p.shown, id as u64, ok, Instant::now()));
            if let Some(p) = st.incoming.take_if(|_| counts) {
                let _ = p.answer.send(ok);
            }
        });
        let c = self.clone();
        ui.on_stop_hosting(move || {
            if let Some(stop) = c.0.state.lock().unwrap().host_stop.take() {
                let _ = stop.send(true);
            }
        });
        let c = self.clone();
        ui.on_unattended_setup(move || {
            c.0.state.lock().unwrap().twofa = Some(TwoFactorSetup::Unattended(None));
            c.ui(|ui| {
                ui.set_twofa_unattended(true);
                ui.set_twofa_step(0);
                ui.set_twofa_password("".into());
                ui.set_twofa_password2("".into());
                ui.set_twofa_code("".into());
                ui.set_twofa_error("".into());
                ui.set_twofa_visible(true);
            });
        });
        let c = self.clone();
        ui.on_unattended_disable(move || {
            // An exchange with a viewer may hold the setup: it won't let them in, and this
            // happens as soon as it ends.
            c.0.unattended_off.store(true, Ordering::SeqCst);
            if c.0.unattended.try_lock().is_err() {
                c.toast("Someone is trying unattended access right now. It turns off once they are done.", false);
            }
            let c = c.clone();
            c.0.rt.clone().spawn(async move {
                let result = c.0.unattended.lock().await.as_mut().map(|u| u.disable());
                c.0.unattended_off.store(false, Ordering::SeqCst);
                match result {
                    Some(Err(e)) => c.toast(format!("Could not turn it off: {e}"), true),
                    // Off, or never on (its setup couldn't be read).
                    Some(Ok(())) | None => {
                        c.ui(|ui| ui.set_unattended(false));
                        c.toast("Unattended access is off", false);
                    }
                }
            });
        });
    }

    /// The setup dialog's next step: the password, then the code from the app.
    pub(super) fn unattended_twofa_next(&self) {
        let Some(ui) = self.0.ui.upgrade() else { return };
        let Some(creds) = self.0.state.lock().unwrap().creds.clone() else { return };
        if ui.get_twofa_step() == 0 {
            let (password, password2) = (ui.get_twofa_password().to_string(), ui.get_twofa_password2().to_string());
            if password != password2 {
                ui.set_twofa_error("The passwords do not match.".into());
                return;
            }
            ui.set_twofa_busy(true);
            let this = self.clone();
            // Deriving the OPAQUE record runs Argon2: not on the UI thread.
            self.0.rt.spawn_blocking(move || {
                let result = Unattended::begin(&creds.device_key().public(), &password);
                this.ui(|ui| ui.set_twofa_busy(false));
                match result {
                    Ok(pending) => {
                        let label = format!("{} ({})", creds.device_name, format_device_id(creds.device_id));
                        let uri = pending.secret.uri("SomeDesk", &label);
                        let text = account::spaced(&pending.secret.base32());
                        this.0.state.lock().unwrap().twofa = Some(TwoFactorSetup::Unattended(Some(pending)));
                        this.ui(move |ui| {
                            ui.set_twofa_password("".into());
                            ui.set_twofa_password2("".into());
                            ui.set_twofa_qr(qr_image(&uri));
                            ui.set_twofa_secret(text.into());
                            ui.set_twofa_error("".into());
                            ui.set_twofa_step(1);
                        });
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        this.ui(move |ui| ui.set_twofa_error(msg.into()));
                    }
                }
            });
            return;
        }
        let code = ui.get_twofa_code().trim().to_string();
        let pending = match &mut self.0.state.lock().unwrap().twofa {
            Some(TwoFactorSetup::Unattended(p @ Some(_))) => p.take().expect("matched"),
            _ => return,
        };
        ui.set_twofa_busy(true);
        let this = self.clone();
        // Waits for an exchange with a viewer that may be holding the setup.
        self.0.rt.spawn(async move {
            let result = match this.0.unattended.lock().await.as_mut() {
                Some(store) => store.confirm(&pending, &code),
                None => Err(somedesk_client::ClientError::Other("unattended access isn't available here".into())),
            };
            this.ui(|ui| ui.set_twofa_busy(false));
            match result {
                Ok(()) => {
                    this.0.state.lock().unwrap().twofa = None;
                    this.ui(|ui| {
                        ui.set_twofa_visible(false);
                        ui.set_twofa_qr(Image::default());
                        ui.set_twofa_code("".into());
                        ui.set_unattended(true);
                    });
                    this.toast("Unattended access is on", false);
                }
                // The setup stays (unless the dialog was closed meanwhile), so another code can
                // be tried.
                Err(e) => {
                    if let Some(TwoFactorSetup::Unattended(p @ None)) = &mut this.0.state.lock().unwrap().twofa {
                        *p = Some(pending);
                    }
                    let msg = e.to_string();
                    this.ui(move |ui| ui.set_twofa_error(msg.into()));
                }
            }
        });
    }

    pub(super) async fn handle_incoming(
        self,
        conn: Arc<ServerConn>,
        session_id: SessionId,
        from: DeviceInfo,
        candidates: Vec<std::net::SocketAddr>,
    ) {
        let Some(creds) = self.0.state.lock().unwrap().creds.clone() else { return };
        let mut ch = match session::accept_routed(&conn, &creds, session_id, &from, &candidates).await {
            Ok((ch, route)) => {
                tracing::info!(?route, "incoming session channel");
                ch
            }
            Err(e) => {
                tracing::warn!("incoming session handshake failed: {e}");
                return;
            }
        };
        // The username shown and remembered is the one the server saw too, not just a claim.
        let peer = access::verified_identity(&ch.peer, &from.identity);
        let label = device_label(from.device_id, &peer);
        if !somedesk_platform::can_share_screen() {
            host::reject(ch, "This device can connect to other computers, but cannot share its own screen.").await;
            return;
        }
        if self.0.busy.swap(true, Ordering::SeqCst) {
            host::reject(ch, "The computer is busy with another session.").await;
            return;
        }
        let admitted = match access::read_request(&mut ch).await {
            Ok(Asked::Password(request)) => {
                let mut store = self.0.unattended.lock().await;
                let Some(unattended) = store.as_mut() else {
                    drop(store);
                    host::reject(ch, "This computer doesn't allow unattended access.").await;
                    self.0.busy.store(false, Ordering::SeqCst);
                    return;
                };
                let mut verdict = unattended.check(&mut ch, &creds.device_key().public(), &request).await;
                // Turned off during the exchange (read before the turning off can go ahead).
                if self.0.unattended_off.load(Ordering::SeqCst) && matches!(verdict, Ok(Verdict::Accepted)) {
                    verdict = Ok(Verdict::Rejected("This computer doesn't allow unattended access.".into()));
                }
                drop(store);
                match verdict {
                    Ok(Verdict::Accepted) => Some(Admitted::Password),
                    Ok(Verdict::Rejected(reason)) => {
                        if reason.starts_with("Wrong") || reason.starts_with("Too many") {
                            self.toast(format!("Someone tried unattended access from {label}: {reason}"), true);
                        }
                        host::reject(ch, &reason).await;
                        self.0.busy.store(false, Ordering::SeqCst);
                        return;
                    }
                    Err(e) => {
                        // Counted as a wrong attempt: the viewer may have learned whether its
                        // password was right before giving up.
                        tracing::warn!("unattended access failed: {e}");
                        self.toast(format!("Someone tried unattended access from {label} and gave up"), true);
                        None
                    }
                }
            }
            Ok(Asked::Access) => {
                if self.own_device_may_enter(&conn, &creds, &from, &peer).await {
                    Some(Admitted::OwnDevice)
                } else {
                    let status = self.0.state.lock().unwrap().trust.as_ref().map(|t| t.status(from.device_id, &peer));
                    let level = match &status {
                        _ if access::same_account(creds.account.as_ref().map(|a| &a.identity_pk), &peer) => {
                            TrustLevel::OwnAccount
                        }
                        Some(PeerStatus::Known) => TrustLevel::Known,
                        Some(PeerStatus::Changed(_)) => TrustLevel::Changed,
                        _ => TrustLevel::NewPeer,
                    };
                    let previous = match &status {
                        Some(PeerStatus::Changed(c)) => fingerprint(c.previous_key()),
                        _ => String::new(),
                    };
                    let declined_lately =
                        recently_declined(&mut self.0.state.lock().unwrap().declined, from.device_id, Instant::now());
                    if declined_lately {
                        tracing::info!(device = from.device_id, "declined without asking: declined a moment ago");
                        host::reject(ch, "The connection was declined.").await;
                        self.0.busy.store(false, Ordering::SeqCst);
                        return;
                    }
                    // If the caller gives up while we are asking, take the question down.
                    let accepted = tokio::select! {
                        answer = self.prompt(from.device_id, &peer, level, previous) => answer,
                        _ = ch.receiver.recv::<SessionMsg>() => {
                            self.0.state.lock().unwrap().incoming = None;
                            self.ui(|ui| ui.set_incoming_visible(false));
                            self.toast(format!("{label} cancelled the connection"), false);
                            self.0.busy.store(false, Ordering::SeqCst);
                            return;
                        }
                    };
                    if !accepted {
                        // Declined or not answered: don't let them ask again right away.
                        self.0.state.lock().unwrap().declined.insert(from.device_id, Instant::now());
                    }
                    accepted.then_some(Admitted::Accepted)
                }
            }
            Err(e) => {
                tracing::warn!("no access request from the viewer: {e}");
                None
            }
        };
        let Some(admitted) = admitted else {
            host::reject(ch, "The connection was declined.").await;
            self.0.busy.store(false, Ordering::SeqCst);
            return;
        };
        self.with_trust(|t| t.remember(from.device_id, &peer));
        self.serve(ch, label, admitted).await;
    }

    /// Whether `peer` gets in as one of the account's own devices: turned on here, the account
    /// has two-factor authentication, the account signed the peer's key (checked in the
    /// handshake), and the server still has the peer on the account (not taken off it).
    async fn own_device_may_enter(
        &self,
        conn: &ServerConn,
        creds: &DeviceCredentials,
        from: &DeviceInfo,
        peer: &DeviceIdentity,
    ) -> bool {
        let (on, totp) = {
            let st = self.0.state.lock().unwrap();
            (st.settings.own_devices_access, st.account_totp)
        };
        if !on || !totp || !access::same_account(creds.account.as_ref().map(|a| &a.identity_pk), peer) {
            return false;
        }
        match conn.lookup_device(from.device_id).await {
            Ok(info) => info.identity.device_pk == peer.device_pk && info.identity.account == peer.account,
            Err(_) => false,
        }
    }

    async fn serve(&self, ch: session::Channel, label: String, admitted: Admitted) {
        // On Wayland this shows the desktop's own permission dialog (once), so it may block.
        let dir = self.0.dir.clone();
        let screen = tokio::task::spawn_blocking(move || somedesk_platform::open_screen(Some(&dir)))
            .await
            .unwrap_or_else(|e| Err(anyhow::anyhow!("{e}")));
        let screen = match screen {
            Ok(s) => {
                tracing::info!(backend = s.backend, can_control = s.can_control, "sharing the screen");
                s
            }
            Err(e) => {
                host::reject(ch, &format!("Screen sharing is not available on this computer: {e}")).await;
                self.toast(format!("Could not share the screen: {e}"), true);
                self.0.busy.store(false, Ordering::SeqCst);
                return;
            }
        };
        let (stop_tx, stop_rx) = watch::channel(false);
        self.0.state.lock().unwrap().host_stop = Some(stop_tx);
        let how = match admitted {
            Admitted::Accepted => "",
            Admitted::Password => " · unattended access",
            Admitted::OwnDevice => " · your own device",
        };
        let shown = format!("{label}{how}");
        // The banner always shows while someone is connected, also after access without asking.
        self.ui(move |ui| {
            ui.set_hosting_peer(shown.into());
            ui.set_hosting_active(true);
            ui.set_home_view(crate::HomeView::Connect);
            bring_to_front(ui);
        });
        if !screen.can_control {
            let reason = screen.view_only_reason.unwrap_or("Remote control is not available here");
            self.toast(format!("{reason}, so the screen is shared view-only"), true);
        }
        let clipboard = self.clipboard();
        let settings = HostSettings { view_only: !screen.can_control, ..Default::default() };
        // A viewer in control could put files here anyway, so its files are saved without
        // asking; a view-only one's need the user's OK.
        let policy = if screen.can_control { AcceptPolicy::Always } else { AcceptPolicy::Ask };
        let files = self.start_transfers(policy, &label);
        let extras = somedesk_client::SessionExtras { clipboard, files: Some(files) };
        let result = host::serve(ch, screen.capturer, screen.injector, extras, settings, stop_rx).await;
        self.end_transfers();
        self.0.state.lock().unwrap().host_stop = None;
        self.0.busy.store(false, Ordering::SeqCst);
        self.ui(|ui| ui.set_hosting_active(false));
        match result {
            Ok(_) => self.toast(format!("Session with {label} ended"), false),
            Err(e) => self.toast(format!("Session with {label} ended: {e}"), true),
        }
    }

    /// Shows the accept/decline prompt and waits for an answer.
    async fn prompt(
        &self,
        device_id: u64,
        peer: &DeviceIdentity,
        trust: TrustLevel,
        previous_fingerprint: String,
    ) -> bool {
        let (tx, rx) = oneshot::channel();
        let id = {
            let mut st = self.0.state.lock().unwrap();
            st.incoming_seq += 1;
            let id = st.incoming_seq;
            st.incoming = Some(Prompt { id, shown: Instant::now(), answer: tx });
            id
        };
        let user = peer.username().map(str::to_owned).unwrap_or_else(|| peer.name.clone());
        let device = match peer.username() {
            Some(_) => format!("{} · ID {}", peer.name, format_device_id(device_id)),
            None => format!("ID {} · not signed in to an account", format_device_id(device_id)),
        };
        let fp = fingerprint(&peer.device_pk);
        let asks = somedesk_platform::will_ask_permission(Some(&self.0.dir));
        let note = match (asks, somedesk_platform::control_without_desktop_consent()) {
            // Hyprland, Sway: the desktop asks about the screen only.
            (true, true) => {
                "Your desktop will then ask which screen to share. Accepting also lets them use the mouse and \
                 keyboard: your desktop doesn't ask about that. You will only be asked once."
            }
            (false, true) => "Accepting lets them see your screen and use the mouse and keyboard.",
            (true, false) => {
                "Your desktop will then ask what to share. Choose Share, and turn on \"Allow Remote Interaction\" so \
                 they can use the mouse and keyboard. You will only be asked once."
            }
            (false, false) => "",
        };
        self.ui(move |ui| {
            ui.set_incoming_note(note.into());
            ui.set_incoming_user_letter(letter(&user).into());
            ui.set_incoming_user(user.into());
            ui.set_incoming_device(device.into());
            ui.set_incoming_fingerprint(fp.into());
            ui.set_incoming_trust(trust);
            ui.set_incoming_previous_fingerprint(previous_fingerprint.into());
            ui.set_incoming_request(id as i32);
            ui.set_incoming_ready(false);
            ui.set_incoming_visible(true);
            bring_to_front(ui);
        });
        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(ACCEPT_DELAY).await;
            if this.0.state.lock().unwrap().incoming.as_ref().is_some_and(|p| p.id == id) {
                this.ui(|ui| ui.set_incoming_ready(true));
            }
        });
        let answer = matches!(tokio::time::timeout(PROMPT_TIMEOUT, rx).await, Ok(Ok(true)));
        self.0.state.lock().unwrap().incoming = None;
        self.ui(|ui| ui.set_incoming_visible(false));
        answer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_counts_only_after_the_delay_and_for_its_prompt() {
        let shown = Instant::now();
        // Too early: a click meant for something else.
        assert!(!answer_counts(3, shown, 3, true, shown + ACCEPT_DELAY / 2));
        assert!(answer_counts(3, shown, 3, true, shown + ACCEPT_DELAY));
        // Declining works at once.
        assert!(answer_counts(3, shown, 3, false, shown));
        // An answer given to an earlier prompt doesn't answer this one.
        assert!(!answer_counts(4, shown, 3, true, shown + ACCEPT_DELAY * 2));
        assert!(!answer_counts(4, shown, 3, false, shown + ACCEPT_DELAY * 2));
    }

    #[test]
    fn declined_callers_are_turned_away_for_a_while() {
        let mut declined = std::collections::HashMap::new();
        let t = Instant::now();
        assert!(!recently_declined(&mut declined, 7, t));
        declined.insert(7, t);
        assert!(recently_declined(&mut declined, 7, t + Duration::from_secs(5)));
        assert!(!recently_declined(&mut declined, 8, t + Duration::from_secs(5)));
        assert!(!recently_declined(&mut declined, 7, t + DECLINE_COOLDOWN));
        assert!(declined.is_empty(), "old entries are forgotten");
    }
}
