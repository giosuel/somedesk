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

/// How a viewer got in.
enum Admitted {
    Accepted,
    Password,
    OwnDevice,
}

impl Controller {
    pub(super) fn install_hosting_callbacks(&self, ui: &AppWindow) {
        let c = self.clone();
        ui.on_incoming_answer(move |ok| {
            if let Some(tx) = c.0.state.lock().unwrap().incoming_answer.take() {
                let _ = tx.send(ok);
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
            let result = c.0.state.lock().unwrap().unattended.as_mut().map(|u| u.disable());
            match result {
                Some(Ok(())) => {
                    c.ui(|ui| ui.set_unattended(false));
                    c.toast("Unattended access is off", false);
                }
                Some(Err(e)) => c.toast(format!("Could not turn it off: {e}"), true),
                None => {}
            }
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
        let result = {
            let mut st = self.0.state.lock().unwrap();
            let st = &mut *st;
            match (&st.twofa, st.unattended.as_mut()) {
                (Some(TwoFactorSetup::Unattended(Some(pending))), Some(store)) => store.confirm(pending, &code),
                _ => return,
            }
        };
        match result {
            Ok(()) => {
                self.0.state.lock().unwrap().twofa = None;
                ui.set_twofa_visible(false);
                ui.set_twofa_qr(Image::default());
                ui.set_twofa_code("".into());
                ui.set_unattended(true);
                self.toast("Unattended access is on", false);
            }
            // The setup stays, so another code can be tried.
            Err(e) => ui.set_twofa_error(e.to_string().into()),
        }
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
                // Take the store out for the exchange (no lock across the awaits).
                let store = self.0.state.lock().unwrap().unattended.take();
                let Some(mut store) = store else {
                    host::reject(ch, "This computer doesn't allow unattended access.").await;
                    self.0.busy.store(false, Ordering::SeqCst);
                    return;
                };
                let verdict = store.check(&mut ch, &creds.device_key().public(), &request).await;
                self.0.state.lock().unwrap().unattended = Some(store);
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
                    // If the caller gives up while we are asking, take the question down.
                    let accepted = tokio::select! {
                        answer = self.prompt(from.device_id, &peer, level, previous) => answer,
                        _ = ch.receiver.recv::<SessionMsg>() => {
                            self.0.state.lock().unwrap().incoming_answer = None;
                            self.ui(|ui| ui.set_incoming_visible(false));
                            self.toast(format!("{label} cancelled the connection"), false);
                            self.0.busy.store(false, Ordering::SeqCst);
                            return;
                        }
                    };
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
        // The viewer controls this computer anyway, so files from it are saved without asking.
        let files = self.start_transfers(AcceptPolicy::Always, &label);
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
        self.0.state.lock().unwrap().incoming_answer = Some(tx);
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
            ui.set_incoming_visible(true);
            bring_to_front(ui);
        });
        let answer = matches!(tokio::time::timeout(PROMPT_TIMEOUT, rx).await, Ok(Ok(true)));
        self.0.state.lock().unwrap().incoming_answer = None;
        self.ui(|ui| ui.set_incoming_visible(false));
        answer
    }
}
