//! The optional account: signing this device in and out, two-factor authentication, and
//! confirming actions that need the account's identity key with the password.

use super::*;
use somedesk_client::ClientError;
use somedesk_crypto::recovery::RecoveryKey;

impl Controller {
    pub(super) fn install_account_callbacks(&self, ui: &AppWindow) {
        let c = self.clone();
        ui.on_sign_in(move || c.open_account_dialog(false, ""));
        let c = self.clone();
        ui.on_create_account(move || c.open_account_dialog(true, ""));
        let c = self.clone();
        ui.on_account_submit(move || c.account_submit());
        let c = self.clone();
        ui.on_account_close(move || {
            let mut st = c.0.state.lock().unwrap();
            st.after_unlock = None;
            st.setup_pending = None;
            drop(st);
            c.close_account_dialog();
        });
        let c = self.clone();
        ui.on_sign_out(move || c.sign_out());
        let c = self.clone();
        ui.on_totp_setup(move || c.totp_setup());
        let c = self.clone();
        ui.on_totp_disable(move || c.totp_disable());
        let c = self.clone();
        ui.on_own_devices_changed(move |on| c.own_devices_changed(on));
        let c = self.clone();
        ui.on_twofa_next(move || c.twofa_next());
        let c = self.clone();
        ui.on_twofa_cancel(move || {
            c.0.state.lock().unwrap().twofa = None;
            c.ui(|ui| {
                ui.set_twofa_visible(false);
                ui.set_twofa_password("".into());
                ui.set_twofa_password2("".into());
                ui.set_twofa_code("".into());
                ui.set_twofa_qr(Image::default());
            });
        });
    }

    /// Opens the account dialog: to sign in (or create an account), or with a `purpose` to
    /// confirm an action with the password of the account this device is signed in to.
    pub(super) fn open_account_dialog(&self, create: bool, purpose: &str) {
        let username = self.0.state.lock().unwrap().creds.as_ref().and_then(|c| c.username().map(str::to_owned));
        let purpose = purpose.to_owned();
        self.ui(move |ui| {
            if let Some(u) = username.filter(|_| !purpose.is_empty()) {
                ui.set_account_username(u.into());
            }
            ui.set_account_create_mode(create);
            ui.set_account_recover_mode(false);
            ui.set_account_need_code(false);
            ui.set_account_code("".into());
            ui.set_account_password("".into());
            ui.set_account_password2("".into());
            ui.set_account_error("".into());
            ui.set_account_purpose(purpose.into());
            ui.set_account_visible(true);
        });
    }

    fn close_account_dialog(&self) {
        self.ui(|ui| {
            ui.set_account_visible(false);
            ui.set_account_busy(false);
            ui.set_account_password("".into());
            ui.set_account_password2("".into());
            ui.set_account_recovery_key("".into());
            ui.set_account_code("".into());
            ui.set_account_need_code(false);
        });
    }

    /// Runs `action` with the account's login on the current connection, asking for the
    /// password (and code) first unless it was given on this connection already.
    pub(super) fn with_login(
        &self,
        purpose: &str,
        action: impl FnOnce(Controller, Arc<ServerConn>, Arc<LoggedIn>) + Send + 'static,
    ) {
        let ready = {
            let st = self.0.state.lock().unwrap();
            match (&st.login, &st.conn) {
                (Some((c, login)), Some(conn)) if Arc::ptr_eq(c, conn) => Some((conn.clone(), login.clone())),
                _ => None,
            }
        };
        match ready {
            Some((conn, login)) => action(self.clone(), conn, login),
            None => {
                self.0.state.lock().unwrap().after_unlock = Some(Box::new(action));
                self.open_account_dialog(false, purpose);
            }
        }
    }

    fn account_submit(&self) {
        let Some(ui) = self.0.ui.upgrade() else { return };
        let username = ui.get_account_username().trim().to_string();
        let password = ui.get_account_password().to_string();
        let password2 = ui.get_account_password2().to_string();
        let code = ui.get_account_code().trim().to_string();
        let need_code = ui.get_account_need_code();
        let recover = ui.get_account_recover_mode();
        let create = ui.get_account_create_mode() && !recover;
        let recovery_key = if recover { Some(RecoveryKey::parse(&ui.get_account_recovery_key())) } else { None };
        let problem = if let Some(Err(e)) = &recovery_key {
            Some(if ui.get_account_recovery_key().trim().is_empty() {
                "Enter your recovery key.".to_string()
            } else {
                let e = e.to_string();
                format!("{}{}.", e[..1].to_uppercase(), &e[1..])
            })
        } else if username.is_empty() || password.is_empty() {
            Some(
                if recover { "Enter your username and a new password." } else { "Enter your username and password." }
                    .into(),
            )
        } else if (create || recover) && password != password2 {
            Some("The passwords do not match.".into())
        } else if need_code && code.is_empty() {
            Some("Enter the code from your authenticator app.".into())
        } else {
            None
        };
        if let Some(p) = problem {
            ui.set_account_error(p.into());
            return;
        }
        // On the first start, signing in sets this device up (see `setup_submit`).
        let setup = self.0.state.lock().unwrap().setup_pending.clone();
        let conn = self.conn();
        if conn.is_none() && setup.is_none() {
            ui.set_account_error("Not connected to the server; try again in a moment.".into());
            return;
        }
        let recovery_key = recovery_key.map(|r| r.expect("checked above"));
        ui.set_account_error("".into());
        ui.set_account_busy(true);
        let this = self.clone();
        self.0.rt.spawn(async move {
            let conn = match conn {
                Some(c) => c,
                None => {
                    let server = setup.as_ref().map(|(s, _)| s.clone()).unwrap_or_default();
                    match ServerConn::connect(&server, None).await {
                        Ok((c, _events)) => c,
                        Err(e) => {
                            let msg = e.to_string();
                            return this.ui(move |ui| {
                                ui.set_account_busy(false);
                                ui.set_account_error(msg.into());
                            });
                        }
                    }
                }
            };
            let result = async {
                // A recovery key to show the user afterwards, and why.
                let mut new_key = None;
                let login = if let Some(rk) = recovery_key {
                    let recovered = conn.recover(&username, &rk, &password).await?;
                    new_key = Some((
                        recovered.new_recovery_key,
                        "Your password was reset. The key you used no longer works; this one replaces it.",
                    ));
                    recovered.login
                } else {
                    if create {
                        new_key = Some((conn.register(&username, &password).await?, "Created with your new account."));
                    }
                    let login = conn.login_with_code(&username, &password, need_code.then_some(code.as_str())).await?;
                    if !login.has_recovery {
                        let rk = conn.set_up_recovery(&login).await?;
                        new_key = Some((rk, "Your account did not have one yet, so SomeDesk created it now."));
                    }
                    login
                };
                Ok::<_, ClientError>((login, new_key))
            }
            .await;
            match result {
                Ok((login, new_key)) => {
                    if let Some((server, name)) = setup {
                        this.0.state.lock().unwrap().setup_pending = None;
                        this.close_account_dialog();
                        if let Some((rk, reason)) = new_key {
                            this.show_recovery_key(&rk, reason);
                        }
                        return this.finish_setup(conn, &login, server, name).await;
                    }
                    let login = Arc::new(login);
                    let action = {
                        let mut st = this.0.state.lock().unwrap();
                        st.login = Some((conn.clone(), login.clone()));
                        st.after_unlock.take()
                    };
                    this.close_account_dialog();
                    if let Some((rk, reason)) = new_key {
                        this.show_recovery_key(&rk, reason);
                    }
                    match action {
                        Some(action) => action(this.clone(), conn, login),
                        None => this.attach_device(conn, login).await,
                    }
                }
                Err(ClientError::TotpRequired) => this.ui(|ui| {
                    ui.set_account_busy(false);
                    ui.set_account_need_code(true);
                }),
                Err(e) => {
                    let msg = e.to_string();
                    this.ui(move |ui| {
                        ui.set_account_busy(false);
                        ui.set_account_error(msg.into());
                    });
                }
            }
        });
    }

    /// Signs this device in to the account just logged in to. It keeps its ID.
    async fn attach_device(&self, conn: Arc<ServerConn>, login: Arc<LoggedIn>) {
        let Some(mut creds) = self.0.state.lock().unwrap().creds.clone() else { return };
        match conn.attach(&login, &mut creds).await {
            Ok(()) => {
                self.0.state.lock().unwrap().creds = Some(creds);
                self.save_creds();
                self.publish_identity();
                self.after_online(&conn);
                self.toast(format!("Signed in as {}", login.username), false);
            }
            Err(e) => self.toast(format!("Could not sign this device in: {e}"), true),
        }
    }

    fn show_recovery_key(&self, rk: &RecoveryKey, reason: &'static str) {
        // Three lines of three groups, easy to copy down by hand.
        let display = rk.display();
        let groups: Vec<&str> = display.split('-').collect();
        let text = groups.chunks(3).map(|c| c.join("-")).collect::<Vec<_>>().join("\n");
        self.ui(move |ui| {
            ui.set_recovery_key(text.into());
            ui.set_recovery_key_reason(reason.into());
            ui.set_recovery_key_copied(false);
            ui.set_recovery_key_visible(true);
        });
    }

    /// Signs this device out of its account. It keeps its ID; passwords saved in the account
    /// are removed from this device.
    fn sign_out(&self) {
        let (conn, creds) = {
            let st = self.0.state.lock().unwrap();
            (st.conn.clone(), st.creds.clone())
        };
        let Some(mut creds) = creds else { return };
        let this = self.clone();
        self.0.rt.spawn(async move {
            if let Some(conn) = conn {
                if let Err(e) = conn.detach(&mut creds).await {
                    this.toast(format!("Could not sign out: {e}"), true);
                    return;
                }
            } else {
                creds.account = None;
            }
            this.0.state.lock().unwrap().creds = Some(creds);
            this.forget_account();
            this.toast("Signed out. This computer keeps its ID.", false);
        });
    }

    /// This device was taken off its account from another device.
    pub(super) fn signed_out_elsewhere(&self) {
        if let Some(creds) = self.0.state.lock().unwrap().creds.as_mut() {
            creds.account = None;
        }
        self.forget_account();
        self.toast("This device was taken off your account. It keeps its ID.", false);
    }

    /// Clears everything that belonged to the account on this device.
    fn forget_account(&self) {
        {
            let mut st = self.0.state.lock().unwrap();
            st.login = None;
            st.account_totp = false;
            st.orgs.clear();
            st.org_admins.clear();
            st.org_selected = None;
            if let Some(book) = st.book.as_mut() {
                book.clear_passwords();
                let _ = book.save();
            }
        }
        self.save_creds();
        self.publish_identity();
        self.publish_book();
        self.publish_orgs();
        self.ui(|ui| {
            ui.set_devices(ModelRc::default());
            ui.set_account_2fa(false);
            if ui.get_home_view() == crate::HomeView::Devices || ui.get_home_view() == crate::HomeView::Orgs {
                ui.set_home_view(crate::HomeView::Connect);
            }
        });
    }

    /// Reads whether the account has two-factor authentication. Access from the account's own
    /// devices only stays on while it does.
    pub(super) fn refresh_account(&self) {
        let Some(conn) = self.conn() else { return };
        let this = self.clone();
        self.0.rt.spawn(async move {
            let Ok((_, totp)) = conn.account_info().await else { return };
            let turned_off = {
                let mut st = this.0.state.lock().unwrap();
                st.account_totp = totp;
                let off = !totp && st.settings.own_devices_access;
                if off {
                    st.settings.own_devices_access = false;
                }
                off
            };
            if turned_off {
                this.save_settings();
                this.toast(
                    "Access from your own devices was turned off, because your account no longer has two-factor authentication.",
                    true,
                );
            }
            this.ui(move |ui| {
                ui.set_account_2fa(totp);
                if turned_off {
                    ui.set_own_devices(false);
                }
            });
        });
    }

    fn own_devices_changed(&self, on: bool) {
        let allowed = {
            let st = self.0.state.lock().unwrap();
            st.account_totp && st.creds.as_ref().is_some_and(|c| c.account.is_some())
        };
        if on && !allowed {
            self.ui(|ui| ui.set_own_devices(false));
            return;
        }
        self.0.state.lock().unwrap().settings.own_devices_access = on;
        self.save_settings();
    }

    fn totp_setup(&self) {
        self.with_login("Confirm with your password to turn on two-factor authentication.", |this, conn, login| {
            this.0.rt.clone().spawn(async move {
                match conn.totp_begin().await {
                    Ok(secret) => {
                        let uri = secret.uri("SomeDesk", &login.username);
                        let text = secret.base32();
                        this.0.state.lock().unwrap().twofa = Some(TwoFactorSetup::Account);
                        this.ui(move |ui| {
                            ui.set_twofa_unattended(false);
                            ui.set_twofa_step(1);
                            ui.set_twofa_qr(qr_image(&uri));
                            ui.set_twofa_secret(spaced(&text).into());
                            ui.set_twofa_code("".into());
                            ui.set_twofa_error("".into());
                            ui.set_twofa_visible(true);
                        });
                    }
                    Err(e) => this.toast(format!("Could not start: {e}"), true),
                }
            });
        });
    }

    fn totp_disable(&self) {
        // Always with a fresh sign-in: the server only takes no code within a few minutes of one.
        self.0.state.lock().unwrap().login = None;
        self.with_login(
            "Confirm with your password and a code to turn off two-factor authentication.",
            |this, conn, _login| {
                this.0.rt.clone().spawn(async move {
                    match conn.totp_disable("").await {
                        Ok(()) => {
                            this.toast("Two-factor authentication is off", false);
                            this.refresh_account();
                        }
                        Err(e) => this.toast(format!("Could not turn it off: {e}"), true),
                    }
                });
            },
        );
    }

    fn twofa_next(&self) {
        let account_secret = matches!(self.0.state.lock().unwrap().twofa, Some(TwoFactorSetup::Account));
        if !account_secret {
            self.unattended_twofa_next();
            return;
        }
        let Some(ui) = self.0.ui.upgrade() else { return };
        let code = ui.get_twofa_code().trim().to_string();
        let Some(conn) = self.conn() else { return };
        ui.set_twofa_busy(true);
        let this = self.clone();
        self.0.rt.spawn(async move {
            let result = conn.totp_enable(&code).await;
            this.ui(|ui| ui.set_twofa_busy(false));
            match result {
                Ok(()) => {
                    this.0.state.lock().unwrap().twofa = None;
                    this.ui(|ui| {
                        ui.set_twofa_visible(false);
                        ui.set_twofa_qr(Image::default());
                        ui.set_twofa_code("".into());
                    });
                    this.toast("Two-factor authentication is on", false);
                    this.refresh_account();
                }
                Err(e) => {
                    let msg = e.to_string();
                    this.ui(move |ui| ui.set_twofa_error(msg.into()));
                }
            }
        });
    }
}

/// A base32 secret in groups of four, easier to type.
pub(super) fn spaced(text: &str) -> String {
    text.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or("")).collect::<Vec<_>>().join(" ")
}
