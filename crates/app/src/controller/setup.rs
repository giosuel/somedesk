//! The first start: this installation gets its key and ID from the server, no account needed.
//! Afterwards it comes online under that ID on every start.

use super::*;

impl Controller {
    pub(super) fn install_setup_callbacks(&self, ui: &AppWindow) {
        let c = self.clone();
        ui.on_setup_submit(move || c.setup_submit());
        let c = self.clone();
        ui.on_rename_device(move |name| c.rename_device(name.to_string()));
    }

    fn setup_submit(&self) {
        let Some(ui) = self.0.ui.upgrade() else { return };
        let server = ui.get_setup_server().trim().to_string();
        let name = ui.get_setup_name().trim().to_string();
        let problem = if server.is_empty() {
            Some("Enter the address of your SomeDesk server.")
        } else if name.is_empty() {
            Some(if cfg!(target_os = "android") { "Give this phone a name." } else { "Give this computer a name." })
        } else {
            None
        };
        if let Some(p) = problem {
            ui.set_setup_error(p.into());
            return;
        }
        ui.set_setup_error("".into());
        ui.set_setup_busy(true);
        let this = self.clone();
        self.0.rt.spawn(async move {
            let result = async {
                let (conn, _events) = ServerConn::connect(&server, None).await?;
                let creds = conn.create_device(&server, &name).await?;
                conn.close();
                Ok::<_, somedesk_client::ClientError>(creds)
            }
            .await;
            this.ui(|ui| ui.set_setup_busy(false));
            match result {
                Ok(creds) => {
                    if let Err(e) = creds.save(&this.creds_path()) {
                        tracing::error!("cannot store credentials: {e:#}");
                    }
                    this.0.state.lock().unwrap().settings.last_server = server;
                    this.save_settings();
                    this.go_online(creds);
                }
                Err(e) => {
                    let msg = match e.code() {
                        Some(somedesk_proto::control::ErrorCode::Forbidden) => {
                            "This server only lets in devices of its accounts. Ask its administrator for an account."
                                .to_string()
                        }
                        _ => e.to_string(),
                    };
                    this.ui(move |ui| ui.set_setup_error(msg.into()));
                }
            }
        });
    }

    /// Shows this device on the home screen and keeps it online.
    pub(super) fn go_online(&self, creds: DeviceCredentials) {
        // Desi shows new users around once.
        let tour = !self.0.state.lock().unwrap().settings.tour_done;
        self.0.state.lock().unwrap().creds = Some(creds);
        self.publish_identity();
        self.ui(move |ui| {
            if tour {
                ui.set_tour_step(0);
                ui.set_tour_visible(true);
            }
            ui.set_online(false);
            ui.set_status_text("Connecting…".into());
            ui.set_page(Page::Home);
        });
        let this = self.clone();
        let task = self.0.rt.spawn(async move { this.online_loop().await });
        let mut st = self.0.state.lock().unwrap();
        if let Some(old) = st.online_task.replace(task) {
            old.abort();
        }
    }

    /// The ID, name, fingerprint and account on the home screen and in Settings.
    pub(super) fn publish_identity(&self) {
        let Some(creds) = self.0.state.lock().unwrap().creds.clone() else { return };
        let id = format_device_id(creds.device_id);
        let name = creds.device_name.clone();
        let user = creds.username().unwrap_or_default().to_owned();
        let fp = fingerprint(&creds.device_key().public());
        let server = creds.server.clone();
        let keychain = self.0.state.lock().unwrap().keychain;
        self.ui(move |ui| {
            ui.set_my_id(id.into());
            ui.set_my_device_name(name.into());
            ui.set_signed_in(!user.is_empty());
            ui.set_user_letter(letter(&user).into());
            ui.set_greeting(greeting(&user).into());
            ui.set_username(user.into());
            ui.set_fingerprint(fp.into());
            ui.set_server_label(format!("Server {server}").into());
            ui.set_keychain(keychain);
        });
    }

    /// Renames this device. A device on an account is named by the account's certificate, so
    /// that takes the password to sign a new one.
    fn rename_device(&self, name: String) {
        let name = name.trim().to_owned();
        if name.is_empty() || name.len() > 64 {
            self.toast("Give it a name of up to 64 characters.", true);
            return;
        }
        let signed_in = {
            let mut st = self.0.state.lock().unwrap();
            let Some(creds) = st.creds.as_mut() else { return };
            if creds.device_name == name {
                return;
            }
            creds.device_name = name.clone();
            creds.account.is_some()
        };
        self.save_creds();
        if signed_in {
            self.with_login(
                "Confirm with your password to rename this device in your account.",
                move |this, conn, login| {
                    let Some(mut creds) = this.0.state.lock().unwrap().creds.clone() else { return };
                    this.0.rt.clone().spawn(async move {
                        match conn.attach(&login, &mut creds).await {
                            Ok(()) => {
                                this.0.state.lock().unwrap().creds = Some(creds);
                                this.save_creds();
                                this.toast("Renamed", false);
                            }
                            Err(e) => this.toast(format!("Could not rename: {e}"), true),
                        }
                    });
                },
            );
        } else if let Some(conn) = self.conn() {
            // Coming online again under the new name updates it on the server.
            let this = self.clone();
            self.0.rt.spawn(async move {
                let Some(mut creds) = this.0.state.lock().unwrap().creds.clone() else { return };
                match conn.authenticate(&mut creds).await {
                    Ok(_) => this.toast("Renamed", false),
                    Err(e) => this.toast(format!("Could not rename: {e}"), true),
                }
            });
        }
        self.publish_identity();
    }
}
