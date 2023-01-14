//! Glue between the Slint UI and the client core.
//!
//! UI callbacks run on the UI thread and hand work to the tokio runtime; async tasks push state
//! back with `upgrade_in_event_loop`. Locks are never held across an `.await`.

use crate::keymap::keysym_for;
use crate::{AppWindow, DeviceItem, Page};
use serde::{Deserialize, Serialize};
use slint::{ComponentHandle, Image, ModelRc, Rgb8Pixel, SharedPixelBuffer, VecModel};
use somedesk_client::credentials::DeviceCredentials;
use somedesk_client::host::{self, HostSettings};
use somedesk_client::server::ServerConn;
use somedesk_client::session;
use somedesk_client::viewer::{self, SessionEnd, ViewerEvent};
use somedesk_codec::RgbFrame;
use somedesk_crypto::keys::fingerprint;
use somedesk_crypto::recovery::RecoveryKey;
use somedesk_proto::control::{DeviceCert, DeviceInfo, ErrorCode, Event, SessionId};
use somedesk_proto::session::{SessionMsg, POINTER_MAX};
use somedesk_proto::{format_device_id, parse_device_id};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

/// How long the incoming-connection prompt waits for an answer.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);
/// Slint reports one mouse-wheel notch as 60 logical pixels.
const WHEEL_STEP: f32 = 60.0;

#[derive(Serialize, Deserialize)]
struct Settings {
    #[serde(default)]
    auto_accept_own_devices: bool,
    #[serde(default = "yes")]
    share_clipboard: bool,
    #[serde(default)]
    last_server: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self { auto_accept_own_devices: false, share_clipboard: true, last_server: String::new() }
    }
}

fn yes() -> bool {
    true
}

#[derive(Default)]
struct State {
    settings: Settings,
    creds: Option<DeviceCredentials>,
    conn: Option<Arc<ServerConn>>,
    online_task: Option<JoinHandle<()>>,
    viewer_task: Option<JoinHandle<()>>,
    viewer_input: Option<mpsc::UnboundedSender<SessionMsg>>,
    scroll_acc: (f32, f32),
    host_stop: Option<watch::Sender<bool>>,
    incoming_answer: Option<oneshot::Sender<bool>>,
    toast_generation: u64,
    /// Keeps copied text available on X11, where the copying app must serve the clipboard.
    copy_clipboard: Option<Box<dyn somedesk_platform::Clipboard>>,
}

struct Inner {
    ui: slint::Weak<AppWindow>,
    rt: Handle,
    dir: PathBuf,
    default_server: Option<String>,
    state: Mutex<State>,
    /// A session (as host or viewer) is in progress or being set up.
    busy: AtomicBool,
    frame: FrameSlot,
    /// Remote frame size, for mapping pointer coordinates.
    frame_w: AtomicU32,
    frame_h: AtomicU32,
}

#[derive(Clone)]
pub struct Controller(Arc<Inner>);

/// Latest decoded frame waiting to be shown. Only one UI update is queued at a time, so a slow
/// UI drops intermediate frames instead of building a backlog.
#[derive(Default)]
struct FrameSlot {
    pending: Mutex<Option<RgbFrame>>,
    scheduled: AtomicBool,
}

fn letter(name: &str) -> String {
    name.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or_default()
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "my-computer".into())
}

/// Un-minimizes and raises the window, so an incoming request is never hidden behind other windows.
fn bring_to_front(ui: &AppWindow) {
    use slint::winit_030::WinitWindowAccessor;
    ui.window().set_minimized(false);
    ui.window().with_winit_window(|w| {
        w.focus_window();
        w.request_user_attention(Some(slint::winit_030::winit::window::UserAttentionType::Critical));
    });
}

fn device_label(cert: &DeviceCert) -> String {
    format!("{} · {}", cert.username, cert.device_name)
}

impl Controller {
    pub fn new(ui: &AppWindow, rt: Handle, dir: PathBuf, default_server: Option<String>) -> Self {
        let c = Controller(Arc::new(Inner {
            ui: ui.as_weak(),
            rt,
            dir,
            default_server,
            state: Mutex::default(),
            busy: AtomicBool::new(false),
            frame: FrameSlot::default(),
            frame_w: AtomicU32::new(0),
            frame_h: AtomicU32::new(0),
        }));
        c.install_callbacks(ui);
        c
    }

    fn creds_path(&self) -> PathBuf {
        self.0.dir.join("device.json")
    }

    fn settings_path(&self) -> PathBuf {
        self.0.dir.join("settings.json")
    }

    fn save_settings(&self) {
        let json = serde_json::to_vec_pretty(&self.0.state.lock().unwrap().settings).expect("serializable");
        let _ = std::fs::create_dir_all(&self.0.dir);
        if let Err(e) = std::fs::write(self.settings_path(), json) {
            tracing::warn!("could not save settings: {e}");
        }
    }

    /// Runs `f` on the UI thread.
    fn ui(&self, f: impl FnOnce(&AppWindow) + Send + 'static) {
        let _ = self.0.ui.upgrade_in_event_loop(move |ui| f(&ui));
    }

    fn toast(&self, text: impl Into<String>, error: bool) {
        let text = text.into();
        let generation = {
            let mut st = self.0.state.lock().unwrap();
            st.toast_generation += 1;
            st.toast_generation
        };
        self.ui(move |ui| {
            ui.set_toast_text(text.into());
            ui.set_toast_error(error);
        });
        let this = self.clone();
        self.0.rt.spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if this.0.state.lock().unwrap().toast_generation == generation {
                this.ui(|ui| ui.set_toast_text("".into()));
            }
        });
    }

    pub fn start(&self) {
        let settings: Settings =
            std::fs::read(self.settings_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let server = self
            .0
            .default_server
            .clone()
            .or_else(|| (!settings.last_server.is_empty()).then(|| settings.last_server.clone()))
            .unwrap_or_else(|| "localhost".into());
        let auto_accept = settings.auto_accept_own_devices;
        let share_clipboard = settings.share_clipboard;
        self.0.state.lock().unwrap().settings = settings;
        self.ui(move |ui| {
            ui.set_login_server(server.into());
            ui.set_login_device_name(hostname().into());
            ui.set_auto_accept(auto_accept);
            ui.set_share_clipboard(share_clipboard);
        });
        match DeviceCredentials::load(&self.creds_path()) {
            Ok(Some(creds)) => self.go_online(creds),
            Ok(None) => self.ui(|ui| ui.set_page(Page::Login)),
            Err(e) => {
                tracing::error!("cannot read stored credentials: {e:#}");
                self.ui(|ui| ui.set_page(Page::Login));
            }
        }
    }

    pub fn shutdown(&self) {
        let mut st = self.0.state.lock().unwrap();
        if let Some(stop) = st.host_stop.take() {
            let _ = stop.send(true);
        }
        st.viewer_input = None;
        if let Some(conn) = st.conn.take() {
            conn.close();
        }
    }

    fn install_callbacks(&self, ui: &AppWindow) {
        let c = self.clone();
        ui.on_login_submit(move || c.login_submit());
        let c = self.clone();
        ui.on_connect(move |id| c.connect(id.to_string()));
        let c = self.clone();
        ui.on_sign_out(move || c.sign_out());
        let c = self.clone();
        ui.on_auto_accept_changed(move |v| {
            c.0.state.lock().unwrap().settings.auto_accept_own_devices = v;
            c.save_settings();
        });
        let c = self.clone();
        ui.on_share_clipboard_changed(move |v| {
            c.0.state.lock().unwrap().settings.share_clipboard = v;
            c.save_settings();
        });
        let c = self.clone();
        ui.on_recovery_key_copy(move || c.copy_recovery_key());
        let c = self.clone();
        ui.on_recovery_key_done(move || {
            c.ui(|ui| {
                ui.set_recovery_key_visible(false);
                ui.set_recovery_key("".into());
            });
        });
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
        ui.on_outgoing_cancel(move || {
            let task = c.0.state.lock().unwrap().viewer_task.take();
            if let Some(t) = task {
                t.abort();
            }
            c.0.busy.store(false, Ordering::SeqCst);
            c.ui(|ui| {
                ui.set_outgoing_visible(false);
                ui.set_connect_busy(false);
            });
        });
        let c = self.clone();
        ui.on_disconnect(move || {
            // Dropping the input sender ends the viewer session gracefully.
            c.0.state.lock().unwrap().viewer_input = None;
        });
        let c = self.clone();
        ui.on_pointer_moved(move |x, y, w, h| c.pointer_moved(x, y, w, h));
        let c = self.clone();
        ui.on_pointer_button(move |b, down| {
            if (1..=3).contains(&b) {
                c.send_input(SessionMsg::PointerButton { button: b as u8, down });
            }
        });
        let c = self.clone();
        ui.on_scroll(move |dx, dy| c.scroll(dx, dy));
        let c = self.clone();
        ui.on_key(move |text, down| {
            if let Some(keysym) = keysym_for(&text) {
                c.send_input(SessionMsg::Key { keysym, down });
            }
        });
    }

    // ------------------------------------------------------------------ sign in / out

    fn login_submit(&self) {
        let Some(ui) = self.0.ui.upgrade() else {
            return;
        };
        let server = ui.get_login_server().trim().to_string();
        let username = ui.get_login_username().trim().to_string();
        let password = ui.get_login_password().to_string();
        let password2 = ui.get_login_password2().to_string();
        let device = ui.get_login_device_name().trim().to_string();
        let recover = ui.get_login_recover_mode();
        let create = ui.get_login_create_mode() && !recover;
        let recovery_key = if recover { Some(RecoveryKey::parse(&ui.get_login_recovery_key())) } else { None };

        let problem = if server.is_empty() {
            Some("Enter the address of your SomeDesk server.".to_string())
        } else if let Some(Err(e)) = &recovery_key {
            Some(if ui.get_login_recovery_key().trim().is_empty() {
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
        } else if device.is_empty() {
            Some("Give this computer a name.".into())
        } else {
            None
        };
        if let Some(p) = problem {
            ui.set_login_error(p.into());
            return;
        }
        let recovery_key = recovery_key.map(|r| r.expect("checked above"));
        ui.set_login_error("".into());
        ui.set_login_busy(true);

        let this = self.clone();
        self.0.rt.spawn(async move {
            let result = async {
                let (conn, _events) = ServerConn::connect(&server, None).await?;
                // A recovery key to show the user once signed in, and why.
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
                    let login = conn.login(&username, &password).await?;
                    if !login.has_recovery {
                        let rk = conn.set_up_recovery(&login).await?;
                        new_key = Some((rk, "Your account did not have one yet, so SomeDesk created it now."));
                    }
                    login
                };
                let creds = conn.enroll_device(&server, &login, &device).await?;
                conn.close();
                Ok::<_, somedesk_client::ClientError>((creds, new_key))
            }
            .await;
            match result {
                Ok((creds, new_key)) => {
                    if let Err(e) = creds.save(&this.creds_path()) {
                        tracing::error!("cannot store credentials: {e:#}");
                    }
                    this.0.state.lock().unwrap().settings.last_server = server;
                    this.save_settings();
                    this.ui(|ui| {
                        ui.set_login_busy(false);
                        ui.set_login_password("".into());
                        ui.set_login_password2("".into());
                        ui.set_login_recovery_key("".into());
                        ui.set_login_recover_mode(false);
                    });
                    this.go_online(creds);
                    if let Some((rk, reason)) = new_key {
                        this.show_recovery_key(&rk, reason);
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    this.ui(move |ui| {
                        ui.set_login_busy(false);
                        ui.set_login_error(msg.into());
                    });
                }
            }
        });
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

    fn copy_recovery_key(&self) {
        let Some(ui) = self.0.ui.upgrade() else {
            return;
        };
        let key = ui.get_recovery_key().replace('\n', "-");
        let result = somedesk_platform::default_clipboard().and_then(|mut c| {
            c.set_text(&key)?;
            Ok(c)
        });
        match result {
            Ok(c) => {
                self.0.state.lock().unwrap().copy_clipboard = Some(c);
                ui.set_recovery_key_copied(true);
            }
            Err(e) => self.toast(format!("Could not copy: {e}"), true),
        }
    }

    fn sign_out(&self) {
        let (conn, creds, task) = {
            let mut st = self.0.state.lock().unwrap();
            (st.conn.take(), st.creds.take(), st.online_task.take())
        };
        if let Some(t) = task {
            t.abort();
        }
        let _ = std::fs::remove_file(self.creds_path());
        self.ui(|ui| {
            ui.set_page(Page::Login);
            ui.set_devices(ModelRc::default());
            ui.set_online(false);
        });
        self.0.rt.spawn(async move {
            if let (Some(conn), Some(creds)) = (conn, creds) {
                // Revoke this device on the server so its token stops working.
                let _ = conn.remove_device(creds.device_id).await;
                conn.close();
            }
        });
    }

    // ------------------------------------------------------------------ presence

    fn go_online(&self, creds: DeviceCredentials) {
        let id = format_device_id(creds.device_id);
        let name = creds.cert.device_name.clone();
        let user = creds.username.clone();
        let fp = fingerprint(&creds.identity_pk);
        let server = creds.server.clone();
        self.ui(move |ui| {
            ui.set_my_id(id.into());
            ui.set_my_device_name(name.into());
            ui.set_user_letter(letter(&user).into());
            ui.set_username(user.into());
            ui.set_fingerprint(fp.into());
            ui.set_server_label(format!("Server {server}").into());
            ui.set_online(false);
            ui.set_status_text("Connecting…".into());
            ui.set_page(Page::Home);
        });
        let this = self.clone();
        let task = self.0.rt.spawn(async move { this.online_loop(creds).await });
        let mut st = self.0.state.lock().unwrap();
        st.creds = None;
        if let Some(old) = st.online_task.replace(task) {
            old.abort();
        }
    }

    async fn online_loop(self, creds: DeviceCredentials) {
        self.0.state.lock().unwrap().creds = Some(creds.clone());
        let mut backoff = Duration::from_secs(1);
        loop {
            match ServerConn::connect(&creds.server, Some(creds.server_fingerprint)).await {
                Ok((conn, mut events)) => match conn.authenticate(&creds).await {
                    Ok(_) => {
                        backoff = Duration::from_secs(1);
                        self.0.state.lock().unwrap().conn = Some(conn.clone());
                        self.ui(|ui| {
                            ui.set_online(true);
                            ui.set_status_text("Online".into());
                        });
                        self.refresh_devices(conn.clone(), creds.device_id);
                        loop {
                            tokio::select! {
                                ev = events.recv() => match ev {
                                    Some(Event::IncomingSession { session_id, from }) => {
                                        let this = self.clone();
                                        let (conn, creds) = (conn.clone(), creds.clone());
                                        tokio::spawn(async move { this.handle_incoming(conn, creds, session_id, from).await });
                                    }
                                    Some(Event::DevicePresence { .. }) => self.refresh_devices(conn.clone(), creds.device_id),
                                    None => break,
                                },
                                reason = conn.closed() => {
                                    tracing::warn!("lost connection to server: {reason}");
                                    break;
                                }
                            }
                        }
                        self.0.state.lock().unwrap().conn = None;
                    }
                    Err(e) if e.code() == Some(ErrorCode::AuthFailed) => {
                        self.toast("This computer was removed from your account. Please sign in again.", true);
                        let _ = std::fs::remove_file(self.creds_path());
                        self.ui(|ui| ui.set_page(Page::Login));
                        return;
                    }
                    Err(e) => tracing::warn!("authentication failed: {e}"),
                },
                Err(e) => tracing::warn!("cannot reach server: {e}"),
            }
            let secs = backoff.as_secs();
            self.ui(move |ui| {
                ui.set_online(false);
                ui.set_status_text(format!("Offline · retrying in {secs}s").into());
            });
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(15));
            self.ui(|ui| ui.set_status_text("Connecting…".into()));
        }
    }

    fn refresh_devices(&self, conn: Arc<ServerConn>, my_id: u64) {
        let this = self.clone();
        self.0.rt.spawn(async move {
            match conn.list_devices().await {
                Ok(devices) => {
                    let mut items: Vec<DeviceItem> = devices
                        .iter()
                        .map(|d| DeviceItem {
                            id: d.device_id.to_string().into(),
                            id_label: format_device_id(d.device_id).into(),
                            name: d.name.clone().into(),
                            online: d.online,
                            is_self: d.device_id == my_id,
                        })
                        .collect();
                    items.sort_by_key(|d| (!d.is_self, !d.online));
                    this.ui(move |ui| ui.set_devices(ModelRc::new(VecModel::from(items))));
                }
                Err(e) => tracing::warn!("cannot list devices: {e}"),
            }
        });
    }

    // ------------------------------------------------------------------ hosting

    async fn handle_incoming(
        self,
        conn: Arc<ServerConn>,
        creds: DeviceCredentials,
        session_id: SessionId,
        from: DeviceInfo,
    ) {
        let ch = match session::accept(&conn, &creds, session_id, &from).await {
            Ok(ch) => ch,
            Err(e) => {
                tracing::warn!("incoming session handshake failed: {e}");
                return;
            }
        };
        let peer = ch.peer.clone();
        if self.0.busy.swap(true, Ordering::SeqCst) {
            host::reject(ch, "The computer is busy with another session.").await;
            return;
        }
        let same_account = peer.identity_pk == creds.identity_pk;
        let auto = same_account && self.0.state.lock().unwrap().settings.auto_accept_own_devices;
        let accepted = auto || self.prompt(&peer, same_account).await;
        if !accepted {
            host::reject(ch, "The connection was declined.").await;
            self.0.busy.store(false, Ordering::SeqCst);
            return;
        }
        let backends =
            somedesk_platform::default_capturer().and_then(|c| Ok((c, somedesk_platform::default_injector()?)));
        let (capturer, injector) = match backends {
            Ok(b) => b,
            Err(e) => {
                host::reject(ch, &format!("Screen sharing is not available on this computer: {e}")).await;
                self.toast(format!("Could not share the screen: {e}"), true);
                self.0.busy.store(false, Ordering::SeqCst);
                return;
            }
        };
        let (stop_tx, stop_rx) = watch::channel(false);
        self.0.state.lock().unwrap().host_stop = Some(stop_tx);
        let label = device_label(&peer);
        let shown = label.clone();
        self.ui(move |ui| {
            ui.set_hosting_peer(shown.into());
            ui.set_hosting_active(true);
        });
        let clipboard = self.clipboard();
        let result = host::serve(ch, capturer, injector, clipboard, HostSettings::default(), stop_rx).await;
        self.0.state.lock().unwrap().host_stop = None;
        self.0.busy.store(false, Ordering::SeqCst);
        self.ui(|ui| ui.set_hosting_active(false));
        match result {
            Ok(_) => self.toast(format!("Session with {label} ended"), false),
            Err(e) => self.toast(format!("Session with {label} ended: {e}"), true),
        }
    }

    /// Shows the accept/decline prompt and waits for an answer.
    async fn prompt(&self, peer: &DeviceCert, same_account: bool) -> bool {
        let (tx, rx) = oneshot::channel();
        self.0.state.lock().unwrap().incoming_answer = Some(tx);
        let (user, device, fp) = (peer.username.clone(), peer.device_name.clone(), fingerprint(&peer.identity_pk));
        self.ui(move |ui| {
            ui.set_incoming_user_letter(letter(&user).into());
            ui.set_incoming_user(user.into());
            ui.set_incoming_device(device.into());
            ui.set_incoming_fingerprint(fp.into());
            ui.set_incoming_same_account(same_account);
            ui.set_incoming_visible(true);
            bring_to_front(ui);
        });
        let answer = matches!(tokio::time::timeout(PROMPT_TIMEOUT, rx).await, Ok(Ok(true)));
        self.0.state.lock().unwrap().incoming_answer = None;
        self.ui(|ui| ui.set_incoming_visible(false));
        answer
    }

    // ------------------------------------------------------------------ viewing

    fn connect(&self, input: String) {
        let Some(device_id) = parse_device_id(&input) else {
            self.toast("Enter a valid 9-digit ID.", true);
            return;
        };
        let (conn, creds) = {
            let st = self.0.state.lock().unwrap();
            (st.conn.clone(), st.creds.clone())
        };
        let (Some(conn), Some(creds)) = (conn, creds) else {
            self.toast("Not connected to the server.", true);
            return;
        };
        if device_id == creds.device_id {
            self.toast("That is this computer's own ID.", true);
            return;
        }
        if self.0.busy.swap(true, Ordering::SeqCst) {
            self.toast("Another session is already in progress.", true);
            return;
        }
        let target = format_device_id(device_id);
        self.ui(move |ui| {
            ui.set_connect_busy(true);
            ui.set_outgoing_target(target.into());
            ui.set_outgoing_visible(true);
        });
        let this = self.clone();
        let task = self.0.rt.spawn(async move {
            let result = this.run_viewer(conn, creds, device_id).await;
            this.0.state.lock().unwrap().viewer_input = None;
            this.0.busy.store(false, Ordering::SeqCst);
            this.ui(|ui| {
                ui.set_outgoing_visible(false);
                ui.set_connect_busy(false);
                ui.set_has_frame(false);
                ui.set_remote_frame(Image::default());
                ui.set_page(Page::Home);
            });
            match result {
                Ok(SessionEnd::Closed) => this.toast("Session ended", false),
                Ok(SessionEnd::Rejected(reason)) => this.toast(reason, true),
                Err(e) => this.toast(e.to_string(), true),
            }
        });
        self.0.state.lock().unwrap().viewer_task = Some(task);
    }

    async fn run_viewer(
        &self,
        conn: Arc<ServerConn>,
        creds: DeviceCredentials,
        device_id: u64,
    ) -> somedesk_client::Result<SessionEnd> {
        let (ch, host_info) = session::connect(&conn, &creds, device_id).await?;
        let peer = ch.peer.clone();
        let name = host_info.name.clone();
        self.ui(move |ui| ui.set_outgoing_target(name.into()));

        let (input_tx, input_rx) = mpsc::unbounded_channel();
        self.0.state.lock().unwrap().viewer_input = Some(input_tx);

        let this = self.clone();
        let peer_label = device_label(&peer);
        let peer_id = format_device_id(device_id);
        let fps = Arc::new(Mutex::new((Instant::now(), 0u32)));
        let sink: viewer::EventSink = Arc::new(move |ev| match ev {
            ViewerEvent::Accepted => {
                let (label, id) = (peer_label.clone(), peer_id.clone());
                this.ui(move |ui| {
                    ui.set_session_peer(label.into());
                    ui.set_session_peer_id(id.into());
                    ui.set_has_frame(false);
                    ui.set_latency("–".into());
                    ui.set_fps("–".into());
                    ui.set_outgoing_visible(false);
                    ui.set_page(Page::Session);
                });
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
        viewer::run(ch, sink, input_rx, self.clipboard()).await
    }

    /// The system clipboard, if clipboard sharing is enabled and the clipboard is available.
    fn clipboard(&self) -> Option<Box<dyn somedesk_platform::Clipboard>> {
        if !self.0.state.lock().unwrap().settings.share_clipboard {
            return None;
        }
        somedesk_platform::default_clipboard()
            .inspect_err(|e| tracing::warn!("clipboard sharing unavailable: {e:#}"))
            .ok()
    }

    fn show_frame(&self, frame: RgbFrame) {
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

    fn send_input(&self, msg: SessionMsg) {
        if let Some(tx) = &self.0.state.lock().unwrap().viewer_input {
            let _ = tx.send(msg);
        }
    }

    /// Maps a position in the viewport to normalized remote coordinates, accounting for the
    /// letterboxing of `image-fit: contain`.
    fn pointer_moved(&self, x: f32, y: f32, w: f32, h: f32) {
        let (fw, fh) = (self.0.frame_w.load(Ordering::Relaxed) as f32, self.0.frame_h.load(Ordering::Relaxed) as f32);
        if let Some((nx, ny)) = map_pointer(x, y, w, h, fw, fh) {
            self.send_input(SessionMsg::PointerMove { x: nx, y: ny });
        }
    }

    fn scroll(&self, dx: f32, dy: f32) {
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
    use super::map_pointer;

    #[test]
    fn pointer_mapping_handles_letterboxing() {
        // 1600x900 viewport showing a 1024x768 frame: 1200x900 image with 200px bars left/right.
        assert_eq!(map_pointer(200.0, 0.0, 1600.0, 900.0, 1024.0, 768.0), Some((0, 0)));
        assert_eq!(map_pointer(1400.0, 900.0, 1600.0, 900.0, 1024.0, 768.0), Some((65535, 65535)));
        assert_eq!(map_pointer(800.0, 450.0, 1600.0, 900.0, 1024.0, 768.0), Some((32768, 32768)));
        assert_eq!(map_pointer(100.0, 450.0, 1600.0, 900.0, 1024.0, 768.0), None);
        assert_eq!(map_pointer(10.0, 10.0, 100.0, 100.0, 0.0, 0.0), None);
    }
}
