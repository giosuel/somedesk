//! Glue between the Slint UI and the client core.
//!
//! UI callbacks run on the UI thread and hand work to the tokio runtime; async tasks push state
//! back with `upgrade_in_event_loop`. Locks are never held across an `.await`.
//!
//! * [`setup`] — the first start, and coming online under this installation's ID.
//! * [`account`] — the optional account: signing in, two-factor authentication, confirming
//!   actions with the password.
//! * [`book`] — the address book and saved passwords.
//! * [`hosting`] — who gets into this computer, and setting up unattended access.
//! * [`viewing`] — connecting to another computer, with or without its password.
//! * [`orgs`] — organisations and their admin.
//! * [`media`] — file transfers, frames and input during a session.

mod account;
mod book;
mod hosting;
mod media;
mod orgs;
mod setup;
mod viewing;

#[cfg_attr(not(target_os = "android"), allow(unused_imports))]
pub(crate) use media::set_download_dir;

use crate::keymap::keysym_for;
use crate::{AppWindow, DeviceItem, MonitorChoice, Page, RecentItem, TransferItem};
use serde::{Deserialize, Serialize};
use slint::{ComponentHandle, Image, ModelRc, Rgb8Pixel, SharedPixelBuffer, VecModel};
use somedesk_client::access::{PendingSetup, Unattended};
use somedesk_client::addressbook::AddressBook;
use somedesk_client::credentials::DeviceCredentials;
use somedesk_client::files::{AcceptPolicy, Direction, FileTransfers, TransferEvent};
use somedesk_client::org::Admin;
use somedesk_client::server::{LoggedIn, ServerConn};
use somedesk_client::trust::TrustStore;
use somedesk_codec::RgbFrame;
use somedesk_crypto::keys::fingerprint;
use somedesk_proto::control::{DeviceIdentity, Event, OrgInfo};
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
/// What the phone's hidden keyboard input starts with, so Backspace always has something to
/// delete (see `soft_input`).
const SOFT_PAD: &str = "                ";

#[derive(Serialize, Deserialize)]
struct Settings {
    /// Devices signed in to the same account may connect without asking (only while the
    /// account has two-factor authentication).
    #[serde(default, alias = "auto_accept_own_devices")]
    own_devices_access: bool,
    #[serde(default = "yes")]
    share_clipboard: bool,
    #[serde(default)]
    last_server: String,
    /// Let sessions connect directly between the two computers (this shares IP addresses with
    /// the peer); otherwise everything goes through the relay.
    #[serde(default = "yes")]
    allow_direct: bool,
    /// Closing the window leaves the app running in the tray.
    #[serde(default = "yes")]
    run_in_background: bool,
    /// Start (in the background) when the user logs in.
    #[serde(default)]
    start_at_login: bool,
    /// Computers this device connected to recently, newest first.
    #[serde(default)]
    recent: Vec<Recent>,
    /// The welcome tour was finished or skipped.
    #[serde(default)]
    tour_done: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct Recent {
    device_id: u64,
    label: String,
}

/// How many recent connections the home screen offers.
const MAX_RECENT: usize = 4;

impl Default for Settings {
    fn default() -> Self {
        Self {
            own_devices_access: false,
            share_clipboard: true,
            allow_direct: true,
            run_in_background: true,
            start_at_login: false,
            last_server: String::new(),
            recent: Vec::new(),
            tour_done: false,
        }
    }
}

/// "Good morning, bob" etc., by local time.
fn greeting(user: &str) -> String {
    use chrono::Timelike;
    let part = match chrono::Local::now().hour() {
        5..12 => "Good morning",
        12..18 => "Good afternoon",
        _ => "Good evening",
    };
    if user.is_empty() {
        part.to_owned()
    } else {
        format!("{part}, {user}")
    }
}

fn yes() -> bool {
    true
}

/// Something to do once the user confirmed their password (and code): it gets the connection
/// the account is logged in on, and the login (with the identity key).
type Unlocked = Box<dyn FnOnce(Controller, Arc<ServerConn>, Arc<LoggedIn>) + Send>;

#[derive(Default)]
struct State {
    settings: Settings,
    creds: Option<DeviceCredentials>,
    conn: Option<Arc<ServerConn>>,
    online_task: Option<JoinHandle<()>>,
    viewer_task: Option<JoinHandle<()>>,
    viewer_input: Option<mpsc::UnboundedSender<SessionMsg>>,
    /// Keys and mouse buttons held down on the remote computer, to let go of when the viewer
    /// window loses the focus (their releases go to another window then).
    held_keys: std::collections::HashSet<u32>,
    held_buttons: std::collections::HashSet<u8>,
    scroll_acc: (f32, f32),
    /// The phone's hidden keyboard input as of the last edit.
    soft_text: String,
    host_stop: Option<watch::Sender<bool>>,
    /// Whether the person at this computer accepted.
    incoming_answer: Option<oneshot::Sender<bool>>,
    /// Remembered device and account keys; loaded at start.
    trust: Option<TrustStore>,
    /// The address book; loaded at start.
    book: Option<AddressBook>,
    /// Whether the system has a keychain for passwords "on this device".
    keychain: bool,
    /// Unattended access to this computer (its password and authenticator).
    unattended: Option<Unattended>,
    /// The account has two-factor authentication.
    account_totp: bool,
    /// The account's login on the current server connection, once the user confirmed their
    /// password. Holds the identity key; dropped on sign-out and when the connection changes.
    login: Option<(Arc<ServerConn>, Arc<LoggedIn>)>,
    /// What to do after the account dialog confirms the password.
    after_unlock: Option<Unlocked>,
    /// The first start on a server that only lets in its accounts' devices: the server and the
    /// device's name, waiting for the user to sign in.
    setup_pending: Option<(String, String)>,
    /// Setting up an authenticator: unattended access (with its password record) or the
    /// account's second factor.
    twofa: Option<TwoFactorSetup>,
    /// The unattended-access dialog's target device, and a password found for it.
    pw_target: Option<(u64, Option<String>)>,
    /// The address-book entry being edited (None: a new one).
    entry_editing: Option<u64>,
    /// A host whose identity changed: its ID and identity, until the user decides; and whether
    /// the connection was to use a password.
    identity_changed: Option<(u64, DeviceIdentity, bool)>,
    /// The organisations of the account, the selected one, and the ones this device can sign
    /// for (their key unlocked).
    orgs: Vec<OrgInfo>,
    org_selected: Option<u64>,
    org_admins: std::collections::HashMap<u64, Admin>,
    toast_generation: u64,
    /// Keeps copied text available on X11, where the copying app must serve the clipboard.
    copy_clipboard: Option<Box<dyn somedesk_platform::Clipboard>>,
    /// File transfers of the running session.
    files: Option<FileTransfers>,
    transfers: Vec<TransferRow>,
    /// Files the peer offered that we have not answered yet, oldest first.
    file_offers: std::collections::VecDeque<(u32, String, u64)>,
    /// The password and where to keep it, for a connection made with one, until it succeeds.
    password_to_save: Option<(u64, String, crate::SaveIn)>,
}

enum TwoFactorSetup {
    Unattended(Option<PendingSetup>),
    Account,
}

struct TransferRow {
    id: u32,
    upload: bool,
    name: String,
    size: u64,
    done: u64,
    /// 0 waiting, 1 running, 2 done, 3 failed (as in the UI).
    state: i32,
    detail: String,
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

/// This computer's name, as a default device name.
fn hostname() -> String {
    #[cfg(target_os = "android")]
    if let Some(model) = std::process::Command::new("getprop")
        .arg("ro.product.model")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|m| !m.is_empty())
    {
        return model;
    }
    std::env::var("COMPUTERNAME") // Windows
        .ok()
        .or_else(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .or_else(|| {
            // macOS (and anything else with a hostname command).
            std::process::Command::new("hostname")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        })
        .map(|s| s.trim().trim_end_matches(".local").to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "my-computer".into())
}

/// Shows, un-minimizes and raises the window, so an incoming request or a session someone
/// started without asking is never hidden.
#[cfg(not(target_os = "android"))]
fn bring_to_front(ui: &AppWindow) {
    use slint::winit_030::WinitWindowAccessor;
    let _ = ui.show();
    ui.window().set_minimized(false);
    ui.window().with_winit_window(|w| {
        w.focus_window();
        w.request_user_attention(Some(slint::winit_030::winit::window::UserAttentionType::Critical));
    });
}

#[cfg(target_os = "android")]
fn bring_to_front(_: &AppWindow) {}

/// "Jane · laptop (123 456 789)" or "laptop (123 456 789)" for a device without an account.
fn device_label(device_id: u64, identity: &DeviceIdentity) -> String {
    match identity.username() {
        Some(user) => format!("{user} · {}", identity.name),
        None => format!("{} ({})", identity.name, format_device_id(device_id)),
    }
}

/// A QR code as an image, for authenticator apps.
fn qr_image(text: &str) -> Image {
    let Ok(code) = qrcode::QrCode::new(text.as_bytes()) else { return Image::default() };
    let modules = code.width();
    let scale = 4;
    let quiet = 2;
    let side = (modules + 2 * quiet) * scale;
    let colors = code.to_colors();
    let mut buffer = SharedPixelBuffer::<Rgb8Pixel>::new(side as u32, side as u32);
    for (i, px) in buffer.make_mut_slice().iter_mut().enumerate() {
        let (x, y) = (i % side / scale, i / side / scale);
        let dark = x >= quiet
            && y >= quiet
            && x < modules + quiet
            && y < modules + quiet
            && colors[(y - quiet) * modules + (x - quiet)] == qrcode::Color::Dark;
        let v = if dark { 0 } else { 255 };
        *px = Rgb8Pixel { r: v, g: v, b: v };
    }
    Image::from_rgb8(buffer)
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

    fn trust_path(&self) -> PathBuf {
        self.0.dir.join("known_peers.json")
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

    /// Stores the device credentials (after they changed).
    fn save_creds(&self) {
        if let Some(creds) = self.0.state.lock().unwrap().creds.clone() {
            if let Err(e) = creds.save(&self.creds_path()) {
                tracing::error!("cannot store credentials: {e:#}");
            }
        }
    }

    /// Changes the trust store and saves it.
    fn with_trust(&self, f: impl FnOnce(&mut TrustStore)) {
        let mut st = self.0.state.lock().unwrap();
        let Some(t) = st.trust.as_mut() else { return };
        f(t);
        if let Err(e) = t.save() {
            tracing::error!("cannot save known devices: {e}");
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

    /// The server connection, while online.
    fn conn(&self) -> Option<Arc<ServerConn>> {
        self.0.state.lock().unwrap().conn.clone()
    }

    pub fn start(&self) {
        let settings: Settings =
            std::fs::read(self.settings_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let server = self
            .0
            .default_server
            .clone()
            .or_else(|| (!settings.last_server.is_empty()).then(|| settings.last_server.clone()))
            // A phone has no server of its own to default to.
            .unwrap_or_else(|| if cfg!(target_os = "android") { String::new() } else { "localhost".into() });
        let (share_clipboard, allow_direct, own_devices, background, at_login) = (
            settings.share_clipboard,
            settings.allow_direct,
            settings.own_devices_access,
            settings.run_in_background,
            settings.start_at_login,
        );
        let trust_path = self.trust_path();
        let trust = TrustStore::load(&trust_path).unwrap_or_else(|e| {
            // Keep the unreadable file for inspection rather than overwriting it.
            let aside = trust_path.with_extension("json.broken");
            tracing::error!("cannot read known devices ({e}); moving it to {}", aside.display());
            let _ = std::fs::rename(&trust_path, aside);
            TrustStore::empty(&trust_path)
        });
        let unattended = Unattended::load(&self.0.dir.join("unattended.json"))
            .map_err(|e| tracing::error!("cannot read the unattended-access setup: {e}"))
            .ok();
        let unattended_on = unattended.as_ref().is_some_and(|u| u.enabled());
        {
            let mut st = self.0.state.lock().unwrap();
            st.settings = settings;
            st.trust = Some(trust);
            st.unattended = unattended;
        }
        self.load_book();
        self.publish_recents();
        self.ui(move |ui| {
            ui.set_setup_server(server.into());
            ui.set_setup_name(hostname().into());
            ui.set_share_clipboard(share_clipboard);
            ui.set_allow_direct(allow_direct);
            ui.set_own_devices(own_devices);
            ui.set_run_in_background(background);
            ui.set_start_at_login(at_login);
            ui.set_unattended(unattended_on);
        });
        match DeviceCredentials::load(&self.creds_path()) {
            Ok(Some(creds)) => self.go_online(creds),
            Ok(None) => self.ui(|ui| ui.set_page(Page::Setup)),
            Err(e) => {
                tracing::error!("cannot read stored credentials: {e:#}");
                self.ui(|ui| ui.set_page(Page::Setup));
            }
        }
    }

    pub fn shutdown(&self) {
        let mut st = self.0.state.lock().unwrap();
        if let Some(stop) = st.host_stop.take() {
            let _ = stop.send(true);
        }
        st.viewer_input = None;
        st.login = None;
        if let Some(conn) = st.conn.take() {
            conn.close();
        }
    }

    /// Whether closing the window should leave the app running (in the tray).
    #[cfg(not(target_os = "android"))]
    pub fn keep_running_in_background(&self) -> bool {
        somedesk_platform::can_share_screen() && self.0.state.lock().unwrap().settings.run_in_background
    }

    fn install_callbacks(&self, ui: &AppWindow) {
        self.install_setup_callbacks(ui);
        self.install_account_callbacks(ui);
        self.install_book_callbacks(ui);
        self.install_hosting_callbacks(ui);
        self.install_viewing_callbacks(ui);
        self.install_org_callbacks(ui);

        let c = self.clone();
        ui.on_share_clipboard_changed(move |v| {
            c.0.state.lock().unwrap().settings.share_clipboard = v;
            c.save_settings();
        });
        let c = self.clone();
        ui.on_allow_direct_changed(move |v| {
            let conn = {
                let mut st = c.0.state.lock().unwrap();
                st.settings.allow_direct = v;
                st.conn.clone()
            };
            c.save_settings();
            if let Some(conn) = conn {
                conn.set_allow_direct(v);
                c.0.rt.spawn(async move {
                    if let Err(e) = conn.announce_candidates().await {
                        tracing::warn!("cannot update direct-connection settings: {e}");
                    }
                });
            }
        });
        let c = self.clone();
        ui.on_run_in_background_changed(move |v| {
            c.0.state.lock().unwrap().settings.run_in_background = v;
            c.save_settings();
        });
        let c = self.clone();
        ui.on_start_at_login_changed(move |v| {
            c.0.state.lock().unwrap().settings.start_at_login = v;
            c.save_settings();
            if let Err(e) = crate::background::set_autostart(v) {
                c.toast(format!("Could not change this: {e}"), true);
            }
        });
        let c = self.clone();
        ui.on_copy_id(move || {
            let id = c.0.ui.upgrade().map(|ui| ui.get_my_id().replace(' ', "")).unwrap_or_default();
            if !id.is_empty() && c.copy_text(&id) {
                c.toast("ID copied", false);
            }
        });
        let c = self.clone();
        ui.on_select_monitor(move |id| {
            c.send_input(SessionMsg::SelectMonitor { id: (id >= 0).then_some(id as u32) });
        });
        let c = self.clone();
        ui.on_send_files(move || c.pick_and_send_files());
        let c = self.clone();
        ui.on_cancel_transfer(move |id, upload| {
            let files = c.0.state.lock().unwrap().files.clone();
            if let Some(f) = files {
                f.cancel(id as u32, if upload { Direction::Upload } else { Direction::Download });
            }
        });
        let c = self.clone();
        ui.on_clear_transfers(move || {
            c.0.state.lock().unwrap().transfers.retain(|t| t.state <= 1);
            c.publish_transfers();
        });
        let c = self.clone();
        ui.on_file_offer_answer(move |ok| c.answer_file_offer(ok));
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
        ui.on_secret_copy(move || {
            let text = c.0.ui.upgrade().map(|ui| ui.get_secret_text().to_string()).unwrap_or_default();
            if c.copy_text(&text) {
                c.ui(|ui| ui.set_secret_copied(true));
            }
        });
        let c = self.clone();
        ui.on_secret_done(move || {
            c.ui(|ui| {
                ui.set_secret_visible(false);
                ui.set_secret_text("".into());
            });
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
        let c = self.clone();
        ui.on_release_input(move || c.release_input());
        let c = self.clone();
        ui.on_soft_input(move |text, ctrl, alt| c.soft_input(&text, ctrl, alt));
        let c = self.clone();
        ui.on_soft_key(move |text, ctrl, alt| c.type_keys(&text, ctrl, alt));
        let c = self.clone();
        ui.on_tour_done(move || {
            c.0.state.lock().unwrap().settings.tour_done = true;
            c.save_settings();
        });
    }

    /// Puts `text` on the system clipboard (kept alive for X11, which serves it from this app).
    fn copy_text(&self, text: &str) -> bool {
        let result = somedesk_platform::default_clipboard().and_then(|mut c| {
            c.set_text(text)?;
            Ok(c)
        });
        match result {
            Ok(c) => {
                self.0.state.lock().unwrap().copy_clipboard = Some(c);
                true
            }
            Err(e) => {
                self.toast(format!("Could not copy: {e}"), true);
                false
            }
        }
    }

    fn copy_recovery_key(&self) {
        let Some(ui) = self.0.ui.upgrade() else {
            return;
        };
        let key = ui.get_recovery_key().replace('\n', "-");
        if self.copy_text(&key) {
            ui.set_recovery_key_copied(true);
        }
    }

    fn remember_recent(&self, device_id: u64, label: String) {
        {
            let mut st = self.0.state.lock().unwrap();
            let recent = &mut st.settings.recent;
            recent.retain(|r| r.device_id != device_id);
            recent.insert(0, Recent { device_id, label });
            recent.truncate(MAX_RECENT);
        }
        self.save_settings();
        self.publish_recents();
    }

    fn publish_recents(&self) {
        let items: Vec<RecentItem> = self
            .0
            .state
            .lock()
            .unwrap()
            .settings
            .recent
            .iter()
            .map(|r| RecentItem { id: r.device_id.to_string().into(), label: r.label.clone().into() })
            .collect();
        self.ui(move |ui| ui.set_recents(ModelRc::new(VecModel::from(items))));
    }

    // ------------------------------------------------------------------ online

    async fn online_loop(self) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let Some(mut creds) = self.0.state.lock().unwrap().creds.clone() else { return };
            match ServerConn::connect(&creds.server, Some(creds.server_fingerprint)).await {
                Ok((conn, mut events)) => {
                    conn.set_allow_direct(self.0.state.lock().unwrap().settings.allow_direct);
                    match conn.authenticate(&mut creds).await {
                        Ok(_) => {
                            backoff = Duration::from_secs(1);
                            {
                                let mut st = self.0.state.lock().unwrap();
                                st.conn = Some(conn.clone());
                                // A login belongs to its connection.
                                st.login = None;
                                st.creds = Some(creds.clone());
                            }
                            self.save_creds();
                            self.publish_identity();
                            self.ui(|ui| {
                                ui.set_online(true);
                                ui.set_status_text("Online".into());
                            });
                            self.after_online(&conn);
                            loop {
                                tokio::select! {
                                    ev = events.recv() => match ev {
                                        Some(Event::IncomingSession { session_id, from, candidates }) => {
                                            let this = self.clone();
                                            let conn = conn.clone();
                                            tokio::spawn(async move { this.handle_incoming(conn, session_id, from, candidates).await });
                                        }
                                        Some(Event::DevicePresence { .. }) => self.refresh_devices(),
                                        Some(Event::SignedOut) => self.signed_out_elsewhere(),
                                        Some(Event::AccountChanged) => self.refresh_account(),
                                        Some(Event::OrgPolicyChanged { .. }) => self.refresh_orgs(),
                                        None => break,
                                    },
                                    reason = conn.closed() => {
                                        tracing::warn!("lost connection to server: {reason}");
                                        break;
                                    }
                                }
                            }
                            let mut st = self.0.state.lock().unwrap();
                            st.conn = None;
                            st.login = None;
                        }
                        Err(e) => {
                            tracing::warn!("cannot come online: {e}");
                            if e.code() == Some(somedesk_proto::control::ErrorCode::Forbidden) {
                                self.toast(format!("{e}. Sign in to an account of this server."), true);
                            }
                        }
                    }
                }
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

    /// Everything to refresh once online: the account's devices, its 2FA state and address
    /// book, and its organisations.
    fn after_online(&self, conn: &Arc<ServerConn>) {
        let signed_in = self.0.state.lock().unwrap().creds.as_ref().is_some_and(|c| c.account.is_some());
        if signed_in {
            self.refresh_devices();
            self.refresh_account();
            self.sync_book();
            self.refresh_orgs();
        }
        let _ = conn;
    }

    fn refresh_devices(&self) {
        let (conn, my_id) = {
            let st = self.0.state.lock().unwrap();
            (st.conn.clone(), st.creds.as_ref().map(|c| c.device_id))
        };
        let (Some(conn), Some(my_id)) = (conn, my_id) else { return };
        let this = self.clone();
        self.0.rt.spawn(async move {
            match conn.list_devices().await {
                Ok(devices) => {
                    let mut items: Vec<DeviceItem> = devices
                        .iter()
                        .map(|d| DeviceItem {
                            id: d.device_id.to_string().into(),
                            id_label: format_device_id(d.device_id).into(),
                            name: d.identity.name.clone().into(),
                            online: d.online,
                            is_self: d.device_id == my_id,
                        })
                        .collect();
                    items.sort_by_key(|d| (!d.is_self, !d.online));
                    this.ui(move |ui| ui.set_devices(ModelRc::new(VecModel::from(items))));
                }
                Err(e) => tracing::debug!("cannot list devices: {e}"),
            }
        });
    }
}
