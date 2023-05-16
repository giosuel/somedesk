//! Test harness: starts a real server on a throwaway PostgreSQL database.

use rand::Rng;
use somedesk_client::credentials::DeviceCredentials;
use somedesk_client::server::ServerConn;
use somedesk_platform::{Capturer, Clipboard, Frame, Injector};
use somedesk_proto::control::Event;
use somedesk_proto::session::SessionMsg;
use somedesk_server::{RunningServer, ServerConfig};
use sqlx::{Connection, PgConnection};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub struct TestServer {
    pub addr: String,
    pub fingerprint: [u8; 32],
    pub db_url: String,
    /// Every byte forwarded by the relay.
    pub relay_bytes: Arc<Mutex<Vec<u8>>>,
    admin_url: String,
    db_name: String,
    server: Option<RunningServer>,
}

pub fn admin_url() -> Option<String> {
    let url = std::env::var("SOMEDESK_TEST_DATABASE_URL").ok();
    if url.is_none() {
        eprintln!("SOMEDESK_TEST_DATABASE_URL not set, skipping database test");
    }
    url
}

impl TestServer {
    pub async fn start() -> Option<Self> {
        Self::start_with(true).await
    }

    /// A server that only lets in its accounts' devices, when `open` is false.
    pub async fn start_with(open: bool) -> Option<Self> {
        Self::start_configured(open, somedesk_server::Registration::Open, somedesk_server::Limits::default()).await
    }

    /// A server with the given registration mode and limits.
    pub async fn start_configured(
        open: bool,
        registration: somedesk_server::Registration,
        limits: somedesk_server::Limits,
    ) -> Option<Self> {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()))
            .with_test_writer()
            .try_init();
        let admin_url = admin_url()?;
        let db_name = format!("somedesk_test_{}", hex::encode(rand::thread_rng().gen::<[u8; 6]>()));
        let mut admin = PgConnection::connect(&admin_url).await.expect("connect to PostgreSQL");
        sqlx::query(&format!("CREATE DATABASE {db_name}")).execute(&mut admin).await.unwrap();
        admin.close().await.unwrap();
        let db_url = format!("{}/{}", admin_url.rsplit_once('/').unwrap().0, db_name);

        let relay_bytes = Arc::new(Mutex::new(Vec::new()));
        let tap_bytes = relay_bytes.clone();
        let server = somedesk_server::start(ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            database_url: db_url.clone(),
            data_dir: std::env::temp_dir().join(&db_name),
            open,
            registration,
            limits,
            relay_tap: Some(Arc::new(move |b: &[u8]| tap_bytes.lock().unwrap().extend_from_slice(b))),
        })
        .await
        .expect("server starts");
        Some(Self {
            addr: server.local_addr.to_string(),
            fingerprint: server.cert_fingerprint,
            db_url,
            relay_bytes,
            admin_url,
            db_name,
            server: Some(server),
        })
    }

    pub async fn connect(&self) -> (Arc<ServerConn>, mpsc::Receiver<Event>) {
        ServerConn::connect(&self.addr, Some(self.fingerprint)).await.expect("connect to server")
    }

    /// Registers `user`, logs in, sets up a device and signs it in to the account.
    pub async fn signup(&self, user: &str, password: &str, device: &str) -> Device {
        let (conn, events) = self.connect().await;
        conn.register(user, password).await.expect("register");
        let login = conn.login(user, password).await.expect("login");
        let mut creds = conn.create_device(&self.addr, device).await.expect("create device");
        conn.attach(&login, &mut creds).await.expect("sign in");
        Device { conn, events, creds }
    }

    /// Adds another device to an existing account.
    pub async fn add_device(&self, user: &str, password: &str, device: &str) -> Device {
        let (conn, events) = self.connect().await;
        let login = conn.login(user, password).await.expect("login");
        let mut creds = conn.create_device(&self.addr, device).await.expect("create device");
        conn.attach(&login, &mut creds).await.expect("sign in");
        Device { conn, events, creds }
    }

    /// Sets up a device without an account.
    pub async fn anonymous(&self, device: &str) -> Device {
        let (conn, events) = self.connect().await;
        let creds = conn.create_device(&self.addr, device).await.expect("create device");
        Device { conn, events, creds }
    }

    pub fn relay_contains(&self, needle: &[u8]) -> bool {
        self.relay_bytes.lock().unwrap().windows(needle.len()).any(|w| w == needle)
    }

    pub async fn stop(mut self) {
        if let Some(s) = self.server.take() {
            s.shutdown().await;
        }
        if let Ok(mut admin) = PgConnection::connect(&self.admin_url).await {
            let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.db_name))
                .execute(&mut admin)
                .await;
        }
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join(&self.db_name));
    }
}

pub struct Device {
    pub conn: Arc<ServerConn>,
    pub events: mpsc::Receiver<Event>,
    pub creds: DeviceCredentials,
}

/// A capturer producing solid-color frames; the color can be changed while running.
pub struct FakeCapturer {
    pub width: u32,
    pub height: u32,
    pub bgra: Arc<Mutex<[u8; 4]>>,
}

impl Device {
    /// Makes this device refuse direct connections, so its sessions use the relay.
    pub async fn relay_only(self) -> Self {
        self.conn.set_allow_direct(false);
        self.conn.announce_candidates().await.expect("announce");
        self
    }
}

impl Capturer for FakeCapturer {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        let px = *self.bgra.lock().unwrap();
        let data = px.repeat((self.width * self.height) as usize);
        Ok(Frame { width: self.width, height: self.height, stride: self.width as usize * 4, data, view: None })
    }
}

/// An injector that records everything it is asked to do.
#[derive(Clone, Default)]
pub struct RecordingInjector {
    pub log: Arc<Mutex<Vec<SessionMsg>>>,
    pub size: (u32, u32),
}

impl Injector for RecordingInjector {
    fn screen_size(&mut self) -> anyhow::Result<(u32, u32)> {
        Ok(self.size)
    }
    fn pointer_move(&mut self, x: u32, y: u32) -> anyhow::Result<()> {
        self.log.lock().unwrap().push(SessionMsg::PointerMove { x: x as u16, y: y as u16 });
        Ok(())
    }
    fn button(&mut self, button: u8, down: bool) -> anyhow::Result<()> {
        self.log.lock().unwrap().push(SessionMsg::PointerButton { button, down });
        Ok(())
    }
    fn scroll(&mut self, dx: i32, dy: i32) -> anyhow::Result<()> {
        self.log.lock().unwrap().push(SessionMsg::Scroll { dx: dx as i16, dy: dy as i16 });
        Ok(())
    }
    fn key(&mut self, keysym: u32, down: bool) -> anyhow::Result<()> {
        self.log.lock().unwrap().push(SessionMsg::Key { keysym, down });
        Ok(())
    }
}

/// An in-memory clipboard. Clones share the same contents.
#[derive(Clone, Default)]
pub struct FakeClipboard {
    state: Arc<Mutex<FakeClipboardState>>,
}

#[derive(Default)]
struct FakeClipboardState {
    text: Option<String>,
    /// Every text written by the code under test, oldest first.
    written: Vec<String>,
}

impl FakeClipboard {
    pub fn with_text(text: &str) -> Self {
        let c = Self::default();
        c.set(text);
        c
    }

    /// Simulates the local user copying something.
    pub fn set(&self, text: &str) {
        self.state.lock().unwrap().text = Some(text.to_owned());
    }

    pub fn get(&self) -> Option<String> {
        self.state.lock().unwrap().text.clone()
    }

    /// How many times the code under test wrote to this clipboard.
    pub fn writes(&self) -> usize {
        self.state.lock().unwrap().written.len()
    }

    pub fn history(&self) -> Vec<String> {
        self.state.lock().unwrap().written.clone()
    }

    pub async fn wait_for(&self, text: &str, timeout: std::time::Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        while self.get().as_deref() != Some(text) {
            assert!(tokio::time::Instant::now() < deadline, "clipboard never became {text:?}, is {:?}", self.get());
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
}

impl Clipboard for FakeClipboard {
    fn get_text(&mut self) -> anyhow::Result<Option<String>> {
        Ok(self.get())
    }
    fn set_text(&mut self, text: &str) -> anyhow::Result<()> {
        let mut s = self.state.lock().unwrap();
        s.text = Some(text.to_owned());
        s.written.push(text.to_owned());
        Ok(())
    }
}

/// A fake screen of two side-by-side monitors: "LEFT" (id 1, 400x300 at 0,0, blue) and "RIGHT"
/// (id 2, 200x300 at 400,0, red).
#[derive(Default)]
pub struct TwoMonitorCapturer {
    pub selected: Option<u32>,
}

impl TwoMonitorCapturer {
    pub const LEFT: u32 = 1;
    pub const RIGHT: u32 = 2;
}

impl Capturer for TwoMonitorCapturer {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        let (w, h, px, view): (u32, u32, [u8; 4], _) = match self.selected {
            None => (600, 300, [0x80, 0x80, 0x80, 0xFF], None),
            Some(Self::LEFT) => (400, 300, [0xE0, 0x40, 0x20, 0xFF], Some((0, 0, 400, 300))),
            Some(_) => (200, 300, [0x20, 0x40, 0xE0, 0xFF], Some((400, 0, 200, 300))),
        };
        Ok(Frame { width: w, height: h, stride: w as usize * 4, data: px.repeat((w * h) as usize), view })
    }

    fn monitors(&mut self) -> anyhow::Result<Vec<somedesk_platform::Monitor>> {
        let m = |id, name: &str, x, width| somedesk_platform::Monitor {
            id,
            name: name.into(),
            x,
            y: 0,
            width,
            height: 300,
            primary: id == Self::LEFT,
        };
        Ok(vec![m(Self::LEFT, "LEFT", 0, 400), m(Self::RIGHT, "RIGHT", 400, 200)])
    }

    fn select_monitor(&mut self, id: Option<u32>) -> anyhow::Result<()> {
        self.selected = id;
        Ok(())
    }
}
