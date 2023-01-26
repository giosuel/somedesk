//! Full remote-control sessions through the relay.

use somedesk_client::files::{AcceptPolicy, Direction, FileTransfers, TransferEvent};
use somedesk_client::host::{self, HostSettings};
use somedesk_client::session;
use somedesk_client::trust::PeerStatus;
use somedesk_client::viewer::{self, SessionEnd, ViewerEvent};
use somedesk_client::SessionExtras;
use somedesk_codec::RgbFrame;
use somedesk_e2e_tests::{Device, FakeCapturer, FakeClipboard, RecordingInjector, TestServer};
use somedesk_proto::control::Event;
use somedesk_proto::session::{SessionMsg, POINTER_MAX};
use sqlx::{Connection, PgConnection};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

const T: Duration = Duration::from_secs(10);

fn clipboard_extras(clip: &FakeClipboard) -> SessionExtras {
    SessionExtras { clipboard: Some(Box::new(clip.clone())), ..Default::default() }
}

struct ViewerSide {
    input: mpsc::UnboundedSender<SessionMsg>,
    frames: mpsc::UnboundedReceiver<RgbFrame>,
    accepted: mpsc::UnboundedReceiver<()>,
    task: tokio::task::JoinHandle<somedesk_client::Result<SessionEnd>>,
}

async fn start_viewer(viewer: &Device, host_id: u64) -> ViewerSide {
    start_viewer_with(viewer, host_id, SessionExtras::default()).await
}

async fn start_viewer_with(viewer: &Device, host_id: u64, extras: SessionExtras) -> ViewerSide {
    let (ch, host_info) = session::connect(&viewer.conn, &viewer.creds, host_id).await.expect("viewer handshake");
    assert_eq!(ch.peer.device_pk, host_info.cert.device_pk);
    let (input, input_rx) = mpsc::unbounded_channel();
    let (ftx, frames) = mpsc::unbounded_channel();
    let (atx, accepted) = mpsc::unbounded_channel();
    let sink: viewer::EventSink = Arc::new(move |ev| match ev {
        ViewerEvent::Frame(f) => {
            let _ = ftx.send(f);
        }
        ViewerEvent::Accepted => {
            let _ = atx.send(());
        }
        _ => {}
    });
    let task = tokio::spawn(viewer::run(ch, sink, input_rx, extras));
    ViewerSide { input, frames, accepted, task }
}

async fn next_incoming(host: &mut Device) -> (somedesk_proto::control::SessionId, somedesk_proto::control::DeviceInfo) {
    loop {
        match tokio::time::timeout(T, host.events.recv()).await.expect("incoming session").unwrap() {
            Event::IncomingSession { session_id, from } => return (session_id, from),
            _ => continue,
        }
    }
}

fn pixel(f: &RgbFrame, x: u32, y: u32) -> [u8; 3] {
    let i = ((y * f.width + x) * 3) as usize;
    [f.data[i], f.data[i + 1], f.data[i + 2]]
}

fn close(a: [u8; 3], b: [u8; 3]) -> bool {
    a.iter().zip(b).all(|(x, y)| x.abs_diff(y) <= 12)
}

async fn frame_matching(frames: &mut mpsc::UnboundedReceiver<RgbFrame>, rgb: [u8; 3]) -> RgbFrame {
    let deadline = tokio::time::Instant::now() + T;
    loop {
        let f = tokio::time::timeout_at(deadline, frames.recv()).await.expect("frame with expected color").unwrap();
        if close(pixel(&f, f.width / 2, f.height / 2), rgb) {
            return f;
        }
    }
}

#[tokio::test]
async fn remote_control_session_end_to_end() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let viewer_dev = ts.signup("alice-marker-user", "correct horse battery", "alice-laptop").await;
    let mut host_dev = ts.signup("bob", "correct horse battery", "bob-desktop").await;
    let host_id = host_dev.creds.device_id;

    let viewer_task = start_viewer(&viewer_dev, host_id);
    let host_side = async {
        let (sid, from) = next_incoming(&mut host_dev).await;
        assert_eq!(from.username, "alice-marker-user");
        let ch = session::accept(&host_dev.conn, &host_dev.creds, sid, &from).await.expect("host handshake");
        assert_eq!(ch.peer.username, "alice-marker-user", "host sees the verified viewer identity");
        ch
    };
    let (mut v, host_ch) = tokio::join!(viewer_task, host_side);

    // Host serves a fake 320x240 screen and records injected input.
    let color = Arc::new(Mutex::new([0x20, 0x40, 0xE0, 0xFF])); // BGRA → RGB (224, 64, 32)
    let injector = RecordingInjector { size: (1920, 1080), ..Default::default() };
    let log = injector.log.clone();
    let (stop_tx, stop_rx) = watch::channel(false);
    let cap = FakeCapturer { width: 320, height: 240, bgra: color.clone() };
    let host_task = tokio::spawn(host::serve(
        host_ch,
        Box::new(cap),
        Box::new(injector),
        SessionExtras::default(),
        HostSettings::default(),
        stop_rx,
    ));

    tokio::time::timeout(T, v.accepted.recv()).await.expect("accepted").unwrap();
    let f = frame_matching(&mut v.frames, [224, 64, 32]).await;
    assert_eq!((f.width, f.height), (320, 240));

    // Screen changes propagate.
    *color.lock().unwrap() = [0x30, 0xC0, 0x30, 0xFF];
    frame_matching(&mut v.frames, [48, 192, 48]).await;

    // Input travels to the host and pointer coordinates are scaled to its screen.
    v.input.send(SessionMsg::PointerMove { x: POINTER_MAX, y: POINTER_MAX / 2 }).unwrap();
    v.input.send(SessionMsg::PointerButton { button: 1, down: true }).unwrap();
    v.input.send(SessionMsg::PointerButton { button: 1, down: false }).unwrap();
    v.input.send(SessionMsg::Scroll { dx: 0, dy: -2 }).unwrap();
    v.input.send(SessionMsg::Key { keysym: 0x61, down: true }).unwrap();
    v.input.send(SessionMsg::Key { keysym: 0x61, down: false }).unwrap();
    // A key left pressed when the viewer disconnects must be released on the host.
    v.input.send(SessionMsg::Key { keysym: 0xffe1, down: true }).unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    drop(v.input);
    let end = tokio::time::timeout(T, v.task).await.unwrap().unwrap().unwrap();
    assert!(matches!(end, SessionEnd::Closed));
    let stats = tokio::time::timeout(T, host_task).await.unwrap().unwrap().unwrap();
    drop(stop_tx);
    assert!(stats.frames_sent >= 2);
    assert_eq!(stats.input_events, 7);

    let log = log.lock().unwrap().clone();
    assert_eq!(
        log,
        vec![
            SessionMsg::PointerMove { x: 1919, y: 539 },
            SessionMsg::PointerButton { button: 1, down: true },
            SessionMsg::PointerButton { button: 1, down: false },
            SessionMsg::Scroll { dx: 0, dy: -2 },
            SessionMsg::Key { keysym: 0x61, down: true },
            SessionMsg::Key { keysym: 0x61, down: false },
            SessionMsg::Key { keysym: 0xffe1, down: true },
            SessionMsg::Key { keysym: 0xffe1, down: false }, // released automatically
        ]
    );

    // The relay carried the whole session but never saw identifying plaintext: names and certs
    // only travel inside the encrypted handshake.
    let relayed = ts.relay_bytes.lock().unwrap().len();
    assert!(relayed > 1000, "relay forwarded {relayed} bytes");
    assert!(!ts.relay_contains(b"alice-marker-user"));
    assert!(!ts.relay_contains(b"bob-desktop"));
    assert!(!ts.relay_contains(&viewer_dev.creds.cert.signature));
    ts.stop().await;
}

#[tokio::test]
async fn host_can_reject() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let viewer_dev = ts.signup("alice", "correct horse battery", "laptop").await;
    let mut host_dev = ts.signup("bob", "correct horse battery", "desktop").await;
    let host_id = host_dev.creds.device_id;
    let reason = "SECRET-REJECT-REASON-visible-only-to-peer";
    let host_side = async {
        let (sid, from) = next_incoming(&mut host_dev).await;
        let ch = session::accept(&host_dev.conn, &host_dev.creds, sid, &from).await.unwrap();
        host::reject(ch, reason).await;
    };
    let (v, _) = tokio::join!(start_viewer(&viewer_dev, host_id), host_side);
    let end = tokio::time::timeout(T, v.task).await.unwrap().unwrap().unwrap();
    assert!(matches!(end, SessionEnd::Rejected(r) if r == reason));
    assert!(!ts.relay_contains(reason.as_bytes()));
    ts.stop().await;
}

#[tokio::test]
async fn host_stop_ends_viewer_session() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let viewer_dev = ts.signup("alice", "correct horse battery", "laptop").await;
    let mut host_dev = ts.signup("bob", "correct horse battery", "desktop").await;
    let host_id = host_dev.creds.device_id;
    let host_side = async {
        let (sid, from) = next_incoming(&mut host_dev).await;
        session::accept(&host_dev.conn, &host_dev.creds, sid, &from).await.unwrap()
    };
    let (mut v, ch) = tokio::join!(start_viewer(&viewer_dev, host_id), host_side);
    let (stop_tx, stop_rx) = watch::channel(false);
    let cap = FakeCapturer { width: 64, height: 64, bgra: Arc::new(Mutex::new([0, 0, 0, 255])) };
    let host_task = tokio::spawn(host::serve(
        ch,
        Box::new(cap),
        Box::new(RecordingInjector::default()),
        SessionExtras::default(),
        HostSettings::default(),
        stop_rx,
    ));
    tokio::time::timeout(T, v.accepted.recv()).await.unwrap().unwrap();
    tokio::time::timeout(T, v.frames.recv()).await.unwrap().unwrap();
    stop_tx.send(true).unwrap();
    host_task.await.unwrap().unwrap();
    let end = tokio::time::timeout(T, v.task).await.expect("viewer notices the host leaving").unwrap().unwrap();
    assert!(matches!(end, SessionEnd::Closed));
    ts.stop().await;
}

#[tokio::test]
async fn third_party_cannot_join_a_session() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let viewer_dev = ts.signup("alice", "correct horse battery", "laptop").await;
    let mut host_dev = ts.signup("bob", "correct horse battery", "desktop").await;
    let host_id = host_dev.creds.device_id;
    let mallory = ts.signup("mallory", "correct horse battery", "evil").await;

    let host_side = async {
        let (sid, from) = next_incoming(&mut host_dev).await;
        // Mallory learns the session id somehow and races to join the relay first.
        let (mut ms, mut mr) = mallory.conn.open_relay(sid).await.unwrap();
        let _ = ms.write_all(b"garbage").await;
        let mut buf = [0u8; 16];
        let got = tokio::time::timeout(Duration::from_millis(500), mr.read(&mut buf)).await;
        assert!(!matches!(got, Ok(Ok(Some(n))) if n > 0), "mallory must not receive session data");
        session::accept(&host_dev.conn, &host_dev.creds, sid, &from).await.unwrap()
    };
    let (mut v, ch) = tokio::join!(start_viewer(&viewer_dev, host_id), host_side);
    let (_stop_tx, stop_rx) = watch::channel(false);
    let cap = FakeCapturer { width: 64, height: 64, bgra: Arc::new(Mutex::new([0, 0, 255, 255])) };
    tokio::spawn(host::serve(
        ch,
        Box::new(cap),
        Box::new(RecordingInjector::default()),
        SessionExtras::default(),
        HostSettings::default(),
        stop_rx,
    ));
    tokio::time::timeout(T, v.accepted.recv()).await.unwrap().unwrap();
    frame_matching(&mut v.frames, [255, 0, 0]).await;
    ts.stop().await;
}

#[tokio::test]
async fn clipboard_is_shared_both_ways() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let viewer_dev = ts.signup("alice", "correct horse battery", "laptop").await;
    let mut host_dev = ts.signup("bob", "correct horse battery", "desktop").await;
    let host_id = host_dev.creds.device_id;

    let viewer_clip = FakeClipboard::with_text("VIEWER-COPIED-sudo apt upgrade");
    let host_clip = FakeClipboard::with_text("HOST-PRIVATE-clipboard-before-session");
    let host_side = async {
        let (sid, from) = next_incoming(&mut host_dev).await;
        session::accept(&host_dev.conn, &host_dev.creds, sid, &from).await.unwrap()
    };
    let (mut v, ch) = tokio::join!(start_viewer_with(&viewer_dev, host_id, clipboard_extras(&viewer_clip)), host_side);
    let (_stop_tx, stop_rx) = watch::channel(false);
    let cap = FakeCapturer { width: 64, height: 64, bgra: Arc::new(Mutex::new([0, 0, 0, 255])) };
    let host_task = tokio::spawn(host::serve(
        ch,
        Box::new(cap),
        Box::new(RecordingInjector::default()),
        clipboard_extras(&host_clip),
        HostSettings::default(),
        stop_rx,
    ));
    tokio::time::timeout(T, v.accepted.recv()).await.unwrap().unwrap();

    // What the viewer had copied before connecting becomes pasteable on the host.
    host_clip.wait_for("VIEWER-COPIED-sudo apt upgrade", T).await;
    // Copying on the host makes it pasteable on the viewer...
    host_clip.set("HOST-COPIED-error log line ✓");
    viewer_clip.wait_for("HOST-COPIED-error log line ✓", T).await;
    // ...and back again.
    viewer_clip.set("VIEWER-COPIED-again");
    host_clip.wait_for("VIEWER-COPIED-again", T).await;

    // Text applied from the peer is not echoed back: each side was written exactly as often as
    // the other side copied something.
    tokio::time::sleep(somedesk_client::clipboard::POLL_INTERVAL * 4).await;
    assert_eq!(host_clip.writes(), 2);
    assert_eq!(viewer_clip.writes(), 1);
    // The host's clipboard from before the session was never shared.
    assert!(!viewer_clip.history().iter().any(|t| t.contains("HOST-PRIVATE")));

    drop(v.input);
    tokio::time::timeout(T, v.task).await.unwrap().unwrap().unwrap();
    tokio::time::timeout(T, host_task).await.unwrap().unwrap().unwrap();
    assert!(!ts.relay_contains(b"VIEWER-COPIED"));
    assert!(!ts.relay_contains(b"HOST-COPIED"));
    ts.stop().await;
}

/// The real thing: capture an X server and inject into it (needs SOMEDESK_TEST_DISPLAY).
#[tokio::test]
async fn x11_host_end_to_end() {
    let Ok(display) = std::env::var("SOMEDESK_TEST_DISPLAY") else {
        eprintln!("SOMEDESK_TEST_DISPLAY not set, skipping");
        return;
    };
    let Some(ts) = TestServer::start().await else {
        return;
    };

    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{ChangeWindowAttributesAux, ConnectionExt};
    let (xc, screen) = x11rb::rust_connection::RustConnection::connect(Some(&display)).unwrap();
    let root = xc.setup().roots[screen].root;
    let (sw, sh) = (xc.setup().roots[screen].width_in_pixels as u32, xc.setup().roots[screen].height_in_pixels as u32);
    xc.change_window_attributes(root, &ChangeWindowAttributesAux::new().background_pixel(0x00C8_3264)).unwrap();
    xc.clear_area(false, root, 0, 0, 0, 0).unwrap();
    xc.get_input_focus().unwrap().reply().unwrap();

    let viewer_dev = ts.signup("alice", "correct horse battery", "laptop").await;
    let mut host_dev = ts.signup("bob", "correct horse battery", "desktop").await;
    let host_id = host_dev.creds.device_id;
    let host_side = async {
        let (sid, from) = next_incoming(&mut host_dev).await;
        session::accept(&host_dev.conn, &host_dev.creds, sid, &from).await.unwrap()
    };
    let (mut v, ch) = tokio::join!(start_viewer(&viewer_dev, host_id), host_side);
    let cap = somedesk_platform::linux::x11::X11Capturer::open(Some(&display)).unwrap();
    let inj = somedesk_platform::linux::x11::X11Injector::open(Some(&display)).unwrap();
    let (_stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(host::serve(
        ch,
        Box::new(cap),
        Box::new(inj),
        SessionExtras::default(),
        HostSettings::default(),
        stop_rx,
    ));

    tokio::time::timeout(T, v.accepted.recv()).await.unwrap().unwrap();
    let f = frame_matching(&mut v.frames, [0xC8, 0x32, 0x64]).await;
    assert_eq!((f.width, f.height), (sw & !1, sh & !1));

    // Move the remote pointer to 25% / 75% of the screen.
    v.input.send(SessionMsg::PointerMove { x: POINTER_MAX / 4, y: POINTER_MAX / 4 * 3 }).unwrap();
    let want = ((sw - 1) / 4, (sh - 1) * 3 / 4);
    let mut pos = (0, 0);
    for _ in 0..50 {
        let p = xc.query_pointer(root).unwrap().reply().unwrap();
        pos = (p.root_x as u32, p.root_y as u32);
        if pos.0.abs_diff(want.0) <= 1 && pos.1.abs_diff(want.1) <= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(pos.0.abs_diff(want.0) <= 1 && pos.1.abs_diff(want.1) <= 1, "pointer at {pos:?}, wanted {want:?}");
    ts.stop().await;
}

/// Asks the headless GNOME session (scripts/wayland-env.sh) where its pointer is.
fn gnome_pointer() -> (u32, u32) {
    let out = std::process::Command::new("gdbus")
        .args(["call", "--session", "--dest", "org.gnome.Shell", "--object-path", "/org/gnome/Shell"])
        .args(["--method", "org.gnome.Shell.Eval", "global.get_pointer().slice(0, 2).join(\",\")"])
        .output()
        .expect("run gdbus");
    let text = String::from_utf8_lossy(&out.stdout);
    // (true, '"123,456"')
    let inner = text.split('"').nth(1).unwrap_or_else(|| panic!("unexpected Shell.Eval output {text:?}"));
    let (x, y) = inner.split_once(',').expect("x,y");
    (x.parse().unwrap(), y.parse().unwrap())
}

/// The real thing on Wayland: share a GNOME session through the desktop portal. Needs the
/// environment from scripts/wayland-env.sh and a granted permission (scripts/wayland-grant.sh),
/// passed as SOMEDESK_TEST_WAYLAND_STATE.
#[tokio::test]
async fn wayland_portal_host_end_to_end() {
    let Ok(state) = std::env::var("SOMEDESK_TEST_WAYLAND_STATE") else {
        eprintln!("SOMEDESK_TEST_WAYLAND_STATE not set, skipping");
        return;
    };
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let viewer_dev = ts.signup("alice", "correct horse battery", "laptop").await;
    let mut host_dev = ts.signup("bob", "correct horse battery", "gnome-desktop").await;
    let host_id = host_dev.creds.device_id;
    let host_side = async {
        let (sid, from) = next_incoming(&mut host_dev).await;
        session::accept(&host_dev.conn, &host_dev.creds, sid, &from).await.unwrap()
    };
    let (mut v, ch) = tokio::join!(start_viewer(&viewer_dev, host_id), host_side);

    let mut screen = tokio::task::spawn_blocking(move || {
        somedesk_platform::open_screen(Some(std::path::Path::new(&state)))
            .expect("portal session (permission granted?)")
    })
    .await
    .unwrap();
    assert_eq!(screen.backend, "portal");
    assert!(screen.can_control, "remote interaction was granted");
    let (sw, sh) = screen.injector.screen_size().unwrap();
    let (_stop_tx, stop_rx) = watch::channel(false);
    let host_task = tokio::spawn(host::serve(
        ch,
        screen.capturer,
        screen.injector,
        SessionExtras::default(),
        HostSettings::default(),
        stop_rx,
    ));

    tokio::time::timeout(T, v.accepted.recv()).await.unwrap().unwrap();
    let f = tokio::time::timeout(T, v.frames.recv()).await.expect("a frame from PipeWire").unwrap();
    assert_eq!((f.width, f.height), (sw & !1, sh & !1));

    // Remote pointer moves land where they should on the GNOME screen.
    for (fx, fy) in [(1, 4), (3, 4), (2, 3)] {
        let (nx, ny) = ((POINTER_MAX as u32 * fx / 4) as u16, (POINTER_MAX as u32 * fy / 4) as u16);
        v.input.send(SessionMsg::PointerMove { x: nx, y: ny }).unwrap();
        let want = ((sw - 1) * fx / 4, (sh - 1) * fy / 4);
        let mut pos = (0, 0);
        for _ in 0..50 {
            pos = gnome_pointer();
            if pos.0.abs_diff(want.0) <= 1 && pos.1.abs_diff(want.1) <= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(pos.0.abs_diff(want.0) <= 1 && pos.1.abs_diff(want.1) <= 1, "pointer at {pos:?}, wanted {want:?}");
    }

    drop(v.input);
    tokio::time::timeout(T, v.task).await.unwrap().unwrap().unwrap();
    let stats = tokio::time::timeout(T, host_task).await.unwrap().unwrap().unwrap();
    assert_eq!(stats.input_events, 3);
    ts.stop().await;
}

fn transfer_events() -> (somedesk_client::files::TransferSink, mpsc::UnboundedReceiver<TransferEvent>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Arc::new(move |ev| drop(tx.send(ev))), rx)
}

/// Waits for a completed or failed event, skipping progress.
async fn transfer_outcome(rx: &mut mpsc::UnboundedReceiver<TransferEvent>) -> TransferEvent {
    loop {
        let ev = tokio::time::timeout(T, rx.recv()).await.expect("transfer outcome").unwrap();
        if matches!(ev, TransferEvent::Completed { .. } | TransferEvent::Failed { .. } | TransferEvent::Offered { .. })
        {
            return ev;
        }
    }
}

/// Retries until the session has attached the transfers.
async fn send_when_ready(files: &FileTransfers, path: &std::path::Path) -> u32 {
    for _ in 0..100 {
        if let Ok(id) = files.send_file(path) {
            return id;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("session never became ready for file transfer");
}

#[tokio::test]
async fn files_are_transferred_both_ways() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let viewer_dev = ts.signup("alice", "correct horse battery", "laptop").await;
    let mut host_dev = ts.signup("bob", "correct horse battery", "desktop").await;
    let host_id = host_dev.creds.device_id;
    let tmp = std::env::temp_dir().join(format!("somedesk-files-{}-{}", std::process::id(), rand::random::<u32>()));
    let (host_dl, viewer_dl, src) = (tmp.join("host-dl"), tmp.join("viewer-dl"), tmp.join("src"));
    std::fs::create_dir_all(&src).unwrap();

    // The host saves files from the viewer straight away; the viewer asks first.
    let (host_sink, mut host_ev) = transfer_events();
    let host_files = FileTransfers::new(host_dl.clone(), AcceptPolicy::Always, host_sink);
    let (viewer_sink, mut viewer_ev) = transfer_events();
    let viewer_files = FileTransfers::new(viewer_dl.clone(), AcceptPolicy::Ask, viewer_sink);

    let host_side = async {
        let (sid, from) = next_incoming(&mut host_dev).await;
        session::accept(&host_dev.conn, &host_dev.creds, sid, &from).await.unwrap()
    };
    let viewer_extras = SessionExtras { files: Some(viewer_files.clone()), ..Default::default() };
    let (mut v, ch) = tokio::join!(start_viewer_with(&viewer_dev, host_id, viewer_extras), host_side);
    let (_stop_tx, stop_rx) = watch::channel(false);
    let cap = FakeCapturer { width: 64, height: 64, bgra: Arc::new(Mutex::new([0, 0, 0, 255])) };
    let host_extras = SessionExtras { files: Some(host_files.clone()), ..Default::default() };
    let host_task = tokio::spawn(host::serve(
        ch,
        Box::new(cap),
        Box::new(RecordingInjector::default()),
        host_extras,
        HostSettings::default(),
        stop_rx,
    ));
    tokio::time::timeout(T, v.accepted.recv()).await.unwrap().unwrap();

    // Viewer → host: 3 MB (many chunks) with a marker the relay must never see.
    let mut big: Vec<u8> = (0..3_000_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    big[1_000_000..1_000_020].copy_from_slice(b"FILE-CONTENT-MARKER!");
    std::fs::write(src.join("backup.tar"), &big).unwrap();
    send_when_ready(&viewer_files, &src.join("backup.tar")).await;
    match transfer_outcome(&mut host_ev).await {
        TransferEvent::Completed { direction: Direction::Download, path: Some(p), name, .. } => {
            assert_eq!(name, "backup.tar");
            assert_eq!(p, host_dl.join("backup.tar"));
            assert_eq!(std::fs::read(&p).unwrap(), big);
        }
        other => panic!("host: {other:?}"),
    }
    assert!(matches!(
        transfer_outcome(&mut viewer_ev).await,
        TransferEvent::Completed { direction: Direction::Upload, .. }
    ));

    // Host → viewer: the viewer is asked and declines.
    std::fs::write(src.join(".profile"), b"export SECRET=1\n").unwrap();
    send_when_ready(&host_files, &src.join(".profile")).await;
    let TransferEvent::Offered { id, name, size } = transfer_outcome(&mut viewer_ev).await else { panic!("no offer") };
    assert_eq!((name.as_str(), size), ("profile", 16), "hidden-file names are made visible");
    viewer_files.respond(id, false);
    match transfer_outcome(&mut host_ev).await {
        TransferEvent::Failed { direction: Direction::Upload, reason, .. } => {
            assert!(reason.contains("declined"), "{reason}")
        }
        other => panic!("host: {other:?}"),
    }
    assert!(!viewer_dl.join("profile").exists());

    // ...and accepts the second time. A second copy of a name does not overwrite the first.
    for expected in ["profile", "profile (2)"] {
        send_when_ready(&host_files, &src.join(".profile")).await;
        let TransferEvent::Offered { id, .. } = transfer_outcome(&mut viewer_ev).await else { panic!("no offer") };
        viewer_files.respond(id, true);
        match transfer_outcome(&mut viewer_ev).await {
            TransferEvent::Completed { direction: Direction::Download, path: Some(p), .. } => {
                assert_eq!(p, viewer_dl.join(expected));
                assert_eq!(std::fs::read(&p).unwrap(), b"export SECRET=1\n");
            }
            other => panic!("viewer: {other:?}"),
        }
        assert!(matches!(
            transfer_outcome(&mut host_ev).await,
            TransferEvent::Completed { direction: Direction::Upload, .. }
        ));
    }
    // No partial files are left behind.
    let leftovers: Vec<_> = std::fs::read_dir(&viewer_dl).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(leftovers.len(), 2, "{leftovers:?}");

    drop(v.input);
    tokio::time::timeout(T, v.task).await.unwrap().unwrap().unwrap();
    tokio::time::timeout(T, host_task).await.unwrap().unwrap().unwrap();
    assert!(!ts.relay_contains(b"FILE-CONTENT-MARKER!"));
    assert!(!ts.relay_contains(b"backup.tar"));
    // Once the session is over, nothing can be sent.
    assert!(viewer_files.send_file(&src.join("backup.tar")).is_err());
    std::fs::remove_dir_all(&tmp).unwrap();
    ts.stop().await;
}

#[tokio::test]
async fn interrupted_transfers_leave_no_partial_files() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let viewer_dev = ts.signup("alice", "correct horse battery", "laptop").await;
    let mut host_dev = ts.signup("bob", "correct horse battery", "desktop").await;
    let host_id = host_dev.creds.device_id;
    let tmp = std::env::temp_dir().join(format!("somedesk-files-{}-{}", std::process::id(), rand::random::<u32>()));
    let (host_dl, src) = (tmp.join("host-dl"), tmp.join("src"));
    std::fs::create_dir_all(&src).unwrap();
    let (host_sink, mut host_ev) = transfer_events();
    let host_files = FileTransfers::new(host_dl.clone(), AcceptPolicy::Always, host_sink);
    let (viewer_sink, _viewer_ev) = transfer_events();
    let viewer_files = FileTransfers::new(tmp.join("viewer-dl"), AcceptPolicy::Ask, viewer_sink);

    let host_side = async {
        let (sid, from) = next_incoming(&mut host_dev).await;
        session::accept(&host_dev.conn, &host_dev.creds, sid, &from).await.unwrap()
    };
    let viewer_extras = SessionExtras { files: Some(viewer_files.clone()), ..Default::default() };
    let (mut v, ch) = tokio::join!(start_viewer_with(&viewer_dev, host_id, viewer_extras), host_side);
    let (_stop_tx, stop_rx) = watch::channel(false);
    let cap = FakeCapturer { width: 64, height: 64, bgra: Arc::new(Mutex::new([0, 0, 0, 255])) };
    let host_extras = SessionExtras { files: Some(host_files.clone()), ..Default::default() };
    let host_task = tokio::spawn(host::serve(
        ch,
        Box::new(cap),
        Box::new(RecordingInjector::default()),
        host_extras,
        HostSettings::default(),
        stop_rx,
    ));
    tokio::time::timeout(T, v.accepted.recv()).await.unwrap().unwrap();

    std::fs::write(src.join("huge.bin"), vec![7u8; 64 * 1024 * 1024]).unwrap();
    send_when_ready(&viewer_files, &src.join("huge.bin")).await;
    // Wait until the host is receiving, then end the session mid-transfer.
    loop {
        match tokio::time::timeout(T, host_ev.recv()).await.unwrap().unwrap() {
            TransferEvent::Progress { done, .. } if done > 0 => break,
            TransferEvent::Completed { .. } => panic!("finished too quickly to interrupt"),
            _ => {}
        }
    }
    drop(v.input);
    tokio::time::timeout(T, v.task).await.unwrap().unwrap().unwrap();
    tokio::time::timeout(T, host_task).await.unwrap().unwrap().unwrap();
    match transfer_outcome(&mut host_ev).await {
        TransferEvent::Failed { direction: Direction::Download, .. } => {}
        other => panic!("host: {other:?}"),
    }
    let left: Vec<_> = std::fs::read_dir(&host_dl).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert!(left.is_empty(), "partial files left behind: {left:?}");
    std::fs::remove_dir_all(&tmp).unwrap();
    ts.stop().await;
}

/// A server that swaps in a different key for a known user (here: the account is deleted and
/// re-created behind everyone's back) is caught by the remembered identity.
#[tokio::test]
async fn swapped_identity_is_detected() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let viewer_dev = ts.signup("alice", "correct horse battery", "laptop").await;
    let mut host_dev = ts.signup("bob", "correct horse battery", "desktop").await;
    let store_path =
        std::env::temp_dir().join(format!("somedesk-known-{}-{}.json", std::process::id(), rand::random::<u32>()));
    let mut trust = somedesk_client::trust::TrustStore::load(&store_path).unwrap();

    // First contact: bob is new, then remembered.
    let host_id = host_dev.creds.device_id;
    let host_side = async {
        let (sid, from) = next_incoming(&mut host_dev).await;
        session::accept(&host_dev.conn, &host_dev.creds, sid, &from).await.unwrap()
    };
    let ((ch, _), _host_ch) = tokio::join!(
        async { session::connect(&viewer_dev.conn, &viewer_dev.creds, host_id).await.unwrap() },
        host_side
    );
    assert_eq!(trust.status(&ch.peer), PeerStatus::New);
    trust.remember(&ch.peer);
    drop(ch);

    // The "server" replaces bob with an impostor of the same name.
    let mut db = PgConnection::connect(&ts.db_url).await.unwrap();
    sqlx::query("DELETE FROM users WHERE username = 'bob'").execute(&mut db).await.unwrap();
    let mut impostor = ts.signup("bob", "attacker password", "desktop").await;
    let impostor_id = impostor.creds.device_id;
    let impostor_side = async {
        let (sid, from) = next_incoming(&mut impostor).await;
        session::accept(&impostor.conn, &impostor.creds, sid, &from).await.unwrap()
    };
    let ((ch, _), _imp_ch) = tokio::join!(
        async { session::connect(&viewer_dev.conn, &viewer_dev.creds, impostor_id).await.unwrap() },
        impostor_side
    );
    assert_eq!(ch.peer.username, "bob");
    assert_eq!(
        trust.status(&ch.peer),
        PeerStatus::Changed { previous_identity_pk: host_dev.creds.identity_pk },
        "a different key under a known name must be flagged"
    );
    let _ = std::fs::remove_file(store_path);
    ts.stop().await;
}
