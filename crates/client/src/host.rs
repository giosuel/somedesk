//! Host side of a session: capture → encode → send, and receive → inject.

use crate::clipboard::ClipboardSync;
use crate::session::Channel;
use crate::{ClientError, Result, SessionExtras};
use somedesk_codec::{EncoderSettings, H264Encoder};
use somedesk_platform::{Capturer, Injector};
use somedesk_proto::session::{MonitorInfo, SessionMsg, POINTER_MAX};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

#[derive(Clone, Debug)]
pub struct HostSettings {
    pub max_fps: u32,
    pub bitrate_bps: u32,
    /// After the screen stops changing, keep encoding this many frames so the encoder can refine
    /// quality, then go idle.
    pub refine_frames: u32,
    /// Share the screen only; input from the viewer is ignored.
    pub view_only: bool,
}

impl Default for HostSettings {
    fn default() -> Self {
        Self { max_fps: 30, bitrate_bps: 6_000_000, refine_frames: 15, view_only: false }
    }
}

#[derive(Debug, Default, Clone)]
pub struct HostStats {
    pub frames_sent: u64,
    pub bytes_sent: u64,
    pub input_events: u64,
}

/// Declines an incoming session.
pub async fn reject(ch: Channel, reason: &str) {
    let mut sender = ch.sender;
    let _ = sender.send(&SessionMsg::Reject { reason: reason.to_owned() }).await;
    let _ = sender.send(&SessionMsg::Bye).await;
    let mut s = sender.into_inner();
    let _ = s.finish();
}

/// Accepts the session and serves it until the viewer leaves, an error occurs, or `stop`
/// becomes `true`. With a clipboard in `extras`, clipboard text is shared in both directions;
/// with file transfers, files can be sent either way.
pub async fn serve(
    ch: Channel,
    capturer: Box<dyn Capturer>,
    injector: Box<dyn Injector>,
    extras: SessionExtras,
    settings: HostSettings,
    mut stop: watch::Receiver<bool>,
) -> Result<HostStats> {
    let Channel { mut sender, mut receiver, peer } = ch;
    tracing::info!(peer = %peer.username, device = %peer.device_name, "session accepted");
    sender.send(&SessionMsg::Accept).await?;
    if settings.view_only {
        sender.send(&SessionMsg::ViewOnly).await?;
    }
    let view_only = settings.view_only;

    let shared = Arc::new(CaptureShared::default());
    shared.running.store(true, Ordering::Relaxed);
    shared.keyframe.store(true, Ordering::Relaxed);
    let (video_tx, mut video_rx) = mpsc::channel::<SessionMsg>(2);
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel::<SessionMsg>();
    let (input_tx, input_rx) = std::sync::mpsc::channel::<SessionMsg>();

    let capture = {
        let (shared, settings) = (shared.clone(), settings.clone());
        std::thread::Builder::new()
            .name("somedesk-capture".into())
            .spawn(move || capture_loop(capturer, settings, video_tx, shared))
            .expect("spawn capture thread")
    };
    let inject = {
        let shared = shared.clone();
        std::thread::Builder::new()
            .name("somedesk-inject".into())
            .spawn(move || inject_loop(injector, input_rx, shared))
            .expect("spawn inject thread")
    };
    // The host's existing clipboard is only shared once the user there copies something new.
    let SessionExtras { clipboard, files } = extras;
    let clipboard = clipboard.map(|c| ClipboardSync::start(c, ctrl_tx.clone(), false));
    let (mut file_rx, _no_files) = crate::file_lane(&files);

    let mut stats = HostStats::default();
    let send_loop = async {
        loop {
            let msg = tokio::select! {
                biased;
                m = ctrl_rx.recv() => m,
                m = video_rx.recv() => m,
                m = file_rx.recv() => m,
            };
            let Some(msg) = msg else { break };
            if let SessionMsg::Video { data, .. } = &msg {
                stats.frames_sent += 1;
                stats.bytes_sent += data.len() as u64;
            }
            sender.send(&msg).await?;
        }
        Ok::<_, ClientError>(())
    };
    let mut input_events = 0u64;
    let recv_loop = async {
        loop {
            match receiver.recv::<SessionMsg>().await? {
                None | Some(SessionMsg::Bye) => return Ok::<_, ClientError>(()),
                Some(SessionMsg::RequestKeyframe) => shared.keyframe.store(true, Ordering::Relaxed),
                Some(SessionMsg::SelectMonitor { id }) => *shared.monitor_request.lock().unwrap() = Some(id),
                Some(SessionMsg::Ping { t }) => {
                    let _ = ctrl_tx.send(SessionMsg::Pong { t });
                }
                Some(
                    m @ (SessionMsg::PointerMove { .. }
                    | SessionMsg::PointerButton { .. }
                    | SessionMsg::Scroll { .. }
                    | SessionMsg::Key { .. }),
                ) => {
                    if !view_only {
                        input_events += 1;
                        let _ = input_tx.send(m);
                    }
                }
                Some(SessionMsg::Clipboard { text }) => {
                    if let Some(c) = &clipboard {
                        c.apply(text);
                    }
                }
                Some(other) => {
                    let handled = match &files {
                        Some(f) => f.handle(&other).await,
                        None => false,
                    };
                    if !handled {
                        tracing::debug!("ignoring unexpected message from viewer: {other:?}")
                    }
                }
            }
        }
    };
    let result = tokio::select! {
        r = send_loop => r,
        r = recv_loop => r,
        _ = stop.wait_for(|s| *s) => Ok(()),
    };
    // The viewer may leave while we are still sending (e.g. during a file transfer); that is an
    // ordinary end of the session.
    let result = match result {
        Err(e) if e.is_peer_gone() => Ok(()),
        r => r,
    };
    shared.running.store(false, Ordering::Relaxed);
    let _ = sender.send(&SessionMsg::Bye).await;
    let _ = sender.into_inner().finish();
    if let Some(f) = &files {
        f.detach().await;
    }
    // Closing the channels unblocks both threads: the capture thread may be waiting in
    // `blocking_send`, and the inject thread exits when its input channel closes.
    drop(video_rx);
    drop(input_tx);
    let clipboard = clipboard.map(ClipboardSync::stop);
    let _ = tokio::task::spawn_blocking(move || {
        let _ = capture.join();
        let _ = inject.join();
        if let Some(c) = clipboard {
            let _ = c.join();
        }
    })
    .await;
    stats.input_events = input_events;
    tracing::info!(?stats, "session ended");
    result.map(|_| stats)
}

/// State shared between the session task and the capture and inject threads.
#[derive(Default)]
struct CaptureShared {
    running: AtomicBool,
    /// The viewer needs an IDR frame.
    keyframe: AtomicBool,
    /// Area of the screen currently shown, in injector coordinates (x, y, width, height); `None`
    /// when the whole screen is shown.
    view: Mutex<Option<(i32, i32, u32, u32)>>,
    /// Monitor selection requested by the viewer, applied by the capture thread.
    monitor_request: Mutex<Option<Option<u32>>>,
}

/// How often the list of monitors is checked for changes.
const MONITOR_POLL: Duration = Duration::from_secs(3);

fn monitors_msg(list: &[somedesk_platform::Monitor], selected: Option<u32>) -> SessionMsg {
    SessionMsg::Monitors {
        list: list
            .iter()
            .map(|m| MonitorInfo {
                id: m.id,
                name: m.name.clone(),
                width: m.width,
                height: m.height,
                primary: m.primary,
            })
            .collect(),
        selected,
    }
}

fn capture_loop(
    mut capturer: Box<dyn Capturer>,
    settings: HostSettings,
    tx: mpsc::Sender<SessionMsg>,
    shared: Arc<CaptureShared>,
) {
    let (running, keyframe) = (&shared.running, &shared.keyframe);
    let mut monitors = capturer.monitors().unwrap_or_default();
    let mut selected: Option<u32> = None;
    let mut monitors_checked = Instant::now();
    if monitors.len() > 1 && tx.blocking_send(monitors_msg(&monitors, selected)).is_err() {
        return;
    }
    let interval = Duration::from_secs_f64(1.0 / settings.max_fps.max(1) as f64);
    let enc_settings = EncoderSettings { bitrate_bps: settings.bitrate_bps, max_fps: settings.max_fps as f32 };
    let mut encoder: Option<H264Encoder> = None;
    let mut previous: Vec<u8> = Vec::new();
    let mut refine_left = 0u32;
    let mut seq = 0u64;

    while running.load(Ordering::Relaxed) {
        let started = Instant::now();
        let request = shared.monitor_request.lock().unwrap().take();
        let mut announce = false;
        if let Some(id) = request {
            match capturer.select_monitor(id) {
                Ok(()) => {
                    selected = id;
                    announce = true;
                    keyframe.store(true, Ordering::Relaxed);
                }
                Err(e) => tracing::warn!("cannot select monitor: {e:#}"),
            }
        }
        if monitors_checked.elapsed() >= MONITOR_POLL {
            monitors_checked = Instant::now();
            let now = capturer.monitors().unwrap_or_default();
            if now != monitors {
                monitors = now;
                // A selected monitor that went away falls back to the whole screen.
                if selected.is_some_and(|id| !monitors.iter().any(|m| m.id == id)) {
                    selected = None;
                    let _ = capturer.select_monitor(None);
                }
                announce = true;
            }
        }
        if announce
            && (monitors.len() > 1 || request.is_some())
            && tx.blocking_send(monitors_msg(&monitors, selected)).is_err()
        {
            return;
        }
        let frame = match capturer.capture() {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("screen capture failed: {e:#}");
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        *shared.view.lock().unwrap() = frame.origin.map(|(x, y)| (x, y, frame.width, frame.height));
        let needs_new_encoder = encoder.as_ref().is_none_or(|e| {
            let (w, h) = e.dimensions();
            (w, h) != (frame.width & !1, frame.height & !1)
        });
        if needs_new_encoder {
            match H264Encoder::new(frame.width, frame.height, &enc_settings) {
                Ok(e) => {
                    let (width, height) = e.dimensions();
                    if tx.blocking_send(SessionMsg::ScreenInfo { width, height }).is_err() {
                        return;
                    }
                    encoder = Some(e);
                    keyframe.store(true, Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::error!("cannot create encoder: {e:#}");
                    return;
                }
            }
        }
        let force = keyframe.swap(false, Ordering::Relaxed);
        if frame.data != previous {
            refine_left = settings.refine_frames;
            previous.clone_from(&frame.data);
        }
        if force || refine_left > 0 {
            refine_left = refine_left.saturating_sub(1);
            let enc = encoder.as_mut().expect("encoder initialized");
            match enc.encode_bgra(&frame.data, frame.stride, force) {
                Ok(Some(e)) => {
                    seq += 1;
                    let msg =
                        SessionMsg::Video { seq, keyframe: e.keyframe, width: e.width, height: e.height, data: e.data };
                    if tx.blocking_send(msg).is_err() {
                        return;
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::warn!("encode failed: {e:#}"),
            }
        }
        if let Some(rest) = interval.checked_sub(started.elapsed()) {
            std::thread::sleep(rest);
        }
    }
}

fn inject_loop(mut injector: Box<dyn Injector>, rx: std::sync::mpsc::Receiver<SessionMsg>, shared: Arc<CaptureShared>) {
    let mut size = injector.screen_size().unwrap_or((1, 1));
    let mut size_checked = Instant::now();
    let mut keys_down: HashSet<u32> = HashSet::new();
    let mut buttons_down: HashSet<u8> = HashSet::new();

    for msg in rx {
        if size_checked.elapsed() > Duration::from_secs(1) {
            size = injector.screen_size().unwrap_or(size);
            size_checked = Instant::now();
        }
        let res = match msg {
            SessionMsg::PointerMove { x, y } => {
                let scale = |v: u16, max: u32| (v as u64 * max.saturating_sub(1) as u64 / POINTER_MAX as u64) as u32;
                // Coordinates are relative to what the viewer sees: one monitor, or the screen.
                let view = *shared.view.lock().unwrap();
                match view {
                    Some((ox, oy, w, h)) => injector
                        .pointer_move((ox + scale(x, w) as i32).max(0) as u32, (oy + scale(y, h) as i32).max(0) as u32),
                    None => injector.pointer_move(scale(x, size.0), scale(y, size.1)),
                }
            }
            SessionMsg::PointerButton { button, down } => {
                if down {
                    buttons_down.insert(button)
                } else {
                    buttons_down.remove(&button)
                };
                injector.button(button, down)
            }
            SessionMsg::Scroll { dx, dy } => injector.scroll(dx as i32, dy as i32),
            SessionMsg::Key { keysym, down } => {
                if down {
                    keys_down.insert(keysym)
                } else {
                    keys_down.remove(&keysym)
                };
                injector.key(keysym, down)
            }
            _ => Ok(()),
        };
        if let Err(e) = res {
            tracing::debug!("input injection failed: {e:#}");
        }
    }
    // Never leave keys or buttons stuck on the host when the session ends.
    for k in keys_down {
        let _ = injector.key(k, false);
    }
    for b in buttons_down {
        let _ = injector.button(b, false);
    }
}
