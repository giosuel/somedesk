//! Wayland backend: the xdg-desktop-portal `RemoteDesktop` + `ScreenCast` interfaces.
//!
//! Wayland compositors don't let ordinary clients read the screen or inject input; the portal
//! asks the user for permission instead (GNOME, KDE, ...). One portal session provides both:
//!
//! * the screen arrives as a PipeWire video stream, received on its own thread, and
//! * input is sent with the portal's `Notify*` calls from a small async runtime thread.
//!
//! The portal hands out a *restore token* on success. Passing it to the next session skips the
//! permission dialog, so the person at the computer only has to allow SomeDesk once.

use crate::{Capturer, Frame, Injector};
use anyhow::{anyhow, bail, Context};
use ashpd::desktop::remote_desktop::{Axis, DeviceType, KeyState, RemoteDesktop, SelectDevicesOptions};
use ashpd::desktop::screencast::{CursorMode, Screencast, SelectSourcesOptions, SourceType};
use ashpd::desktop::PersistMode;
use pipewire as pw;
use pw::spa;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc;

/// How long to wait for the person at the computer to answer the permission dialog.
const PERMISSION_TIMEOUT: Duration = Duration::from_secs(120);
/// How long to wait for the first frame once the stream is set up.
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

// Linux evdev button codes (linux/input-event-codes.h).
const BTN_LEFT: i32 = 0x110;
const BTN_RIGHT: i32 = 0x111;
const BTN_MIDDLE: i32 = 0x112;

/// Opens a portal session. `restore_token` comes from a previous session; the returned
/// [`PortalSession::restore_token`] should be stored for the next one.
pub fn open(restore_token: Option<String>) -> anyhow::Result<PortalSession> {
    let (setup_tx, setup_rx) = std::sync::mpsc::channel();
    let (input_tx, input_rx) = mpsc::unbounded_channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    runtime()?.spawn(async move {
        portal_main(restore_token, setup_tx, input_rx).await;
        let _ = done_tx.send(());
    });

    let setup = match setup_rx.recv_timeout(PERMISSION_TIMEOUT + Duration::from_secs(10)) {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e),
        Err(_) => bail!("the screen sharing portal did not respond"),
    };

    let frames = Arc::new(FrameSlot::default());
    let (quit_tx, quit_rx) = pw::channel::channel::<()>();
    let pw_thread = {
        let frames = frames.clone();
        let (fd, node_id) = (setup.fd, setup.node_id);
        std::thread::Builder::new()
            .name("somedesk-pipewire".into())
            .spawn(move || {
                if let Err(e) = pipewire_main(fd, node_id, frames.clone(), quit_rx) {
                    tracing::error!("PipeWire stream failed: {e:#}");
                }
                let mut s = frames.state.lock().unwrap();
                s.ended = true;
                frames.cond.notify_all();
            })
            .context("spawning the PipeWire thread")?
    };

    Ok(PortalSession {
        shared: Arc::new(Shared {
            input: input_tx,
            frames,
            quit: Mutex::new(Some(quit_tx)),
            pw_thread: Mutex::new(Some(pw_thread)),
            portal_done: Mutex::new(done_rx),
        }),
        node_id: setup.node_id,
        size: setup.size,
        restore_token: setup.restore_token,
        can_control: setup.can_control,
    })
}

/// A running portal session. Split it into a capturer and an injector; it ends when both are
/// dropped.
pub struct PortalSession {
    shared: Arc<Shared>,
    node_id: u32,
    /// Logical size of the shared monitor, the coordinate space for absolute pointer motion.
    size: Option<(u32, u32)>,
    restore_token: Option<String>,
    can_control: bool,
}

impl PortalSession {
    /// Whether the user allowed remote input, not just viewing.
    pub fn can_control(&self) -> bool {
        self.can_control
    }

    /// Token that lets the next session start without asking again.
    pub fn restore_token(&self) -> Option<&str> {
        self.restore_token.as_deref()
    }

    pub fn split(self) -> (PortalCapturer, PortalInjector) {
        let capturer = PortalCapturer { shared: self.shared.clone() };
        let injector = PortalInjector { shared: self.shared, node_id: self.node_id, size: self.size };
        (capturer, injector)
    }
}

struct Shared {
    input: mpsc::UnboundedSender<Input>,
    frames: Arc<FrameSlot>,
    quit: Mutex<Option<pw::channel::Sender<()>>>,
    pw_thread: Mutex<Option<JoinHandle<()>>>,
    /// Signalled when the portal task has closed the session.
    portal_done: Mutex<std::sync::mpsc::Receiver<()>>,
}

/// The runtime all portal calls run on. ashpd shares one D-Bus connection per process, and
/// that connection lives on the runtime that created it, so the runtime must outlive every
/// session rather than being created per session.
fn runtime() -> anyhow::Result<&'static tokio::runtime::Runtime> {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    if let Some(rt) = RT.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("somedesk-portal")
        .enable_all()
        .build()
        .context("starting the portal runtime")?;
    Ok(RT.get_or_init(|| rt))
}

impl Drop for Shared {
    fn drop(&mut self) {
        // Stop the PipeWire loop; the portal thread ends once `input` (dropped with us) closes.
        if let Some(q) = self.quit.lock().unwrap().take() {
            let _ = q.send(());
        }
        let (tx, _) = mpsc::unbounded_channel();
        drop(std::mem::replace(&mut self.input, tx));
        if let Some(t) = self.pw_thread.lock().unwrap().take() {
            let _ = t.join();
        }
        // Wait (briefly) for the portal session to be closed, so a new one can start right away.
        let _ = self.portal_done.lock().unwrap().recv_timeout(Duration::from_secs(3));
    }
}

#[derive(Default)]
struct FrameSlot {
    state: Mutex<FrameState>,
    cond: Condvar,
}

#[derive(Default)]
struct FrameState {
    latest: Option<Frame>,
    ended: bool,
}

pub struct PortalCapturer {
    shared: Arc<Shared>,
}

impl Capturer for PortalCapturer {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        let slot = &self.shared.frames;
        let guard = slot.state.lock().unwrap();
        // The compositor only sends frames when something changes, so after the first one the
        // latest frame is returned again; the caller skips unchanged frames anyway.
        let (s, timeout) =
            slot.cond.wait_timeout_while(guard, FIRST_FRAME_TIMEOUT, |s| s.latest.is_none() && !s.ended).unwrap();
        if s.ended {
            bail!("the screen sharing stream ended");
        }
        if timeout.timed_out() && s.latest.is_none() {
            bail!("no frames from the screen sharing stream");
        }
        let f = s.latest.as_ref().expect("checked above");
        Ok(Frame { width: f.width, height: f.height, stride: f.stride, data: f.data.clone(), origin: None })
    }
}

pub struct PortalInjector {
    shared: Arc<Shared>,
    node_id: u32,
    size: Option<(u32, u32)>,
}

impl PortalInjector {
    fn send(&self, input: Input) -> anyhow::Result<()> {
        self.shared.input.send(input).map_err(|_| anyhow!("the remote desktop session has ended"))
    }
}

impl Injector for PortalInjector {
    fn screen_size(&mut self) -> anyhow::Result<(u32, u32)> {
        if let Some(s) = self.size {
            return Ok(s);
        }
        // Not every portal reports the stream size; fall back to the frame size.
        let s = self.shared.frames.state.lock().unwrap();
        s.latest.as_ref().map(|f| (f.width, f.height)).ok_or_else(|| anyhow!("screen size unknown"))
    }

    fn pointer_move(&mut self, x: u32, y: u32) -> anyhow::Result<()> {
        self.send(Input::Motion { stream: self.node_id, x: x as f64, y: y as f64 })
    }

    fn button(&mut self, button: u8, down: bool) -> anyhow::Result<()> {
        let code = match button {
            1 => BTN_LEFT,
            2 => BTN_MIDDLE,
            3 => BTN_RIGHT,
            _ => bail!("unsupported mouse button {button}"),
        };
        self.send(Input::Button { code, down })
    }

    fn scroll(&mut self, dx: i32, dy: i32) -> anyhow::Result<()> {
        if dy != 0 {
            self.send(Input::Scroll { axis: Axis::Vertical, steps: dy })?;
        }
        if dx != 0 {
            self.send(Input::Scroll { axis: Axis::Horizontal, steps: dx })?;
        }
        Ok(())
    }

    fn key(&mut self, keysym: u32, down: bool) -> anyhow::Result<()> {
        self.send(Input::Key { keysym: keysym as i32, down })
    }
}

#[derive(Debug)]
enum Input {
    Motion { stream: u32, x: f64, y: f64 },
    Button { code: i32, down: bool },
    Scroll { axis: Axis, steps: i32 },
    Key { keysym: i32, down: bool },
}

struct Setup {
    fd: OwnedFd,
    node_id: u32,
    size: Option<(u32, u32)>,
    restore_token: Option<String>,
    can_control: bool,
}

fn state(down: bool) -> KeyState {
    if down {
        KeyState::Pressed
    } else {
        KeyState::Released
    }
}

/// Runs the portal session: sets it up, reports back through `setup_tx`, then forwards input
/// until `input` closes.
///
/// Uses a combined remote desktop + screen cast session where the desktop supports remote input
/// (GNOME, KDE), and a screen-cast-only, view-only session where it doesn't (e.g. wlroots).
async fn portal_main(
    restore_token: Option<String>,
    setup_tx: std::sync::mpsc::Sender<anyhow::Result<Setup>>,
    input: mpsc::UnboundedReceiver<Input>,
) {
    let cast = match Screencast::new().await {
        Ok(c) => c,
        Err(e) => {
            let _ = setup_tx.send(Err(anyhow!(e).context("the screen cast portal is not available")));
            return;
        }
    };
    let remote = match RemoteDesktop::new().await {
        Ok(r) if r.available_device_types().await.is_ok_and(|d| d.contains(DeviceType::Pointer)) => Some(r),
        _ => None,
    };
    match remote {
        Some(remote) => remote_session(remote, cast, restore_token, setup_tx, input).await,
        None => {
            tracing::info!("the desktop offers no remote input portal; sharing view-only");
            cast_only_session(cast, restore_token, setup_tx, input).await
        }
    }
}

async fn remote_session(
    remote: RemoteDesktop,
    cast: Screencast,
    restore_token: Option<String>,
    setup_tx: std::sync::mpsc::Sender<anyhow::Result<Setup>>,
    mut input: mpsc::UnboundedReceiver<Input>,
) {
    let started = async {
        let session = remote.create_session(Default::default()).await?;
        // Persistence is requested on the remote desktop side; it covers the screen cast too.
        remote
            .select_devices(
                &session,
                SelectDevicesOptions::default()
                    .set_devices(DeviceType::Keyboard | DeviceType::Pointer)
                    .set_persist_mode(PersistMode::ExplicitlyRevoked)
                    .set_restore_token(restore_token.as_deref()),
            )
            .await?
            .response()?;
        cast.select_sources(&session, source_options(&cast).await).await?.response()?;
        let response =
            wait_for_permission(async { remote.start(&session, None, Default::default()).await?.response() }).await?;
        let can_control =
            response.devices().contains(DeviceType::Pointer) && response.devices().contains(DeviceType::Keyboard);
        if !can_control {
            tracing::warn!(devices = ?response.devices(), "remote control was not granted, sharing view-only");
        }
        let (node_id, size) = first_stream(response.streams())?;
        let fd = cast.open_pipe_wire_remote(&session, Default::default()).await?;
        let restore_token = response.restore_token().map(str::to_owned);
        Ok::<_, anyhow::Error>((session, Setup { fd, node_id, size, restore_token, can_control }))
    }
    .await;

    let session = match started {
        Ok((session, setup)) => {
            tracing::info!(node_id = setup.node_id, size = ?setup.size, "portal session started");
            if setup_tx.send(Ok(setup)).is_err() {
                let _ = session.close().await;
                return;
            }
            session
        }
        Err(e) => {
            let _ = setup_tx.send(Err(e));
            return;
        }
    };

    while let Some(ev) = input.recv().await {
        let res = match ev {
            Input::Motion { stream, x, y } => {
                remote.notify_pointer_motion_absolute(&session, stream, x, y, Default::default()).await
            }
            Input::Button { code, down } => {
                remote.notify_pointer_button(&session, code, state(down), Default::default()).await
            }
            Input::Scroll { axis, steps } => {
                remote.notify_pointer_axis_discrete(&session, axis, steps, Default::default()).await
            }
            Input::Key { keysym, down } => {
                remote.notify_keyboard_keysym(&session, keysym, state(down), Default::default()).await
            }
        };
        if let Err(e) = res {
            tracing::debug!("portal input failed: {e}");
        }
    }
    let _ = session.close().await;
}

async fn cast_only_session(
    cast: Screencast,
    restore_token: Option<String>,
    setup_tx: std::sync::mpsc::Sender<anyhow::Result<Setup>>,
    mut input: mpsc::UnboundedReceiver<Input>,
) {
    let started = async {
        let session = cast.create_session(Default::default()).await?;
        let options = source_options(&cast)
            .await
            .set_persist_mode(PersistMode::ExplicitlyRevoked)
            .set_restore_token(restore_token.as_deref());
        cast.select_sources(&session, options).await?.response()?;
        let response =
            wait_for_permission(async { cast.start(&session, None, Default::default()).await?.response() }).await?;
        let (node_id, size) = first_stream(response.streams())?;
        let fd = cast.open_pipe_wire_remote(&session, Default::default()).await?;
        let restore_token = response.restore_token().map(str::to_owned);
        Ok::<_, anyhow::Error>((session, Setup { fd, node_id, size, restore_token, can_control: false }))
    }
    .await;

    match started {
        Ok((session, setup)) => {
            tracing::info!(node_id = setup.node_id, size = ?setup.size, "portal session started (view-only)");
            if setup_tx.send(Ok(setup)).is_ok() {
                // No way to inject input; just wait for the session to end.
                while input.recv().await.is_some() {}
            }
            let _ = session.close().await;
        }
        Err(e) => {
            let _ = setup_tx.send(Err(e));
        }
    }
}

/// Share one monitor, with the pointer drawn into the picture where supported.
async fn source_options(cast: &Screencast) -> SelectSourcesOptions {
    let cursor = match cast.available_cursor_modes().await {
        Ok(m) if m.contains(CursorMode::Embedded) => CursorMode::Embedded,
        _ => CursorMode::Hidden,
    };
    SelectSourcesOptions::default()
        .set_cursor_mode(cursor)
        .set_sources(enumflags2::BitFlags::from(SourceType::Monitor))
        .set_multiple(false)
}

/// Waits for the user's answer to the permission dialog (immediate with a restore token).
async fn wait_for_permission<T>(
    start: impl std::future::Future<Output = Result<T, ashpd::Error>>,
) -> anyhow::Result<T> {
    match tokio::time::timeout(PERMISSION_TIMEOUT, start).await {
        Err(_) => bail!("nobody allowed screen sharing on this computer in time"),
        Ok(Err(ashpd::Error::Response(ashpd::desktop::ResponseError::Cancelled))) => {
            bail!("screen sharing was not allowed on this computer")
        }
        Ok(r) => r.map_err(Into::into),
    }
}

fn first_stream(streams: &[ashpd::desktop::screencast::Stream]) -> anyhow::Result<(u32, Option<(u32, u32)>)> {
    let stream = streams.first().ok_or_else(|| anyhow!("no screen was shared"))?;
    let size = stream.size().and_then(|(w, h)| Some((u32::try_from(w).ok()?, u32::try_from(h).ok()?)));
    Ok((stream.pipe_wire_node_id(), size))
}

/// Receives the screen from PipeWire until told to quit.
fn pipewire_main(
    fd: OwnedFd,
    node_id: u32,
    frames: Arc<FrameSlot>,
    quit: pw::channel::Receiver<()>,
) -> anyhow::Result<()> {
    pw::init();
    let mainloop = pw::main_loop::MainLoopRc::new(None)?;
    let context = pw::context::ContextRc::new(&mainloop, None)?;
    let core = context.connect_fd_rc(fd, None)?;

    let _quit = quit.attach(mainloop.loop_(), {
        let mainloop = mainloop.clone();
        move |()| mainloop.quit()
    });

    let stream = pw::stream::StreamBox::new(
        &core,
        "somedesk-screen",
        pw::properties::properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        },
    )?;

    let _listener = stream
        .add_local_listener_with_user_data(spa::param::video::VideoInfoRaw::default())
        .state_changed({
            let mainloop = mainloop.clone();
            move |_, _, old, new| {
                tracing::debug!("PipeWire stream state {old:?} -> {new:?}");
                if let pw::stream::StreamState::Error(e) = &new {
                    tracing::error!("PipeWire stream error: {e}");
                    mainloop.quit();
                }
                if matches!(new, pw::stream::StreamState::Unconnected) {
                    mainloop.quit();
                }
            }
        })
        .param_changed(|_, info, id, param| {
            let Some(param) = param else { return };
            if id != spa::param::ParamType::Format.as_raw() {
                return;
            }
            if info.parse(param).is_ok() {
                tracing::info!(format = ?info.format(), size = ?info.size(), "PipeWire video format");
            }
        })
        .process(move |stream, info| {
            let Some(mut buffer) = stream.dequeue_buffer() else { return };
            let datas = buffer.datas_mut();
            let Some(d) = datas.first_mut() else { return };
            let (size, offset, stride) = (d.chunk().size() as usize, d.chunk().offset() as usize, d.chunk().stride());
            if size == 0 || stride <= 0 {
                return; // e.g. a cursor-only update
            }
            let (w, h) = (info.size().width, info.size().height);
            let Some(bytes) = d.data() else { return };
            let stride = stride as usize;
            let Some(src) = bytes.get(offset..offset + stride * h as usize) else { return };
            let data = match info.format() {
                spa::param::video::VideoFormat::BGRx | spa::param::video::VideoFormat::BGRA => src.to_vec(),
                spa::param::video::VideoFormat::RGBx | spa::param::video::VideoFormat::RGBA => {
                    let mut v = src.to_vec();
                    v.as_chunks_mut::<4>().0.iter_mut().for_each(|px| px.swap(0, 2));
                    v
                }
                other => {
                    tracing::warn!("unsupported PipeWire video format {other:?}");
                    return;
                }
            };
            let mut s = frames.state.lock().unwrap();
            s.latest = Some(Frame { width: w, height: h, stride, data, origin: None });
            frames.cond.notify_all();
        })
        .register()?;

    // Only shared-memory formats are offered (no DMA-BUF modifiers), so frames can be read
    // directly from the mapped buffers.
    use spa::param::format::{FormatProperties, MediaSubtype, MediaType};
    use spa::param::video::VideoFormat;
    let obj = spa::pod::object!(
        spa::utils::SpaTypes::ObjectParamFormat,
        spa::param::ParamType::EnumFormat,
        spa::pod::property!(FormatProperties::MediaType, Id, MediaType::Video),
        spa::pod::property!(FormatProperties::MediaSubtype, Id, MediaSubtype::Raw),
        spa::pod::property!(
            FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            VideoFormat::BGRx,
            VideoFormat::BGRx,
            VideoFormat::BGRA,
            VideoFormat::RGBx,
            VideoFormat::RGBA
        ),
        spa::pod::property!(
            FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            spa::utils::Rectangle { width: 1920, height: 1080 },
            spa::utils::Rectangle { width: 1, height: 1 },
            spa::utils::Rectangle { width: 8192, height: 8192 }
        ),
        spa::pod::property!(
            FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            spa::utils::Fraction { num: 30, denom: 1 },
            spa::utils::Fraction { num: 0, denom: 1 },
            spa::utils::Fraction { num: 60, denom: 1 }
        ),
    );
    let values: Vec<u8> =
        spa::pod::serialize::PodSerializer::serialize(std::io::Cursor::new(Vec::new()), &spa::pod::Value::Object(obj))
            .map_err(|e| anyhow!("serializing stream parameters: {e:?}"))?
            .0
            .into_inner();
    let mut params = [spa::pod::Pod::from_bytes(&values).ok_or_else(|| anyhow!("invalid stream parameters"))?];
    stream.connect(
        spa::utils::Direction::Input,
        Some(node_id),
        pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
        &mut params,
    )?;
    mainloop.run();
    Ok(())
}
