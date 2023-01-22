//! Viewer side of a session: receive → decode → display, and forward local input.

use crate::clipboard::ClipboardSync;
use crate::session::Channel;
use crate::{ClientError, Result, SessionExtras};
use somedesk_codec::{H264Decoder, RgbFrame};
use somedesk_proto::session::SessionMsg;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub enum ViewerEvent {
    /// The host accepted; frames will follow.
    Accepted,
    ScreenInfo {
        width: u32,
        height: u32,
    },
    Frame(RgbFrame),
    /// The host only allows viewing; input is ignored.
    ViewOnly,
    /// Round-trip time measured with pings.
    Latency(Duration),
}

pub type EventSink = Arc<dyn Fn(ViewerEvent) + Send + Sync>;

/// How long to wait for the person at the host to accept.
pub const ACCEPT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub enum SessionEnd {
    /// The host or viewer ended the session normally.
    Closed,
    Rejected(String),
}

/// Runs the viewer until the session ends. Input events to forward (pointer, keys, scroll) are
/// read from `input`; dropping its sender ends the session. With a clipboard in `extras`,
/// clipboard text is shared in both directions, starting with what the viewer's clipboard holds
/// now; with file transfers, files can be sent either way.
pub async fn run(
    ch: Channel,
    events: EventSink,
    mut input: mpsc::UnboundedReceiver<SessionMsg>,
    extras: SessionExtras,
) -> Result<SessionEnd> {
    let SessionExtras { clipboard, files } = extras;
    let Channel { mut sender, mut receiver, .. } = ch;

    let first = tokio::time::timeout(ACCEPT_TIMEOUT, receiver.recv::<SessionMsg>())
        .await
        .map_err(|_| ClientError::Other("the remote side did not accept in time".into()))??;
    match first {
        Some(SessionMsg::Accept) => events(ViewerEvent::Accepted),
        Some(SessionMsg::Reject { reason }) => return Ok(SessionEnd::Rejected(reason)),
        None | Some(SessionMsg::Bye) => return Ok(SessionEnd::Rejected("the connection was declined".into())),
        Some(_) => return Err(ClientError::Protocol("expected accept or reject")),
    }

    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel::<SessionMsg>();
    let (video_tx, video_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let decoder = {
        let (events, ctrl_tx) = (events.clone(), ctrl_tx.clone());
        std::thread::Builder::new()
            .name("somedesk-decode".into())
            .spawn(move || decode_loop(video_rx, events, ctrl_tx))
            .expect("spawn decoder thread")
    };
    let clipboard = clipboard.map(|c| ClipboardSync::start(c, ctrl_tx.clone(), true));
    let (mut file_rx, _no_files) = crate::file_lane(&files);

    let start = Instant::now();
    let send_loop = async {
        let mut ping = tokio::time::interval(Duration::from_secs(2));
        loop {
            let msg = tokio::select! {
                biased;
                m = ctrl_rx.recv() => m,
                m = input.recv() => match m { Some(m) => Some(m), None => return Ok::<_, ClientError>(()) },
                _ = ping.tick() => Some(SessionMsg::Ping { t: start.elapsed().as_micros() as u64 }),
                m = file_rx.recv() => m,
            };
            if let Some(msg) = msg {
                sender.send(&msg).await?;
            }
        }
    };
    let recv_loop = async {
        loop {
            match receiver.recv::<SessionMsg>().await? {
                None | Some(SessionMsg::Bye) => return Ok::<_, ClientError>(()),
                Some(SessionMsg::Video { data, .. }) => {
                    if video_tx.send(data).is_err() {
                        return Ok(());
                    }
                }
                Some(SessionMsg::ScreenInfo { width, height }) => events(ViewerEvent::ScreenInfo { width, height }),
                Some(SessionMsg::ViewOnly) => events(ViewerEvent::ViewOnly),
                Some(SessionMsg::Pong { t }) => {
                    let rtt = start.elapsed().saturating_sub(Duration::from_micros(t));
                    events(ViewerEvent::Latency(rtt));
                }
                Some(SessionMsg::Ping { t }) => {
                    let _ = ctrl_tx.send(SessionMsg::Pong { t });
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
                        tracing::debug!("ignoring unexpected message from host: {other:?}")
                    }
                }
            }
        }
    };
    let result = match tokio::select! {
        r = send_loop => r,
        r = recv_loop => r,
    } {
        Err(e) if e.is_peer_gone() => Ok(()),
        r => r,
    };
    let _ = sender.send(&SessionMsg::Bye).await;
    let _ = sender.into_inner().finish();
    if let Some(f) = &files {
        f.detach().await;
    }
    drop(video_tx);
    let clipboard = clipboard.map(ClipboardSync::stop);
    let _ = tokio::task::spawn_blocking(move || {
        let _ = decoder.join();
        if let Some(c) = clipboard {
            let _ = c.join();
        }
    })
    .await;
    result.map(|_| SessionEnd::Closed)
}

fn decode_loop(rx: std::sync::mpsc::Receiver<Vec<u8>>, events: EventSink, ctrl: mpsc::UnboundedSender<SessionMsg>) {
    let mut decoder = match H264Decoder::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("cannot create decoder: {e:#}");
            return;
        }
    };
    let mut last_keyframe_request: Option<Instant> = None;
    while let Ok(mut data) = rx.recv() {
        // If we fall behind, decode everything (H.264 needs every frame) but only display the newest.
        let mut latest = None;
        loop {
            match decoder.decode(&data) {
                Ok(Some(frame)) => latest = Some(frame),
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!("decode error: {e:#}");
                    if last_keyframe_request.is_none_or(|t| t.elapsed() > Duration::from_millis(500)) {
                        let _ = ctrl.send(SessionMsg::RequestKeyframe);
                        last_keyframe_request = Some(Instant::now());
                    }
                }
            }
            match rx.try_recv() {
                Ok(next) => data = next,
                Err(_) => break,
            }
        }
        if let Some(frame) = latest {
            events(ViewerEvent::Frame(frame));
        }
    }
}
