//! Viewer side of a session: receive → decode → display, and forward local input.

use crate::clipboard::ClipboardSync;
use crate::session::Channel;
use crate::{ClientError, Result, SessionExtras};
use somedesk_codec::{H264Decoder, RgbFrame};
use somedesk_proto::session::SessionMsg;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
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
    /// The host has several monitors; `selected` is the one shown (`None`: all).
    Monitors {
        list: Vec<somedesk_proto::session::MonitorInfo>,
        selected: Option<u32>,
    },
    /// Round-trip time measured with pings.
    Latency(Duration),
}

pub type EventSink = Arc<dyn Fn(ViewerEvent) + Send + Sync>;

/// How long to wait for the person at the host to accept.
pub const ACCEPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Video messages that may wait for the decoder, in number and in bytes. A decoder that falls
/// further behind skips ahead to the next keyframe.
const VIDEO_QUEUE_FRAMES: usize = 8;
const VIDEO_QUEUE_BYTES: usize = 64 * 1024 * 1024;
/// Control messages (pongs, keyframe requests, clipboard) waiting to be sent.
const CTRL_QUEUE: usize = 64;

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

    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<SessionMsg>(CTRL_QUEUE);
    let (mut video, video_rx) = VideoQueue::new();
    let decoder = {
        let (events, ctrl_tx, queued) = (events.clone(), ctrl_tx.clone(), video.bytes.clone());
        std::thread::Builder::new()
            .name("somedesk-decode".into())
            .spawn(move || decode_loop(video_rx, queued, events, ctrl_tx))
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
                Some(SessionMsg::Video { data, keyframe, .. }) => match video.push(data, keyframe) {
                    Queued::Yes => {}
                    Queued::Dropped { request_keyframe } => {
                        if request_keyframe {
                            let _ = ctrl_tx.try_send(SessionMsg::RequestKeyframe);
                        }
                    }
                    Queued::Closed => return Ok(()),
                },
                Some(SessionMsg::ScreenInfo { width, height }) => events(ViewerEvent::ScreenInfo { width, height }),
                Some(SessionMsg::ViewOnly) => events(ViewerEvent::ViewOnly),
                Some(SessionMsg::Monitors { list, selected }) => events(ViewerEvent::Monitors { list, selected }),
                Some(SessionMsg::Pong { t }) => {
                    let rtt = start.elapsed().saturating_sub(Duration::from_micros(t));
                    events(ViewerEvent::Latency(rtt));
                }
                Some(SessionMsg::Ping { t }) => {
                    // A host that pings faster than we can answer gets fewer answers.
                    let _ = ctrl_tx.try_send(SessionMsg::Pong { t });
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
    crate::session::finish_stream(sender.into_inner()).await;
    if let Some(f) = &files {
        f.detach().await;
    }
    drop(video);
    // Unblocks the clipboard thread if it waits for room in the queue.
    drop(ctrl_rx);
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

/// The decoder's queue, bounded in frames and bytes. H.264 frames depend on the ones before, so
/// once one has to be dropped, everything up to the next keyframe is dropped too.
struct VideoQueue {
    tx: SyncSender<Vec<u8>>,
    /// Bytes queued and not yet taken by the decoder.
    bytes: Arc<AtomicUsize>,
    skipping: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Queued {
    Yes,
    /// Dropped; ask the host for a keyframe if `request_keyframe`.
    Dropped {
        request_keyframe: bool,
    },
    /// The decoder is gone.
    Closed,
}

impl VideoQueue {
    fn new() -> (Self, Receiver<Vec<u8>>) {
        let (tx, rx) = std::sync::mpsc::sync_channel(VIDEO_QUEUE_FRAMES);
        (Self { tx, bytes: Arc::default(), skipping: false }, rx)
    }

    fn push(&mut self, data: Vec<u8>, keyframe: bool) -> Queued {
        if self.skipping && !keyframe {
            return Queued::Dropped { request_keyframe: false };
        }
        let len = data.len();
        let queued = self.bytes.fetch_add(len, Ordering::AcqRel);
        if queued > 0 && queued + len > VIDEO_QUEUE_BYTES {
            self.bytes.fetch_sub(len, Ordering::AcqRel);
            return self.skip();
        }
        match self.tx.try_send(data) {
            Ok(()) => {
                self.skipping = false;
                Queued::Yes
            }
            Err(TrySendError::Full(_)) => {
                self.bytes.fetch_sub(len, Ordering::AcqRel);
                self.skip()
            }
            Err(TrySendError::Disconnected(_)) => Queued::Closed,
        }
    }

    /// Starts (or goes on) waiting for a keyframe; asks for one when starting, and again when a
    /// keyframe itself had to be dropped.
    fn skip(&mut self) -> Queued {
        tracing::debug!("the decoder is behind; skipping to the next keyframe");
        self.skipping = true;
        Queued::Dropped { request_keyframe: true }
    }
}

fn decode_loop(rx: Receiver<Vec<u8>>, queued: Arc<AtomicUsize>, events: EventSink, ctrl: mpsc::Sender<SessionMsg>) {
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
            queued.fetch_sub(data.len(), Ordering::AcqRel);
            match decoder.decode(&data) {
                Ok(Some(frame)) => latest = Some(frame),
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!("decode error: {e:#}");
                    if last_keyframe_request.is_none_or(|t| t.elapsed() > Duration::from_millis(500)) {
                        let _ = ctrl.try_send(SessionMsg::RequestKeyframe);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_decoder_that_falls_behind_skips_to_the_next_keyframe() {
        let (mut q, rx) = VideoQueue::new();
        assert_eq!(q.push(vec![1; 10], true), Queued::Yes);
        for _ in 1..VIDEO_QUEUE_FRAMES {
            assert_eq!(q.push(vec![2; 10], false), Queued::Yes);
        }
        assert_eq!(q.push(vec![3; 10], false), Queued::Dropped { request_keyframe: true }, "full");
        // Room again, but frames that build on the dropped one are no use.
        let taken = rx.recv().unwrap();
        q.bytes.fetch_sub(taken.len(), Ordering::AcqRel);
        assert_eq!(q.push(vec![4; 10], false), Queued::Dropped { request_keyframe: false });
        assert_eq!(q.push(vec![5; 10], true), Queued::Yes, "a keyframe starts over");
        assert_eq!(q.push(vec![6; 10], false), Queued::Dropped { request_keyframe: true }, "full again");
        drop(rx);
        assert_eq!(q.push(vec![7; 10], true), Queued::Closed);
    }

    #[test]
    fn the_queue_is_bounded_in_bytes_too() {
        let (mut q, rx) = VideoQueue::new();
        assert_eq!(q.push(vec![0; VIDEO_QUEUE_BYTES / 2], true), Queued::Yes);
        assert_eq!(q.push(vec![0; VIDEO_QUEUE_BYTES / 2], false), Queued::Yes);
        assert_eq!(q.push(vec![0; 1], false), Queued::Dropped { request_keyframe: true });
        assert_eq!(q.bytes.load(Ordering::Relaxed), VIDEO_QUEUE_BYTES);
        // A single frame larger than the budget still gets through an empty queue.
        let (mut q, _rx2) = VideoQueue::new();
        assert_eq!(q.push(vec![0; VIDEO_QUEUE_BYTES + 1], true), Queued::Yes);
        drop(rx);
    }
}
