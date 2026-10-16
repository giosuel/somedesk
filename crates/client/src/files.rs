//! File transfer within a session, in both directions.
//!
//! Files travel inside the encrypted session as [`SessionMsg::FileChunk`]s on a low-priority
//! lane, so screen updates and input keep flowing during big transfers. The receiver writes to a
//! hidden partial file, checks size and SHA-256 at the end, and only then gives the file its real
//! name. Names are sanitized so a peer can never write outside the download folder.

use sha2::{Digest, Sha256};
use somedesk_proto::session::{SessionMsg, FILE_CHUNK};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Handle;
use tokio::sync::mpsc;

/// How many outgoing file messages may queue up before senders wait.
const LANE_CAPACITY: usize = 8;
/// Offers from the peer that may wait for the user's answer at once; more are declined.
const MAX_PENDING_OFFERS: usize = 16;
/// Files that may be coming in at once, waiting or accepted.
const MAX_INCOMING: usize = 64;
/// Minimum time between progress events for one transfer.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(150);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// We send.
    Upload,
    /// We receive.
    Download,
}

/// Whether incoming files are saved straight away or need the user's OK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptPolicy {
    Always,
    /// Emit [`TransferEvent::Offered`] and wait for [`FileTransfers::respond`].
    Ask,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransferEvent {
    /// The peer wants to send us a file (only with [`AcceptPolicy::Ask`]).
    Offered {
        id: u32,
        name: String,
        size: u64,
    },
    /// A transfer started (an upload waits for the peer to accept until the first progress).
    Started {
        id: u32,
        direction: Direction,
        name: String,
        size: u64,
    },
    Progress {
        id: u32,
        direction: Direction,
        done: u64,
        total: u64,
    },
    /// Finished and verified. For downloads, `path` is where the file was saved.
    Completed {
        id: u32,
        direction: Direction,
        name: String,
        path: Option<PathBuf>,
    },
    Failed {
        id: u32,
        direction: Direction,
        name: String,
        reason: String,
    },
}

pub type TransferSink = Arc<dyn Fn(TransferEvent) + Send + Sync>;

/// File transfers for one session. Cheap to clone; all clones are the same.
#[derive(Clone)]
pub struct FileTransfers {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    policy: AcceptPolicy,
    events: TransferSink,
    next_id: AtomicU32,
    /// Set while attached to a running session.
    lane: Mutex<Option<(mpsc::Sender<SessionMsg>, Handle)>>,
    outgoing: Mutex<HashMap<u32, Outgoing>>,
    incoming: tokio::sync::Mutex<HashMap<u32, Incoming>>,
}

struct Outgoing {
    replies: mpsc::UnboundedSender<Reply>,
    cancel: Arc<AtomicBool>,
}

#[derive(Debug)]
enum Reply {
    Accepted,
    Rejected(String),
    Result { ok: bool, message: String },
    Cancelled,
}

struct Incoming {
    name: String,
    size: u64,
    /// `None` until accepted.
    file: Option<tokio::fs::File>,
    part: PathBuf,
    received: u64,
    hasher: Sha256,
    last_progress: Instant,
}

impl FileTransfers {
    /// `dir` is where received files are saved (created on demand).
    pub fn new(dir: PathBuf, policy: AcceptPolicy, events: TransferSink) -> Self {
        Self {
            inner: Arc::new(Inner {
                dir,
                policy,
                events,
                next_id: AtomicU32::new(1),
                lane: Mutex::new(None),
                outgoing: Mutex::default(),
                incoming: tokio::sync::Mutex::default(),
            }),
        }
    }

    pub fn download_dir(&self) -> &Path {
        &self.inner.dir
    }

    /// Connects to a session: returns the lane of outgoing messages the session must send.
    /// Must be called from within the tokio runtime.
    pub(crate) fn attach(&self) -> mpsc::Receiver<SessionMsg> {
        let (tx, rx) = mpsc::channel(LANE_CAPACITY);
        *self.inner.lane.lock().unwrap() = Some((tx, Handle::current()));
        rx
    }

    /// Disconnects from the session: aborts every transfer and removes partial files.
    pub(crate) async fn detach(&self) {
        *self.inner.lane.lock().unwrap() = None;
        let outgoing: Vec<_> = self.inner.outgoing.lock().unwrap().drain().collect();
        for (_, o) in outgoing {
            o.cancel.store(true, Ordering::Relaxed);
            let _ = o.replies.send(Reply::Cancelled);
        }
        let incoming: Vec<_> = self.inner.incoming.lock().await.drain().collect();
        for (id, inc) in incoming {
            drop(inc.file);
            let _ = tokio::fs::remove_file(&inc.part).await;
            self.emit(TransferEvent::Failed {
                id,
                direction: Direction::Download,
                name: inc.name,
                reason: "the session ended".into(),
            });
        }
    }

    fn emit(&self, ev: TransferEvent) {
        (self.inner.events)(ev);
    }

    fn lane(&self) -> Option<(mpsc::Sender<SessionMsg>, Handle)> {
        self.inner.lane.lock().unwrap().clone()
    }

    /// Starts sending `path` to the peer. Returns the transfer id; progress is reported through
    /// the event sink.
    pub fn send_file(&self, path: &Path) -> crate::Result<u32> {
        let Some((lane, rt)) = self.lane() else {
            return Err(crate::ClientError::Other("no session is running".into()));
        };
        let meta =
            std::fs::metadata(path).map_err(|e| crate::ClientError::Other(format!("{}: {e}", path.display())))?;
        if !meta.is_file() {
            return Err(crate::ClientError::Other(format!("{} is not a file", path.display())));
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(sanitize_file_name)
            .ok_or_else(|| crate::ClientError::Other(format!("{} has no usable name", path.display())))?;
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let (replies_tx, replies) = mpsc::unbounded_channel();
        let cancel = Arc::new(AtomicBool::new(false));
        self.inner.outgoing.lock().unwrap().insert(id, Outgoing { replies: replies_tx, cancel: cancel.clone() });
        let this = self.clone();
        let path = path.to_owned();
        rt.spawn(async move {
            let size = meta.len();
            this.emit(TransferEvent::Started { id, direction: Direction::Upload, name: name.clone(), size });
            let job = Upload { id, path: &path, name: &name, size };
            let result = this.upload(job, lane.clone(), replies, &cancel).await;
            this.inner.outgoing.lock().unwrap().remove(&id);
            match result {
                Ok(()) => this.emit(TransferEvent::Completed { id, direction: Direction::Upload, name, path: None }),
                Err(reason) => {
                    if reason.notify_peer {
                        let _ = lane.send(SessionMsg::FileCancel { id, by_sender: true }).await;
                    }
                    this.emit(TransferEvent::Failed { id, direction: Direction::Upload, name, reason: reason.message })
                }
            }
        });
        Ok(id)
    }

    async fn upload(
        &self,
        Upload { id, path, name, size }: Upload<'_>,
        lane: mpsc::Sender<SessionMsg>,
        mut replies: mpsc::UnboundedReceiver<Reply>,
        cancel: &AtomicBool,
    ) -> Result<(), UploadError> {
        let gone = || UploadError::quiet("the session ended");
        lane.send(SessionMsg::FileOffer { id, name: name.to_owned(), size }).await.map_err(|_| gone())?;
        match replies.recv().await {
            Some(Reply::Accepted) => {}
            Some(Reply::Rejected(reason)) => return Err(UploadError::quiet(format!("declined: {reason}"))),
            Some(Reply::Cancelled) | None => return Err(UploadError::quiet("cancelled")),
            Some(Reply::Result { .. }) => return Err(UploadError::loud("unexpected reply")),
        }
        let mut file = tokio::fs::File::open(path).await.map_err(|e| UploadError::loud(e.to_string()))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; FILE_CHUNK];
        let mut offset = 0u64;
        let mut last_progress = Instant::now();
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(UploadError::loud("cancelled"));
            }
            let n = file.read(&mut buf).await.map_err(|e| UploadError::loud(e.to_string()))?;
            if n == 0 {
                break;
            }
            if offset + n as u64 > size {
                return Err(UploadError::loud("the file changed while it was being sent"));
            }
            hasher.update(&buf[..n]);
            lane.send(SessionMsg::FileChunk { id, offset, data: buf[..n].to_vec() }).await.map_err(|_| gone())?;
            offset += n as u64;
            if last_progress.elapsed() >= PROGRESS_INTERVAL {
                last_progress = Instant::now();
                self.emit(TransferEvent::Progress { id, direction: Direction::Upload, done: offset, total: size });
            }
        }
        if offset != size {
            return Err(UploadError::loud("the file changed while it was being sent"));
        }
        self.emit(TransferEvent::Progress { id, direction: Direction::Upload, done: size, total: size });
        lane.send(SessionMsg::FileDone { id, sha256: hasher.finalize().into() }).await.map_err(|_| gone())?;
        match replies.recv().await {
            Some(Reply::Result { ok: true, .. }) => Ok(()),
            Some(Reply::Result { ok: false, message }) => Err(UploadError::quiet(message)),
            _ => Err(UploadError::quiet("the other side did not confirm the file")),
        }
    }

    /// Cancels one of our transfers (either direction).
    pub fn cancel(&self, id: u32, direction: Direction) {
        match direction {
            Direction::Upload => {
                if let Some(o) = self.inner.outgoing.lock().unwrap().get(&id) {
                    o.cancel.store(true, Ordering::Relaxed);
                    let _ = o.replies.send(Reply::Cancelled);
                }
            }
            Direction::Download => {
                let this = self.clone();
                if let Some((lane, rt)) = self.lane() {
                    rt.spawn(async move {
                        if let Some(inc) = this.inner.incoming.lock().await.remove(&id) {
                            drop(inc.file);
                            let _ = tokio::fs::remove_file(&inc.part).await;
                            let _ = lane.send(SessionMsg::FileCancel { id, by_sender: false }).await;
                            this.emit(TransferEvent::Failed {
                                id,
                                direction: Direction::Download,
                                name: inc.name,
                                reason: "cancelled".into(),
                            });
                        }
                    });
                }
            }
        }
    }

    /// Answers a [`TransferEvent::Offered`].
    pub fn respond(&self, id: u32, accept: bool) {
        let this = self.clone();
        if let Some((_, rt)) = self.lane() {
            rt.spawn(async move {
                if accept {
                    this.accept(id).await;
                } else {
                    this.reject(id, "declined").await;
                }
            });
        }
    }

    async fn send_msg(&self, msg: SessionMsg) {
        if let Some((lane, _)) = self.lane() {
            let _ = lane.send(msg).await;
        }
    }

    async fn accept(&self, id: u32) {
        let mut incoming = self.inner.incoming.lock().await;
        let Some(inc) = incoming.get_mut(&id).filter(|i| i.file.is_none()) else { return };
        let opened = async {
            tokio::fs::create_dir_all(&self.inner.dir).await?;
            tokio::fs::OpenOptions::new().write(true).create_new(true).open(&inc.part).await
        }
        .await;
        match opened {
            Ok(f) => {
                inc.file = Some(f);
                let (name, size) = (inc.name.clone(), inc.size);
                drop(incoming);
                self.emit(TransferEvent::Started { id, direction: Direction::Download, name, size });
                self.send_msg(SessionMsg::FileAccept { id }).await;
            }
            Err(e) => {
                let name = inc.name.clone();
                incoming.remove(&id);
                drop(incoming);
                let reason = format!("cannot save the file: {e}");
                self.emit(TransferEvent::Failed { id, direction: Direction::Download, name, reason: reason.clone() });
                self.send_msg(SessionMsg::FileReject { id, reason }).await;
            }
        }
    }

    async fn reject(&self, id: u32, reason: &str) {
        if self.inner.incoming.lock().await.remove(&id).is_some() {
            self.send_msg(SessionMsg::FileReject { id, reason: reason.into() }).await;
        }
    }

    /// Handles a file message from the peer. Returns `false` if `msg` is not a file message.
    pub(crate) async fn handle(&self, msg: &SessionMsg) -> bool {
        match msg {
            SessionMsg::FileOffer { id, name, size } => self.on_offer(*id, name, *size).await,
            SessionMsg::FileChunk { id, offset, data } => self.on_chunk(*id, *offset, data).await,
            SessionMsg::FileDone { id, sha256 } => self.on_done(*id, sha256).await,
            SessionMsg::FileCancel { id, by_sender: true } => {
                if let Some(inc) = self.inner.incoming.lock().await.remove(id) {
                    drop(inc.file);
                    let _ = tokio::fs::remove_file(&inc.part).await;
                    self.emit(TransferEvent::Failed {
                        id: *id,
                        direction: Direction::Download,
                        name: inc.name,
                        reason: "cancelled by the other side".into(),
                    });
                }
            }
            SessionMsg::FileAccept { id } => self.reply(*id, Reply::Accepted),
            SessionMsg::FileReject { id, reason } => self.reply(*id, Reply::Rejected(reason.clone())),
            SessionMsg::FileResult { id, ok, message } => {
                self.reply(*id, Reply::Result { ok: *ok, message: message.clone() })
            }
            SessionMsg::FileCancel { id, by_sender: false } => {
                if let Some(o) = self.inner.outgoing.lock().unwrap().get(id) {
                    o.cancel.store(true, Ordering::Relaxed);
                    let _ = o.replies.send(Reply::Rejected("cancelled by the other side".into()));
                }
            }
            _ => return false,
        }
        true
    }

    fn reply(&self, id: u32, reply: Reply) {
        if let Some(o) = self.inner.outgoing.lock().unwrap().get(&id) {
            let _ = o.replies.send(reply);
        }
    }

    async fn on_offer(&self, id: u32, name: &str, size: u64) {
        let named = sanitize_file_name(name)
            .and_then(|name| Some((inside(&self.inner.dir, &format!(".{name}.{id}.somedesk-part"))?, name)));
        let Some((part, name)) = named else {
            self.send_msg(SessionMsg::FileReject { id, reason: "invalid file name".into() }).await;
            return;
        };
        {
            let mut incoming = self.inner.incoming.lock().await;
            if incoming.contains_key(&id) {
                return;
            }
            let waiting = incoming.values().filter(|i| i.file.is_none()).count();
            if waiting >= MAX_PENDING_OFFERS || incoming.len() >= MAX_INCOMING {
                drop(incoming);
                self.send_msg(SessionMsg::FileReject { id, reason: "too many files at once".into() }).await;
                return;
            }
            incoming.insert(
                id,
                Incoming {
                    name: name.clone(),
                    size,
                    file: None,
                    part,
                    received: 0,
                    hasher: Sha256::new(),
                    last_progress: Instant::now(),
                },
            );
        }
        match self.inner.policy {
            AcceptPolicy::Always => self.accept(id).await,
            AcceptPolicy::Ask => self.emit(TransferEvent::Offered { id, name, size }),
        }
    }

    async fn on_chunk(&self, id: u32, offset: u64, data: &[u8]) {
        let mut incoming = self.inner.incoming.lock().await;
        let Some(inc) = incoming.get_mut(&id) else { return };
        let problem = match &mut inc.file {
            None => Some("data arrived before the file was accepted".to_string()),
            Some(_) if offset != inc.received => Some("data arrived out of order".into()),
            Some(_) if inc.received + data.len() as u64 > inc.size => Some("more data than announced".into()),
            Some(f) => f.write_all(data).await.err().map(|e| format!("cannot write the file: {e}")),
        };
        if let Some(reason) = problem {
            let inc = incoming.remove(&id).expect("present");
            drop(incoming);
            drop(inc.file);
            let _ = tokio::fs::remove_file(&inc.part).await;
            self.send_msg(SessionMsg::FileCancel { id, by_sender: false }).await;
            self.emit(TransferEvent::Failed { id, direction: Direction::Download, name: inc.name, reason });
            return;
        }
        inc.hasher.update(data);
        inc.received += data.len() as u64;
        if inc.last_progress.elapsed() >= PROGRESS_INTERVAL {
            inc.last_progress = Instant::now();
            let ev =
                TransferEvent::Progress { id, direction: Direction::Download, done: inc.received, total: inc.size };
            drop(incoming);
            self.emit(ev);
        }
    }

    async fn on_done(&self, id: u32, sha256: &[u8; 32]) {
        let Some(mut inc) = self.inner.incoming.lock().await.remove(&id) else { return };
        let result = async {
            let mut file = inc.file.take().ok_or("the file was never accepted")?;
            file.flush().await.map_err(|_| "cannot write the file")?;
            file.sync_all().await.map_err(|_| "cannot write the file")?;
            drop(file);
            if inc.received != inc.size {
                return Err("the file arrived incomplete");
            }
            let digest: [u8; 32] = std::mem::take(&mut inc.hasher).finalize().into();
            if &digest != sha256 {
                return Err("the file arrived damaged (checksum mismatch)");
            }
            let dest = unique_path(&self.inner.dir, &inc.name).await.ok_or("invalid file name")?;
            tokio::fs::rename(&inc.part, &dest).await.map_err(|_| "cannot save the file")?;
            Ok(dest)
        }
        .await;
        match result {
            Ok(path) => {
                self.send_msg(SessionMsg::FileResult { id, ok: true, message: String::new() }).await;
                self.emit(TransferEvent::Progress {
                    id,
                    direction: Direction::Download,
                    done: inc.size,
                    total: inc.size,
                });
                self.emit(TransferEvent::Completed {
                    id,
                    direction: Direction::Download,
                    name: inc.name,
                    path: Some(path),
                });
            }
            Err(reason) => {
                let _ = tokio::fs::remove_file(&inc.part).await;
                self.send_msg(SessionMsg::FileResult { id, ok: false, message: reason.into() }).await;
                self.emit(TransferEvent::Failed {
                    id,
                    direction: Direction::Download,
                    name: inc.name,
                    reason: reason.into(),
                });
            }
        }
    }
}

struct Upload<'a> {
    id: u32,
    path: &'a Path,
    name: &'a str,
    size: u64,
}

struct UploadError {
    message: String,
    /// Tell the peer to throw away what it has so far.
    notify_peer: bool,
}

impl UploadError {
    fn quiet(m: impl Into<String>) -> Self {
        Self { message: m.into(), notify_peer: false }
    }
    fn loud(m: impl Into<String>) -> Self {
        Self { message: m.into(), notify_peer: true }
    }
}

/// Makes a file name from the peer safe to use, on every system the file may end up on: no
/// directories, no drive prefixes or NTFS streams (`:`), none of the characters Windows forbids
/// (they become `_`), no control or invisible formatting characters (such as the bidi overrides
/// that make `exe.txt` out of `txt.exe`), no hidden files, no trailing dots or spaces, no reserved
/// device names (`CON`, `NUL.txt`, `COM1`, ...), at most 200 bytes. Returns `None` if nothing
/// usable is left.
pub fn sanitize_file_name(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && !is_format_char(*c))
        .map(|c| if matches!(c, ':' | '<' | '>' | '"' | '|' | '?' | '*') { '_' } else { c })
        .collect();
    let cleaned = trim_name(cleaned.trim_start().trim_start_matches('.'));
    if cleaned.is_empty() {
        return None;
    }
    let mut out = cleaned.to_owned();
    if out.len() > 200 {
        // Keep the extension when shortening.
        let ext = Path::new(&out).extension().and_then(|e| e.to_str()).filter(|e| e.len() <= 16).map(str::to_owned);
        let keep = 200 - ext.as_ref().map_or(0, |e| e.len() + 1);
        let mut cut = keep;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.truncate(trim_name(&out).len());
        if let Some(ext) = ext {
            out.push('.');
            out.push_str(&ext);
        }
    }
    if is_reserved_device_name(&out) {
        out.insert(0, '_');
    }
    Some(out).filter(|n| is_plain_name(n))
}

/// Without the leading and trailing spaces and the trailing dots Windows drops from names.
fn trim_name(name: &str) -> &str {
    name.trim().trim_end_matches(['.', ' ']).trim()
}

/// Unicode format characters (category Cf): invisible, and some reorder the text around them.
fn is_format_char(c: char) -> bool {
    matches!(c,
        '\u{ad}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}' | '\u{180e}'
        | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}'
        | '\u{e0001}' | '\u{e0020}'..='\u{e007f}')
}

/// Names Windows maps to devices, with any extension: `NUL.txt` is the device too.
fn is_reserved_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    match stem.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        s => ["COM", "LPT"].iter().any(|p| {
            s.strip_prefix(p)
                .is_some_and(|d| (d.len() == 1 && d.as_bytes()[0].is_ascii_digit()) || matches!(d, "¹" | "²" | "³"))
        }),
    }
}

/// Whether `name`, joined to a directory, names an entry right inside it on any system.
fn is_plain_name(name: &str) -> bool {
    let mut parts = Path::new(name).components();
    matches!(parts.next(), Some(std::path::Component::Normal(_)))
        && parts.next().is_none()
        && !name.contains(['/', '\\', ':'])
}

/// `dir.join(name)`, refusing anything that would not end up right inside `dir`.
fn inside(dir: &Path, name: &str) -> Option<PathBuf> {
    let path = dir.join(name);
    (is_plain_name(name) && path.parent() == Some(dir)).then_some(path)
}

/// `dir/name`, or `dir/name (2).ext`, ... if that exists already. `None` if `name` would not
/// land right inside `dir`.
async fn unique_path(dir: &Path, name: &str) -> Option<PathBuf> {
    let first = inside(dir, name)?;
    if tokio::fs::try_exists(&first).await.ok() == Some(false) {
        return Some(first);
    }
    let p = Path::new(name);
    let (stem, ext) = match (p.file_stem().and_then(|s| s.to_str()), p.extension().and_then(|e| e.to_str())) {
        (Some(s), Some(e)) => (s.to_owned(), format!(".{e}")),
        _ => (name.to_owned(), String::new()),
    };
    for i in 2.. {
        let candidate = inside(dir, &format!("{stem} ({i}){ext}"))?;
        if tokio::fs::try_exists(&candidate).await.ok() == Some(false) {
            return Some(candidate);
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_are_sanitized() {
        assert_eq!(sanitize_file_name("report.pdf").as_deref(), Some("report.pdf"));
        assert_eq!(sanitize_file_name("../../etc/passwd").as_deref(), Some("passwd"));
        assert_eq!(sanitize_file_name("C:\\Users\\bob\\notes.txt").as_deref(), Some("notes.txt"));
        assert_eq!(sanitize_file_name(".bashrc").as_deref(), Some("bashrc"));
        assert_eq!(sanitize_file_name("a\u{0}b\nc.txt").as_deref(), Some("abc.txt"));
        assert_eq!(sanitize_file_name("Übersicht 2026 ✓.odt").as_deref(), Some("Übersicht 2026 ✓.odt"));
        assert_eq!(sanitize_file_name(".."), None);
        assert_eq!(sanitize_file_name("dir/"), None);
        assert_eq!(sanitize_file_name("   "), None);
        // Windows: drive prefixes, streams, forbidden characters, devices, trailing dots.
        assert_eq!(sanitize_file_name("C:evil.exe").as_deref(), Some("C_evil.exe"));
        assert_eq!(sanitize_file_name("D:x.bat").as_deref(), Some("D_x.bat"));
        assert_eq!(sanitize_file_name("notes.txt:hidden").as_deref(), Some("notes.txt_hidden"));
        assert_eq!(sanitize_file_name("a<b>c\"d|e?f*.txt").as_deref(), Some("a_b_c_d_e_f_.txt"));
        assert_eq!(sanitize_file_name("CON").as_deref(), Some("_CON"));
        assert_eq!(sanitize_file_name("nul.txt").as_deref(), Some("_nul.txt"));
        assert_eq!(sanitize_file_name("Com1.tar.gz").as_deref(), Some("_Com1.tar.gz"));
        assert_eq!(sanitize_file_name("LPT9").as_deref(), Some("_LPT9"));
        assert_eq!(sanitize_file_name("COM¹").as_deref(), Some("_COM¹"));
        assert_eq!(sanitize_file_name("console.log").as_deref(), Some("console.log"));
        assert_eq!(sanitize_file_name("COM10").as_deref(), Some("COM10"));
        assert_eq!(sanitize_file_name("äé").as_deref(), Some("äé"));
        assert_eq!(sanitize_file_name("report.pdf. . ").as_deref(), Some("report.pdf"));
        assert_eq!(sanitize_file_name("..."), None);
        assert_eq!(sanitize_file_name(". ."), None);
        // Invisible characters, among them the override that shows "exe.txt" for "txt.exe".
        assert_eq!(sanitize_file_name("invoice\u{202e}txt.exe").as_deref(), Some("invoicetxt.exe"));
        assert_eq!(sanitize_file_name("a\u{200b}b\u{feff}.txt").as_deref(), Some("ab.txt"));
        assert_eq!(sanitize_file_name("\u{2066}\u{2069}"), None);
        let long = format!("{}.tar.gz", "ä".repeat(300));
        let s = sanitize_file_name(&long).unwrap();
        assert!(s.len() <= 200 && s.ends_with(".gz"), "{s}");
        let dotted = format!("{}.{}.txt", "a".repeat(190), ".".repeat(20));
        let s = sanitize_file_name(&dotted).unwrap();
        assert!(!s.contains("..") && s.ends_with("a.txt"), "{s}");
    }

    #[test]
    fn sanitized_names_stay_inside_the_folder() {
        let dir = Path::new("downloads");
        for name in ["C:evil.exe", "\\\\server\\share\\x", "a/../../b", "..\\..\\x", "/abs", "x:", "CON", "?"] {
            if let Some(clean) = sanitize_file_name(name) {
                assert_eq!(inside(dir, &clean).unwrap().parent(), Some(dir), "{name} -> {clean}");
            }
        }
    }

    #[tokio::test]
    async fn unanswered_offers_are_capped() {
        let dir = std::env::temp_dir().join(format!("somedesk-offers-{}", std::process::id()));
        let offered = Arc::new(AtomicU32::new(0));
        let sink: TransferSink = {
            let offered = offered.clone();
            Arc::new(move |ev| {
                if matches!(ev, TransferEvent::Offered { .. }) {
                    offered.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        let ft = FileTransfers::new(dir.clone(), AcceptPolicy::Ask, sink);
        let mut lane = ft.attach();
        for id in 0..MAX_PENDING_OFFERS as u32 + 3 {
            assert!(ft.handle(&SessionMsg::FileOffer { id, name: format!("f{id}"), size: 1 }).await);
        }
        assert_eq!(offered.load(Ordering::Relaxed), MAX_PENDING_OFFERS as u32, "only so many dialogs");
        for _ in 0..3 {
            assert!(matches!(lane.recv().await, Some(SessionMsg::FileReject { .. })));
        }
        ft.detach().await;
        assert!(!dir.exists(), "nothing was written");
    }

    #[tokio::test]
    async fn unique_paths_do_not_overwrite() {
        let dir = std::env::temp_dir().join(format!("somedesk-unique-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique_path(&dir, "a.txt").await, Some(dir.join("a.txt")));
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "a.txt").await, Some(dir.join("a (2).txt")));
        std::fs::write(dir.join("a (2).txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "a.txt").await, Some(dir.join("a (3).txt")));
        std::fs::write(dir.join("noext"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "noext").await, Some(dir.join("noext (2)")));
        for bad in ["../x", "a/b", "C:x.exe", "..", "/etc/passwd", ""] {
            assert_eq!(unique_path(&dir, bad).await, None, "{bad}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
