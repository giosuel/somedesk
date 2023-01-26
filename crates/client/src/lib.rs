//! SomeDesk client core, shared by the desktop app and the integration tests.
//!
//! * [`server`] — connection to the SomeDesk server (control protocol, account flows, relay).
//! * [`credentials`] — what a device persists after enrollment.
//! * [`session`] — establishing the end-to-end encrypted channel to a peer device.
//! * [`host`] / [`viewer`] — the two ends of a remote-control session.
//! * [`trust`] — remembered peer identities and devices allowed to connect unattended.
//! * [`clipboard`] / [`files`] — clipboard sharing and file transfer within a session.

pub mod clipboard;
pub mod credentials;
pub mod files;
pub mod host;
pub mod server;
pub mod session;
mod tls;
pub mod trust;
pub mod viewer;

use somedesk_proto::control::ErrorInfo;

/// Optional parts of a session, for either side.
#[derive(Default)]
pub struct SessionExtras {
    /// Share this clipboard with the peer.
    pub clipboard: Option<Box<dyn somedesk_platform::Clipboard>>,
    /// Send and receive files.
    pub files: Option<files::FileTransfers>,
}

/// The file lane of a session: the transfers' outgoing messages, or a lane that never yields.
pub(crate) fn file_lane(
    files: &Option<files::FileTransfers>,
) -> (
    tokio::sync::mpsc::Receiver<somedesk_proto::session::SessionMsg>,
    Option<tokio::sync::mpsc::Sender<somedesk_proto::session::SessionMsg>>,
) {
    match files {
        Some(f) => (f.attach(), None),
        None => {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            (rx, Some(tx))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("{}", .0.message)]
    Server(ErrorInfo),
    #[error("connection: {0}")]
    Transport(String),
    #[error(transparent)]
    Crypto(#[from] somedesk_crypto::CryptoError),
    #[error("secure channel: {0}")]
    Channel(#[from] somedesk_crypto::channel::ChannelError),
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("{0}")]
    Other(String),
}

impl ClientError {
    /// The peer stopped reading or reset the stream, i.e. it left the session.
    pub fn is_peer_gone(&self) -> bool {
        use somedesk_crypto::channel::ChannelError;
        use somedesk_proto::frame::FrameError;
        matches!(
            self,
            ClientError::Channel(ChannelError::Frame(FrameError::Io(e)))
                if matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe)
        )
    }

    pub fn code(&self) -> Option<somedesk_proto::control::ErrorCode> {
        match self {
            ClientError::Server(e) => Some(e.code),
            _ => None,
        }
    }
}

impl From<somedesk_proto::frame::FrameError> for ClientError {
    fn from(e: somedesk_proto::frame::FrameError) -> Self {
        ClientError::Transport(e.to_string())
    }
}

pub type Result<T, E = ClientError> = std::result::Result<T, E>;
