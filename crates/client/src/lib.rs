//! SomeDesk client core, shared by the desktop app and the integration tests.
//!
//! * [`server`] — connection to the SomeDesk server (control protocol, account flows, relay).
//! * [`credentials`] — what a device persists after enrollment.
//! * [`session`] — establishing the end-to-end encrypted channel to a peer device.
//! * [`host`] / [`viewer`] — the two ends of a remote-control session.
//! * [`trust`] — remembered device and account keys (trust on first use).
//! * [`addressbook`] — the user's devices to connect to, synced through the account's vault.
//! * [`wallet`] — passwords saved in the system's keychain.
//! * [`access`] — who may get in: asking the person at the host, unattended access with the
//!   host's password and authenticator code, the same account, or an organisation's policy.
//! * [`clipboard`] / [`files`] — clipboard sharing and file transfer within a session.

pub mod access;
pub mod addressbook;
pub mod clipboard;
pub mod credentials;
pub mod direct;
pub mod files;
pub mod host;
pub mod org;
pub mod server;
pub mod session;
mod tls;
pub mod trust;
pub mod viewer;
pub mod wallet;

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
    /// The remote device turned the session down.
    #[error("{0}")]
    Rejected(String),
    /// The password was right; the account wants the code from its authenticator app too.
    #[error("enter the code from your authenticator app")]
    TotpRequired,
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
