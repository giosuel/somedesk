//! SomeDesk client core, shared by the desktop app and the integration tests.
//!
//! * [`server`] — connection to the SomeDesk server (control protocol, account flows, relay).
//! * [`credentials`] — what a device persists after enrollment.
//! * [`session`] — establishing the end-to-end encrypted channel to a peer device.
//! * [`host`] / [`viewer`] — the two ends of a remote-control session.

pub mod credentials;
pub mod host;
pub mod server;
pub mod session;
mod tls;
pub mod viewer;

use somedesk_proto::control::ErrorInfo;

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
