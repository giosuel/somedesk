//! Client ⇄ server control protocol.
//!
//! The first bidirectional QUIC stream a client opens is the control stream. The client
//! sends [`ClientFrame`]s, the server answers each with a [`ServerFrame::Response`] carrying
//! the same `id`, and may push [`ServerFrame::Event`]s at any time.
//!
//! Every further bidirectional stream starts with a [`RelayJoin`] frame and is then spliced
//! by the server to the matching stream of the other peer.

// Wire messages are short-lived (serialized right away), so variant size differences don't matter.
#![allow(clippy::large_enum_variant)]

use serde::{Deserialize, Serialize};

pub type SessionId = [u8; 16];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientFrame {
    pub id: u32,
    pub req: Request,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Hello {
        version: u32,
    },
    /// OPAQUE registration, step 1 (`RegistrationRequest`).
    RegisterStart {
        username: String,
        message: Vec<u8>,
    },
    /// OPAQUE registration, step 2 (`RegistrationUpload`) plus the user's public identity key
    /// and the identity private key encrypted under the password-derived key.
    RegisterFinish {
        message: Vec<u8>,
        identity_pk: [u8; 32],
        key_bundle: EncryptedKeyBundle,
    },
    /// OPAQUE login, step 1 (`CredentialRequest`).
    LoginStart {
        username: String,
        message: Vec<u8>,
    },
    /// OPAQUE login, step 2 (`CredentialFinalization`).
    LoginFinish {
        message: Vec<u8>,
    },
    /// Enrolls this machine. Requires a password login on this connection.
    RegisterDevice {
        cert: DeviceCert,
    },
    /// Authenticates as an enrolled device and marks it online.
    TokenAuth {
        device_id: u64,
        token: [u8; 32],
    },
    ListDevices,
    LookupDevice {
        device_id: u64,
    },
    /// Asks the server to set up a relayed session to `device_id`.
    Connect {
        device_id: u64,
    },
    /// Removes one of the caller's own devices (also usable to sign out the current one).
    RemoveDevice {
        device_id: u64,
    },
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerFrame {
    Response { id: u32, result: Result<Response, ErrorInfo> },
    Event(Event),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Hello { version: u32 },
    RegisterStart { message: Vec<u8> },
    LoginStart { message: Vec<u8> },
    LoginFinish { identity_pk: [u8; 32], key_bundle: EncryptedKeyBundle },
    DeviceRegistered { device_id: u64, token: [u8; 32] },
    Authenticated { username: String, device: DeviceInfo },
    Devices(Vec<DeviceInfo>),
    Device(DeviceInfo),
    Connect { session_id: SessionId, host: DeviceInfo },
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    /// Another device wants to open a session with us. Join the relay with `session_id`.
    IncomingSession { session_id: SessionId, from: DeviceInfo },
    /// Presence of one of our own devices changed.
    DevicePresence { device_id: u64, online: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    BadRequest,
    VersionMismatch,
    /// Wrong username or password. Deliberately identical for both cases.
    AuthFailed,
    UsernameTaken,
    NotAuthenticated,
    NotFound,
    Offline,
    RateLimited,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub code: ErrorCode,
    pub message: String,
}

impl ErrorInfo {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

impl std::fmt::Display for ErrorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for ErrorInfo {}

/// The user's identity private key, encrypted with a key derived from the password
/// (via the OPAQUE export key). The server stores this blob but cannot open it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedKeyBundle {
    pub version: u8,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Binds a device's Noise static key to a user identity. Signed by the user's identity key,
/// so peers can check it without trusting the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCert {
    pub username: String,
    /// Ed25519 public key of the user.
    pub identity_pk: [u8; 32],
    /// X25519 public key the device uses in Noise handshakes.
    pub device_pk: [u8; 32],
    pub device_name: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Ed25519 signature (64 bytes) over [`DeviceCert::signed_bytes`].
    pub signature: Vec<u8>,
}

impl DeviceCert {
    /// Domain-separated encoding of every field except the signature.
    pub fn signed_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Tbs<'a> {
            domain: &'static str,
            username: &'a str,
            identity_pk: &'a [u8; 32],
            device_pk: &'a [u8; 32],
            device_name: &'a str,
            created_at: i64,
        }
        postcard::to_stdvec(&Tbs {
            domain: "somedesk device cert v1",
            username: &self.username,
            identity_pk: &self.identity_pk,
            device_pk: &self.device_pk,
            device_name: &self.device_name,
            created_at: self.created_at,
        })
        .expect("serializing to a Vec cannot fail")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: u64,
    pub username: String,
    pub name: String,
    pub online: bool,
    pub cert: DeviceCert,
}

/// First frame on every relay stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayJoin {
    pub session_id: SessionId,
}
