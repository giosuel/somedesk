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

use crate::org::{OrgDeviceCert, SignedPolicy};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

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
        /// The invite code, on a server where only invited people create accounts.
        invite: Option<String>,
    },
    /// OPAQUE registration, step 2 (`RegistrationUpload`) plus the user's public identity key
    /// and the identity private key encrypted under the password-derived key.
    RegisterFinish {
        message: Vec<u8>,
        identity_pk: [u8; 32],
        key_bundle: EncryptedKeyBundle,
        recovery: RecoverySetup,
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
    /// Replaces the account's recovery key. Requires a password login (or a completed recovery)
    /// on this connection.
    SetRecovery {
        recovery: RecoverySetup,
    },
    /// Password reset with the recovery key, step 1: asks for a challenge to sign.
    RecoveryStart {
        username: String,
    },
    /// Step 2: proves possession of the recovery key and starts a new OPAQUE registration
    /// (`RegistrationRequest`).
    RecoveryProve {
        proof: Vec<u8>,
        message: Vec<u8>,
    },
    /// Step 3: the new OPAQUE record, the identity key sealed under the new password, and a new
    /// recovery key (recovery keys are single-use). Afterwards the connection is logged in.
    RecoveryFinish {
        message: Vec<u8>,
        key_bundle: EncryptedKeyBundle,
        recovery: RecoverySetup,
    },
    /// Bringing a device online, step 1: asks for a challenge for this device key.
    DeviceChallenge {
        device_pk: [u8; 32],
    },
    /// Step 2: proves this connection holds the private device key (see
    /// `somedesk_crypto::keys::DeviceKey::prove`). A key the server doesn't know yet is
    /// registered under a new random ID, if the server lets devices without an account in.
    /// Afterwards the device is online.
    DeviceAuth {
        name: String,
        proof: [u8; 32],
        /// A device enrolled into an organisation by a service worker presents its certificate.
        org: Option<OrgDeviceCert>,
    },
    /// Signs this (online) device in to the account logged in on this connection: `cert` binds
    /// the device key to the account. The device keeps its ID.
    AttachDevice {
        cert: DeviceCert,
    },
    /// Signs this device out of its account. It keeps its ID.
    DetachDevice,
    /// Where this device can be reached directly (its local addresses; the server adds the
    /// public address it sees). With `allow_direct: false` no addresses are shared with peers
    /// and sessions always use the relay.
    SetCandidates {
        local: Vec<SocketAddr>,
        allow_direct: bool,
    },
    ListDevices,
    LookupDevice {
        device_id: u64,
    },
    /// The encrypted vault (address book and saved passwords) of this connection's account.
    GetVault,
    /// Replaces the vault, if it is still at `base_version` (0: there is none yet).
    PutVault {
        base_version: u64,
        blob: Vec<u8>,
    },
    /// What the server knows about this connection's account.
    AccountInfo,
    /// Starts turning on two-factor authentication. Requires a password login.
    TotpBegin,
    /// Turns it on, with a code from the authenticator app for the secret from `TotpBegin`.
    TotpEnable {
        code: String,
    },
    /// Turns it off, with a code (or with none, within minutes of logging in with one on this
    /// connection).
    TotpDisable {
        code: String,
    },
    /// Second step of a login on an account with two-factor authentication.
    LoginTotp {
        code: String,
    },
    /// An account's identity key (to add it to an organisation).
    LookupUser {
        username: String,
    },
    /// Creates an organisation with this account as its admin. `sealed_key`: the organisation's
    /// private key, sealed to the account's identity key.
    CreateOrg {
        name: String,
        org_pk: [u8; 32],
        sealed_key: Vec<u8>,
    },
    /// The organisations this account belongs to.
    ListOrgs,
    /// Publishes a new policy. Only admins of the current policy can.
    PutOrgPolicy {
        org_id: u64,
        policy: SignedPolicy,
    },
    /// Gives another admin the organisation's key (sealed to their identity key).
    ShareOrgKey {
        org_id: u64,
        username: String,
        sealed_key: Vec<u8>,
    },
    /// The current policy: for members, and for the organisation's own devices.
    GetOrgPolicy {
        org_id: u64,
    },
    /// The devices enrolled into an organisation (for its members).
    ListOrgDevices {
        org_id: u64,
    },
    /// Asks the server to set up a relayed session to `device_id`.
    Connect {
        device_id: u64,
    },
    /// Takes one of the account's devices off the account. It keeps its ID.
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
    Hello {
        version: u32,
    },
    RegisterStart {
        message: Vec<u8>,
    },
    LoginStart {
        message: Vec<u8>,
    },
    LoginFinish {
        identity_pk: [u8; 32],
        key_bundle: EncryptedKeyBundle,
        has_recovery: bool,
    },
    RecoveryChallenge {
        challenge: [u8; 32],
    },
    /// The recovery-key copy of the identity key, plus the OPAQUE `RegistrationResponse`.
    RecoveryProve {
        identity_pk: [u8; 32],
        recovery_bundle: EncryptedKeyBundle,
        message: Vec<u8>,
    },
    DeviceChallenge {
        /// The server's one-time X25519 key and nonce for this challenge.
        server_pk: [u8; 32],
        nonce: [u8; 32],
    },
    /// The device is online.
    Authenticated {
        device: DeviceInfo,
    },
    Devices(Vec<DeviceInfo>),
    Vault {
        version: u64,
        blob: Vec<u8>,
    },
    VaultSaved {
        version: u64,
    },
    Account {
        username: String,
        totp_enabled: bool,
    },
    TotpSecret {
        secret: Vec<u8>,
    },
    /// The password was right; the code from the authenticator app comes next (`LoginTotp`).
    TotpRequired,
    User {
        username: String,
        identity_pk: [u8; 32],
    },
    OrgCreated {
        org_id: u64,
    },
    Orgs(Vec<OrgInfo>),
    OrgPolicy(Option<SignedPolicy>),
    Device(DeviceInfo),
    /// `candidates`: addresses where the host might be reached directly (empty: relay only).
    Connect {
        session_id: SessionId,
        host: DeviceInfo,
        candidates: Vec<SocketAddr>,
    },
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    /// Another device wants to open a session with us. Join the relay with `session_id`.
    /// `candidates`: addresses where the viewer might be reached directly (empty: relay only).
    IncomingSession { session_id: SessionId, from: DeviceInfo, candidates: Vec<SocketAddr> },
    /// Presence of one of our own devices changed.
    DevicePresence { device_id: u64, online: bool },
    /// This device was taken off its account (from another device). It keeps its ID.
    SignedOut,
    /// An organisation this device or account belongs to has a new policy.
    OrgPolicyChanged { org_id: u64 },
    /// The account changed (two-factor authentication turned on or off): ask `AccountInfo`.
    AccountChanged,
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
    /// Not allowed, e.g. a server that only lets its accounts' devices in.
    Forbidden,
    /// Changed in the meantime (e.g. the vault, by another device): read it again and retry.
    Conflict,
    Internal,
    /// The server only creates accounts with an invite code, and there was none (or not a
    /// valid one).
    InviteRequired,
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

/// What the server stores for a recovery key: the public key that checks recovery proofs, and
/// the identity private key sealed under a key derived from the recovery key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverySetup {
    pub recovery_pk: [u8; 32],
    pub key_bundle: EncryptedKeyBundle,
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

/// Who a device is: its key, the name it gives itself and, when it is signed in to an account,
/// the account's certificate for it. This is what each side presents in the Noise handshake (and
/// checks there itself); the server hands out the same for lookups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// X25519 public key the device uses in Noise handshakes.
    pub device_pk: [u8; 32],
    /// Chosen by the device; only meaningful together with its ID or account.
    pub name: String,
    /// The account's certificate for `device_pk`, if the device is signed in to one.
    pub account: Option<DeviceCert>,
    /// The organisation's certificate for `device_pk`, if a service worker enrolled the device.
    pub org: Option<OrgDeviceCert>,
}

impl DeviceIdentity {
    /// The account the device is signed in to.
    pub fn username(&self) -> Option<&str> {
        self.account.as_ref().map(|c| c.username.as_str())
    }
}

/// An organisation as one of its members sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgInfo {
    pub org_id: u64,
    pub name: String,
    pub org_pk: [u8; 32],
    /// The organisation's key, sealed to this account's identity key (admins only).
    pub sealed_key: Option<Vec<u8>>,
    pub policy: Option<SignedPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: u64,
    pub online: bool,
    pub identity: DeviceIdentity,
}

/// First frame on every direct (peer-to-peer) stream, naming the session it belongs to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectHello {
    pub session_id: SessionId,
}

/// First frame on every relay stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayJoin {
    pub session_id: SessionId,
}
