//! Cryptography for SomeDesk.
//!
//! * [`opaque`] — password authentication. The server never sees the password.
//! * [`keys`] — the user's identity key, its password-wrapped bundle, and device certificates.
//! * [`channel`] — the end-to-end encrypted Noise channel between two devices.

pub mod channel;
pub mod keys;
pub mod opaque;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("authentication failed")]
    AuthFailed,
    #[error("malformed protocol message")]
    Malformed,
    #[error("could not decrypt the key bundle (wrong password or tampered data)")]
    BundleDecrypt,
    #[error("invalid device certificate: {0}")]
    BadCert(&'static str),
}
