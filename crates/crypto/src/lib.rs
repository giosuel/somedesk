//! Cryptography for SomeDesk.
//!
//! * [`opaque`] — password authentication. The server never sees the password.
//! * [`keys`] — the user's identity key, its password-wrapped bundle, and device certificates.
//! * [`recovery`] — recovery keys, the fallback when the password is forgotten.
//! * [`channel`] — the end-to-end encrypted Noise channel between two devices.
//! * [`unattended`] — a host's own password for unattended access, checked end to end.
//! * [`totp`] — authenticator-app codes (the second factor).
//! * [`vault`] — the account's encrypted address book and saved passwords.
//! * [`org`] — organisation keys, signed policies and service-worker enrollment.

pub mod channel;
pub mod keys;
pub mod opaque;
pub mod org;
pub mod recovery;
pub mod totp;
pub mod unattended;
pub mod vault;

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
    #[error("could not decrypt the vault (wrong key or tampered data)")]
    VaultDecrypt,
}
