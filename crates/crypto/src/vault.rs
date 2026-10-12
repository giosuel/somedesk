//! The account's vault: its address book and the passwords saved to the account.
//!
//! The server keeps one encrypted blob per account. The key is derived from the account's
//! identity key, which only the account's devices ever hold in the clear, so the server stores
//! the vault without being able to read it. A device keeps the vault key once it is signed in,
//! so it can sync without asking for the password again.

use crate::keys::IdentityKey;
use crate::CryptoError;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

const VAULT_KEY_INFO: &[u8] = b"somedesk vault key v1";
const VERSION: u8 = 1;

#[derive(Clone)]
pub struct VaultKey(Zeroizing<[u8; 32]>);

impl VaultKey {
    pub fn derive(identity: &IdentityKey) -> Self {
        Self(identity.derive(VAULT_KEY_INFO))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0
    }

    fn aad(username: &str) -> Vec<u8> {
        [VAULT_KEY_INFO, username.as_bytes()].concat()
    }

    /// Encrypts the vault contents of `username`'s account.
    pub fn seal(&self, plain: &[u8], username: &str) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new(self.0.as_slice().into());
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad: &Self::aad(username) })
            .expect("encryption with a valid key cannot fail");
        [&[VERSION][..], &nonce, &ct].concat()
    }

    pub fn open(&self, blob: &[u8], username: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if blob.len() < 25 || blob[0] != VERSION {
            return Err(CryptoError::VaultDecrypt);
        }
        let cipher = XChaCha20Poly1305::new(self.0.as_slice().into());
        cipher
            .decrypt(XNonce::from_slice(&blob[1..25]), Payload { msg: &blob[25..], aad: &Self::aad(username) })
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::VaultDecrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_account_opens_its_vault() {
        let id = IdentityKey::generate();
        let key = VaultKey::derive(&id);
        assert_eq!(VaultKey::derive(&id).to_bytes(), key.to_bytes(), "the same key on every device");
        let blob = key.seal(b"address book", "alice");
        assert!(!blob.windows(12).any(|w| w == b"address book"));
        assert_eq!(key.open(&blob, "alice").unwrap().as_slice(), b"address book");
        assert!(key.open(&blob, "bob").is_err(), "bound to the account");
        assert!(VaultKey::derive(&IdentityKey::generate()).open(&blob, "alice").is_err());
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(key.open(&tampered, "alice").is_err());
    }
}
