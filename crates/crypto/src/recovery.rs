//! Recovery keys: a second way to unlock the identity key when the password is forgotten.
//!
//! A recovery key is 160 random bits, shown to the user once as 36 characters
//! (`XXXX-XXXX-…`, Crockford base32 with a 20-bit checksum so typos are caught locally). Two
//! things are derived from it:
//!
//! * a key that seals a second copy of the identity key, stored on the server next to the
//!   password-sealed copy, and
//! * an Ed25519 key pair whose public half the server stores. To reset the password, the client
//!   signs a fresh server challenge with it, proving it holds the recovery key without revealing
//!   it.
//!
//! The server therefore can neither open the recovery copy nor reset the password on its own,
//! and 160 bits are far beyond guessing, so no slow KDF is needed.

use crate::keys::IdentityKey;
use crate::CryptoError;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use somedesk_proto::control::EncryptedKeyBundle;
use zeroize::Zeroizing;

const SECRET_LEN: usize = 20;
const CHECKSUM_BITS: usize = 20;
/// Characters in the printed form, without separators.
const CHARS: usize = (SECRET_LEN * 8 + CHECKSUM_BITS) / 5;
/// Crockford base32: no I, L, O or U, so the key survives being read aloud or handwritten.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const SEAL_INFO: &[u8] = b"somedesk recovery seal v1";
const AUTH_INFO: &[u8] = b"somedesk recovery auth v1";
const PROOF_DOMAIN: &[u8] = b"somedesk recovery proof v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecoveryKeyError {
    #[error("a recovery key has {CHARS} characters, this has {0}")]
    Length(usize),
    #[error("'{0}' cannot appear in a recovery key")]
    Character(char),
    #[error("this recovery key contains a typo, please check it")]
    Checksum,
}

pub struct RecoveryKey(Zeroizing<[u8; SECRET_LEN]>);

impl RecoveryKey {
    pub fn generate() -> Self {
        let mut k = Zeroizing::new([0u8; SECRET_LEN]);
        OsRng.fill_bytes(k.as_mut_slice());
        Self(k)
    }

    /// Parses the printed form. Case, spaces and dashes don't matter, and the commonly confused
    /// letters O, I and L are read as 0, 1 and 1.
    pub fn parse(text: &str) -> Result<Self, RecoveryKeyError> {
        let mut digits = Vec::with_capacity(CHARS);
        for c in text.chars().filter(|c| !c.is_whitespace() && *c != '-') {
            let c = match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            };
            let d = ALPHABET.iter().position(|&a| a as char == c).ok_or(RecoveryKeyError::Character(c))?;
            digits.push(d as u8);
        }
        if digits.len() != CHARS {
            return Err(RecoveryKeyError::Length(digits.len()));
        }
        let mut bits = Zeroizing::new([0u8; (CHARS * 5).div_ceil(8)]);
        for (i, d) in digits.iter().enumerate() {
            for b in 0..5 {
                if d & (0x10 >> b) != 0 {
                    let pos = i * 5 + b;
                    bits[pos / 8] |= 0x80 >> (pos % 8);
                }
            }
        }
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        secret.copy_from_slice(&bits[..SECRET_LEN]);
        let key = Self(secret);
        if bits[SECRET_LEN..] != key.checksum_bytes()[..] {
            return Err(RecoveryKeyError::Checksum);
        }
        Ok(key)
    }

    /// The printed form, nine groups of four: `ABCD-EFGH-…`.
    pub fn display(&self) -> String {
        let mut bits = Zeroizing::new(self.0.to_vec());
        bits.extend_from_slice(&self.checksum_bytes());
        let mut out = String::with_capacity(CHARS + CHARS / 4);
        for i in 0..CHARS {
            let mut d = 0u8;
            for b in 0..5 {
                let pos = i * 5 + b;
                d = (d << 1) | ((bits[pos / 8] >> (7 - pos % 8)) & 1);
            }
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(ALPHABET[d as usize] as char);
        }
        out
    }

    /// The 20 checksum bits, left-aligned in 3 bytes.
    fn checksum_bytes(&self) -> [u8; 3] {
        let h = Sha256::new().chain_update(b"somedesk recovery checksum").chain_update(self.0.as_slice()).finalize();
        [h[0], h[1], h[2] & 0xF0]
    }

    fn derive(&self, info: &[u8]) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(None, self.0.as_slice());
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(info, out.as_mut_slice()).expect("32 bytes is a valid HKDF length");
        out
    }

    fn auth_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.derive(AUTH_INFO))
    }

    /// Public key the server stores to check recovery proofs.
    pub fn public(&self) -> [u8; 32] {
        self.auth_key().verifying_key().to_bytes()
    }

    /// Proves possession of the recovery key for `username` to the server.
    pub fn prove(&self, username: &str, challenge: &[u8; 32]) -> [u8; 64] {
        self.auth_key().sign(&proof_message(username, challenge)).to_bytes()
    }

    /// Seals a copy of the identity key that this recovery key can open.
    pub fn seal(&self, identity: &IdentityKey, username: &str) -> EncryptedKeyBundle {
        identity.seal(self.derive(SEAL_INFO).as_slice(), username)
    }

    /// Opens a bundle produced by [`RecoveryKey::seal`].
    pub fn open(
        &self,
        bundle: &EncryptedKeyBundle,
        username: &str,
        identity_pk: &[u8; 32],
    ) -> Result<IdentityKey, CryptoError> {
        IdentityKey::open(bundle, self.derive(SEAL_INFO).as_slice(), username, identity_pk)
    }
}

fn proof_message(username: &str, challenge: &[u8; 32]) -> Vec<u8> {
    let mut m = PROOF_DOMAIN.to_vec();
    m.extend_from_slice(&(username.len() as u32).to_be_bytes());
    m.extend_from_slice(username.as_bytes());
    m.extend_from_slice(challenge);
    m
}

/// Server side: checks a proof made with [`RecoveryKey::prove`].
pub fn verify_proof(
    recovery_pk: &[u8; 32],
    username: &str,
    challenge: &[u8; 32],
    proof: &[u8],
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(recovery_pk).map_err(|_| CryptoError::AuthFailed)?;
    let sig: [u8; 64] = proof.try_into().map_err(|_| CryptoError::AuthFailed)?;
    vk.verify_strict(&proof_message(username, challenge), &Signature::from_bytes(&sig))
        .map_err(|_| CryptoError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_parse_round_trip() {
        for _ in 0..200 {
            let k = RecoveryKey::generate();
            let s = k.display();
            assert_eq!(s.len(), 44, "{s}");
            assert_eq!(s.split('-').count(), 9);
            assert!(s.split('-').all(|g| g.len() == 4));
            assert_eq!(RecoveryKey::parse(&s).unwrap().0, k.0);
        }
    }

    #[test]
    fn parsing_is_forgiving_about_formatting() {
        let k = RecoveryKey::generate();
        let s = k.display();
        let sloppy = s.to_lowercase().replace('-', " ").replace('0', "o").replace('1', "l");
        assert_eq!(RecoveryKey::parse(&format!("  {sloppy}\n")).unwrap().0, k.0);
        assert_eq!(RecoveryKey::parse(&s.replace('-', "")).unwrap().0, k.0);
    }

    #[test]
    fn typos_are_detected() {
        let s = RecoveryKey::generate().display();
        // Changing any single character is caught by the checksum (or yields an invalid
        // encoding), never accepted as a different key.
        for i in s.char_indices().filter(|(_, c)| *c != '-').map(|(i, _)| i) {
            let orig = s.as_bytes()[i];
            let replacement = if orig == b'7' { b'8' } else { b'7' };
            let mut typo = s.clone().into_bytes();
            typo[i] = replacement;
            let typo = String::from_utf8(typo).unwrap();
            assert_eq!(RecoveryKey::parse(&typo).err(), Some(RecoveryKeyError::Checksum), "{typo}");
        }
        assert_eq!(RecoveryKey::parse(&s[..s.len() - 1]).err(), Some(RecoveryKeyError::Length(35)));
        assert_eq!(RecoveryKey::parse(&s.replacen(&s[..1], "U", 1)).err(), Some(RecoveryKeyError::Character('U')));
    }

    #[test]
    fn recovery_copy_opens_only_with_the_recovery_key() {
        let identity = IdentityKey::generate();
        let rk = RecoveryKey::generate();
        let bundle = rk.seal(&identity, "alice");
        let opened = rk.open(&bundle, "alice", &identity.public()).unwrap();
        assert_eq!(opened.public(), identity.public());

        assert!(RecoveryKey::generate().open(&bundle, "alice", &identity.public()).is_err());
        assert!(rk.open(&bundle, "mallory", &identity.public()).is_err());
        // The recovery copy is not the password copy: the raw secret as an "export key" fails.
        assert!(IdentityKey::open(&bundle, rk.0.as_slice(), "alice", &identity.public()).is_err());
    }

    #[test]
    fn proofs_are_bound_to_user_and_challenge() {
        let rk = RecoveryKey::generate();
        let c = [7u8; 32];
        let proof = rk.prove("alice", &c);
        verify_proof(&rk.public(), "alice", &c, &proof).unwrap();
        assert!(verify_proof(&rk.public(), "bob", &c, &proof).is_err());
        assert!(verify_proof(&rk.public(), "alice", &[8u8; 32], &proof).is_err());
        assert!(verify_proof(&RecoveryKey::generate().public(), "alice", &c, &proof).is_err());
        assert!(verify_proof(&rk.public(), "alice", &c, &proof[..63]).is_err());
    }
}
