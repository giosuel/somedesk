//! Identity keys, password-wrapped key bundles and device certificates.
//!
//! Trust model: each user has an Ed25519 *identity key*. Its private half only ever exists in
//! plaintext on the user's own devices, and is stored on the server encrypted under a key
//! derived from the OPAQUE export key (i.e. from the password). Each device has its own X25519
//! key, certified by the identity key. Peers verify these certificates themselves.

use crate::CryptoError;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use somedesk_proto::control::{DeviceCert, EncryptedKeyBundle};
use zeroize::Zeroizing;

const BUNDLE_VERSION: u8 = 1;
const BUNDLE_KDF_INFO: &[u8] = b"somedesk key bundle v1";

/// The user's long-term identity key.
pub struct IdentityKey(SigningKey);

impl IdentityKey {
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Encrypts the private key under a key derived from `export_key`.
    pub fn seal(&self, export_key: &[u8], username: &str) -> EncryptedKeyBundle {
        let cipher = bundle_cipher(export_key);
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let aad = bundle_aad(username, &self.public());
        let secret = Zeroizing::new(self.0.to_bytes());
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: secret.as_slice(), aad: &aad })
            .expect("encryption with a valid key cannot fail");
        EncryptedKeyBundle { version: BUNDLE_VERSION, nonce, ciphertext }
    }

    /// Decrypts a bundle produced by [`IdentityKey::seal`] and checks it matches `identity_pk`.
    pub fn open(
        bundle: &EncryptedKeyBundle,
        export_key: &[u8],
        username: &str,
        identity_pk: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        if bundle.version != BUNDLE_VERSION {
            return Err(CryptoError::BundleDecrypt);
        }
        let cipher = bundle_cipher(export_key);
        let aad = bundle_aad(username, identity_pk);
        let plain = Zeroizing::new(
            cipher
                .decrypt(XNonce::from_slice(&bundle.nonce), Payload { msg: &bundle.ciphertext, aad: &aad })
                .map_err(|_| CryptoError::BundleDecrypt)?,
        );
        let bytes: [u8; 32] = plain.as_slice().try_into().map_err(|_| CryptoError::BundleDecrypt)?;
        let key = SigningKey::from_bytes(&bytes);
        if key.verifying_key().to_bytes() != *identity_pk {
            return Err(CryptoError::BundleDecrypt);
        }
        Ok(Self(key))
    }

    /// A key for `purpose`, derived from the identity key: only the account's own (signed-in)
    /// devices can derive it.
    pub(crate) fn derive(&self, purpose: &[u8]) -> Zeroizing<[u8; 32]> {
        let secret = Zeroizing::new(self.0.to_bytes());
        let hk = Hkdf::<Sha256>::new(None, secret.as_slice());
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(purpose, out.as_mut_slice()).expect("32 bytes is a valid HKDF length");
        out
    }

    /// The X25519 form of the private key, for opening what was sealed to the identity key
    /// (see [`crate::org::seal_for`]).
    pub(crate) fn montgomery_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_scalar_bytes())
    }

    /// Issues a certificate binding `device_pk` to this identity.
    pub fn certify_device(
        &self,
        username: &str,
        device_pk: [u8; 32],
        device_name: &str,
        created_at: i64,
    ) -> DeviceCert {
        let mut cert = DeviceCert {
            username: username.to_owned(),
            identity_pk: self.public(),
            device_pk,
            device_name: device_name.to_owned(),
            created_at,
            signature: Vec::new(),
        };
        cert.signature = self.0.sign(&cert.signed_bytes()).to_bytes().to_vec();
        cert
    }
}

fn bundle_cipher(export_key: &[u8]) -> XChaCha20Poly1305 {
    let hk = Hkdf::<Sha256>::new(None, export_key);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(BUNDLE_KDF_INFO, key.as_mut_slice()).expect("32 bytes is a valid HKDF length");
    XChaCha20Poly1305::new(key.as_slice().into())
}

fn bundle_aad(username: &str, identity_pk: &[u8; 32]) -> Vec<u8> {
    let mut aad = BUNDLE_KDF_INFO.to_vec();
    aad.extend_from_slice(&(username.len() as u32).to_be_bytes());
    aad.extend_from_slice(username.as_bytes());
    aad.extend_from_slice(identity_pk);
    aad
}

/// Checks that `cert` is signed by the identity key it names.
pub fn verify_device_cert(cert: &DeviceCert) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(&cert.identity_pk).map_err(|_| CryptoError::BadCert("bad identity key"))?;
    let sig: [u8; 64] =
        cert.signature.as_slice().try_into().map_err(|_| CryptoError::BadCert("bad signature length"))?;
    vk.verify(&cert.signed_bytes(), &Signature::from_bytes(&sig))
        .map_err(|_| CryptoError::BadCert("signature does not verify"))
}

/// A device's X25519 static key used in Noise handshakes.
#[derive(Clone)]
pub struct DeviceKey(Zeroizing<[u8; 32]>);

impl DeviceKey {
    pub fn generate() -> Self {
        let mut k = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(k.as_mut_slice());
        Self(k)
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn public(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*self.0)).to_bytes()
    }
}

const DEVICE_PROOF_INFO: &[u8] = b"somedesk device proof v1";

impl DeviceKey {
    /// Proves to the server that this device holds its private key: a key derived from a
    /// Diffie-Hellman exchange with the server's one-time key in [`DeviceChallenge`], bound to
    /// both keys and the nonce.
    pub fn prove(&self, server_pk: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
        let secret = x25519_dalek::StaticSecret::from(*self.0);
        let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*server_pk));
        device_proof(shared.as_bytes(), &self.public(), server_pk, nonce)
    }
}

fn device_proof(shared: &[u8; 32], device_pk: &[u8; 32], server_pk: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(nonce), shared);
    let mut out = [0u8; 32];
    hk.expand_multi_info(&[DEVICE_PROOF_INFO, device_pk, server_pk], &mut out)
        .expect("32 bytes is a valid HKDF length");
    out
}

/// The server's side of [`DeviceKey::prove`]: a one-time key and nonce, and the check.
pub struct DeviceChallenge {
    secret: x25519_dalek::StaticSecret,
    pub device_pk: [u8; 32],
    pub server_pk: [u8; 32],
    pub nonce: [u8; 32],
}

impl DeviceChallenge {
    pub fn new(device_pk: [u8; 32]) -> Self {
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let server_pk = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        Self { secret, device_pk, server_pk, nonce }
    }

    /// Whether `proof` shows possession of the private key of `device_pk`.
    pub fn verify(&self, proof: &[u8; 32]) -> bool {
        let shared = self.secret.diffie_hellman(&x25519_dalek::PublicKey::from(self.device_pk));
        // A low-order "public key" would make the shared secret predictable.
        if !shared.was_contributory() {
            return false;
        }
        let expected = device_proof(shared.as_bytes(), &self.device_pk, &self.server_pk, &self.nonce);
        subtle::ConstantTimeEq::ct_eq(expected.as_slice(), proof.as_slice()).into()
    }
}

/// Human-comparable fingerprint of a public key (an account's identity key or a device key),
/// e.g. `1A2B 3C4D 5E6F 7A8B 9C0D`.
pub fn fingerprint(identity_pk: &[u8; 32]) -> String {
    let digest = Sha256::digest([b"somedesk fingerprint v1".as_slice(), identity_pk].concat());
    hex::encode_upper(&digest[..10])
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPORT: [u8; 64] = [7u8; 64];

    #[test]
    fn device_proofs() {
        let key = DeviceKey::generate();
        let challenge = DeviceChallenge::new(key.public());
        assert!(challenge.verify(&key.prove(&challenge.server_pk, &challenge.nonce)));
        let other = DeviceKey::generate();
        assert!(!challenge.verify(&other.prove(&challenge.server_pk, &challenge.nonce)), "another key");
        let again = DeviceChallenge::new(key.public());
        assert!(!again.verify(&key.prove(&challenge.server_pk, &challenge.nonce)), "an old proof");
        let zero = DeviceChallenge::new([0u8; 32]);
        assert!(!zero.verify(&[0u8; 32]), "a low-order key");
    }

    #[test]
    fn bundle_roundtrip() {
        let id = IdentityKey::generate();
        let b = id.seal(&EXPORT, "alice");
        let opened = IdentityKey::open(&b, &EXPORT, "alice", &id.public()).unwrap();
        assert_eq!(opened.public(), id.public());
    }

    #[test]
    fn bundle_does_not_leak_private_key() {
        let id = IdentityKey::generate();
        let b = id.seal(&EXPORT, "alice");
        let sk = id.0.to_bytes();
        assert!(!b.ciphertext.windows(32).any(|w| w == sk));
    }

    #[test]
    fn bundle_wrong_export_key_fails() {
        let id = IdentityKey::generate();
        let b = id.seal(&EXPORT, "alice");
        assert!(IdentityKey::open(&b, &[8u8; 64], "alice", &id.public()).is_err());
    }

    #[test]
    fn bundle_tampering_fails() {
        let id = IdentityKey::generate();
        let mut b = id.seal(&EXPORT, "alice");
        b.ciphertext[0] ^= 1;
        assert!(IdentityKey::open(&b, &EXPORT, "alice", &id.public()).is_err());
    }

    #[test]
    fn bundle_bound_to_username_and_public_key() {
        let id = IdentityKey::generate();
        let other = IdentityKey::generate();
        let b = id.seal(&EXPORT, "alice");
        assert!(IdentityKey::open(&b, &EXPORT, "bob", &id.public()).is_err());
        assert!(IdentityKey::open(&b, &EXPORT, "alice", &other.public()).is_err());
    }

    #[test]
    fn cert_verifies() {
        let id = IdentityKey::generate();
        let dev = DeviceKey::generate();
        let cert = id.certify_device("alice", dev.public(), "laptop", 1_700_000_000);
        verify_device_cert(&cert).unwrap();
    }

    #[test]
    fn cert_tampering_is_detected() {
        let id = IdentityKey::generate();
        let dev = DeviceKey::generate();
        let cert = id.certify_device("alice", dev.public(), "laptop", 1);

        let mut c = cert.clone();
        c.device_pk = DeviceKey::generate().public();
        assert!(verify_device_cert(&c).is_err());

        let mut c = cert.clone();
        c.username = "mallory".into();
        assert!(verify_device_cert(&c).is_err());

        let mut c = cert.clone();
        c.identity_pk = IdentityKey::generate().public();
        assert!(verify_device_cert(&c).is_err());

        let mut c = cert;
        c.signature.truncate(10);
        assert!(verify_device_cert(&c).is_err());
    }

    #[test]
    fn fingerprint_format() {
        let fp = fingerprint(&[1u8; 32]);
        assert_eq!(fp.len(), 24);
        assert_eq!(fp.split(' ').count(), 5);
        assert_ne!(fp, fingerprint(&[2u8; 32]));
    }

    #[test]
    fn device_public_key_matches_x25519() {
        let k = DeviceKey::generate();
        assert_eq!(k.public(), DeviceKey::from_bytes(*k.secret_bytes()).public());
    }
}
