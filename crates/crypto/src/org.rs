//! Organisation keys, signed policies, service-worker keys and enrolled devices' certificates.
//!
//! * The organisation key (Ed25519) signs policies. Only admins hold it: the server keeps one
//!   copy per admin, sealed to that admin's identity key and signed by the admin who sealed it
//!   ([`seal_for`] / [`open_sealed`]), so the server can't hand an admin a key of its own.
//!   An admin who leaves keeps their copy, so the key is then replaced ([`OrgKey::rotate_to`]).
//! * A service worker's key (Ed25519) signs the certificates of the devices it enrolls. The
//!   admin hands it out as an enrollment string ([`EnrollmentKey`]), which also carries the
//!   organisation's public key, so an enrolled device never has to take the server's word for it.

use crate::keys::IdentityKey;
use crate::CryptoError;
use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use somedesk_proto::org::{OrgDeviceCert, OrgPolicy, OrgRotation, SignedPolicy};
use zeroize::Zeroizing;

const SEAL_INFO: &[u8] = b"somedesk sealed to identity v2";
const ENROLLMENT_PREFIX: &str = "sdw1-";

/// An organisation's signing key.
pub struct OrgKey(SigningKey);

impl OrgKey {
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn sign_policy(&self, policy: &OrgPolicy) -> SignedPolicy {
        let bytes = postcard::to_stdvec(policy).expect("serializing to a Vec cannot fail");
        let signature = self.0.sign(&SignedPolicy::signed_bytes(&bytes)).to_bytes().to_vec();
        SignedPolicy { policy: bytes, signature }
    }

    /// Hands the organisation over from this key to `next`, from policy `version` on.
    pub fn rotate_to(&self, org_id: u64, next: &OrgKey, version: u64) -> OrgRotation {
        let mut rotation =
            OrgRotation { org_id, from_pk: self.public(), to_pk: next.public(), version, signature: Vec::new() };
        rotation.signature = self.0.sign(&rotation.signed_bytes()).to_bytes().to_vec();
        rotation
    }
}

fn verify_strict(pk: &[u8; 32], message: &[u8], signature: &[u8], what: &'static str) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(pk).map_err(|_| CryptoError::BadCert("bad key"))?;
    let sig: [u8; 64] = signature.try_into().map_err(|_| CryptoError::BadCert("bad signature"))?;
    vk.verify_strict(message, &Signature::from_bytes(&sig)).map_err(|_| CryptoError::BadCert(what))
}

/// Checks a policy's signature against the organisation key and reads it.
pub fn verify_policy(signed: &SignedPolicy, org_pk: &[u8; 32]) -> Result<OrgPolicy, CryptoError> {
    verify_strict(
        org_pk,
        &SignedPolicy::signed_bytes(&signed.policy),
        &signed.signature,
        "policy signature does not verify",
    )?;
    postcard::from_bytes(&signed.policy).map_err(|_| CryptoError::Malformed)
}

/// Follows `rotations` (oldest first) from the key `known_pk` for organisation `org_id`, each
/// signed by the key before it. Returns the key they lead to and the policy version from which
/// it signs (0 if there was no rotation to follow). Rotations that don't continue the chain from
/// `known_pk` (older ones, or another branch) are skipped.
pub fn follow_rotations(
    org_id: u64,
    known_pk: &[u8; 32],
    rotations: &[OrgRotation],
) -> Result<([u8; 32], u64), CryptoError> {
    let (mut pk, mut since) = (*known_pk, 0);
    for r in rotations.iter().filter(|r| r.org_id == org_id) {
        if r.from_pk != pk || r.version <= since {
            continue;
        }
        verify_strict(&pk, &r.signed_bytes(), &r.signature, "key rotation signature does not verify")?;
        (pk, since) = (r.to_pk, r.version);
    }
    Ok((pk, since))
}

/// Seals `secret` from `sender` so that only the holder of the identity key `recipient_pk` can
/// open it: an X25519 exchange with the Montgomery form of the Ed25519 identity key, and the
/// sender's signature over the result, so the recipient knows who sealed it.
pub fn seal_for(sender: &IdentityKey, recipient_pk: &[u8; 32], secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let recipient = VerifyingKey::from_bytes(recipient_pk).map_err(|_| CryptoError::BadCert("bad identity key"))?;
    let recipient = x25519_dalek::PublicKey::from(recipient.to_montgomery().to_bytes());
    let ephemeral = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let ephemeral_pk = x25519_dalek::PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        return Err(CryptoError::BadCert("bad identity key"));
    }
    let sender_pk = sender.public();
    let cipher = seal_cipher(shared.as_bytes(), &ephemeral_pk, recipient_pk);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let aad = [recipient_pk.as_slice(), &sender_pk].concat();
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: secret, aad: &aad })
        .expect("encryption with a valid key cannot fail");
    let body = [&sender_pk[..], &ephemeral_pk, &nonce, &ct].concat();
    let signature = sender.sign(&seal_signed_bytes(recipient_pk, &body));
    Ok([&body[..], &signature].concat())
}

/// Opens what [`seal_for`] sealed to `identity`. Returns the secret and the identity key of the
/// account that sealed it (its signature checked).
pub fn open_sealed(identity: &IdentityKey, sealed: &[u8]) -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), CryptoError> {
    if sealed.len() < 32 + 32 + 24 + 16 + 64 {
        return Err(CryptoError::BundleDecrypt);
    }
    let (body, signature) = sealed.split_at(sealed.len() - 64);
    let recipient_pk = identity.public();
    let sender_pk: [u8; 32] = body[..32].try_into().expect("checked length");
    verify_strict(&sender_pk, &seal_signed_bytes(&recipient_pk, body), signature, "not sealed by who it says")?;
    let ephemeral_pk: [u8; 32] = body[32..64].try_into().expect("checked length");
    let secret = x25519_dalek::StaticSecret::from(*identity.montgomery_secret());
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(ephemeral_pk));
    if !shared.was_contributory() {
        return Err(CryptoError::BundleDecrypt);
    }
    let cipher = seal_cipher(shared.as_bytes(), &ephemeral_pk, &recipient_pk);
    let aad = [recipient_pk.as_slice(), &sender_pk].concat();
    let plain = cipher
        .decrypt(XNonce::from_slice(&body[64..88]), Payload { msg: &body[88..], aad: &aad })
        .map_err(|_| CryptoError::BundleDecrypt)?;
    Ok((Zeroizing::new(plain), sender_pk))
}

fn seal_signed_bytes(recipient_pk: &[u8; 32], body: &[u8]) -> Vec<u8> {
    [SEAL_INFO, recipient_pk.as_slice(), body].concat()
}

fn seal_cipher(shared: &[u8; 32], ephemeral_pk: &[u8; 32], identity_pk: &[u8; 32]) -> XChaCha20Poly1305 {
    let hk = Hkdf::<Sha256>::new(Some(ephemeral_pk), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand_multi_info(&[SEAL_INFO, identity_pk], key.as_mut_slice()).expect("32 bytes is a valid HKDF length");
    XChaCha20Poly1305::new(key.as_slice().into())
}

/// A service worker's enrollment key, as the admin hands it out: `sdw1-…`.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnrollmentKey {
    pub org_id: u64,
    pub org_pk: [u8; 32],
    pub org_name: String,
    worker_secret: [u8; 32],
}

impl std::fmt::Debug for EnrollmentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentKey").field("org_id", &self.org_id).finish_non_exhaustive()
    }
}

impl EnrollmentKey {
    /// A new service worker for an organisation.
    pub fn generate(org_id: u64, org_pk: [u8; 32], org_name: &str) -> Self {
        let mut worker_secret = [0u8; 32];
        OsRng.fill_bytes(&mut worker_secret);
        Self { org_id, org_pk, org_name: org_name.to_owned(), worker_secret }
    }

    pub fn worker_pk(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.worker_secret).verifying_key().to_bytes()
    }

    pub fn encode(&self) -> Zeroizing<String> {
        let bytes = Zeroizing::new(postcard::to_stdvec(self).expect("serializing to a Vec cannot fail"));
        Zeroizing::new(format!(
            "{ENROLLMENT_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*bytes)
        ))
    }

    pub fn decode(text: &str) -> Result<Self, CryptoError> {
        let body = text.trim().strip_prefix(ENROLLMENT_PREFIX).ok_or(CryptoError::Malformed)?;
        let bytes = Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).map_err(|_| CryptoError::Malformed)?,
        );
        postcard::from_bytes(&bytes).map_err(|_| CryptoError::Malformed)
    }

    /// The certificate for a device this worker enrolls.
    pub fn certify_device(&self, device_pk: [u8; 32], device_name: &str, created_at: i64) -> OrgDeviceCert {
        let mut cert = OrgDeviceCert {
            org_id: self.org_id,
            org_pk: self.org_pk,
            org_name: self.org_name.clone(),
            device_pk,
            device_name: device_name.to_owned(),
            worker_pk: self.worker_pk(),
            created_at,
            signature: Vec::new(),
        };
        cert.signature = SigningKey::from_bytes(&self.worker_secret).sign(&cert.signed_bytes()).to_bytes().to_vec();
        cert
    }
}

/// Checks that `cert` is signed by the service worker it names. That alone proves nothing about
/// the organisation (anyone can make a worker key): whether that worker may enroll devices is up
/// to the organisation's policy ([`OrgPolicy::worker_can_enroll`]), checked against an
/// organisation key the checker already trusts.
pub fn verify_device_cert(cert: &OrgDeviceCert) -> Result<(), CryptoError> {
    verify_strict(&cert.worker_pk, &cert.signed_bytes(), &cert.signature, "organisation certificate does not verify")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(org_id: u64, version: u64) -> OrgPolicy {
        OrgPolicy {
            org_id,
            org_name: "ACME".into(),
            version,
            prev_hash: [0; 32],
            issued_at: 0,
            expires_at: 10,
            members: vec![],
            groups: vec![],
            device_groups: vec![],
            rules: vec![],
            workers: vec![],
        }
    }

    #[test]
    fn policies_verify_only_with_the_org_key() {
        let org = OrgKey::generate();
        let signed = org.sign_policy(&policy(1, 3));
        assert_eq!(verify_policy(&signed, &org.public()).unwrap().version, 3);
        assert!(verify_policy(&signed, &OrgKey::generate().public()).is_err());
        let mut forged = signed.clone();
        forged.policy = postcard::to_stdvec(&policy(1, 4)).unwrap();
        assert!(verify_policy(&forged, &org.public()).is_err(), "a changed policy");
    }

    #[test]
    fn org_keys_are_sealed_to_admins_by_admins() {
        let (jane, tom) = (IdentityKey::generate(), IdentityKey::generate());
        let org = OrgKey::generate();
        let sealed = seal_for(&jane, &tom.public(), org.to_bytes().as_slice()).unwrap();
        let (key, sender) = open_sealed(&tom, &sealed).unwrap();
        assert_eq!((key.as_slice(), sender), (org.to_bytes().as_slice(), jane.public()));
        assert!(open_sealed(&IdentityKey::generate(), &sealed).is_err(), "only that admin");

        // The server can seal a key of its own to tom, but not as jane: it signs as itself.
        let server = IdentityKey::generate();
        let forged = seal_for(&server, &tom.public(), OrgKey::generate().to_bytes().as_slice()).unwrap();
        assert_eq!(open_sealed(&tom, &forged).unwrap().1, server.public());
        let mut relabeled = forged.clone();
        relabeled[..32].copy_from_slice(&jane.public());
        assert!(open_sealed(&tom, &relabeled).is_err(), "claiming to be jane");

        // Nor to a low-order "identity key".
        assert!(seal_for(&jane, &[0; 32], b"secret").is_err());
    }

    #[test]
    fn rotations_chain_from_the_known_key() {
        let (k1, k2, k3) = (OrgKey::generate(), OrgKey::generate(), OrgKey::generate());
        let chain = [k1.rotate_to(7, &k2, 5), k2.rotate_to(7, &k3, 9)];
        assert_eq!(follow_rotations(7, &k1.public(), &chain).unwrap(), (k3.public(), 9));
        assert_eq!(follow_rotations(7, &k2.public(), &chain).unwrap(), (k3.public(), 9), "joined halfway");
        assert_eq!(follow_rotations(7, &k3.public(), &chain).unwrap(), (k3.public(), 0), "nothing to follow");
        assert_eq!(follow_rotations(8, &k1.public(), &chain).unwrap(), (k1.public(), 0), "another org");

        let mut forged = k1.rotate_to(7, &k3, 5);
        forged.to_pk = OrgKey::generate().public();
        assert!(follow_rotations(7, &k1.public(), &[forged]).is_err());
        // A rotation from a key we never knew is not a way in.
        let elsewhere = OrgKey::generate().rotate_to(7, &k3, 5);
        assert_eq!(follow_rotations(7, &k1.public(), &[elsewhere]).unwrap(), (k1.public(), 0));
    }

    #[test]
    fn enrollment_keys_roundtrip_and_certify_devices() {
        let org = OrgKey::generate();
        let key = EnrollmentKey::generate(7, org.public(), "ACME");
        let text = key.encode();
        assert!(text.starts_with("sdw1-"));
        let decoded = EnrollmentKey::decode(&text).unwrap();
        assert_eq!((decoded.org_id, decoded.org_pk, decoded.worker_pk()), (7, org.public(), key.worker_pk()));
        assert!(EnrollmentKey::decode("sdw1-garbage").is_err());

        let cert = decoded.certify_device([3; 32], "kiosk", 0);
        verify_device_cert(&cert).unwrap();
        let mut renamed = cert.clone();
        renamed.device_name = "other".into();
        assert!(verify_device_cert(&renamed).is_err());
    }
}
