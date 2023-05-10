//! Organisations, from an admin's and from an enrolled device's point of view.
//!
//! Admins change the organisation's policy by signing a new version with the organisation key
//! ([`Admin`]). Devices a service worker enrolled keep the newest policy they have seen and decide
//! from it alone who gets in ([`PolicyStore`]); the organisation key they trust comes from their
//! enrollment, not from the server, and changes only through rotations the key before signed.
//!
//! An admin's account remembers each organisation's key and the newest policy it has seen
//! ([`OrgPin`], kept in the address book and so on all of the account's devices). The server can
//! then neither hand it a key of its own nor an older policy to build on.

use crate::server::{LoggedIn, ServerConn};
use crate::trust::hex32;
use crate::{ClientError, Result};
use serde::{Deserialize, Serialize};
use somedesk_crypto::org::{follow_rotations, open_sealed, seal_for, verify_device_cert, verify_policy};
use somedesk_crypto::org::{EnrollmentKey, OrgKey};
use somedesk_proto::control::{DeviceIdentity, OrgInfo};
use somedesk_proto::org::*;
use std::path::{Path, PathBuf};

/// Admins sign a fresh copy when the current one has less than this left.
const RENEW_BEFORE_SECS: i64 = 14 * 24 * 3600;

fn now() -> i64 {
    somedesk_crypto::totp::now() as i64
}

/// What an admin's account remembers about an organisation: its key and the newest policy seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgPin {
    pub org_id: u64,
    #[serde(with = "hex32")]
    pub org_pk: [u8; 32],
    pub version: u64,
    #[serde(with = "hex32")]
    pub policy_hash: [u8; 32],
}

/// An admin's handle on an organisation: its key and current policy.
pub struct Admin {
    pub org_id: u64,
    pub key: OrgKey,
    pub policy: OrgPolicy,
    /// [`policy_hash`] of the signed `policy`.
    hash: [u8; 32],
    /// The organisation's keys before this one (enrolled devices may still carry them).
    earlier_keys: Vec<[u8; 32]>,
}

/// An organisation key opened for the first time on this account: who shared it.
pub struct SharedBy {
    pub username: String,
    pub identity_pk: [u8; 32],
}

impl Admin {
    /// Creates an organisation with `login`'s account as its only admin and member, in a group
    /// "Admins" that reaches all of the organisation's devices.
    pub async fn create(conn: &ServerConn, login: &LoggedIn, name: &str) -> Result<Self> {
        let key = OrgKey::generate();
        let sealed = seal_for(&login.identity, &login.identity.public(), key.to_bytes().as_slice())?;
        let org_id = conn.create_org(name, key.public(), sealed).await?;
        let first = OrgPolicy {
            org_id,
            org_name: name.trim().to_owned(),
            version: 0,
            prev_hash: [0; 32],
            issued_at: 0,
            expires_at: 0,
            members: vec![OrgMember {
                username: login.username.clone(),
                identity_pk: login.identity.public(),
                admin: true,
            }],
            groups: vec![OrgGroup { name: "Admins".into(), members: vec![login.username.clone()] }],
            device_groups: vec![],
            rules: vec![AccessRule { group: "Admins".into(), device_group: ALL_DEVICES.into() }],
            workers: vec![],
        };
        let mut admin = Self { org_id, key, policy: first.clone(), hash: [0; 32], earlier_keys: vec![] };
        admin.publish(conn, first).await?;
        Ok(admin)
    }

    /// Opens an organisation the logged-in account administers: its key is sealed to the
    /// account's identity key, by the admin who shared it.
    ///
    /// With `pin` (what the account saw before), the key has to be the pinned one or follow from
    /// it, and the policy can't be older. Without one (the first time), `Some` [`SharedBy`] says
    /// which other admin sealed the key, for the user to check; the caller pins what it got
    /// ([`Admin::pin`]) either way.
    pub fn open(info: &OrgInfo, login: &LoggedIn, pin: Option<&OrgPin>) -> Result<(Self, Option<SharedBy>)> {
        let sealed = info
            .sealed_key
            .as_ref()
            .ok_or_else(|| ClientError::Other("you are not an admin of this organisation".into()))?;
        let (bytes, sender_pk) = open_sealed(&login.identity, sealed)?;
        let key =
            OrgKey::from_bytes(bytes.as_slice().try_into().map_err(|_| ClientError::Protocol("bad organisation key"))?);
        let admin = Self::from_key(info, key, pin)?;
        let shared_by = if sender_pk == login.identity.public() {
            None
        } else {
            // Only an admin the policy (signed with this very key) names can have sealed it.
            let m = admin
                .policy
                .members
                .iter()
                .find(|m| m.admin && m.identity_pk == sender_pk)
                .ok_or(ClientError::Protocol("the organisation key wasn't shared by one of its admins"))?;
            Some(SharedBy { username: m.username.clone(), identity_pk: sender_pk })
        };
        if pin.is_some() {
            return Ok((admin, None));
        }
        Ok((admin, shared_by))
    }

    /// [`Admin::open`] with the organisation key kept on this device.
    pub fn from_key(info: &OrgInfo, key: OrgKey, pin: Option<&OrgPin>) -> Result<Self> {
        if key.public() != info.org_pk {
            return Err(ClientError::Protocol("the organisation key doesn't match"));
        }
        if let Some(pin) = pin {
            let (expected, _) = follow_rotations(info.org_id, &pin.org_pk, &info.rotations)?;
            if expected != info.org_pk {
                return Err(ClientError::Other(
                    "the server presents another key for this organisation than your account knows".into(),
                ));
            }
        }
        let signed = info.policy.as_ref().ok_or(ClientError::Protocol("the organisation has no policy"))?;
        let policy = verify_policy(signed, &info.org_pk)?;
        let hash = policy_hash(signed);
        if policy.org_id != info.org_id {
            return Err(ClientError::Protocol("the policy is for another organisation"));
        }
        if let Some(pin) = pin {
            if policy.version < pin.version || (policy.version == pin.version && hash != pin.policy_hash) {
                return Err(ClientError::Other(
                    "the server sent an older policy for this organisation than your account has seen".into(),
                ));
            }
        }
        let earlier_keys = info.rotations.iter().filter(|r| r.org_id == info.org_id).map(|r| r.from_pk).collect();
        Ok(Self { org_id: info.org_id, key, policy, hash, earlier_keys })
    }

    /// What the account should remember now.
    pub fn pin(&self) -> OrgPin {
        OrgPin { org_id: self.org_id, org_pk: self.key.public(), version: self.policy.version, policy_hash: self.hash }
    }

    /// Fills in what makes `next` the version after the current policy.
    fn successor(&self, mut next: OrgPolicy) -> OrgPolicy {
        next.version = self.policy.version + 1;
        next.prev_hash = self.hash;
        next.issued_at = now();
        next.expires_at = next.issued_at + POLICY_LIFETIME_SECS;
        next
    }

    /// Signs `next` as the next version (valid for [`POLICY_LIFETIME_SECS`]) and publishes it.
    /// The admin's policy only changes once the server took it.
    async fn publish(&mut self, conn: &ServerConn, next: OrgPolicy) -> Result<()> {
        let next = self.successor(next);
        let signed = self.key.sign_policy(&next);
        conn.put_org_policy(self.org_id, signed.clone()).await?;
        self.hash = policy_hash(&signed);
        self.policy = next;
        Ok(())
    }

    /// Replaces the organisation key with a new one and publishes `next` with it: the old key
    /// signs the handover, and every admin of `next` gets the new key, sealed by `login`.
    async fn rotate(&mut self, conn: &ServerConn, login: &LoggedIn, next: OrgPolicy) -> Result<()> {
        let next = self.successor(next);
        let new_key = OrgKey::generate();
        let rotation = self.key.rotate_to(self.org_id, &new_key, next.version);
        let signed = new_key.sign_policy(&next);
        let mut sealed = Vec::new();
        for m in next.members.iter().filter(|m| m.admin) {
            sealed
                .push((m.username.clone(), seal_for(&login.identity, &m.identity_pk, new_key.to_bytes().as_slice())?));
        }
        conn.rotate_org_key(self.org_id, rotation, signed.clone(), sealed).await?;
        self.earlier_keys.push(self.key.public());
        self.key = new_key;
        self.hash = policy_hash(&signed);
        self.policy = next;
        Ok(())
    }

    /// Re-publishes the policy unchanged if it expires soon.
    pub async fn renew_if_due(&mut self, conn: &ServerConn) -> Result<bool> {
        if self.policy.expires_at - now() > RENEW_BEFORE_SECS {
            return Ok(false);
        }
        self.publish(conn, self.policy.clone()).await?;
        Ok(true)
    }

    /// Adds an account as a member, with the identity key the server has for it (shown to the
    /// admin as a fingerprint to compare), and puts it into `group`. An admin also gets the
    /// organisation key, sealed by `login`.
    pub async fn add_member(
        &mut self,
        conn: &ServerConn,
        login: &LoggedIn,
        username: &str,
        group: &str,
        admin: bool,
    ) -> Result<[u8; 32]> {
        let username =
            somedesk_proto::normalize_username(username).ok_or(ClientError::Other("invalid username".into()))?;
        let identity_pk = conn.lookup_user(&username).await?;
        let mut next = self.policy.clone();
        next.members.retain(|m| m.username != username);
        next.members.push(OrgMember { username: username.clone(), identity_pk, admin });
        add_to_group(&mut next, &username, group);
        self.publish(conn, next).await?;
        if admin {
            let sealed = seal_for(&login.identity, &identity_pk, self.key.to_bytes().as_slice())?;
            conn.share_org_key(self.org_id, &username, sealed).await?;
        }
        Ok(identity_pk)
    }

    /// Takes a member out of the organisation. An admin's copy of the key would still sign
    /// policies, so then the key is replaced too.
    pub async fn remove_member(&mut self, conn: &ServerConn, login: &LoggedIn, username: &str) -> Result<()> {
        let was_admin = self.policy.member(username).is_some_and(|m| m.admin);
        let mut next = self.policy.clone();
        next.members.retain(|m| m.username != username);
        for g in &mut next.groups {
            g.members.retain(|m| m != username);
        }
        if !next.members.iter().any(|m| m.admin) {
            return Err(ClientError::Other("an organisation needs at least one admin".into()));
        }
        if was_admin {
            self.rotate(conn, login, next).await
        } else {
            self.publish(conn, next).await
        }
    }

    /// Lets `group` reach `device_group` (or [`ALL_DEVICES`]).
    pub async fn allow(&mut self, conn: &ServerConn, group: &str, device_group: &str) -> Result<()> {
        let rule = AccessRule { group: group.to_owned(), device_group: device_group.to_owned() };
        let mut next = self.policy.clone();
        if !next.rules.contains(&rule) {
            next.rules.push(rule);
        }
        self.publish(conn, next).await
    }

    pub async fn disallow(&mut self, conn: &ServerConn, group: &str, device_group: &str) -> Result<()> {
        let mut next = self.policy.clone();
        next.rules.retain(|r| !(r.group == group && r.device_group == device_group));
        self.publish(conn, next).await
    }

    /// Puts enrolled devices (by ID) into a device group (creating it). The policy names them by
    /// their keys, which their enrollment certificates vouch for, not the server.
    pub async fn set_device_group(&mut self, conn: &ServerConn, name: &str, device_ids: &[u64]) -> Result<()> {
        let enrolled = conn.list_org_devices(self.org_id).await?;
        let mut devices = Vec::new();
        for id in device_ids {
            let device = enrolled
                .iter()
                .find(|d| d.device_id == *id && self.enrolled_here(&d.identity))
                .ok_or_else(|| ClientError::Other(format!("{id} is not one of the organisation's devices")))?;
            devices.push(GroupDevice { device_pk: device.identity.device_pk, device_id: *id });
        }
        let mut next = self.policy.clone();
        next.device_groups.retain(|g| g.name != name);
        next.device_groups.push(DeviceGroup { name: name.to_owned(), devices });
        self.publish(conn, next).await
    }

    /// Whether `device` carries a certificate from one of this organisation's service workers.
    fn enrolled_here(&self, device: &DeviceIdentity) -> bool {
        let Some(cert) = &device.org else { return false };
        verify_device_cert(cert).is_ok()
            && cert.device_pk == device.device_pk
            && cert.org_id == self.org_id
            && (cert.org_pk == self.key.public() || self.earlier_keys.contains(&cert.org_pk))
            && self.policy.workers.iter().any(|w| w.worker_pk == cert.worker_pk)
    }

    /// Creates a service worker. The returned key enrolls devices (`somedesk-agent enroll`); it
    /// is shown once and not kept anywhere.
    pub async fn create_worker(
        &mut self,
        conn: &ServerConn,
        name: &str,
        expires_at: Option<i64>,
    ) -> Result<EnrollmentKey> {
        let key = EnrollmentKey::generate(self.org_id, self.key.public(), &self.policy.org_name);
        let mut next = self.policy.clone();
        next.workers.push(ServiceWorker {
            worker_pk: key.worker_pk(),
            name: name.trim().to_owned(),
            created_at: now(),
            expires_at,
            revoked: false,
        });
        self.publish(conn, next).await?;
        Ok(key)
    }

    /// Stops a service worker from enrolling further devices.
    pub async fn revoke_worker(&mut self, conn: &ServerConn, worker_pk: &[u8; 32]) -> Result<()> {
        let mut next = self.policy.clone();
        for w in next.workers.iter_mut().filter(|w| &w.worker_pk == worker_pk) {
            w.revoked = true;
        }
        self.publish(conn, next).await
    }
}

fn add_to_group(policy: &mut OrgPolicy, username: &str, group: &str) {
    match policy.groups.iter_mut().find(|g| g.name == group) {
        Some(g) if !g.members.iter().any(|m| m == username) => g.members.push(username.to_owned()),
        Some(_) => {}
        None => policy.groups.push(OrgGroup { name: group.to_owned(), members: vec![username.to_owned()] }),
    }
}

/// An enrolled device's copy of its organisation's policy, and the organisation key it got to.
#[derive(Serialize, Deserialize)]
struct StoredPolicy {
    signed: SignedPolicy,
    #[serde(with = "hex32")]
    org_pk: [u8; 32],
}

pub struct PolicyStore {
    path: PathBuf,
    org_id: u64,
    org_pk: [u8; 32],
    policy: Option<OrgPolicy>,
}

impl PolicyStore {
    /// Loads the policy kept at `path` for organisation `org_id`, trusting only signatures by
    /// `enrolled_pk` (from the device's enrollment) or a key it handed over to since.
    pub fn load(path: &Path, org_id: u64, enrolled_pk: [u8; 32]) -> Self {
        let stored = std::fs::read(path).ok().and_then(|b| serde_json::from_slice::<StoredPolicy>(&b).ok());
        let mut store = Self { path: path.to_owned(), org_id, org_pk: enrolled_pk, policy: None };
        if let Some(stored) = stored {
            if let Ok(policy) = verify_policy(&stored.signed, &stored.org_pk) {
                if policy.org_id == org_id {
                    (store.org_pk, store.policy) = (stored.org_pk, Some(policy));
                }
            }
        }
        store
    }

    /// Takes a policy from the server if it is signed by the organisation (following its key
    /// rotations), newer than the one we have, and not expired. Returns whether it replaced it.
    pub fn update(&mut self, bundle: PolicyBundle) -> Result<bool> {
        let (org_pk, _) = follow_rotations(self.org_id, &self.org_pk, &bundle.rotations)?;
        let policy = verify_policy(&bundle.policy, &org_pk)?;
        if policy.org_id != self.org_id {
            return Err(ClientError::Protocol("the policy is for another organisation"));
        }
        if self.policy.as_ref().is_some_and(|p| p.version >= policy.version) || policy.expires_at <= now() {
            return Ok(false);
        }
        let stored = serde_json::to_vec(&StoredPolicy { signed: bundle.policy, org_pk }).expect("serializable");
        crate::credentials::write_private(&self.path, &stored).map_err(|e| ClientError::Other(e.to_string()))?;
        self.org_pk = org_pk;
        self.policy = Some(policy);
        Ok(true)
    }

    /// The policy, if it hasn't expired.
    pub fn current(&self) -> Option<&OrgPolicy> {
        self.policy.as_ref().filter(|p| now() < p.expires_at)
    }

    /// Whether `peer` (verified in the handshake, and its account checked with the server) may
    /// connect to this device, `device_pk`. The peer has to be signed in to a member account
    /// whose identity key the policy names.
    pub fn allows(&self, peer: &DeviceIdentity, device_pk: &[u8; 32]) -> bool {
        let (Some(policy), Some(cert)) = (self.current(), &peer.account) else { return false };
        policy.allows(&cert.username, &cert.identity_pk, device_pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use somedesk_crypto::keys::IdentityKey;

    fn login(username: &str) -> LoggedIn {
        LoggedIn { username: username.into(), identity: IdentityKey::generate(), has_recovery: true }
    }

    fn policy(org_id: u64, version: u64, admins: &[(&str, [u8; 32])]) -> OrgPolicy {
        OrgPolicy {
            org_id,
            org_name: "ACME".into(),
            version,
            prev_hash: [0; 32],
            issued_at: 0,
            expires_at: now() + 1000,
            members: admins
                .iter()
                .map(|(u, pk)| OrgMember { username: (*u).into(), identity_pk: *pk, admin: true })
                .collect(),
            groups: vec![],
            device_groups: vec![],
            rules: vec![],
            workers: vec![],
        }
    }

    /// What the server lists for `to`: the organisation with `key`, sealed by `by`.
    fn info(key: &OrgKey, policy: &OrgPolicy, by: &IdentityKey, to: &LoggedIn) -> OrgInfo {
        OrgInfo {
            org_id: policy.org_id,
            name: "ACME".into(),
            org_pk: key.public(),
            sealed_key: Some(seal_for(by, &to.identity.public(), key.to_bytes().as_slice()).unwrap()),
            policy: Some(key.sign_policy(policy)),
            rotations: vec![],
            joined: true,
        }
    }

    #[test]
    fn a_server_cant_swap_the_key_or_go_back() {
        let jane = login("jane");
        let key = OrgKey::generate();
        let v3 = policy(5, 3, &[("jane", jane.identity.public())]);
        let (admin, by) = Admin::open(&info(&key, &v3, &jane.identity, &jane), &jane, None).unwrap();
        assert!(by.is_none(), "she sealed it herself");
        let pin = admin.pin();

        // A key of the server's own, sealed by the server, with a policy that names itself
        // "jane": without a pin, the user is told who sealed it (and the app compares that key
        // with the one it knows for jane); with the pin, it's refused outright.
        let server = IdentityKey::generate();
        let fake = OrgKey::generate();
        let fake_policy = policy(5, 9, &[("jane", server.public())]);
        let swapped = info(&fake, &fake_policy, &server, &jane);
        let (_, by) = Admin::open(&swapped, &jane, None).unwrap();
        assert_eq!(by.unwrap().identity_pk, server.public());
        assert!(Admin::open(&swapped, &jane, Some(&pin)).is_err());

        // Sealed by someone the policy doesn't name as an admin: refused.
        let stranger = info(&key, &v3, &IdentityKey::generate(), &jane);
        assert!(Admin::open(&stranger, &jane, None).is_err());

        // The right key, but an older policy than the account saw.
        let v2 = policy(5, 2, &[("jane", jane.identity.public())]);
        assert!(Admin::open(&info(&key, &v2, &jane.identity, &jane), &jane, Some(&pin)).is_err());
        // Or another one under the same version.
        let mut other = v3.clone();
        other.org_name = "ACME 2".into();
        assert!(Admin::open(&info(&key, &other, &jane.identity, &jane), &jane, Some(&pin)).is_err());

        // A newer one with a rotation from the pinned key is fine.
        let next = OrgKey::generate();
        let v4 = policy(5, 4, &[("jane", jane.identity.public())]);
        let mut rotated = info(&next, &v4, &jane.identity, &jane);
        rotated.rotations = vec![key.rotate_to(5, &next, 4)];
        assert_eq!(Admin::open(&rotated, &jane, Some(&pin)).unwrap().0.policy.version, 4);
    }

    #[test]
    fn stubs_take_only_newer_unexpired_policies_of_their_organisation() {
        let key = OrgKey::generate();
        let path = std::env::temp_dir().join(format!("somedesk-policy-{}-{}.json", std::process::id(), now()));
        let mut store = PolicyStore::load(&path, 5, key.public());
        let bundle = |p: &OrgPolicy| PolicyBundle { policy: key.sign_policy(p), rotations: vec![] };
        let mut expired = policy(5, 1, &[]);
        expired.expires_at = now() - 1;
        assert!(!store.update(bundle(&expired)).unwrap(), "expired");
        assert!(store.update(bundle(&policy(5, 2, &[]))).unwrap());
        assert!(!store.update(bundle(&policy(5, 2, &[]))).unwrap(), "the same version");
        assert!(!store.update(bundle(&policy(5, 1, &[]))).unwrap(), "an older one");
        assert!(store.update(bundle(&policy(6, 3, &[]))).is_err(), "another organisation's");
        assert_eq!(PolicyStore::load(&path, 5, key.public()).current().unwrap().version, 2, "kept on disk");
        let _ = std::fs::remove_file(path);
    }
}
