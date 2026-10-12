//! Organisations, from an admin's and from an enrolled device's point of view.
//!
//! Admins change the organisation's policy by signing a new version with the organisation key
//! ([`Admin`]). Devices a service worker enrolled keep the newest policy they have seen and decide
//! from it alone who gets in ([`PolicyStore`]); the organisation key they trust comes from their
//! enrollment, not from the server.

use crate::server::{LoggedIn, ServerConn};
use crate::{ClientError, Result};
use serde::{Deserialize, Serialize};
use somedesk_crypto::org::{open_sealed, seal_for, verify_policy, EnrollmentKey, OrgKey};
use somedesk_proto::control::{DeviceIdentity, OrgInfo};
use somedesk_proto::org::*;
use std::path::{Path, PathBuf};

/// Admins sign a fresh copy when the current one has less than this left.
const RENEW_BEFORE_SECS: i64 = 14 * 24 * 3600;

fn now() -> i64 {
    somedesk_crypto::totp::now() as i64
}

/// An admin's handle on an organisation: its key and current policy.
pub struct Admin {
    pub org_id: u64,
    pub key: OrgKey,
    pub policy: OrgPolicy,
}

impl Admin {
    /// Creates an organisation with `login`'s account as its only admin and member, in a group
    /// "Admins" that reaches all of the organisation's devices.
    pub async fn create(conn: &ServerConn, login: &LoggedIn, name: &str) -> Result<Self> {
        let key = OrgKey::generate();
        let sealed = seal_for(&login.identity.public(), key.to_bytes().as_slice())?;
        let org_id = conn.create_org(name, key.public(), sealed).await?;
        let policy = OrgPolicy {
            org_id,
            org_name: name.trim().to_owned(),
            version: 0,
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
        let mut admin = Self { org_id, key, policy };
        admin.publish(conn).await?;
        Ok(admin)
    }

    /// Opens an organisation the logged-in account administers (its key is sealed to the
    /// account's identity key).
    pub fn open(info: &OrgInfo, login: &LoggedIn) -> Result<Self> {
        let sealed = info
            .sealed_key
            .as_ref()
            .ok_or_else(|| ClientError::Other("you are not an admin of this organisation".into()))?;
        let bytes = open_sealed(&login.identity, sealed)?;
        let key =
            OrgKey::from_bytes(bytes.as_slice().try_into().map_err(|_| ClientError::Protocol("bad organisation key"))?);
        Self::from_key(info, key)
    }

    /// [`Admin::open`] with the organisation key kept on this device.
    pub fn from_key(info: &OrgInfo, key: OrgKey) -> Result<Self> {
        if key.public() != info.org_pk {
            return Err(ClientError::Protocol("the organisation key doesn't match"));
        }
        let signed = info.policy.as_ref().ok_or(ClientError::Protocol("the organisation has no policy"))?;
        let policy = verify_policy(signed, &info.org_pk)?;
        Ok(Self { org_id: info.org_id, key, policy })
    }

    /// Signs the policy as the next version (valid for [`POLICY_LIFETIME_SECS`]) and publishes it.
    pub async fn publish(&mut self, conn: &ServerConn) -> Result<()> {
        let mut next = self.policy.clone();
        next.version += 1;
        next.issued_at = now();
        next.expires_at = next.issued_at + POLICY_LIFETIME_SECS;
        conn.put_org_policy(self.org_id, self.key.sign_policy(&next)).await?;
        self.policy = next;
        Ok(())
    }

    /// Re-publishes the policy unchanged if it expires soon.
    pub async fn renew_if_due(&mut self, conn: &ServerConn) -> Result<bool> {
        if self.policy.expires_at - now() > RENEW_BEFORE_SECS {
            return Ok(false);
        }
        self.publish(conn).await?;
        Ok(true)
    }

    /// Adds an account as a member, with the identity key the server has for it (shown to the
    /// admin as a fingerprint to compare), and puts it into `group`.
    pub async fn add_member(
        &mut self,
        conn: &ServerConn,
        username: &str,
        group: &str,
        admin: bool,
    ) -> Result<[u8; 32]> {
        let username =
            somedesk_proto::normalize_username(username).ok_or(ClientError::Other("invalid username".into()))?;
        let identity_pk = conn.lookup_user(&username).await?;
        self.policy.members.retain(|m| m.username != username);
        self.policy.members.push(OrgMember { username: username.clone(), identity_pk, admin });
        self.add_to_group(&username, group);
        self.publish(conn).await?;
        if admin {
            let sealed = seal_for(&identity_pk, self.key.to_bytes().as_slice())?;
            conn.share_org_key(self.org_id, &username, sealed).await?;
        }
        Ok(identity_pk)
    }

    pub async fn remove_member(&mut self, conn: &ServerConn, username: &str) -> Result<()> {
        self.policy.members.retain(|m| m.username != username);
        for g in &mut self.policy.groups {
            g.members.retain(|m| m != username);
        }
        self.publish(conn).await
    }

    fn add_to_group(&mut self, username: &str, group: &str) {
        match self.policy.groups.iter_mut().find(|g| g.name == group) {
            Some(g) if !g.members.iter().any(|m| m == username) => g.members.push(username.to_owned()),
            Some(_) => {}
            None => self.policy.groups.push(OrgGroup { name: group.to_owned(), members: vec![username.to_owned()] }),
        }
    }

    /// Lets `group` reach `device_group` (or [`ALL_DEVICES`]).
    pub async fn allow(&mut self, conn: &ServerConn, group: &str, device_group: &str) -> Result<()> {
        let rule = AccessRule { group: group.to_owned(), device_group: device_group.to_owned() };
        if !self.policy.rules.contains(&rule) {
            self.policy.rules.push(rule);
        }
        self.publish(conn).await
    }

    pub async fn disallow(&mut self, conn: &ServerConn, group: &str, device_group: &str) -> Result<()> {
        self.policy.rules.retain(|r| !(r.group == group && r.device_group == device_group));
        self.publish(conn).await
    }

    /// Puts enrolled devices into a device group (creating it).
    pub async fn set_device_group(&mut self, conn: &ServerConn, name: &str, devices: Vec<u64>) -> Result<()> {
        self.policy.device_groups.retain(|g| g.name != name);
        self.policy.device_groups.push(DeviceGroup { name: name.to_owned(), devices });
        self.publish(conn).await
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
        self.policy.workers.push(ServiceWorker {
            worker_pk: key.worker_pk(),
            name: name.trim().to_owned(),
            created_at: now(),
            expires_at,
            revoked: false,
        });
        self.publish(conn).await?;
        Ok(key)
    }

    /// Stops a service worker from enrolling further devices.
    pub async fn revoke_worker(&mut self, conn: &ServerConn, worker_pk: &[u8; 32]) -> Result<()> {
        for w in self.policy.workers.iter_mut().filter(|w| &w.worker_pk == worker_pk) {
            w.revoked = true;
        }
        self.publish(conn).await
    }
}

/// An enrolled device's copy of its organisation's policy.
#[derive(Serialize, Deserialize)]
struct StoredPolicy {
    signed: SignedPolicy,
}

pub struct PolicyStore {
    path: PathBuf,
    org_pk: [u8; 32],
    policy: Option<OrgPolicy>,
    signed: Option<SignedPolicy>,
}

impl PolicyStore {
    /// Loads the policy kept at `path`, trusting only signatures by `org_pk` (from the device's
    /// enrollment).
    pub fn load(path: &Path, org_pk: [u8; 32]) -> Self {
        let signed =
            std::fs::read(path).ok().and_then(|b| serde_json::from_slice::<StoredPolicy>(&b).ok()).map(|s| s.signed);
        let policy = signed.as_ref().and_then(|s| verify_policy(s, &org_pk).ok());
        Self { path: path.to_owned(), org_pk, signed: policy.as_ref().and(signed), policy }
    }

    /// Takes a policy from the server if it is signed by the organisation and not older than
    /// the one we have. Returns whether it replaced it.
    pub fn update(&mut self, signed: SignedPolicy) -> Result<bool> {
        let policy = verify_policy(&signed, &self.org_pk)?;
        if self.policy.as_ref().is_some_and(|p| p.version >= policy.version) {
            return Ok(false);
        }
        let stored = serde_json::to_vec(&StoredPolicy { signed: signed.clone() }).expect("serializable");
        std::fs::write(&self.path, stored).map_err(|e| ClientError::Other(e.to_string()))?;
        self.policy = Some(policy);
        self.signed = Some(signed);
        Ok(true)
    }

    /// The policy, if it hasn't expired.
    pub fn current(&self) -> Option<&OrgPolicy> {
        self.policy.as_ref().filter(|p| now() < p.expires_at)
    }

    /// Whether `peer` (verified in the handshake) may connect to this device, `device_id`. The
    /// peer has to be signed in to a member account whose identity key the policy names.
    pub fn allows(&self, peer: &DeviceIdentity, device_id: u64) -> bool {
        let (Some(policy), Some(cert)) = (self.current(), &peer.account) else { return false };
        policy.allows(&cert.username, &cert.identity_pk, device_id)
    }
}
