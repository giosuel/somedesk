//! Organisations: signed access policies, service workers and the devices they enroll.
//!
//! An organisation has its own Ed25519 key, held by its admins only. Everything that decides who
//! may reach the organisation's devices is in an [`OrgPolicy`] signed with that key. The server
//! stores and delivers policies but cannot write one, and the enrolled devices (stubs) check the
//! signature against the organisation key they were enrolled with: a server that wanted to let
//! someone in would have to forge the organisation's signature.
//!
//! The key can be replaced (when an admin leaves, so their copy stops counting): the old key signs
//! an [`OrgRotation`] to the new one, and devices follow the chain of rotations from the key they
//! know.

use serde::{Deserialize, Serialize};

/// How long a policy is valid after it is signed. Admin devices sign a fresh copy well before
/// that; a stub that hears nothing newer stops accepting anyone once its copy expired.
pub const POLICY_LIFETIME_SECS: i64 = 30 * 24 * 3600;

/// The device group that stands for all of the organisation's devices.
pub const ALL_DEVICES: &str = "*";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgPolicy {
    pub org_id: u64,
    pub org_name: String,
    /// Increases with every change; stubs never go back to an older version.
    pub version: u64,
    /// [`policy_hash`] of the version this one was made from (zero for the first), so an admin
    /// can tell a policy that doesn't follow the one it last saw.
    pub prev_hash: [u8; 32],
    /// Unix seconds.
    pub issued_at: i64,
    pub expires_at: i64,
    pub members: Vec<OrgMember>,
    /// Named groups of members.
    pub groups: Vec<OrgGroup>,
    /// Named groups of enrolled devices ([`ALL_DEVICES`] needs no definition), by their keys.
    pub device_groups: Vec<DeviceGroup>,
    /// Who may connect to which devices, unattended.
    pub rules: Vec<AccessRule>,
    pub workers: Vec<ServiceWorker>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgMember {
    pub username: String,
    /// The account's identity key, as the admin added it.
    pub identity_pk: [u8; 32],
    pub admin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgGroup {
    pub name: String,
    /// Usernames.
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGroup {
    pub name: String,
    pub devices: Vec<GroupDevice>,
}

/// An enrolled device in a [`DeviceGroup`]. The device key decides (the server assigns IDs, so
/// it could move one); the ID is only there to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupDevice {
    pub device_pk: [u8; 32],
    pub device_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRule {
    /// A member group.
    pub group: String,
    /// A device group, or [`ALL_DEVICES`].
    pub device_group: String,
}

/// A service-worker account: its key enrolls devices into the organisation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceWorker {
    /// Ed25519 key that signs enrolled devices' certificates.
    pub worker_pk: [u8; 32],
    pub name: String,
    pub created_at: i64,
    /// No more devices enroll with it after this (Unix seconds).
    pub expires_at: Option<i64>,
    /// Revoked: no more devices enroll with it. Devices it enrolled stay enrolled.
    pub revoked: bool,
}

/// The organisation key `from_pk` handing over to `to_pk`, signed by `from_pk`. Takes effect with
/// the policy `version` (the first one `to_pk` signs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgRotation {
    pub org_id: u64,
    pub from_pk: [u8; 32],
    pub to_pk: [u8; 32],
    pub version: u64,
    pub signature: Vec<u8>,
}

impl OrgRotation {
    pub fn signed_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(&(b"somedesk org key rotation v1", self.org_id, &self.from_pk, &self.to_pk, self.version))
            .expect("serializing to a Vec cannot fail")
    }
}

/// What an organisation's device needs to check the current policy: the policy and the
/// rotations since the key it was enrolled with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub policy: SignedPolicy,
    /// Oldest first.
    pub rotations: Vec<OrgRotation>,
}

/// A policy with the organisation key's signature over [`SignedPolicy::policy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolicy {
    /// The postcard encoding of an [`OrgPolicy`].
    pub policy: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedPolicy {
    /// What the signature covers: a domain tag and the policy bytes.
    pub fn signed_bytes(policy: &[u8]) -> Vec<u8> {
        [b"somedesk org policy v2".as_slice(), policy].concat()
    }
}

/// Identifies a signed policy (for [`OrgPolicy::prev_hash`]).
pub fn policy_hash(signed: &SignedPolicy) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::new().chain_update(&signed.policy).chain_update(&signed.signature).finalize().into()
}

/// Binds an enrolled device's key to an organisation. Signed by the service worker that
/// enrolled it, which the organisation's policy lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgDeviceCert {
    pub org_id: u64,
    pub org_pk: [u8; 32],
    pub org_name: String,
    pub device_pk: [u8; 32],
    pub device_name: String,
    pub worker_pk: [u8; 32],
    pub created_at: i64,
    pub signature: Vec<u8>,
}

impl OrgDeviceCert {
    pub fn signed_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Tbs<'a> {
            domain: &'static str,
            org_id: u64,
            org_pk: &'a [u8; 32],
            org_name: &'a str,
            device_pk: &'a [u8; 32],
            device_name: &'a str,
            worker_pk: &'a [u8; 32],
            created_at: i64,
        }
        postcard::to_stdvec(&Tbs {
            domain: "somedesk org device cert v1",
            org_id: self.org_id,
            org_pk: &self.org_pk,
            org_name: &self.org_name,
            device_pk: &self.device_pk,
            device_name: &self.device_name,
            worker_pk: &self.worker_pk,
            created_at: self.created_at,
        })
        .expect("serializing to a Vec cannot fail")
    }
}

impl OrgPolicy {
    pub fn member(&self, username: &str) -> Option<&OrgMember> {
        self.members.iter().find(|m| m.username == username)
    }

    /// Whether the member `username` (with `identity_pk`) may connect to the device `device_pk`.
    pub fn allows(&self, username: &str, identity_pk: &[u8; 32], device_pk: &[u8; 32]) -> bool {
        if self.member(username).is_none_or(|m| &m.identity_pk != identity_pk) {
            return false;
        }
        self.rules.iter().any(|rule| {
            let in_group = self.groups.iter().any(|g| g.name == rule.group && g.members.iter().any(|m| m == username));
            let device_in = rule.device_group == ALL_DEVICES
                || self
                    .device_groups
                    .iter()
                    .any(|g| g.name == rule.device_group && g.devices.iter().any(|d| &d.device_pk == device_pk));
            in_group && device_in
        })
    }

    /// Whether the service worker `worker_pk` may enroll devices at `now`.
    pub fn worker_can_enroll(&self, worker_pk: &[u8; 32], now: i64) -> bool {
        self.workers.iter().any(|w| &w.worker_pk == worker_pk && !w.revoked && w.expires_at.is_none_or(|e| now < e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> OrgPolicy {
        OrgPolicy {
            org_id: 1,
            org_name: "ACME".into(),
            version: 1,
            prev_hash: [0; 32],
            issued_at: 0,
            expires_at: 100,
            members: vec![
                OrgMember { username: "jane".into(), identity_pk: [1; 32], admin: true },
                OrgMember { username: "tom".into(), identity_pk: [2; 32], admin: false },
            ],
            groups: vec![
                OrgGroup { name: "IT".into(), members: vec!["jane".into()] },
                OrgGroup { name: "Support".into(), members: vec!["tom".into()] },
            ],
            device_groups: vec![DeviceGroup {
                name: "Office".into(),
                devices: vec![GroupDevice { device_pk: [11; 32], device_id: 111 }],
            }],
            rules: vec![
                AccessRule { group: "IT".into(), device_group: ALL_DEVICES.into() },
                AccessRule { group: "Support".into(), device_group: "Office".into() },
            ],
            workers: vec![ServiceWorker {
                worker_pk: [9; 32],
                name: "rollout".into(),
                created_at: 0,
                expires_at: Some(50),
                revoked: false,
            }],
        }
    }

    #[test]
    fn rules_decide_who_reaches_which_devices() {
        let p = policy();
        assert!(p.allows("jane", &[1; 32], &[11; 32]));
        assert!(p.allows("jane", &[1; 32], &[22; 32]), "IT reaches all devices");
        assert!(p.allows("tom", &[2; 32], &[11; 32]));
        assert!(!p.allows("tom", &[2; 32], &[22; 32]), "Support only reaches the office");
        assert!(!p.allows("tom", &[3; 32], &[11; 32]), "another key under tom's name");
        assert!(!p.allows("eve", &[4; 32], &[11; 32]), "not a member");
    }

    #[test]
    fn workers_enroll_until_they_expire_or_are_revoked() {
        let mut p = policy();
        assert!(p.worker_can_enroll(&[9; 32], 10));
        assert!(!p.worker_can_enroll(&[9; 32], 60), "expired");
        assert!(!p.worker_can_enroll(&[8; 32], 10), "unknown");
        p.workers[0].revoked = true;
        assert!(!p.worker_can_enroll(&[9; 32], 10), "revoked");
    }
}
