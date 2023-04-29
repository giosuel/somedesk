//! Remembering who we have connected with, SSH-style.
//!
//! The server vouches for nothing: devices and accounts are only trusted because this device
//! remembers the keys it saw the first time ("trust on first use"):
//!
//! * the device key behind every device ID we dealt with, and
//! * the identity key of every account we saw.
//!
//! If either ever changes, the person at the computer is warned, because that is exactly what a
//! compromised or malicious server would have to do to get in between.

use serde::{Deserialize, Serialize};
use somedesk_proto::control::DeviceIdentity;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerStatus {
    /// Never dealt with this device (or its account) before.
    New,
    /// Same keys as before.
    Known,
    /// A different key than last time.
    Changed(Changed),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Changed {
    /// The device ID now belongs to another device key.
    Device { previous_pk: [u8; 32] },
    /// The account has another identity key.
    Account { previous_identity_pk: [u8; 32] },
}

impl Changed {
    /// The key we knew before.
    pub fn previous_key(&self) -> &[u8; 32] {
        match self {
            Changed::Device { previous_pk } => previous_pk,
            Changed::Account { previous_identity_pk } => previous_identity_pk,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownDevice {
    #[serde(with = "hex32")]
    pub device_pk: [u8; 32],
    pub name: String,
    /// The account it was signed in to when we last saw it.
    #[serde(default)]
    pub username: Option<String>,
    /// Unix seconds.
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownAccount {
    #[serde(with = "hex32")]
    pub identity_pk: [u8; 32],
    pub first_seen: i64,
    pub last_seen: i64,
}

/// Keys are stored as hex strings, so the file stays readable.
pub(crate) mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(serde::de::Error::custom)?;
        Ok(out)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    /// By device ID.
    #[serde(default)]
    devices: BTreeMap<u64, KnownDevice>,
    /// By username.
    #[serde(default)]
    accounts: BTreeMap<String, KnownAccount>,
    /// Before device IDs were pinned, the file only had accounts ("peers"), with devices that
    /// could connect without asking. That permission no longer exists; the keys carry over.
    #[serde(default, skip_serializing)]
    peers: BTreeMap<String, KnownAccount>,
}

/// The persistent list of known devices and accounts, kept in one JSON file.
pub struct TrustStore {
    path: PathBuf,
    file: File,
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

impl TrustStore {
    /// Loads the store, starting empty if the file does not exist yet.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let mut file: File = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(std::io::Error::other)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => File::default(),
            Err(e) => return Err(e),
        };
        for (username, account) in std::mem::take(&mut file.peers) {
            file.accounts.entry(username).or_insert(account);
        }
        Ok(Self { path: path.to_owned(), file })
    }

    /// An empty store that will be saved to `path`.
    pub fn empty(path: &Path) -> Self {
        Self { path: path.to_owned(), file: File::default() }
    }

    pub fn save(&self) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.file).expect("serializable"))?;
        std::fs::rename(tmp, &self.path)
    }

    /// How the device `device_id`, presenting `identity`, compares with what we remember. A
    /// changed device key wins over a changed account key.
    pub fn status(&self, device_id: u64, identity: &DeviceIdentity) -> PeerStatus {
        let device = self.file.devices.get(&device_id);
        if let Some(d) = device.filter(|d| d.device_pk != identity.device_pk) {
            return PeerStatus::Changed(Changed::Device { previous_pk: d.device_pk });
        }
        if let Some(cert) = &identity.account {
            match self.file.accounts.get(&cert.username) {
                Some(a) if a.identity_pk != cert.identity_pk => {
                    return PeerStatus::Changed(Changed::Account { previous_identity_pk: a.identity_pk })
                }
                Some(_) if device.is_none() => return PeerStatus::Known,
                _ => {}
            }
        }
        if device.is_some() {
            PeerStatus::Known
        } else {
            PeerStatus::New
        }
    }

    /// Records a successful connection with `device_id`, accepting its keys (also changed ones).
    pub fn remember(&mut self, device_id: u64, identity: &DeviceIdentity) {
        let t = now();
        let username = identity.username().map(str::to_owned);
        let device = self.file.devices.entry(device_id).or_insert_with(|| KnownDevice {
            device_pk: identity.device_pk,
            name: identity.name.clone(),
            username: username.clone(),
            first_seen: t,
            last_seen: t,
        });
        if device.device_pk != identity.device_pk {
            device.device_pk = identity.device_pk;
            device.first_seen = t;
        }
        device.name = identity.name.clone();
        device.username = username;
        device.last_seen = t;
        if let Some(cert) = &identity.account {
            let account = self.file.accounts.entry(cert.username.clone()).or_insert_with(|| KnownAccount {
                identity_pk: cert.identity_pk,
                first_seen: t,
                last_seen: t,
            });
            if account.identity_pk != cert.identity_pk {
                *account = KnownAccount { identity_pk: cert.identity_pk, first_seen: t, last_seen: t };
            }
            account.last_seen = t;
        }
    }

    /// The key we have pinned for `device_id`.
    pub fn device(&self, device_id: u64) -> Option<&KnownDevice> {
        self.file.devices.get(&device_id)
    }

    /// Forgets a device; the next connection with it is treated as the first.
    pub fn forget_device(&mut self, device_id: u64) {
        self.file.devices.remove(&device_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use somedesk_proto::control::DeviceCert;

    fn identity(user: Option<(&str, u8)>, device: u8) -> DeviceIdentity {
        DeviceIdentity {
            device_pk: [device; 32],
            name: format!("pc-{device}"),
            account: user.map(|(user, identity)| DeviceCert {
                username: user.into(),
                identity_pk: [identity; 32],
                device_pk: [device; 32],
                device_name: format!("pc-{device}"),
                created_at: 0,
                signature: vec![],
            }),
            org: None,
        }
    }

    fn store() -> (TrustStore, PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("somedesk-trust-{}-{n}.json", std::process::id()));
        (TrustStore::load(&path).unwrap(), path)
    }

    #[test]
    fn devices_first_use_then_known_then_changed() {
        let (mut s, _) = store();
        let laptop = identity(None, 10);
        assert_eq!(s.status(111, &laptop), PeerStatus::New);
        s.remember(111, &laptop);
        assert_eq!(s.status(111, &laptop), PeerStatus::Known);
        // Another key under the same ID is not.
        assert_eq!(s.status(111, &identity(None, 11)), PeerStatus::Changed(Changed::Device { previous_pk: [10; 32] }));
        assert_eq!(s.status(222, &identity(None, 11)), PeerStatus::New);
    }

    #[test]
    fn accounts_are_pinned_too() {
        let (mut s, _) = store();
        s.remember(111, &identity(Some(("alice", 1)), 10));
        // Another device of the same account is known through the account.
        assert_eq!(s.status(222, &identity(Some(("alice", 1)), 20)), PeerStatus::Known);
        // A different identity key under the same name is not.
        assert_eq!(
            s.status(222, &identity(Some(("alice", 2)), 20)),
            PeerStatus::Changed(Changed::Account { previous_identity_pk: [1; 32] })
        );
        // Accepting the change pins the new key.
        s.remember(222, &identity(Some(("alice", 2)), 20));
        assert_eq!(s.status(222, &identity(Some(("alice", 2)), 20)), PeerStatus::Known);
        s.forget_device(222);
        assert_eq!(s.status(222, &identity(None, 20)), PeerStatus::New);
    }

    #[test]
    fn survives_a_restart_and_reads_the_old_format() {
        let (mut s, path) = store();
        s.remember(111, &identity(Some(("bob", 3)), 30));
        s.save().unwrap();
        let s2 = TrustStore::load(&path).unwrap();
        assert_eq!(s2.status(111, &identity(Some(("bob", 3)), 30)), PeerStatus::Known);
        assert_eq!(s2.device(111).unwrap().username.as_deref(), Some("bob"));

        let old = r#"{"peers":{"alice":{"username":"alice","identity_pk":"0101010101010101010101010101010101010101010101010101010101010101","first_seen":1,"last_seen":2,"unattended":[]}}}"#;
        std::fs::write(&path, old).unwrap();
        let s3 = TrustStore::load(&path).unwrap();
        assert_eq!(
            s3.status(5, &identity(Some(("alice", 2)), 9)),
            PeerStatus::Changed(Changed::Account { previous_identity_pk: [1; 32] })
        );
        std::fs::remove_file(path).unwrap();
    }
}
