//! Remembering who we have connected with, SSH-style.
//!
//! The server vouches for nothing: identities are only trusted because each device remembers the
//! identity key it saw the first time it dealt with a user ("trust on first use"). If a user's
//! key ever changes, the person at the computer is warned, because that is exactly what a
//! compromised or malicious server would have to do to get in between.
//!
//! On top of that, individual devices of other users can be allowed to connect without asking
//! (unattended access), tied to both the device key and the user's identity key.

use serde::{Deserialize, Serialize};
use somedesk_proto::control::DeviceCert;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerStatus {
    /// Never seen this user before.
    New,
    /// Same identity key as before.
    Known,
    /// The user has a different identity key than last time.
    Changed { previous_identity_pk: [u8; 32] },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownPeer {
    pub username: String,
    #[serde(with = "hex32")]
    pub identity_pk: [u8; 32],
    /// Unix seconds.
    pub first_seen: i64,
    pub last_seen: i64,
    /// Devices of this user that may connect without asking.
    #[serde(default)]
    pub unattended: Vec<TrustedDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedDevice {
    #[serde(with = "hex32")]
    pub device_pk: [u8; 32],
    pub device_name: String,
    pub added: i64,
}

/// Keys are stored as hex strings, so the file stays readable.
mod hex32 {
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
    peers: BTreeMap<String, KnownPeer>,
}

/// The persistent list of known peers, kept in one JSON file.
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
        let file = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(std::io::Error::other)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => File::default(),
            Err(e) => return Err(e),
        };
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

    /// How `cert`'s user compares with what we remember.
    pub fn status(&self, cert: &DeviceCert) -> PeerStatus {
        match self.file.peers.get(&cert.username) {
            None => PeerStatus::New,
            Some(p) if p.identity_pk == cert.identity_pk => PeerStatus::Known,
            Some(p) => PeerStatus::Changed { previous_identity_pk: p.identity_pk },
        }
    }

    /// Records a successful connection with `cert`'s user, accepting its identity key. If the key
    /// changed, everything trusted under the old key is dropped.
    pub fn remember(&mut self, cert: &DeviceCert) {
        let t = now();
        let peer = self.file.peers.entry(cert.username.clone()).or_insert_with(|| KnownPeer {
            username: cert.username.clone(),
            identity_pk: cert.identity_pk,
            first_seen: t,
            last_seen: t,
            unattended: Vec::new(),
        });
        if peer.identity_pk != cert.identity_pk {
            *peer = KnownPeer {
                username: cert.username.clone(),
                identity_pk: cert.identity_pk,
                first_seen: t,
                last_seen: t,
                unattended: Vec::new(),
            };
        }
        peer.last_seen = t;
    }

    /// Lets `cert`'s device connect without asking from now on (also remembers the user).
    pub fn allow_unattended(&mut self, cert: &DeviceCert) {
        self.remember(cert);
        let peer = self.file.peers.get_mut(&cert.username).expect("just remembered");
        if !peer.unattended.iter().any(|d| d.device_pk == cert.device_pk) {
            peer.unattended.push(TrustedDevice {
                device_pk: cert.device_pk,
                device_name: cert.device_name.clone(),
                added: now(),
            });
        }
    }

    /// Whether `cert` may connect without asking: the device was allowed explicitly and its
    /// user's identity key is still the one we know.
    pub fn is_unattended(&self, cert: &DeviceCert) -> bool {
        self.file.peers.get(&cert.username).is_some_and(|p| {
            p.identity_pk == cert.identity_pk && p.unattended.iter().any(|d| d.device_pk == cert.device_pk)
        })
    }

    /// Stops a device from connecting without asking.
    pub fn revoke_unattended(&mut self, username: &str, device_pk: &[u8; 32]) {
        if let Some(p) = self.file.peers.get_mut(username) {
            p.unattended.retain(|d| &d.device_pk != device_pk);
        }
    }

    /// Forgets a user entirely; the next connection is treated as the first.
    pub fn forget(&mut self, username: &str) {
        self.file.peers.remove(username);
    }

    pub fn peers(&self) -> impl Iterator<Item = &KnownPeer> {
        self.file.peers.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(user: &str, identity: u8, device: u8) -> DeviceCert {
        DeviceCert {
            username: user.into(),
            identity_pk: [identity; 32],
            device_pk: [device; 32],
            device_name: format!("{user}-pc-{device}"),
            created_at: 0,
            signature: vec![],
        }
    }

    fn store() -> (TrustStore, PathBuf) {
        let path = std::env::temp_dir().join(format!("somedesk-trust-{}-{}.json", std::process::id(), rand_suffix()));
        (TrustStore::load(&path).unwrap(), path)
    }

    fn rand_suffix() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn first_use_then_known_then_changed() {
        let (mut s, _) = store();
        let alice = cert("alice", 1, 10);
        assert_eq!(s.status(&alice), PeerStatus::New);
        s.remember(&alice);
        assert_eq!(s.status(&alice), PeerStatus::Known);
        // Another device of the same user is fine.
        assert_eq!(s.status(&cert("alice", 1, 11)), PeerStatus::Known);
        // A different identity key under the same name is not.
        assert_eq!(s.status(&cert("alice", 2, 10)), PeerStatus::Changed { previous_identity_pk: [1; 32] });
        assert_eq!(s.status(&cert("bob", 2, 20)), PeerStatus::New);
    }

    #[test]
    fn unattended_access_is_per_device_and_identity() {
        let (mut s, _) = store();
        let laptop = cert("alice", 1, 10);
        assert!(!s.is_unattended(&laptop));
        s.allow_unattended(&laptop);
        assert!(s.is_unattended(&laptop));
        assert_eq!(s.status(&laptop), PeerStatus::Known);
        // Not her other devices, and not if her identity changed.
        assert!(!s.is_unattended(&cert("alice", 1, 11)));
        assert!(!s.is_unattended(&cert("alice", 2, 10)));
        // Accepting a changed identity drops what was trusted under the old one.
        s.remember(&cert("alice", 2, 10));
        assert!(!s.is_unattended(&cert("alice", 2, 10)));
        s.allow_unattended(&cert("alice", 2, 10));
        s.revoke_unattended("alice", &[10; 32]);
        assert!(!s.is_unattended(&cert("alice", 2, 10)));
        s.forget("alice");
        assert_eq!(s.status(&laptop), PeerStatus::New);
    }

    #[test]
    fn survives_a_restart() {
        let (mut s, path) = store();
        s.allow_unattended(&cert("alice", 1, 10));
        s.remember(&cert("bob", 3, 30));
        s.save().unwrap();
        let s2 = TrustStore::load(&path).unwrap();
        assert!(s2.is_unattended(&cert("alice", 1, 10)));
        assert_eq!(s2.status(&cert("bob", 3, 31)), PeerStatus::Known);
        assert_eq!(s2.peers().count(), 2);
        std::fs::remove_file(path).unwrap();
    }
}
