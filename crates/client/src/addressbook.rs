//! The address book: the devices this user connects to, by ID.
//!
//! It is a local file. While the device is signed in to an account, it is also kept in the
//! account's vault on the server, encrypted with a key only the account's devices have
//! ([`somedesk_crypto::vault`]), so every device of the account sees the same book. Each entry
//! remembers the device key seen the first time (so a server can't swap the device behind an ID
//! unnoticed, on any of the account's devices) and can hold the unattended-access password, if
//! the user saved it to the account. Passwords saved "on this device" live in the system's
//! keychain instead ([`crate::wallet`]).
//!
//! Changes made on several devices are merged entry by entry, the newer change winning. A deleted
//! entry is kept as a tombstone for a while, so the deletion reaches the other devices instead of
//! the entry coming back from them.

use crate::server::ServerConn;
use crate::trust::hex32;
use crate::{ClientError, Result};
use serde::{Deserialize, Serialize};
use somedesk_crypto::vault::VaultKey;
use somedesk_proto::control::ErrorCode;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// How long a deletion is remembered (milliseconds).
const TOMBSTONE_MS: i64 = 180 * 24 * 3600 * 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub device_id: u64,
    /// The name the user gave it.
    pub label: String,
    /// The device key seen when connecting the first time.
    #[serde(default, with = "opt_hex32")]
    pub device_pk: Option<[u8; 32]>,
    /// The account it was signed in to then.
    #[serde(default)]
    pub username: Option<String>,
    /// The device's unattended-access password, if saved to the account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Unix milliseconds of the last change, for merging.
    pub modified: i64,
    #[serde(default)]
    pub deleted: bool,
}

impl Drop for Entry {
    fn drop(&mut self) {
        if let Some(p) = &mut self.password {
            p.zeroize();
        }
    }
}

mod opt_hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => super::hex32::serialize(v, s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let s: Option<String> = Option::deserialize(d)?;
        s.map(|s| {
            let mut out = [0u8; 32];
            hex::decode_to_slice(s, &mut out).map_err(serde::de::Error::custom)?;
            Ok(out)
        })
        .transpose()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Contents {
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    #[serde(default)]
    entries: BTreeMap<u64, Entry>,
    /// The vault version this book was last merged with.
    #[serde(default)]
    synced_version: u64,
}

pub struct AddressBook {
    path: PathBuf,
    file: File,
}

/// Unix milliseconds.
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

impl AddressBook {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let file = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(std::io::Error::other)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => File::default(),
            Err(e) => return Err(e),
        };
        Ok(Self { path: path.to_owned(), file })
    }

    /// Writes the file atomically with owner-only permissions (it may hold passwords).
    pub fn save(&self) -> std::io::Result<()> {
        use std::io::Write;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(&self.file).expect("serializable"))?;
        f.sync_all()?;
        std::fs::rename(tmp, &self.path)
    }

    /// The entries, without deleted ones, by name.
    pub fn entries(&self) -> Vec<&Entry> {
        let mut list: Vec<_> = self.file.entries.values().filter(|e| !e.deleted).collect();
        list.sort_by_key(|e| e.label.to_lowercase());
        list
    }

    pub fn get(&self, device_id: u64) -> Option<&Entry> {
        self.file.entries.get(&device_id).filter(|e| !e.deleted)
    }

    /// Adds a device, or renames it if it is there already.
    pub fn add(&mut self, device_id: u64, label: &str) {
        let label = label.trim().to_owned();
        match self.file.entries.get_mut(&device_id) {
            Some(e) => {
                e.label = label;
                e.deleted = false;
                e.modified = now();
            }
            None => {
                self.file.entries.insert(
                    device_id,
                    Entry {
                        device_id,
                        label,
                        device_pk: None,
                        username: None,
                        password: None,
                        modified: now(),
                        deleted: false,
                    },
                );
            }
        }
    }

    /// Pins the device key behind an entry (on the first connection), or replaces it after the
    /// user accepted a changed one.
    pub fn pin(&mut self, device_id: u64, device_pk: [u8; 32], username: Option<&str>) {
        if let Some(e) = self.file.entries.get_mut(&device_id).filter(|e| !e.deleted) {
            if e.device_pk != Some(device_pk) || e.username.as_deref() != username {
                e.device_pk = Some(device_pk);
                e.username = username.map(str::to_owned);
                e.modified = now();
            }
        }
    }

    /// Saves (or with `None` removes) the entry's password in the account.
    pub fn set_password(&mut self, device_id: u64, password: Option<&str>) {
        if let Some(e) = self.file.entries.get_mut(&device_id).filter(|e| !e.deleted) {
            e.password = password.map(str::to_owned);
            e.modified = now();
        }
    }

    pub fn remove(&mut self, device_id: u64) {
        if let Some(e) = self.file.entries.get_mut(&device_id) {
            e.deleted = true;
            e.password = None;
            e.modified = now();
        }
    }

    /// Forgets every password saved in the book (e.g. when signing out of the account).
    pub fn clear_passwords(&mut self) {
        for e in self.file.entries.values_mut() {
            e.password = None;
        }
    }

    /// Merges `remote` into this book: per entry, the newer change wins (this device's own on a
    /// tie). Returns whether the merged book differs from `remote` (and has to be uploaded).
    fn merge(&mut self, remote: Contents) -> bool {
        let mut remote: BTreeMap<u64, Entry> = remote.entries.into_iter().map(|e| (e.device_id, e)).collect();
        let mut differs = false;
        for (id, local) in std::mem::take(&mut self.file.entries) {
            match remote.remove(&id) {
                // The server has a newer version: take it.
                Some(r) if r.modified > local.modified => {
                    self.file.entries.insert(id, r);
                }
                // Ours is newer (or the same): it goes up unless it is the same.
                Some(r) => {
                    differs |= r != local;
                    self.file.entries.insert(id, local);
                }
                None => {
                    differs = true;
                    self.file.entries.insert(id, local);
                }
            }
        }
        self.file.entries.extend(remote);
        let cutoff = now() - TOMBSTONE_MS;
        self.file.entries.retain(|_, e| !(e.deleted && e.modified < cutoff));
        differs
    }

    fn contents(&self) -> Contents {
        Contents { entries: self.file.entries.values().cloned().collect() }
    }

    /// Syncs the book with the account's vault on the server: downloads it, merges, and uploads
    /// the result if it changed (retrying if another device wrote in between). Saves the book.
    pub async fn sync(&mut self, conn: &ServerConn, key: &VaultKey, username: &str) -> Result<()> {
        for _ in 0..5 {
            let (version, blob) = conn.get_vault().await?;
            let remote = if blob.is_empty() {
                Contents::default()
            } else {
                let plain = key.open(&blob, username)?;
                serde_json::from_slice(&plain).map_err(|_| ClientError::Protocol("unreadable vault"))?
            };
            let changed = self.merge(remote) || version == 0;
            if !changed {
                self.file.synced_version = version;
                self.save().map_err(|e| ClientError::Other(e.to_string()))?;
                return Ok(());
            }
            let plain = zeroize::Zeroizing::new(serde_json::to_vec(&self.contents()).expect("serializable"));
            match conn.put_vault(version, key.seal(&plain, username)).await {
                Ok(new) => {
                    self.file.synced_version = new;
                    self.save().map_err(|e| ClientError::Other(e.to_string()))?;
                    return Ok(());
                }
                Err(e) if e.code() == Some(ErrorCode::Conflict) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(ClientError::Other("the address book keeps changing on another device; try again".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn book() -> AddressBook {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        AddressBook::load(&std::env::temp_dir().join(format!("somedesk-book-{}-{n}.json", std::process::id()))).unwrap()
    }

    fn entry(id: u64, label: &str, modified: i64) -> Entry {
        Entry {
            device_id: id,
            label: label.into(),
            device_pk: None,
            username: None,
            password: None,
            modified,
            deleted: false,
        }
    }

    #[test]
    fn the_newer_change_wins() {
        let mut b = book();
        b.file.entries.insert(1, entry(1, "old name", 100));
        b.file.entries.insert(2, entry(2, "only here", 100));
        let remote = Contents { entries: vec![entry(1, "new name", 200), entry(3, "only there", 50)] };
        assert!(b.merge(remote), "the local-only entry has to go up");
        let labels: Vec<_> = b.entries().iter().map(|e| e.label.clone()).collect();
        assert_eq!(labels, ["new name", "only here", "only there"]);
    }

    #[test]
    fn deletions_reach_other_devices() {
        let mut b = book();
        b.add(1, "desktop");
        b.remove(1);
        let mut stale = entry(1, "desktop", 0);
        stale.modified = b.file.entries[&1].modified - 10;
        assert!(b.merge(Contents { entries: vec![stale] }));
        assert!(b.get(1).is_none(), "the older remote entry doesn't bring it back");
        assert!(b.contents().entries[0].deleted, "the tombstone goes up");
    }

    #[test]
    fn nothing_to_upload_when_equal() {
        let mut b = book();
        b.file.entries.insert(1, entry(1, "a", 5));
        assert!(!b.merge(Contents { entries: vec![entry(1, "a", 5)] }));
    }

    #[test]
    fn pins_and_passwords() {
        let mut b = book();
        b.add(7, " office ");
        b.pin(7, [1; 32], Some("bob"));
        b.set_password(7, Some("pw"));
        let e = b.get(7).unwrap();
        assert_eq!((e.label.as_str(), e.device_pk, e.password.as_deref()), ("office", Some([1; 32]), Some("pw")));
        b.save().unwrap();
        let again = AddressBook::load(&b.path).unwrap();
        assert_eq!(again.get(7).unwrap().username.as_deref(), Some("bob"));
        b.clear_passwords();
        assert_eq!(b.get(7).unwrap().password, None);
        std::fs::remove_file(&b.path).unwrap();
    }
}
