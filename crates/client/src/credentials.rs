//! What a device keeps on disk: its key, its ID and, when signed in, its account certificate.

use serde::{Deserialize, Serialize};
use somedesk_crypto::keys::DeviceKey;
use somedesk_proto::control::{DeviceCert, DeviceIdentity};
use std::path::Path;

/// Everything a device needs to come online. Created on the first start; the ID stays the same
/// as long as this file exists.
///
/// Note the user's identity *private* key is not here: it is only needed to sign a device in to
/// the account and stays encrypted on the server under the password.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceCredentials {
    pub server: String,
    /// SHA-256 of the server TLS certificate, pinned on first use.
    pub server_fingerprint: [u8; 32],
    pub device_id: u64,
    pub device_secret: [u8; 32],
    pub device_name: String,
    /// The account this device is signed in to.
    #[serde(default)]
    pub account: Option<AccountCredentials>,
}

/// A device's sign-in to an account: the account's certificate for the device key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountCredentials {
    pub username: String,
    pub identity_pk: [u8; 32],
    pub cert: DeviceCert,
}

impl std::fmt::Debug for DeviceCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCredentials")
            .field("server", &self.server)
            .field("device_id", &self.device_id)
            .field("account", &self.account.as_ref().map(|a| &a.username))
            .finish_non_exhaustive()
    }
}

/// The file before installation IDs: the device was always on an account, and came online
/// with a token.
#[derive(Deserialize)]
struct Legacy {
    server: String,
    server_fingerprint: [u8; 32],
    username: String,
    identity_pk: [u8; 32],
    device_id: u64,
    device_secret: [u8; 32],
    cert: DeviceCert,
}

impl DeviceCredentials {
    pub fn device_key(&self) -> DeviceKey {
        DeviceKey::from_bytes(self.device_secret)
    }

    /// Who this device is, as it presents itself to peers.
    pub fn identity(&self) -> DeviceIdentity {
        DeviceIdentity {
            device_pk: self.device_key().public(),
            name: self.device_name.clone(),
            account: self.account.as_ref().map(|a| a.cert.clone()),
        }
    }

    pub fn username(&self) -> Option<&str> {
        self.account.as_ref().map(|a| a.username.as_str())
    }

    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if let Ok(creds) = serde_json::from_slice::<Self>(&bytes) {
            return Ok(Some(creds));
        }
        let old: Legacy = serde_json::from_slice(&bytes)?;
        Ok(Some(Self {
            server: old.server,
            server_fingerprint: old.server_fingerprint,
            device_id: old.device_id,
            device_secret: old.device_secret,
            device_name: old.cert.device_name.clone(),
            account: Some(AccountCredentials { username: old.username, identity_pk: old.identity_pk, cert: old.cert }),
        }))
    }

    /// Writes the file atomically with owner-only permissions.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        use std::io::Write;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(self)?)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_files_keep_their_id_and_account() {
        let cert = DeviceCert {
            username: "alice".into(),
            identity_pk: [1; 32],
            device_pk: [2; 32],
            device_name: "laptop".into(),
            created_at: 0,
            signature: vec![3; 64],
        };
        let (fingerprint, identity_pk, secret, token) = ([4u8; 32], [1u8; 32], [5u8; 32], [6u8; 32]);
        let old = serde_json::json!({
            "server": "example.org",
            "server_fingerprint": fingerprint,
            "username": "alice",
            "identity_pk": identity_pk,
            "device_id": 123456789,
            "device_secret": secret,
            "cert": cert,
            "token": token,
        });
        let path = std::env::temp_dir().join(format!("somedesk-creds-{}.json", std::process::id()));
        std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        let creds = DeviceCredentials::load(&path).unwrap().unwrap();
        assert_eq!(creds.device_id, 123456789);
        assert_eq!(creds.device_name, "laptop");
        assert_eq!(creds.username(), Some("alice"));
        creds.save(&path).unwrap();
        let again = DeviceCredentials::load(&path).unwrap().unwrap();
        assert_eq!(again.account.unwrap().cert, cert);
        std::fs::remove_file(path).unwrap();
    }
}
