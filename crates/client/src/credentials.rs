//! Device credentials persisted after enrollment.

use serde::{Deserialize, Serialize};
use somedesk_crypto::keys::DeviceKey;
use somedesk_proto::control::DeviceCert;
use std::path::Path;

/// Everything a device needs to come online without the user's password.
///
/// Note the user's identity *private* key is not here: it is only needed to enroll a device and
/// stays encrypted on the server under the password.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceCredentials {
    pub server: String,
    /// SHA-256 of the server TLS certificate, pinned on first use.
    pub server_fingerprint: [u8; 32],
    pub username: String,
    pub identity_pk: [u8; 32],
    pub device_id: u64,
    pub device_secret: [u8; 32],
    pub cert: DeviceCert,
    pub token: [u8; 32],
}

impl std::fmt::Debug for DeviceCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCredentials")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

impl DeviceCredentials {
    pub fn device_key(&self) -> DeviceKey {
        DeviceKey::from_bytes(self.device_secret)
    }

    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
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
