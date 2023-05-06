//! Passwords saved "on this device": in the system's keychain (the Secret Service on Linux, the
//! Credential Manager on Windows, the Keychain on macOS).
//!
//! Only the unattended-access passwords of other devices are kept here, never the codes from an
//! authenticator app. Where the system has no keychain (or it is locked away, as in some
//! headless sessions), this option simply isn't offered; a signed-in device can save passwords
//! to its account instead (see [`crate::addressbook`]). The calls block, so run them off the
//! async runtime's worker threads.

/// The keychain's service name for SomeDesk's entries.
#[cfg(not(target_os = "android"))]
const SERVICE: &str = "SomeDesk";

fn account(server: &str, device_id: u64) -> String {
    format!("{device_id}@{server}")
}

/// Whether this system has a usable keychain.
pub fn available() -> bool {
    #[cfg(not(target_os = "android"))]
    {
        if keyring::Entry::store_status().is_err() {
            return false;
        }
        match keyring::Entry::new(SERVICE, "availability check").and_then(|e| e.get_password()) {
            Ok(_) | Err(keyring::Error::NoEntry) => true,
            Err(e) => {
                tracing::info!("the system keychain is not usable: {e}");
                false
            }
        }
    }
    #[cfg(target_os = "android")]
    false
}

/// The password saved for `device_id` on `server`, if any.
pub fn get(server: &str, device_id: u64) -> Option<String> {
    #[cfg(not(target_os = "android"))]
    {
        match keyring::Entry::new(SERVICE, &account(server, device_id)).and_then(|e| e.get_password()) {
            Ok(p) => Some(p),
            Err(keyring::Error::NoEntry) => None,
            Err(e) => {
                tracing::warn!("cannot read from the system keychain: {e}");
                None
            }
        }
    }
    #[cfg(target_os = "android")]
    {
        let _ = account(server, device_id);
        None
    }
}

/// Saves (or with `None` removes) the password for `device_id` on `server`.
pub fn set(server: &str, device_id: u64, password: Option<&str>) -> anyhow::Result<()> {
    #[cfg(not(target_os = "android"))]
    {
        let entry = keyring::Entry::new(SERVICE, &account(server, device_id))?;
        match password {
            Some(p) => entry.set_password(p)?,
            None => match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(e) => return Err(e.into()),
            },
        }
        Ok(())
    }
    #[cfg(target_os = "android")]
    {
        let _ = (account(server, device_id), password);
        anyhow::bail!("this device has no keychain")
    }
}
