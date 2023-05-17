//! The address book, and the passwords saved for unattended access to other computers: in the
//! system keychain ("on this device") or in the account's encrypted vault ("in my account").

use super::*;
use crate::{BookItem, SaveIn};
use somedesk_client::wallet;
use somedesk_crypto::vault::VaultKey;

impl Controller {
    pub(super) fn install_book_callbacks(&self, ui: &AppWindow) {
        let c = self.clone();
        ui.on_book_add(move || c.open_entry(None));
        let c = self.clone();
        ui.on_book_edit(move |id| c.open_entry(id.parse().ok()));
        let c = self.clone();
        ui.on_book_remove(move |id| {
            if let Ok(id) = id.parse::<u64>() {
                c.remove_entry(id);
            }
        });
        let c = self.clone();
        ui.on_entry_submit(move || c.entry_submit());
        let c = self.clone();
        ui.on_entry_cancel(move || {
            c.0.state.lock().unwrap().entry_editing = None;
            c.ui(|ui| {
                ui.set_entry_visible(false);
                ui.set_entry_password("".into());
            });
        });
    }

    fn book_path(&self) -> PathBuf {
        self.0.dir.join("addressbook.json")
    }

    pub(super) fn load_book(&self) {
        let path = self.book_path();
        let book = AddressBook::load(&path).unwrap_or_else(|e| {
            let aside = path.with_extension("json.broken");
            tracing::error!("cannot read the address book ({e}); moving it to {}", aside.display());
            let _ = std::fs::rename(&path, aside);
            AddressBook::load(&path).expect("a missing file loads empty")
        });
        self.0.state.lock().unwrap().book = Some(book);
        self.publish_book();
        // Asking the keychain may block (or unlock it): do it off the UI thread.
        let this = self.clone();
        self.0.rt.spawn_blocking(move || {
            let available = wallet::available();
            this.0.state.lock().unwrap().keychain = available;
            this.ui(move |ui| ui.set_keychain(available));
        });
    }

    fn server(&self) -> String {
        self.0.state.lock().unwrap().creds.as_ref().map(|c| c.server.clone()).unwrap_or_default()
    }

    /// The vault key and username of the account, if this device is signed in to one.
    fn vault(&self) -> Option<(VaultKey, String)> {
        let st = self.0.state.lock().unwrap();
        let account = st.creds.as_ref()?.account.as_ref()?;
        Some((VaultKey::from_bytes(account.vault_key?), account.username.clone()))
    }

    pub(super) fn publish_book(&self) {
        let items: Vec<BookItem> = {
            let st = self.0.state.lock().unwrap();
            let Some(book) = st.book.as_ref() else { return };
            book.entries()
                .into_iter()
                .map(|e| BookItem {
                    id: e.device_id.to_string().into(),
                    id_label: format_device_id(e.device_id).into(),
                    label: e.label.clone().into(),
                    account: e.username.clone().unwrap_or_default().into(),
                    saved: if e.password.is_some() { "account".into() } else { "".into() },
                    online: false,
                    org: "".into(),
                })
                .collect()
        };
        self.ui(move |ui| ui.set_book(ModelRc::new(VecModel::from(items))));
    }

    /// Changes the address book, saves it, shows it, and syncs it with the account.
    pub(super) fn with_book(&self, f: impl FnOnce(&mut AddressBook)) {
        {
            let mut st = self.0.state.lock().unwrap();
            let Some(book) = st.book.as_mut() else { return };
            f(book);
            if let Err(e) = book.save() {
                tracing::error!("cannot save the address book: {e}");
            }
            st.book_generation += 1;
        }
        self.publish_book();
        self.sync_book();
    }

    /// Syncs the address book with the account's vault, if signed in.
    pub(super) fn sync_book(&self) {
        let (Some(conn), Some((key, username))) = (self.conn(), self.vault()) else { return };
        let Some(book_path) = Some(self.book_path()) else { return };
        let this = self.clone();
        self.0.rt.spawn(async move {
            // One at a time, each starting from what the one before left.
            let _turn = this.0.book_sync.lock().await;
            // Sync a copy, so the book isn't locked across the network round trips.
            let generation = this.0.state.lock().unwrap().book_generation;
            let mut book = match AddressBook::load(&book_path) {
                Ok(b) => b,
                Err(e) => return tracing::warn!("cannot read the address book: {e}"),
            };
            match book.sync(&conn, &key, &username).await {
                Ok(()) => {
                    let mut st = this.0.state.lock().unwrap();
                    if st.book_generation == generation {
                        st.book = Some(book);
                    } else if let Some(current) = st.book.as_ref() {
                        // Changed here meanwhile: keep that (the sync saved over it on disk).
                        // The sync that change started merges both.
                        if let Err(e) = current.save() {
                            tracing::error!("cannot save the address book: {e}");
                        }
                    }
                    drop(st);
                    this.publish_book();
                }
                Err(e) => tracing::warn!("cannot sync the address book: {e}"),
            }
        });
    }

    /// A saved password for `device_id`: from the account's vault, or this device's keychain.
    /// Blocks on the keychain.
    pub(super) fn saved_password(&self, device_id: u64) -> Option<(String, SaveIn)> {
        let in_account = self.0.state.lock().unwrap().book.as_ref().and_then(|b| b.get(device_id)?.password.clone());
        if let Some(p) = in_account {
            return Some((p, SaveIn::Account));
        }
        if self.0.state.lock().unwrap().keychain {
            return wallet::get(&self.server(), device_id).map(|p| (p, SaveIn::Device));
        }
        None
    }

    /// Keeps (or with [`SaveIn::Nowhere`] forgets) the password for `device_id`, in one place
    /// only. Blocks on the keychain.
    pub(super) fn store_password(&self, device_id: u64, password: Option<&str>, save: SaveIn) {
        let server = self.server();
        let keychain = self.0.state.lock().unwrap().keychain;
        let in_book = self.0.state.lock().unwrap().book.as_ref().is_some_and(|b| b.get(device_id).is_some());
        if save == SaveIn::Account && !in_book {
            // A password lives in an entry; add one.
            let label = format_device_id(device_id);
            self.with_book(|b| b.add(device_id, &label));
        }
        let account_pw = if save == SaveIn::Account { password } else { None };
        self.with_book(|b| b.set_password(device_id, account_pw));
        if keychain {
            let device_pw = if save == SaveIn::Device { password } else { None };
            if let Err(e) = wallet::set(&server, device_id, device_pw) {
                self.toast(format!("Could not use the keychain: {e}"), true);
            }
        }
    }

    fn open_entry(&self, device_id: Option<u64>) {
        let entry =
            device_id.and_then(|id| self.0.state.lock().unwrap().book.as_ref().and_then(|b| b.get(id).cloned()));
        let this = self.clone();
        self.0.rt.spawn_blocking(move || {
            let saved = device_id.and_then(|id| this.saved_password(id)).map(|(_, s)| s);
            this.0.state.lock().unwrap().entry_editing = device_id;
            let (id, label) = match &entry {
                Some(e) => (format_device_id(e.device_id), e.label.clone()),
                None => (String::new(), String::new()),
            };
            let signed_in = this.vault().is_some();
            let keychain = this.0.state.lock().unwrap().keychain;
            let default = if keychain {
                SaveIn::Device
            } else if signed_in {
                SaveIn::Account
            } else {
                SaveIn::Nowhere
            };
            this.ui(move |ui| {
                ui.set_entry_new(entry.is_none());
                ui.set_entry_id(id.into());
                ui.set_entry_label(label.into());
                ui.set_entry_password("".into());
                ui.set_entry_has_password(saved.is_some());
                ui.set_entry_save(saved.unwrap_or(default));
                ui.set_entry_error("".into());
                ui.set_entry_visible(true);
            });
        });
    }

    fn entry_submit(&self) {
        let Some(ui) = self.0.ui.upgrade() else { return };
        let editing = self.0.state.lock().unwrap().entry_editing;
        let Some(device_id) = editing.or_else(|| parse_device_id(&ui.get_entry_id())) else {
            ui.set_entry_error("Enter a valid 9-digit ID.".into());
            return;
        };
        let label = match ui.get_entry_label().trim() {
            "" => format_device_id(device_id),
            l => l.to_owned(),
        };
        let password = ui.get_entry_password().to_string();
        let save = ui.get_entry_save();
        let had_password = ui.get_entry_has_password();
        ui.set_entry_visible(false);
        ui.set_entry_password("".into());
        self.0.state.lock().unwrap().entry_editing = None;
        self.with_book(|b| b.add(device_id, &label));
        let this = self.clone();
        self.0.rt.spawn_blocking(move || {
            if !password.is_empty() {
                this.store_password(device_id, Some(&password), save);
            } else if had_password {
                // No new password: keep the saved one, but where the user now wants it.
                if let Some((current, _)) = this.saved_password(device_id) {
                    this.store_password(device_id, Some(&current), save);
                }
            }
        });
    }

    fn remove_entry(&self, device_id: u64) {
        self.with_book(|b| b.remove(device_id));
        let this = self.clone();
        self.0.rt.spawn_blocking(move || {
            if this.0.state.lock().unwrap().keychain {
                let _ = wallet::set(&this.server(), device_id, None);
            }
        });
    }
}
