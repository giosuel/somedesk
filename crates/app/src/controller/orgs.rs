//! Organisations: what members see (the enrolled devices they may reach) and what admins do
//! (members, groups, rules, service workers). Admin actions sign a new policy with the
//! organisation's key, which the account's identity key unlocks, so they ask for the password
//! once per connection. The account remembers each organisation's key and newest policy in its
//! address book, so a server can't swap either behind an admin's back.

use super::*;
use crate::{BookItem, DeviceGroupItem, MemberItem, OrgItem, RuleItem, WorkerItem};
use somedesk_client::org::OrgPin;
use somedesk_client::ClientError;
use somedesk_crypto::org::verify_policy;
use somedesk_proto::org::OrgPolicy;

impl Controller {
    pub(super) fn install_org_callbacks(&self, ui: &AppWindow) {
        let c = self.clone();
        ui.on_org_select(move |id| {
            c.0.state.lock().unwrap().org_selected = id.parse().ok();
            c.publish_orgs();
        });
        let c = self.clone();
        ui.on_org_create(move |name| c.create_org(name.trim().to_owned()));
        let c = self.clone();
        ui.on_org_add_member(move |user, group, admin| {
            let (user, group) = (user.trim().to_owned(), group.trim().to_owned());
            c.with_admin(move |this, conn, login, mut a| async move {
                let r = a.add_member(&conn, &login, &user, &group, admin).await.map(|pk| {
                    this.toast(format!("Added {user} (fingerprint {}). Compare it with them.", fingerprint(&pk)), false)
                });
                (a, r)
            });
        });
        let c = self.clone();
        ui.on_org_remove_member(move |user| {
            let user = user.to_string();
            c.with_admin(move |_, conn, login, mut a| async move {
                let r = a.remove_member(&conn, &login, &user).await;
                (a, r)
            });
        });
        let c = self.clone();
        ui.on_org_add_rule(move |group, devices| {
            let (group, devices) = (group.trim().to_owned(), devices.trim().to_owned());
            c.with_admin(move |_, conn, _, mut a| async move {
                let r = a.allow(&conn, &group, &devices).await;
                (a, r)
            });
        });
        let c = self.clone();
        ui.on_org_remove_rule(move |group, devices| {
            let (group, devices) = (group.to_string(), devices.to_string());
            c.with_admin(move |_, conn, _, mut a| async move {
                let r = a.disallow(&conn, &group, &devices).await;
                (a, r)
            });
        });
        let c = self.clone();
        ui.on_org_set_device_group(move |name, ids| {
            let name = name.trim().to_owned();
            let parsed: Option<Vec<u64>> =
                ids.split([',', ';', '\n']).map(str::trim).filter(|s| !s.is_empty()).map(parse_device_id).collect();
            let Some(devices) = parsed else {
                c.toast("Use 9-digit IDs, separated by commas.", true);
                return;
            };
            c.with_admin(move |_, conn, _, mut a| async move {
                let r = a.set_device_group(&conn, &name, &devices).await;
                (a, r)
            });
        });
        let c = self.clone();
        ui.on_org_new_worker(move |name| {
            let name = name.trim().to_owned();
            c.with_admin(move |this, conn, _, mut a| async move {
                let r = a.create_worker(&conn, &name, None).await.map(|key| {
                    let server = this.server_address();
                    let text = key.encode().to_string();
                    let detail = format!(
                        "Install SomeDesk on a machine and enroll it with this key:\n\nSOMEDESK_ENROLLMENT_KEY=<the key> somedesk-agent enroll --server {server}\n\nThe machine then runs in the background and accepts the members your rules allow."
                    );
                    this.ui(move |ui| {
                        ui.set_secret_title(format!("Enrollment key for \"{name}\"").into());
                        ui.set_secret_detail(detail.into());
                        ui.set_secret_text(text.into());
                        ui.set_secret_copied(false);
                        ui.set_secret_visible(true);
                    });
                });
                (a, r)
            });
        });
        let c = self.clone();
        ui.on_org_answer_invite(move |join| c.answer_invite(join));
        let c = self.clone();
        ui.on_org_revoke_worker(move |key| {
            let mut pk = [0u8; 32];
            if hex::decode_to_slice(key.as_str(), &mut pk).is_err() {
                return;
            }
            c.with_admin(move |_, conn, _, mut a| async move {
                let r = a.revoke_worker(&conn, &pk).await;
                (a, r)
            });
        });
    }

    fn answer_invite(&self, join: bool) {
        let org_id = self.0.state.lock().unwrap().org_selected;
        let (Some(org_id), Some(conn)) = (org_id, self.conn()) else { return };
        let this = self.clone();
        self.ui(|ui| ui.set_org_busy(true));
        self.0.rt.spawn(async move {
            let result = conn.answer_org_invite(org_id, join).await;
            this.ui(|ui| ui.set_org_busy(false));
            match result {
                Ok(()) if !join => this.toast("Declined", false),
                Ok(()) => {}
                Err(e) => this.toast(e.to_string(), true),
            }
            if !join {
                this.0.state.lock().unwrap().org_selected = None;
            }
            this.refresh_orgs();
        });
    }

    fn server_address(&self) -> String {
        self.0.state.lock().unwrap().creds.as_ref().map(|c| c.server.clone()).unwrap_or_default()
    }

    fn create_org(&self, name: String) {
        if name.is_empty() {
            return;
        }
        self.with_login(&format!("Confirm with your password to create \"{name}\"."), move |this, conn, login| {
            this.ui(|ui| ui.set_org_busy(true));
            this.0.rt.clone().spawn(async move {
                let result = Admin::create(&conn, &login, &name).await;
                this.ui(|ui| ui.set_org_busy(false));
                match result {
                    Ok(admin) => {
                        let id = admin.org_id;
                        this.pin_org(admin.pin());
                        {
                            let mut st = this.0.state.lock().unwrap();
                            st.org_admins.insert(id, admin);
                            st.org_selected = Some(id);
                        }
                        this.toast(format!("Created {name}"), false);
                        this.refresh_orgs();
                    }
                    Err(e) => this.toast(format!("Could not create it: {e}"), true),
                }
            });
        });
    }

    /// Runs an admin action on the selected organisation, unlocking its key first if needed.
    /// The action hands the admin back, with its result; the organisation is shown again after.
    /// After a failure the admin isn't kept: the next action starts from the server's policy.
    fn with_admin<F, Fut>(&self, action: F)
    where
        F: FnOnce(Controller, Arc<ServerConn>, Arc<LoggedIn>, Admin) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = (Admin, somedesk_client::Result<()>)> + Send + 'static,
    {
        let Some(org_id) = self.0.state.lock().unwrap().org_selected else { return };
        let Some(name) = self.0.state.lock().unwrap().orgs.iter().find(|o| o.org_id == org_id).map(|o| o.name.clone())
        else {
            return;
        };
        self.with_login(&format!("Confirm with your password to manage \"{name}\"."), move |this, conn, login| {
            let cached = this.0.state.lock().unwrap().org_admins.remove(&org_id);
            let admin = match cached.map_or_else(|| this.open_admin(org_id, &login), Ok) {
                Ok(admin) => admin,
                Err(e) => return this.toast(e.to_string(), true),
            };
            this.ui(|ui| ui.set_org_busy(true));
            this.0.rt.clone().spawn(async move {
                let (admin, result) = action(this.clone(), conn, login, admin).await;
                match result {
                    Ok(()) => {
                        this.pin_org(admin.pin());
                        this.0.state.lock().unwrap().org_admins.insert(org_id, admin);
                    }
                    Err(e) => this.toast(e.to_string(), true),
                }
                this.ui(|ui| ui.set_org_busy(false));
                this.refresh_orgs();
            });
        });
    }

    /// Unlocks an organisation's key, checked against what the account remembers about it. The
    /// first time, the admin who shared it has to be one this device knows by the same key, or
    /// the user is shown their fingerprint to compare.
    fn open_admin(&self, org_id: u64, login: &LoggedIn) -> somedesk_client::Result<Admin> {
        let (info, pin) = {
            let st = self.0.state.lock().unwrap();
            let info = st.orgs.iter().find(|o| o.org_id == org_id).cloned();
            (info, st.book.as_ref().and_then(|b| b.org_pin(org_id).cloned()))
        };
        let info = info.ok_or(ClientError::Other("no such organisation".into()))?;
        let (admin, shared_by) = Admin::open(&info, login, pin.as_ref())?;
        if let Some(by) = shared_by {
            let remembered = {
                let st = self.0.state.lock().unwrap();
                st.trust.as_ref().and_then(|t| t.account(&by.username).map(|a| a.identity_pk))
            };
            match remembered {
                Some(pk) if pk != by.identity_pk => {
                    return Err(ClientError::Other(format!(
                        "The key for {} was shared by someone presenting as {}, but with another key than this \
                         device knows for {}. Don't use it.",
                        info.name, by.username, by.username
                    )));
                }
                Some(_) => {}
                None => self.toast(
                    format!(
                        "{} shared {} with you (fingerprint {}). Compare it with them.",
                        by.username,
                        info.name,
                        fingerprint(&by.identity_pk)
                    ),
                    false,
                ),
            }
        }
        self.pin_org(admin.pin());
        Ok(admin)
    }

    fn pin_org(&self, pin: OrgPin) {
        self.with_book(move |b| b.pin_org(pin));
    }

    /// Reads the account's organisations (and renews policies about to expire, for those this
    /// device has unlocked).
    pub(super) fn refresh_orgs(&self) {
        let Some(conn) = self.conn() else { return };
        let this = self.clone();
        self.0.rt.spawn(async move {
            let orgs = match conn.list_orgs().await {
                Ok(o) => o,
                Err(e) => return tracing::debug!("cannot list organisations: {e}"),
            };
            let renew: Vec<u64> = this.0.state.lock().unwrap().org_admins.keys().copied().collect();
            for id in renew {
                let admin = this.0.state.lock().unwrap().org_admins.remove(&id);
                if let Some(mut admin) = admin {
                    // Another admin (or device) changed it since: unlock it afresh next time.
                    let newer = orgs.iter().any(|o| {
                        o.org_id == id
                            && (o.org_pk != admin.key.public()
                                || o.policy.as_ref().is_some_and(|p| {
                                    verify_policy(p, &o.org_pk).is_ok_and(|p| p.version > admin.policy.version)
                                }))
                    });
                    if newer {
                        continue;
                    }
                    match admin.renew_if_due(&conn).await {
                        Ok(renewed) => {
                            if renewed {
                                this.pin_org(admin.pin());
                            }
                            this.0.state.lock().unwrap().org_admins.insert(id, admin);
                        }
                        Err(e) => tracing::warn!("cannot renew the policy of organisation {id}: {e}"),
                    }
                }
            }
            {
                let mut st = this.0.state.lock().unwrap();
                if st.org_selected.is_none_or(|s| !orgs.iter().any(|o| o.org_id == s)) {
                    st.org_selected = orgs.first().map(|o| o.org_id);
                }
                st.orgs = orgs;
            }
            this.publish_orgs();
        });
    }

    /// Shows the organisations, and the selected one's details.
    pub(super) fn publish_orgs(&self) {
        let (orgs, selected) = {
            let st = self.0.state.lock().unwrap();
            (st.orgs.clone(), st.org_selected)
        };
        let items: Vec<OrgItem> = orgs
            .iter()
            .map(|o| OrgItem {
                id: o.org_id.to_string().into(),
                name: o.name.clone().into(),
                admin: o.sealed_key.is_some(),
                invited: !o.joined,
            })
            .collect();
        let info = selected.and_then(|id| orgs.iter().find(|o| o.org_id == id).cloned());
        let policy: Option<OrgPolicy> =
            info.as_ref().and_then(|o| o.policy.as_ref().and_then(|p| verify_policy(p, &o.org_pk).ok()));
        let members: Vec<MemberItem> = policy
            .iter()
            .flat_map(|p| {
                p.members.iter().map(|m| MemberItem {
                    username: m.username.clone().into(),
                    fingerprint: fingerprint(&m.identity_pk).into(),
                    admin: m.admin,
                    groups: p
                        .groups
                        .iter()
                        .filter(|g| g.members.contains(&m.username))
                        .map(|g| g.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                        .into(),
                })
            })
            .collect();
        let rules: Vec<RuleItem> = policy
            .iter()
            .flat_map(|p| {
                p.rules
                    .iter()
                    .map(|r| RuleItem { group: r.group.clone().into(), device_group: r.device_group.clone().into() })
            })
            .collect();
        let groups: Vec<DeviceGroupItem> = policy
            .iter()
            .flat_map(|p| {
                p.device_groups.iter().map(|g| DeviceGroupItem {
                    name: g.name.clone().into(),
                    devices: g
                        .devices
                        .iter()
                        .map(|d| format_device_id(d.device_id))
                        .collect::<Vec<_>>()
                        .join(", ")
                        .into(),
                })
            })
            .collect();
        let date = |t: i64| {
            chrono::DateTime::from_timestamp(t, 0).map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default()
        };
        let workers: Vec<WorkerItem> = policy
            .iter()
            .flat_map(|p| {
                p.workers.iter().map(|w| WorkerItem {
                    key: hex::encode(w.worker_pk).into(),
                    name: w.name.clone().into(),
                    detail: match w.expires_at {
                        Some(e) => format!("Created {} · expires {}", date(w.created_at), date(e)),
                        None => format!("Created {}", date(w.created_at)),
                    }
                    .into(),
                    revoked: w.revoked,
                })
            })
            .collect();
        let (name, admin, invited) = info
            .as_ref()
            .map_or((String::new(), false, false), |o| (o.name.clone(), o.sealed_key.is_some(), !o.joined));
        let selected = selected.map(|s| s.to_string()).unwrap_or_default();
        self.ui(move |ui| {
            ui.set_orgs(ModelRc::new(VecModel::from(items)));
            ui.set_org_selected(selected.into());
            ui.set_org_name(name.into());
            ui.set_org_admin(admin);
            ui.set_org_invited(invited);
            ui.set_org_members(ModelRc::new(VecModel::from(members)));
            ui.set_org_rules(ModelRc::new(VecModel::from(rules)));
            ui.set_org_device_groups(ModelRc::new(VecModel::from(groups)));
            ui.set_org_workers(ModelRc::new(VecModel::from(workers)));
        });
        // The enrolled devices come from the server.
        let (Some(conn), Some(info)) = (self.conn(), info.filter(|o| o.joined)) else {
            self.ui(|ui| ui.set_org_devices(ModelRc::default()));
            return;
        };
        let this = self.clone();
        self.0.rt.spawn(async move {
            let devices = conn.list_org_devices(info.org_id).await.unwrap_or_default();
            let items: Vec<BookItem> = devices
                .iter()
                .map(|d| BookItem {
                    id: d.device_id.to_string().into(),
                    id_label: format_device_id(d.device_id).into(),
                    label: d.identity.name.clone().into(),
                    account: "".into(),
                    saved: "".into(),
                    online: d.online,
                    org: info.name.clone().into(),
                })
                .collect();
            this.ui(move |ui| ui.set_org_devices(ModelRc::new(VecModel::from(items))));
        });
    }
}
