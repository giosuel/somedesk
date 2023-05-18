//! The ways in: the address book synced through the vault, unattended access with the host's
//! password and authenticator code, two-factor authentication on accounts, and organisations
//! with their service workers and enrolled devices.

use somedesk_client::access::{self, Asked, Unattended, Verdict};
use somedesk_client::addressbook::AddressBook;
use somedesk_client::org::{Admin, PolicyStore};
use somedesk_client::session::{self, Channel};
use somedesk_client::ClientError;
use somedesk_crypto::totp::{self, TotpSecret};
use somedesk_crypto::vault::VaultKey;
use somedesk_e2e_tests::{Device, TestServer};
use somedesk_proto::control::{ErrorCode, Event, SessionId};
use somedesk_proto::org::PolicyBundle;
use somedesk_proto::session::SessionMsg;
use sqlx::{Connection, PgConnection, Row};
use std::time::Duration;

const T: Duration = Duration::from_secs(10);

fn temp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("somedesk-modes-{name}-{}-{}.json", std::process::id(), rand::random::<u32>()))
}

fn code<T>(r: Result<T, ClientError>) -> ErrorCode {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.code().unwrap_or_else(|| panic!("expected a server error, got {e}")),
    }
}

async fn next_incoming(
    host: &mut Device,
) -> (SessionId, somedesk_proto::control::DeviceInfo, Vec<std::net::SocketAddr>) {
    loop {
        match tokio::time::timeout(T, host.events.recv()).await.expect("incoming session").unwrap() {
            Event::IncomingSession { session_id, from, candidates } => return (session_id, from, candidates),
            _ => continue,
        }
    }
}

/// Opens a session from `viewer` to `host` and returns both ends.
async fn open(viewer: &Device, host: &mut Device) -> (Channel, Channel) {
    let (v, h, _) = open_from(viewer, host).await;
    (v, h)
}

/// [`open`], also with the viewer as the server introduced it to the host.
async fn open_from(viewer: &Device, host: &mut Device) -> (Channel, Channel, somedesk_proto::control::DeviceInfo) {
    let id = host.creds.device_id;
    let host_side = async {
        let (sid, from, cands) = next_incoming(host).await;
        (session::accept(&host.conn, &host.creds, sid, &from, &cands).await.unwrap(), from)
    };
    let ((v, _), (h, from)) =
        tokio::join!(async { session::connect(&viewer.conn, &viewer.creds, id).await.unwrap() }, host_side);
    (v, h, from)
}

fn vault_key(d: &Device) -> VaultKey {
    VaultKey::from_bytes(d.creds.account.as_ref().unwrap().vault_key.unwrap())
}

#[tokio::test]
async fn the_address_book_syncs_between_an_accounts_devices() {
    let Some(ts) = TestServer::start().await else { return };
    let laptop = ts.signup("alice", "correct horse battery", "laptop").await;
    let desktop = ts.add_device("alice", "correct horse battery", "desktop").await;
    let mut book_a = AddressBook::load(&temp("book-a")).unwrap();
    let mut book_b = AddressBook::load(&temp("book-b")).unwrap();

    book_a.add(123_456_789, "Office PC");
    book_a.pin(123_456_789, [1; 32], None);
    book_a.set_password(123_456_789, Some("the office password"));
    book_a.sync(&laptop.conn, &vault_key(&laptop), "alice").await.unwrap();
    book_b.sync(&desktop.conn, &vault_key(&desktop), "alice").await.unwrap();
    let e = book_b.get(123_456_789).expect("synced to the other device");
    assert_eq!(
        (e.label.as_str(), e.device_pk, e.password.as_deref()),
        ("Office PC", Some([1; 32]), Some("the office password"))
    );

    // The server holds it, but can't read it.
    let mut db = PgConnection::connect(&ts.db_url).await.unwrap();
    let blob: Vec<u8> = sqlx::query("SELECT blob FROM vaults").fetch_one(&mut db).await.unwrap().get("blob");
    for secret in [b"Office PC".as_slice(), b"the office password"] {
        assert!(!blob.windows(secret.len()).any(|w| w == secret));
    }

    // A deletion on one device reaches the other.
    book_b.remove(123_456_789);
    book_b.sync(&desktop.conn, &vault_key(&desktop), "alice").await.unwrap();
    book_a.sync(&laptop.conn, &vault_key(&laptop), "alice").await.unwrap();
    assert!(book_a.get(123_456_789).is_none());

    // Devices without the account can't get at the vault.
    let other = ts.anonymous("other").await;
    assert_eq!(code(other.conn.get_vault().await), ErrorCode::NotAuthenticated);
    ts.stop().await;
}

/// Sets up unattended access on `host`; returns the authenticator secret.
fn set_up_unattended(host: &Device, path: &std::path::Path, password: &str) -> (Unattended, TotpSecret) {
    let mut store = Unattended::load(path).unwrap();
    let pending = Unattended::begin(&host.creds.device_key().public(), password).unwrap();
    let secret = pending.secret.clone();
    store.confirm(&pending, &secret.code_at(totp::now() / 30)).unwrap();
    (store, secret)
}

/// One unattended attempt from `viewer`: the host's verdict.
async fn attempt(viewer: &Device, host: &mut Device, store: &mut Unattended, password: &str, code: &str) -> Verdict {
    let host_pk = host.creds.device_key().public();
    let (mut v, mut h) = open(viewer, host).await;
    let host_side = async {
        let Asked::Password(request) = access::read_request(&mut h).await.unwrap() else {
            panic!("expected a password")
        };
        let verdict = store.check(&mut h, &host_pk, &request).await.unwrap();
        let reply = match &verdict {
            Verdict::Accepted => SessionMsg::Accept,
            Verdict::Rejected(reason) => SessionMsg::Reject { reason: reason.clone() },
        };
        h.sender.send(&reply).await.unwrap();
        verdict
    };
    let viewer_side = async {
        match access::sign_in_unattended(&mut v, password, code).await {
            Ok(()) | Err(ClientError::Rejected(_)) => {}
            Err(e) => panic!("{e}"),
        }
    };
    let (verdict, ()) = tokio::join!(host_side, viewer_side);
    verdict
}

/// A guesser that leaves once it has the host's challenge, which already tells it whether its
/// password was right: whether the host could tell something went wrong.
async fn abandoned_attempt(viewer: &Device, host: &mut Device, store: &mut Unattended, password: &str) -> bool {
    let host_pk = host.creds.device_key().public();
    let (mut v, mut h) = open(viewer, host).await;
    let (request, _state) = somedesk_crypto::unattended::viewer_start(password).unwrap();
    v.sender.send(&SessionMsg::UnattendedStart { request }).await.unwrap();
    let host_side = async {
        let Asked::Password(request) = access::read_request(&mut h).await.unwrap() else {
            panic!("expected a password")
        };
        store.check(&mut h, &host_pk, &request).await.is_err()
    };
    let viewer_side = async {
        let challenge = v.receiver.recv::<SessionMsg>().await.unwrap();
        assert!(matches!(challenge, Some(SessionMsg::UnattendedChallenge { .. })));
        drop(v);
    };
    tokio::join!(host_side, viewer_side).0
}

#[tokio::test]
async fn guesses_that_stop_at_the_challenge_count_too() {
    let Some(ts) = TestServer::start().await else { return };
    let viewer = ts.anonymous("laptop").await;
    let mut host = ts.anonymous("office").await;
    let path = temp("abandoned");
    let (mut store, _secret) = set_up_unattended(&host, &path, "office unattended password");
    for _ in 0..3 {
        assert!(abandoned_attempt(&viewer, &mut host, &mut store, "guess").await);
    }
    assert!(store.locked_for() > 0);
    // And the count is on disk, so restarting the host doesn't reset it.
    assert!(Unattended::load(&path).unwrap().locked_for() > 0);
    let _ = std::fs::remove_file(path);
    ts.stop().await;
}

#[tokio::test]
async fn unattended_access_needs_the_password_and_a_fresh_code() {
    let Some(ts) = TestServer::start().await else { return };
    let viewer = ts.anonymous("laptop").await;
    let mut host = ts.anonymous("office").await;
    let path = temp("unattended");
    let (mut store, secret) = set_up_unattended(&host, &path, "office unattended password");
    let step = totp::now() / 30;

    // The code from setting up is used already; the next one works with the right password.
    assert!(matches!(
        attempt(&viewer, &mut host, &mut store, "office unattended password", &secret.code_at(step)).await,
        Verdict::Rejected(_)
    ));
    assert_eq!(
        attempt(&viewer, &mut host, &mut store, "office unattended password", &secret.code_at(step + 1)).await,
        Verdict::Accepted
    );
    // Not twice with the same code.
    assert!(matches!(
        attempt(&viewer, &mut host, &mut store, "office unattended password", &secret.code_at(step + 1)).await,
        Verdict::Rejected(_)
    ));
    // A wrong password.
    assert!(matches!(
        attempt(&viewer, &mut host, &mut store, "guess", &secret.code_at(step + 1)).await,
        Verdict::Rejected(_)
    ));
    // A success starts the count afresh; with a third wrong attempt in a row, the host makes the
    // next one wait.
    assert_eq!(store.locked_for(), 0);
    assert!(matches!(
        attempt(&viewer, &mut host, &mut store, "guess again", &secret.code_at(step + 1)).await,
        Verdict::Rejected(_)
    ));
    assert!(store.locked_for() > 0);
    match attempt(&viewer, &mut host, &mut store, "office unattended password", &secret.code_at(step + 1)).await {
        Verdict::Rejected(reason) => assert!(reason.contains("Too many"), "{reason}"),
        v => panic!("{v:?}"),
    }
    // The relay never saw the password.
    assert!(!ts.relay_contains(b"office unattended password"));
    let _ = std::fs::remove_file(path);
    ts.stop().await;
}

#[tokio::test]
async fn accounts_can_have_two_factor_authentication() {
    let Some(ts) = TestServer::start().await else { return };
    let laptop = ts.signup("alice", "correct horse battery", "laptop").await;
    assert_eq!(laptop.conn.account_info().await.unwrap(), ("alice".into(), false));
    // Turning it on needs a password login on the connection, not just a signed-in device.
    let (device_conn, mut device_events) = ts.connect().await;
    device_conn.authenticate(&mut laptop.creds.clone()).await.unwrap();
    assert_eq!(code(device_conn.totp_begin().await), ErrorCode::NotAuthenticated);
    let (conn, _) = ts.connect().await;
    conn.login("alice", "correct horse battery").await.unwrap();
    let secret = conn.totp_begin().await.unwrap();
    let step = totp::now() / 30;
    assert_eq!(code(conn.totp_enable("000000").await), ErrorCode::AuthFailed);
    conn.totp_enable(&secret.code_at(step)).await.unwrap();
    assert!(laptop.conn.account_info().await.unwrap().1);
    // The account's devices hear about it (to switch off access from the same account, should
    // two-factor authentication go away).
    // (The laptop is online on its newest connection, `device_conn`.)
    let ev = tokio::time::timeout(T, device_events.recv()).await.unwrap().unwrap();
    assert!(matches!(ev, Event::AccountChanged), "{ev:?}");

    // Logging in now takes the code too, each code only once.
    let (c, _) = ts.connect().await;
    assert!(matches!(c.login("alice", "correct horse battery").await, Err(ClientError::TotpRequired)));
    let (c, _) = ts.connect().await;
    assert_eq!(
        code(c.login_with_code("alice", "correct horse battery", Some(&secret.code_at(step))).await),
        ErrorCode::AuthFailed
    );
    let (logged_in, _) = ts.connect().await;
    logged_in.login_with_code("alice", "correct horse battery", Some(&secret.code_at(step + 1))).await.unwrap();
    // A wrong password doesn't get as far as the code.
    let (c, _) = ts.connect().await;
    assert_eq!(code(c.login_with_code("alice", "wrong password!", Some("123456")).await), ErrorCode::AuthFailed);

    // Turning it off takes a valid code as well (the remaining ones are used up by now).
    assert_eq!(code(logged_in.totp_disable("000000").await), ErrorCode::AuthFailed);
    assert!(laptop.conn.account_info().await.unwrap().1);
    ts.stop().await;
}

#[tokio::test]
async fn organisations_let_their_members_reach_enrolled_devices() {
    let Some(ts) = TestServer::start_with(false).await else { return };
    let jane = ts.signup("jane", "correct horse battery", "jane-laptop").await;
    let tom = ts.signup("tom", "correct horse battery", "tom-laptop").await;
    let eve = ts.signup("eve", "correct horse battery", "eve-laptop").await;

    // Jane creates the organisation and a service worker.
    let (conn, _) = ts.connect().await;
    let login = conn.login("jane", "correct horse battery").await.unwrap();
    let mut admin = Admin::create(&conn, &login, "ACME").await.unwrap();
    let key = admin.create_worker(&conn, "office rollout", None).await.unwrap();
    let enrollment = somedesk_crypto::org::EnrollmentKey::decode(&key.encode()).unwrap();
    let org_id = enrollment.org_id;

    // A machine enrolls with it, even on a server that only lets in its accounts' devices.
    let (stub_conn, stub_events) = ts.connect().await;
    let stub_creds = stub_conn.enroll_device(&ts.addr, &enrollment, "front-desk").await.unwrap();
    let mut stub = Device { conn: stub_conn, events: stub_events, creds: stub_creds };
    let (stub_id, stub_pk) = (stub.creds.device_id, stub.creds.device_key().public());
    let info = jane.conn.lookup_device(stub_id).await.unwrap();
    assert_eq!(info.identity.org.as_ref().map(|c| c.org_name.as_str()), Some("ACME"));

    // Tom joins the support group, which may reach the office devices. The organisation shows up
    // for him as an invitation until he joins it.
    admin.add_member(&conn, &login, "tom", "Support", false).await.unwrap();
    admin.set_device_group(&conn, "Office", &[stub_id]).await.unwrap();
    assert_eq!(admin.policy.device_groups[0].devices[0].device_pk, stub_pk, "named by its key");
    assert!(admin.set_device_group(&conn, "Office", &[jane.creds.device_id]).await.is_err(), "not enrolled");
    admin.allow(&conn, "Support", "Office").await.unwrap();
    let invited = tom.conn.list_orgs().await.unwrap();
    assert!(invited.len() == 1 && !invited[0].joined);
    assert_eq!(code(tom.conn.list_org_devices(org_id).await), ErrorCode::Forbidden, "not before joining");
    tom.conn.answer_org_invite(org_id, true).await.unwrap();
    assert!(tom.conn.list_orgs().await.unwrap()[0].joined);

    // The stub takes the newest policy, checked against the key from its enrollment.
    let mut store = PolicyStore::load(&temp("policy"), org_id, enrollment.org_pk);
    let bundle = stub.conn.get_org_policy(org_id).await.unwrap().unwrap();
    assert!(store.update(bundle.clone()).unwrap());
    assert!(!store.update(bundle).unwrap(), "not the same version twice");

    let (_, from_tom) = open(&tom, &mut stub).await;
    assert!(store.allows(&from_tom.peer, &stub_pk), "tom is in Support, and Support reaches the office");
    let (_, from_jane) = open(&jane, &mut stub).await;
    assert!(store.allows(&from_jane.peer, &stub_pk), "admins reach all devices");
    assert!(!store.allows(&from_tom.peer, &[7; 32]), "Support reaches no other device");
    let (_, from_eve) = open(&eve, &mut stub).await;
    assert!(!store.allows(&from_eve.peer, &stub_pk), "eve isn't a member");

    // Members see the organisation's devices; the stub never starts a session itself.
    assert_eq!(tom.conn.list_org_devices(org_id).await.unwrap().len(), 1);
    assert_eq!(code(eve.conn.list_org_devices(org_id).await), ErrorCode::Forbidden);
    assert_eq!(code(stub.conn.request_session(jane.creds.device_id).await), ErrorCode::Forbidden);

    // Only admins change the policy, only with the organisation's key, and only from the
    // current version.
    let forged = somedesk_crypto::org::OrgKey::generate().sign_policy(&admin.policy);
    assert_eq!(code(conn.put_org_policy(org_id, forged.clone()).await), ErrorCode::BadRequest);
    assert!(store.update(PolicyBundle { policy: forged, rotations: vec![] }).is_err(), "the stub doesn't either");
    let (tom_conn, _) = ts.connect().await;
    tom_conn.login("tom", "correct horse battery").await.unwrap();
    let signed = admin.key.sign_policy(&admin.policy);
    assert_eq!(code(tom_conn.put_org_policy(org_id, signed).await), ErrorCode::Forbidden);
    let mut stale = admin.policy.clone();
    stale.version += 1;
    assert_eq!(code(conn.put_org_policy(org_id, admin.key.sign_policy(&stale)).await), ErrorCode::Conflict);

    // A revoked worker enrolls nobody else; the devices it enrolled stay.
    admin.revoke_worker(&conn, &enrollment.worker_pk()).await.unwrap();
    let (c, _) = ts.connect().await;
    assert_eq!(code(c.enroll_device(&ts.addr, &enrollment, "another").await), ErrorCode::Forbidden);
    let (c, _) = ts.connect().await;
    let mut creds = stub.creds.clone();
    assert_eq!(c.authenticate(&mut creds).await.unwrap().device_id, stub_id);

    // Removing tom takes effect on the stub with the next policy.
    admin.remove_member(&conn, &login, "tom").await.unwrap();
    store.update(stub.conn.get_org_policy(org_id).await.unwrap().unwrap()).unwrap();
    assert!(!store.allows(&from_tom.peer, &stub_pk));

    // Eve, added without asking, can decline: the organisation is gone from her list.
    admin.add_member(&conn, &login, "eve", "Support", false).await.unwrap();
    assert_eq!(eve.conn.list_orgs().await.unwrap().len(), 1);
    eve.conn.answer_org_invite(org_id, false).await.unwrap();
    assert!(eve.conn.list_orgs().await.unwrap().is_empty());
    admin.allow(&conn, "Support", "*").await.unwrap();
    assert!(eve.conn.list_orgs().await.unwrap().is_empty(), "and stays gone");
    ts.stop().await;
}

#[tokio::test]
async fn a_departing_admin_takes_no_working_key_along() {
    let Some(ts) = TestServer::start_with(false).await else { return };
    ts.signup("jane", "correct horse battery", "jane-laptop").await;
    ts.signup("tom", "correct horse battery", "tom-laptop").await;
    let (conn, _) = ts.connect().await;
    let login = conn.login("jane", "correct horse battery").await.unwrap();
    let mut admin = Admin::create(&conn, &login, "ACME").await.unwrap();
    let key = admin.create_worker(&conn, "rollout", None).await.unwrap();
    let enrollment = somedesk_crypto::org::EnrollmentKey::decode(&key.encode()).unwrap();
    let org_id = enrollment.org_id;
    let (stub_conn, _) = ts.connect().await;
    stub_conn.enroll_device(&ts.addr, &enrollment, "front-desk").await.unwrap();
    let mut store = PolicyStore::load(&temp("rotation"), org_id, enrollment.org_pk);
    store.update(stub_conn.get_org_policy(org_id).await.unwrap().unwrap()).unwrap();

    // Tom becomes an admin: jane seals the key to him, and he can tell it came from her.
    admin.add_member(&conn, &login, "tom", "Admins", true).await.unwrap();
    let (tom_conn, _) = ts.connect().await;
    let tom_login = tom_conn.login("tom", "correct horse battery").await.unwrap();
    tom_conn.answer_org_invite(org_id, true).await.unwrap();
    let info = tom_conn.list_orgs().await.unwrap().remove(0);
    let (mut tom_admin, shared_by) = Admin::open(&info, &tom_login, None).unwrap();
    let shared_by = shared_by.expect("shared by jane");
    assert_eq!((shared_by.username.as_str(), shared_by.identity_pk), ("jane", login.identity.public()));
    let old_key = tom_admin.key.to_bytes();

    // As an admin he can share the key, but not replace jane's copy with garbage.
    let jane_copy = conn.list_orgs().await.unwrap().remove(0).sealed_key;
    tom_conn.share_org_key(org_id, "jane", vec![7; 48]).await.unwrap();
    let info = conn.list_orgs().await.unwrap().remove(0);
    assert_eq!(info.sealed_key, jane_copy, "kept");
    assert!(Admin::open(&info, &login, None).is_ok());

    // Jane removes him: the organisation gets a new key, which he doesn't get.
    admin.remove_member(&conn, &login, "tom").await.unwrap();
    assert_ne!(admin.key.public(), enrollment.org_pk);
    let info = conn.list_orgs().await.unwrap().remove(0);
    assert_eq!(info.org_pk, admin.key.public());
    assert_eq!(info.rotations.len(), 1);
    assert!(tom_conn.list_orgs().await.unwrap().is_empty());

    // The server takes nothing from him any more.
    assert_eq!(code(tom_admin.allow(&tom_conn, "Admins", "*").await), ErrorCode::Forbidden);

    // The stub follows the rotation from the key it was enrolled with; from then on, whatever
    // he signs with the old key counts for nothing there either (even if a server handed it
    // over).
    assert!(store.update(stub_conn.get_org_policy(org_id).await.unwrap().unwrap()).unwrap());
    assert!(store.current().unwrap().member("tom").is_none());
    let mut grab = admin.policy.clone();
    grab.version += 5;
    grab.members.push(somedesk_proto::org::OrgMember {
        username: "tom".into(),
        identity_pk: tom_login.identity.public(),
        admin: true,
    });
    let old = somedesk_crypto::org::OrgKey::from_bytes(&old_key);
    assert!(store.update(PolicyBundle { policy: old.sign_policy(&grab), rotations: vec![] }).is_err());

    // A machine enrolled afterwards with the worker key from before follows it too.
    let (late_conn, _) = ts.connect().await;
    late_conn.enroll_device(&ts.addr, &enrollment, "back-office").await.unwrap();
    let mut late = PolicyStore::load(&temp("late"), org_id, enrollment.org_pk);
    assert!(late.update(late_conn.get_org_policy(org_id).await.unwrap().unwrap()).unwrap());

    // Jane's account remembers the new key: opening the organisation again checks out.
    let pin = admin.pin();
    let (reopened, by) = Admin::open(&info, &login, Some(&pin)).unwrap();
    assert!(by.is_none());
    assert_eq!(reopened.policy.version, admin.policy.version);
    ts.stop().await;
}

#[tokio::test]
async fn a_device_taken_off_an_account_loses_its_organisation_access() {
    let Some(ts) = TestServer::start_with(false).await else { return };
    let jane = ts.signup("jane", "correct horse battery", "jane-laptop").await;
    let (conn, _) = ts.connect().await;
    let login = conn.login("jane", "correct horse battery").await.unwrap();
    let mut admin = Admin::create(&conn, &login, "ACME").await.unwrap();
    let key = admin.create_worker(&conn, "rollout", None).await.unwrap();
    let enrollment = somedesk_crypto::org::EnrollmentKey::decode(&key.encode()).unwrap();
    let (stub_conn, stub_events) = ts.connect().await;
    let stub_creds = stub_conn.enroll_device(&ts.addr, &enrollment, "front-desk").await.unwrap();
    let mut stub = Device { conn: stub_conn, events: stub_events, creds: stub_creds };
    let stub_pk = stub.creds.device_key().public();
    let mut store = PolicyStore::load(&temp("removed"), enrollment.org_id, enrollment.org_pk);
    store.update(stub.conn.get_org_policy(enrollment.org_id).await.unwrap().unwrap()).unwrap();

    // Jane's laptop gets in as hers...
    let (_, h, from) = open_from(&jane, &mut stub).await;
    assert!(store.allows(&access::verified_identity(&h.peer, &from.identity), &stub_pk));

    // ...until it is taken off her account (stolen, say). It still has its certificate, but the
    // server no longer has it on her account, and the stub goes by that.
    conn.remove_device(jane.creds.device_id).await.unwrap();
    let (_, h, from) = open_from(&jane, &mut stub).await;
    assert!(h.peer.account.is_some(), "the laptop still presents its certificate");
    assert!(!store.allows(&access::verified_identity(&h.peer, &from.identity), &stub_pk));
    ts.stop().await;
}
