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
    let id = host.creds.device_id;
    let host_side = async {
        let (sid, from, cands) = next_incoming(host).await;
        session::accept(&host.conn, &host.creds, sid, &from, &cands).await.unwrap()
    };
    let ((v, _), h) =
        tokio::join!(async { session::connect(&viewer.conn, &viewer.creds, id).await.unwrap() }, host_side);
    (v, h)
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

    // A machine enrolls with it, even on a server that only lets in its accounts' devices.
    let (stub_conn, stub_events) = ts.connect().await;
    let stub_creds = stub_conn.enroll_device(&ts.addr, &enrollment, "front-desk").await.unwrap();
    let mut stub = Device { conn: stub_conn, events: stub_events, creds: stub_creds };
    let stub_id = stub.creds.device_id;
    let info = jane.conn.lookup_device(stub_id).await.unwrap();
    assert_eq!(info.identity.org.as_ref().map(|c| c.org_name.as_str()), Some("ACME"));

    // Tom joins the support group, which may reach the office devices.
    admin.add_member(&conn, "tom", "Support", false).await.unwrap();
    admin.set_device_group(&conn, "Office", vec![stub_id]).await.unwrap();
    admin.allow(&conn, "Support", "Office").await.unwrap();

    // The stub takes the newest policy, checked against the key from its enrollment.
    let mut store = PolicyStore::load(&temp("policy"), enrollment.org_pk);
    let signed = stub.conn.get_org_policy(enrollment.org_id).await.unwrap().unwrap();
    assert!(store.update(signed.clone()).unwrap());
    assert!(!store.update(signed).unwrap(), "not the same version twice");

    let (_, from_tom) = open(&tom, &mut stub).await;
    assert!(store.allows(&from_tom.peer, stub_id), "tom is in Support, and Support reaches the office");
    let (_, from_jane) = open(&jane, &mut stub).await;
    assert!(store.allows(&from_jane.peer, stub_id), "admins reach all devices");
    let (_, from_eve) = open(&eve, &mut stub).await;
    assert!(!store.allows(&from_eve.peer, stub_id), "eve isn't a member");

    // Members see the organisation's devices; the stub never starts a session itself.
    assert_eq!(tom.conn.list_org_devices(enrollment.org_id).await.unwrap().len(), 1);
    assert_eq!(code(eve.conn.list_org_devices(enrollment.org_id).await), ErrorCode::Forbidden);
    assert_eq!(code(stub.conn.request_session(jane.creds.device_id).await), ErrorCode::Forbidden);

    // Only admins change the policy, and only with the organisation's key.
    let forged = somedesk_crypto::org::OrgKey::generate().sign_policy(&admin.policy);
    assert_eq!(code(conn.put_org_policy(enrollment.org_id, forged.clone()).await), ErrorCode::BadRequest);
    assert!(store.update(forged).is_err(), "the stub doesn't take it either");
    let (tom_conn, _) = ts.connect().await;
    tom_conn.login("tom", "correct horse battery").await.unwrap();
    let signed = admin.key.sign_policy(&admin.policy);
    assert_eq!(code(tom_conn.put_org_policy(enrollment.org_id, signed).await), ErrorCode::Forbidden);

    // A revoked worker enrolls nobody else; the devices it enrolled stay.
    admin.revoke_worker(&conn, &enrollment.worker_pk()).await.unwrap();
    let (c, _) = ts.connect().await;
    assert_eq!(code(c.enroll_device(&ts.addr, &enrollment, "another").await), ErrorCode::Forbidden);
    let (c, _) = ts.connect().await;
    let mut creds = stub.creds.clone();
    assert_eq!(c.authenticate(&mut creds).await.unwrap().device_id, stub_id);

    // Removing tom takes effect on the stub with the next policy.
    admin.remove_member(&conn, "tom").await.unwrap();
    store.update(stub.conn.get_org_policy(enrollment.org_id).await.unwrap().unwrap()).unwrap();
    assert!(!store.allows(&from_tom.peer, stub_id));
    ts.stop().await;
}
