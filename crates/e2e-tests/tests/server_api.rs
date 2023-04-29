//! Account, device and presence behaviour of the server.

use somedesk_client::server::ServerConn;
use somedesk_client::ClientError;
use somedesk_crypto::keys::{DeviceKey, IdentityKey};
use somedesk_e2e_tests::TestServer;
use somedesk_proto::control::{ErrorCode, Event, Request};
use sqlx::{Connection, PgConnection, Row};
use std::time::Duration;

fn code<T>(r: Result<T, ClientError>) -> ErrorCode {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.code().unwrap_or_else(|| panic!("expected a server error, got {e}")),
    }
}

#[tokio::test]
async fn register_login_and_sign_a_device_in() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let alice = ts.signup("alice", "correct horse battery", "alice-laptop").await;
    assert!((100_000_000..=999_999_999).contains(&alice.creds.device_id));
    assert_eq!(alice.creds.username(), Some("alice"));

    let devices = alice.conn.list_devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].identity.name, "alice-laptop");
    assert!(devices[0].online);
    somedesk_crypto::keys::verify_device_cert(devices[0].identity.account.as_ref().unwrap()).unwrap();

    // The same identity key is recovered on a second login (it came out of the encrypted bundle).
    let (conn2, _) = ts.connect().await;
    let login = conn2.login("ALICE", "correct horse battery").await.unwrap();
    assert_eq!(login.identity.public(), alice.creds.account.as_ref().unwrap().identity_pk);
    ts.stop().await;
}

#[tokio::test]
async fn devices_get_an_id_without_an_account() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let mut laptop = ts.anonymous("laptop").await;
    let id = laptop.creds.device_id;
    assert!((100_000_000..=999_999_999).contains(&id));
    assert_eq!(laptop.creds.account.as_ref().map(|a| &a.username), None);

    // Anyone can look it up by its ID, and it has no account.
    let other = ts.anonymous("phone").await;
    let info = other.conn.lookup_device(id).await.unwrap();
    assert!(info.online);
    assert_eq!(info.identity.name, "laptop");
    assert_eq!(info.identity.account, None);
    // Only accounts have a device list.
    assert_eq!(code(other.conn.list_devices().await), ErrorCode::NotAuthenticated);

    // The ID belongs to the key: it comes back the same after a restart (a new connection), and
    // the name follows the device.
    laptop.conn.close();
    let (conn, _) = ts.connect().await;
    laptop.creds.device_name = "laptop 2".into();
    let again = conn.authenticate(&mut laptop.creds).await.unwrap();
    assert_eq!((again.device_id, again.identity.name.as_str()), (id, "laptop 2"));
    ts.stop().await;
}

#[tokio::test]
async fn signing_in_and_out_keeps_the_id() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let mut laptop = ts.signup("alice", "correct horse battery", "laptop").await;
    let mut desktop = ts.anonymous("desktop").await;
    let id = desktop.creds.device_id;

    let login = desktop.conn.login("alice", "correct horse battery").await.unwrap();
    desktop.conn.attach(&login, &mut desktop.creds).await.unwrap();
    assert_eq!(desktop.creds.device_id, id);
    assert_eq!(desktop.creds.username(), Some("alice"));
    let ev = tokio::time::timeout(Duration::from_secs(5), laptop.events.recv()).await.unwrap().unwrap();
    assert!(matches!(ev, Event::DevicePresence { device_id, online: true } if device_id == id));
    assert_eq!(laptop.conn.list_devices().await.unwrap().len(), 2);

    desktop.conn.detach(&mut desktop.creds).await.unwrap();
    assert_eq!(desktop.creds.username(), None);
    let ev = tokio::time::timeout(Duration::from_secs(5), laptop.events.recv()).await.unwrap().unwrap();
    assert!(matches!(ev, Event::DevicePresence { device_id, online: false } if device_id == id));
    assert_eq!(laptop.conn.list_devices().await.unwrap().len(), 1);
    // Still online under the same ID, just without the account.
    let info = laptop.conn.lookup_device(id).await.unwrap();
    assert!(info.online && info.identity.account.is_none());
    ts.stop().await;
}

#[tokio::test]
async fn an_accounts_only_server_turns_other_devices_away() {
    let Some(ts) = TestServer::start_with(false).await else {
        return;
    };
    let (conn, _) = ts.connect().await;
    assert_eq!(code(conn.create_device(&ts.addr, "laptop").await), ErrorCode::Forbidden);
    // With an account it works: log in first, then sign the new device in.
    let alice = ts.signup("alice", "correct horse battery", "laptop").await;
    // Signed out, the device can't come back.
    let mut creds = alice.creds.clone();
    alice.conn.detach(&mut creds).await.unwrap();
    let (conn, _) = ts.connect().await;
    assert_eq!(code(conn.authenticate(&mut creds).await), ErrorCode::Forbidden);
    ts.stop().await;
}

#[tokio::test]
async fn wrong_password_and_unknown_user_look_the_same() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let _alice = ts.signup("alice", "correct horse battery", "pc").await;
    let (conn, _) = ts.connect().await;
    let wrong = conn.login("alice", "wrong password!").await;
    let unknown = conn.login("nobody", "wrong password!").await;
    assert_eq!(code(wrong), ErrorCode::AuthFailed);
    assert_eq!(code(unknown), ErrorCode::AuthFailed);
    ts.stop().await;
}

#[tokio::test]
async fn usernames_are_unique_case_insensitively() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let _alice = ts.signup("alice", "correct horse battery", "pc").await;
    let (conn, _) = ts.connect().await;
    assert_eq!(code(conn.register("Alice", "another password").await), ErrorCode::UsernameTaken);
    assert_eq!(code(conn.register("a", "another password").await), ErrorCode::BadRequest);
    assert_eq!(code(conn.register("bob", "short").await), ErrorCode::BadRequest);
    ts.stop().await;
}

#[tokio::test]
async fn database_holds_no_password_and_no_plaintext_key() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let password = "my-very-secret-password-42";
    let _alice = ts.signup("alice", password, "pc").await;
    let mut db = PgConnection::connect(&ts.db_url).await.unwrap();
    let row = sqlx::query("SELECT password_file, key_bundle, identity_pk FROM users WHERE username = 'alice'")
        .fetch_one(&mut db)
        .await
        .unwrap();
    for col in ["password_file", "key_bundle", "identity_pk"] {
        let bytes: Vec<u8> = row.get(col);
        assert!(!bytes.windows(password.len()).any(|w| w == password.as_bytes()), "{col} contains the password");
    }
    let bundle: Vec<u8> = row.get("key_bundle");
    let bundle: somedesk_proto::control::EncryptedKeyBundle = postcard::from_bytes(&bundle).unwrap();
    // 32-byte key + 16-byte AEAD tag: it is ciphertext, not a raw key.
    assert_eq!(bundle.ciphertext.len(), 48);
    ts.stop().await;
}

#[tokio::test]
async fn signing_in_needs_a_password_login_and_a_valid_certificate() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let _alice = ts.signup("alice", "correct horse battery", "pc").await;
    let device = ts.anonymous("evil").await;
    let key = device.creds.device_key();
    let rogue = IdentityKey::generate();

    // Without logging in.
    let cert = rogue.certify_device("alice", key.public(), "evil", 0);
    assert_eq!(code(device.conn.request(Request::AttachDevice { cert }).await), ErrorCode::NotAuthenticated);

    // Logged in, but the certificate is signed by a different identity key.
    let login = device.conn.login("alice", "correct horse battery").await.unwrap();
    let cert = rogue.certify_device("alice", key.public(), "evil", 0);
    assert_eq!(code(device.conn.request(Request::AttachDevice { cert }).await), ErrorCode::BadRequest);
    // Signed by the account, but for another device.
    let cert = login.identity.certify_device("alice", DeviceKey::generate().public(), "evil", 0);
    assert_eq!(code(device.conn.request(Request::AttachDevice { cert }).await), ErrorCode::BadRequest);
    ts.stop().await;
}

#[tokio::test]
async fn devices_must_prove_their_key() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let alice = ts.signup("alice", "correct horse battery", "pc").await;
    let (conn, _) = ts.connect().await;
    // No challenge asked for.
    assert_eq!(
        code(conn.request(Request::DeviceAuth { name: "x".into(), proof: [0; 32], org: None }).await),
        ErrorCode::BadRequest
    );
    // Alice's public key, without her private key.
    let public = alice.creds.device_key().public();
    conn.request(Request::DeviceChallenge { device_pk: public }).await.unwrap();
    assert_eq!(
        code(conn.request(Request::DeviceAuth { name: "x".into(), proof: [7; 32], org: None }).await),
        ErrorCode::AuthFailed
    );
    // The real key works from a fresh connection (e.g. after a restart), with the same ID.
    let mut creds = alice.creds.clone();
    assert_eq!(conn.authenticate(&mut creds).await.unwrap().device_id, alice.creds.device_id);
    ts.stop().await;
}

#[tokio::test]
async fn requests_need_authentication() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let (conn, _) = ts.connect().await;
    assert_eq!(code(conn.list_devices().await), ErrorCode::NotAuthenticated);
    assert_eq!(code(conn.lookup_device(123_456_789).await), ErrorCode::NotAuthenticated);
    assert_eq!(code(conn.request_session(123_456_789).await), ErrorCode::NotAuthenticated);
    ts.stop().await;
}

#[tokio::test]
async fn presence_events_between_own_devices() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let mut laptop = ts.signup("alice", "correct horse battery", "laptop").await;
    let desktop = ts.add_device("alice", "correct horse battery", "desktop").await;
    let id = desktop.creds.device_id;

    let ev = tokio::time::timeout(Duration::from_secs(5), laptop.events.recv()).await.unwrap().unwrap();
    assert!(matches!(ev, Event::DevicePresence { device_id, online: true } if device_id == id));
    let list = laptop.conn.list_devices().await.unwrap();
    assert_eq!(list.len(), 2);
    assert!(list.iter().all(|d| d.online));

    desktop.conn.close();
    drop(desktop);
    let ev = tokio::time::timeout(Duration::from_secs(5), laptop.events.recv()).await.unwrap().unwrap();
    assert!(matches!(ev, Event::DevicePresence { device_id, online: false } if device_id == id));
    let list = laptop.conn.list_devices().await.unwrap();
    assert!(!list.iter().find(|d| d.device_id == id).unwrap().online);
    ts.stop().await;
}

#[tokio::test]
async fn connect_errors() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let alice = ts.signup("alice", "correct horse battery", "pc").await;
    let bob = ts.signup("bob", "correct horse battery", "pc").await;
    let bob_id = bob.creds.device_id;
    assert_eq!(code(alice.conn.request_session(alice.creds.device_id).await), ErrorCode::BadRequest);
    assert_eq!(code(alice.conn.request_session(111_111_111).await), ErrorCode::NotFound);
    bob.conn.close();
    drop(bob);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(code(alice.conn.request_session(bob_id).await), ErrorCode::Offline);
    ts.stop().await;
}

#[tokio::test]
async fn login_attempts_are_rate_limited() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let (conn, _) = ts.connect().await;
    let mut limited = false;
    for _ in 0..25 {
        if let Err(e) = conn.login("victim", "guess-guess").await {
            if e.code() == Some(ErrorCode::RateLimited) {
                limited = true;
                break;
            }
        }
    }
    assert!(limited, "25 login attempts within a minute should be rate limited");
    ts.stop().await;
}

#[tokio::test]
async fn pinned_certificate_mismatch_is_refused() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let mut wrong = ts.fingerprint;
    wrong[0] ^= 0xff;
    let res = ServerConn::connect(&ts.addr, Some(wrong)).await;
    assert!(matches!(res, Err(ClientError::Transport(_))));
    // Trust-on-first-use reports the real fingerprint.
    let (conn, _) = ServerConn::connect(&ts.addr, None).await.unwrap();
    assert_eq!(conn.fingerprint(), ts.fingerprint);
    ts.stop().await;
}

#[tokio::test]
async fn a_removed_device_leaves_the_account_but_keeps_its_id() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let laptop = ts.signup("alice", "correct horse battery", "laptop").await;
    let mut old = ts.add_device("alice", "correct horse battery", "old-pc").await;
    let id = old.creds.device_id;
    laptop.conn.remove_device(id).await.unwrap();
    let ev = tokio::time::timeout(Duration::from_secs(5), old.events.recv()).await.unwrap().unwrap();
    assert!(matches!(ev, Event::SignedOut), "the device is told: {ev:?}");
    assert_eq!(laptop.conn.list_devices().await.unwrap().len(), 1);
    // On its next start it finds itself signed out, under the same ID.
    let (conn, _) = ts.connect().await;
    let info = conn.authenticate(&mut old.creds).await.unwrap();
    assert_eq!(info.device_id, id);
    assert_eq!(old.creds.account.as_ref().map(|a| &a.username), None);
    // Other users cannot remove your devices.
    let bob = ts.signup("bob", "correct horse battery", "pc").await;
    assert_eq!(code(bob.conn.remove_device(laptop.creds.device_id).await), ErrorCode::NotFound);
    ts.stop().await;
}
