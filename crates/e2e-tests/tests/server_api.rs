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
async fn register_login_enroll_authenticate() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let alice = ts.signup("alice", "correct horse battery", "alice-laptop").await;
    assert!((100_000_000..=999_999_999).contains(&alice.creds.device_id));
    assert_eq!(alice.creds.username, "alice");

    let devices = alice.conn.list_devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, "alice-laptop");
    assert!(devices[0].online);
    somedesk_crypto::keys::verify_device_cert(&devices[0].cert).unwrap();

    // The same identity key is recovered on a second login (it came out of the encrypted bundle).
    let (conn2, _) = ts.connect().await;
    let login = conn2.login("ALICE", "correct horse battery").await.unwrap();
    assert_eq!(login.identity.public(), alice.creds.identity_pk);
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
async fn device_enrollment_requires_password_login_and_valid_cert() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let _alice = ts.signup("alice", "correct horse battery", "pc").await;

    // Without logging in.
    let (conn, _) = ts.connect().await;
    let rogue = IdentityKey::generate();
    let cert = rogue.certify_device("alice", DeviceKey::generate().public(), "evil", 0);
    assert_eq!(code(conn.request(Request::RegisterDevice { cert }).await), ErrorCode::NotAuthenticated);

    // Logged in, but the certificate is signed by a different identity key.
    conn.login("alice", "correct horse battery").await.unwrap();
    let cert = rogue.certify_device("alice", DeviceKey::generate().public(), "evil", 0);
    assert_eq!(code(conn.request(Request::RegisterDevice { cert }).await), ErrorCode::BadRequest);
    ts.stop().await;
}

#[tokio::test]
async fn token_auth_rejects_bad_tokens() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let alice = ts.signup("alice", "correct horse battery", "pc").await;
    let (conn, _) = ts.connect().await;
    let mut creds = alice.creds.clone();
    creds.token[0] ^= 1;
    assert_eq!(code(conn.authenticate(&creds).await), ErrorCode::AuthFailed);
    creds = alice.creds.clone();
    creds.device_id = 111_111_111;
    assert_eq!(code(conn.authenticate(&creds).await), ErrorCode::AuthFailed);
    // The real token works from a fresh connection (e.g. after a restart).
    conn.authenticate(&alice.creds).await.unwrap();
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
async fn removed_device_cannot_authenticate() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let laptop = ts.signup("alice", "correct horse battery", "laptop").await;
    let phone = ts.add_device("alice", "correct horse battery", "old-pc").await;
    laptop.conn.remove_device(phone.creds.device_id).await.unwrap();
    let (conn, _) = ts.connect().await;
    assert_eq!(code(conn.authenticate(&phone.creds).await), ErrorCode::AuthFailed);
    // Other users cannot remove your devices.
    let bob = ts.signup("bob", "correct horse battery", "pc").await;
    assert_eq!(code(bob.conn.remove_device(laptop.creds.device_id).await), ErrorCode::NotFound);
    ts.stop().await;
}
