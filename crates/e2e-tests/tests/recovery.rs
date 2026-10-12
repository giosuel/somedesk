//! Password reset with the recovery key.

use somedesk_client::ClientError;
use somedesk_crypto::recovery::RecoveryKey;
use somedesk_e2e_tests::TestServer;
use somedesk_proto::control::{ErrorCode, Request, Response};
use sqlx::{Connection, PgConnection, Row};

fn code<T>(r: Result<T, ClientError>) -> ErrorCode {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.code().unwrap_or_else(|| panic!("expected a server error, got {e}")),
    }
}

#[tokio::test]
async fn recovery_key_resets_the_password_and_keeps_the_identity() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let (conn, _) = ts.connect().await;
    let rk = conn.register("alice", "forgotten password").await.unwrap();
    let device = ts.add_device("alice", "forgotten password", "laptop").await;

    // Typed back from paper: lowercase, spaces instead of dashes.
    let typed = RecoveryKey::parse(&rk.display().to_lowercase().replace('-', " ")).unwrap();
    let (conn, _) = ts.connect().await;
    let recovered = conn.recover("alice", &typed, "brand new password").await.unwrap();
    let identity_pk = device.creds.account.as_ref().unwrap().identity_pk;
    assert_eq!(recovered.login.identity.public(), identity_pk, "same identity key as before");

    // The recovered connection is logged in and can sign a device in straight away.
    let mut creds = conn.create_device(&ts.addr, "new-laptop").await.unwrap();
    conn.attach(&recovered.login, &mut creds).await.unwrap();
    somedesk_crypto::keys::verify_device_cert(&creds.account.as_ref().unwrap().cert).unwrap();

    // Old password is gone, new one works and opens the same identity key.
    let (c, _) = ts.connect().await;
    assert_eq!(code(c.login("alice", "forgotten password").await), ErrorCode::AuthFailed);
    let login = c.login("alice", "brand new password").await.unwrap();
    assert_eq!(login.identity.public(), identity_pk);
    assert!(login.has_recovery);

    // Existing devices keep working.
    let (c, _) = ts.connect().await;
    c.authenticate(&mut device.creds.clone()).await.unwrap();

    // Recovery keys are single-use: the old one is replaced by the new one.
    let (c, _) = ts.connect().await;
    assert_eq!(code(c.recover("alice", &rk, "yet another password").await), ErrorCode::AuthFailed);
    let (c, _) = ts.connect().await;
    c.recover("alice", &recovered.new_recovery_key, "yet another password").await.unwrap();
    ts.stop().await;
}

#[tokio::test]
async fn wrong_recovery_key_and_unknown_user_look_the_same() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let _alice = ts.signup("alice", "correct horse battery", "pc").await;
    let wrong = RecoveryKey::generate();
    let (c, _) = ts.connect().await;
    let a = c.recover("alice", &wrong, "new password here").await;
    let (c, _) = ts.connect().await;
    let b = c.recover("nobody", &wrong, "new password here").await;
    // Even a malformed username gets a challenge from the server.
    let (c, _) = ts.connect().await;
    let r = c.request(Request::RecoveryStart { username: "x".into() }).await.unwrap();
    assert!(matches!(r, Response::RecoveryChallenge { .. }));
    for (r, what) in [(a, "wrong key"), (b, "unknown user")] {
        match r {
            Err(ClientError::Server(e)) => {
                assert_eq!(e.code, ErrorCode::AuthFailed, "{what}");
                assert_eq!(e.message, "wrong username or recovery key", "{what}");
            }
            Err(e) => panic!("{what}: {e}"),
            Ok(_) => panic!("{what}: recovery succeeded"),
        }
    }
    // A failed attempt changes nothing.
    let (c, _) = ts.connect().await;
    c.login("alice", "correct horse battery").await.unwrap();
    ts.stop().await;
}

#[tokio::test]
async fn recovery_steps_cannot_be_skipped() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let _alice = ts.signup("alice", "correct horse battery", "pc").await;
    let (c, _) = ts.connect().await;
    let rk = RecoveryKey::generate();
    let setup = somedesk_proto::control::RecoverySetup {
        recovery_pk: rk.public(),
        key_bundle: rk.seal(&somedesk_crypto::keys::IdentityKey::generate(), "alice"),
    };
    // Finishing without a proof, or proving without a challenge, is refused.
    let finish =
        Request::RecoveryFinish { message: vec![0; 64], key_bundle: setup.key_bundle.clone(), recovery: setup };
    assert_eq!(code(c.request(finish.clone()).await), ErrorCode::BadRequest);
    assert_eq!(
        code(c.request(Request::RecoveryProve { proof: vec![0; 64], message: vec![] }).await),
        ErrorCode::BadRequest
    );
    // A bad proof also ends the attempt: retrying the finish step is still refused.
    let Response::RecoveryChallenge { .. } =
        c.request(Request::RecoveryStart { username: "alice".into() }).await.unwrap()
    else {
        panic!("expected a challenge")
    };
    assert_eq!(
        code(c.request(Request::RecoveryProve { proof: vec![0; 64], message: vec![] }).await),
        ErrorCode::AuthFailed
    );
    assert_eq!(code(c.request(finish).await), ErrorCode::BadRequest);
    // Replacing the recovery key needs a password login.
    let setup = somedesk_proto::control::RecoverySetup {
        recovery_pk: rk.public(),
        key_bundle: rk.seal(&somedesk_crypto::keys::IdentityKey::generate(), "alice"),
    };
    assert_eq!(code(c.request(Request::SetRecovery { recovery: setup }).await), ErrorCode::NotAuthenticated);
    ts.stop().await;
}

#[tokio::test]
async fn accounts_without_a_recovery_key_can_add_one() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let alice = ts.signup("alice", "correct horse battery", "pc").await;
    // Simulate an account created before recovery keys existed.
    let mut db = PgConnection::connect(&ts.db_url).await.unwrap();
    sqlx::query("UPDATE users SET recovery_pk = NULL, recovery_bundle = NULL").execute(&mut db).await.unwrap();

    let (c, _) = ts.connect().await;
    let login = c.login("alice", "correct horse battery").await.unwrap();
    assert!(!login.has_recovery);
    let rk = c.set_up_recovery(&login).await.unwrap();
    let row = sqlx::query("SELECT recovery_pk FROM users WHERE username = 'alice'").fetch_one(&mut db).await.unwrap();
    assert_eq!(row.get::<Vec<u8>, _>("recovery_pk"), rk.public().to_vec());

    let (c, _) = ts.connect().await;
    let recovered = c.recover("alice", &rk, "a new password").await.unwrap();
    assert_eq!(recovered.login.identity.public(), alice.creds.account.as_ref().unwrap().identity_pk);
    ts.stop().await;
}

#[tokio::test]
async fn recovery_attempts_are_rate_limited() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let _alice = ts.signup("alice", "correct horse battery", "pc").await;
    let (c, _) = ts.connect().await;
    let mut limited = false;
    for _ in 0..25 {
        match c.request(Request::RecoveryStart { username: "alice".into() }).await {
            Ok(_) => {}
            Err(e) if e.code() == Some(ErrorCode::RateLimited) => {
                limited = true;
                break;
            }
            Err(e) => panic!("{e}"),
        }
    }
    assert!(limited, "recovery attempts must be rate limited");
    ts.stop().await;
}
