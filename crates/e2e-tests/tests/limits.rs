//! What keeps one client from spoiling the server for others: invites, waits after wrong
//! passwords, connection limits, and logins that end when the account changes.

use somedesk_client::server::ServerConn;
use somedesk_client::ClientError;
use somedesk_e2e_tests::TestServer;
use somedesk_proto::control::ErrorCode;
use somedesk_server::{Limits, Registration};
use std::time::Duration;

fn code<T>(r: Result<T, ClientError>) -> ErrorCode {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.code().unwrap_or_else(|| panic!("expected a server error, got {e}")),
    }
}

#[tokio::test]
async fn invite_only_servers_create_accounts_with_a_code() {
    let Some(ts) = TestServer::start_configured(false, Registration::Invite, Limits::default()).await else {
        return;
    };
    let (conn, _) = ts.connect().await;
    assert_eq!(code(conn.register("alice", "a long password").await), ErrorCode::InviteRequired);
    assert_eq!(
        code(conn.register_with_invite("alice", "a long password", Some("ABCDE-FGHJK-LMNPQ-RSTUV")).await),
        ErrorCode::InviteRequired
    );

    let invite = somedesk_server::create_invite(&ts.db_url, 1, Some(7)).await.unwrap();
    // Typed in lowercase, without the dashes.
    let typed = invite.to_lowercase().replace('-', "");
    conn.register_with_invite("alice", "a long password", Some(&typed)).await.unwrap();
    conn.login("alice", "a long password").await.unwrap();

    // Used up.
    let (conn, _) = ts.connect().await;
    assert_eq!(
        code(conn.register_with_invite("bob", "a long password", Some(&invite)).await),
        ErrorCode::InviteRequired
    );

    // A taken username doesn't use up the invite.
    let invite = somedesk_server::create_invite(&ts.db_url, 1, None).await.unwrap();
    assert_eq!(
        code(conn.register_with_invite("alice", "a long password", Some(&invite)).await),
        ErrorCode::UsernameTaken
    );
    conn.register_with_invite("bob", "a long password", Some(&invite)).await.unwrap();
    ts.stop().await;
}

#[tokio::test]
async fn closed_servers_create_no_accounts() {
    let Some(ts) = TestServer::start_configured(false, Registration::Closed, Limits::default()).await else {
        return;
    };
    let (conn, _) = ts.connect().await;
    let invite = somedesk_server::create_invite(&ts.db_url, 1, None).await.unwrap();
    assert_eq!(code(conn.register_with_invite("alice", "a long password", Some(&invite)).await), ErrorCode::Forbidden);
    ts.stop().await;
}

#[tokio::test]
async fn wrong_passwords_make_that_address_wait_for_that_account() {
    let Some(ts) = TestServer::start().await else { return };
    let (conn, _) = ts.connect().await;
    conn.register("alice", "the right password").await.unwrap();
    conn.register("bob", "bob's right password").await.unwrap();
    for _ in 0..5 {
        assert_eq!(code(conn.login("alice", "a wrong password").await), ErrorCode::AuthFailed);
    }
    // One more wrong one, and the address waits, even with the right password...
    assert_eq!(code(conn.login("alice", "a wrong password").await), ErrorCode::AuthFailed);
    match conn.login("alice", "the right password").await {
        Err(e) => {
            assert_eq!(e.code(), Some(ErrorCode::RateLimited));
            assert!(e.to_string().contains("wrong attempts"), "{e}");
        }
        Ok(_) => panic!("expected a wait"),
    }
    // ...for that account only.
    conn.login("bob", "bob's right password").await.unwrap();
    ts.stop().await;
}

#[tokio::test]
async fn a_password_reset_ends_other_logins() {
    let Some(ts) = TestServer::start().await else { return };
    let (conn, _) = ts.connect().await;
    let rk = conn.register("alice", "the old password").await.unwrap();
    let (stolen, _) = ts.connect().await;
    stolen.login("alice", "the old password").await.unwrap();
    stolen.account_info().await.unwrap();

    let (owner, _) = ts.connect().await;
    owner.recover("alice", &rk, "a brand new password").await.unwrap();
    owner.account_info().await.unwrap();
    assert_eq!(code(stolen.account_info().await), ErrorCode::NotAuthenticated);
    ts.stop().await;
}

#[tokio::test]
async fn turning_on_two_factor_authentication_ends_other_logins() {
    let Some(ts) = TestServer::start().await else { return };
    let (conn, _) = ts.connect().await;
    conn.register("alice", "the right password").await.unwrap();
    let (other, _) = ts.connect().await;
    other.login("alice", "the right password").await.unwrap();
    conn.login("alice", "the right password").await.unwrap();
    let secret = conn.totp_begin().await.unwrap();
    conn.totp_enable(&secret.code_at(somedesk_crypto::totp::now() / 30)).await.unwrap();
    conn.account_info().await.unwrap();
    assert_eq!(code(other.account_info().await), ErrorCode::NotAuthenticated);
    ts.stop().await;
}

#[tokio::test]
async fn connections_per_address_are_limited() {
    let limits = Limits { connections_per_ip: 2, ..Limits::default() };
    let Some(ts) = TestServer::start_configured(true, Registration::Open, limits).await else { return };
    let _a = ts.anonymous("one").await;
    let b = ts.anonymous("two").await;
    assert!(ServerConn::connect(&ts.addr, Some(ts.fingerprint)).await.is_err(), "a third one is refused");
    b.conn.close();
    drop(b);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _c = ts.anonymous("three").await;
    ts.stop().await;
}

#[tokio::test]
async fn connections_that_never_sign_in_are_closed() {
    let limits = Limits { sign_in_timeout: Duration::from_millis(500), ..Limits::default() };
    let Some(ts) = TestServer::start_configured(true, Registration::Open, limits).await else { return };
    let (idle, _) = ts.connect().await;
    let online = ts.anonymous("laptop").await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(idle.list_devices().await.is_err(), "closed");
    online.conn.lookup_device(online.creds.device_id).await.unwrap();
    ts.stop().await;
}
