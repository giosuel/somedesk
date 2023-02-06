//! A minimal SomeDesk peer for the NAT traversal test (scripts/nat-test.sh): signs up, comes
//! online and either waits for a session (`host`) or opens one (`viewer`), then prints which
//! path the session took.
//!
//!     nat_peer <server> <username> host <id-file>
//!     nat_peer <server> <username> viewer <id-file>

use somedesk_client::server::ServerConn;
use somedesk_client::session;
use somedesk_proto::control::Event;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info,zbus=warn,quinn=warn").with_writer(std::io::stderr).init();
    let args: Vec<String> = std::env::args().collect();
    let [_, server, user, mode, id_file] = &args[..] else {
        anyhow::bail!("usage: nat_peer <server> <username> host|viewer <id-file>");
    };
    let password = "nat test password";
    let (conn, mut events) = ServerConn::connect(server, None).await?;
    conn.register(user, password).await?;
    let login = conn.login(user, password).await?;
    let creds = conn.enroll_device(server, &login, user).await?;
    conn.authenticate(&creds).await?;

    match mode.as_str() {
        "host" => {
            std::fs::write(id_file, creds.device_id.to_string())?;
            let (sid, from, candidates) = loop {
                match tokio::time::timeout(Duration::from_secs(60), events.recv()).await? {
                    Some(Event::IncomingSession { session_id, from, candidates }) => {
                        break (session_id, from, candidates)
                    }
                    Some(_) => continue,
                    None => anyhow::bail!("server connection lost"),
                }
            };
            eprintln!("host: viewer candidates {candidates:?}");
            let (mut ch, route) = session::accept_routed(&conn, &creds, sid, &from, &candidates).await?;
            let msg = ch.receiver.recv_bytes().await?.unwrap_or_default();
            println!("host route={route:?} received={}", String::from_utf8_lossy(&msg));
            ch.sender.send_bytes(b"ack").await?;
            session::finish_stream(ch.sender.into_inner()).await;
        }
        "viewer" => {
            let id: u64 = loop {
                if let Ok(s) = std::fs::read_to_string(id_file) {
                    if let Ok(id) = s.trim().parse() {
                        break id;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            };
            let (mut ch, _, route) = session::connect_routed(&conn, &creds, id).await?;
            ch.sender.send_bytes(b"hello through the NAT").await?;
            let ack = ch.receiver.recv_bytes().await?.unwrap_or_default();
            println!("viewer route={route:?} ack={}", String::from_utf8_lossy(&ack));
        }
        _ => anyhow::bail!("mode must be host or viewer"),
    }
    Ok(())
}
