//! Direct (peer-to-peer) sessions and the fallback to the relay.

use somedesk_client::session::{self, Route};
use somedesk_client::SessionExtras;
use somedesk_client::{host, viewer};
use somedesk_e2e_tests::{Device, FakeCapturer, RecordingInjector, TestServer};
use somedesk_proto::control::{DeviceInfo, Event, SessionId};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

const T: Duration = Duration::from_secs(10);

async fn next_incoming(host: &mut Device) -> (SessionId, DeviceInfo, Vec<SocketAddr>) {
    loop {
        match tokio::time::timeout(T, host.events.recv()).await.expect("incoming session").unwrap() {
            Event::IncomingSession { session_id, from, candidates } => return (session_id, from, candidates),
            _ => continue,
        }
    }
}

/// Connects `viewer` to `host`; returns both routes and the candidates each side was given.
async fn connect(
    viewer: &Device,
    host: &mut Device,
) -> (Route, Route, Vec<SocketAddr>, session::Channel, session::Channel) {
    let host_id = host.creds.device_id;
    let viewer_side = async { session::connect_routed(&viewer.conn, &viewer.creds, host_id).await.expect("viewer") };
    let host_side = async {
        let (sid, from, cands) = next_incoming(host).await;
        let (ch, route) = session::accept_routed(&host.conn, &host.creds, sid, &from, &cands).await.expect("host");
        (ch, route, cands)
    };
    let ((vch, _, vroute), (hch, hroute, cands)) = tokio::join!(viewer_side, host_side);
    (vroute, hroute, cands, vch, hch)
}

#[tokio::test]
async fn sessions_go_direct_when_both_sides_can_reach_each_other() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let viewer_dev = ts.signup("alice", "correct horse battery", "laptop").await;
    let mut host_dev = ts.signup("bob", "correct horse battery", "desktop").await;
    let (vroute, hroute, cands, vch, hch) = connect(&viewer_dev, &mut host_dev).await;
    assert_eq!((vroute, hroute), (Route::Direct, Route::Direct));
    assert!(!cands.is_empty(), "the host learned where the viewer can be reached");

    // A whole session runs over the direct path; the relay forwards nothing.
    let (ftx, mut frames) = mpsc::unbounded_channel();
    let sink: viewer::EventSink = Arc::new(move |ev| {
        if let viewer::ViewerEvent::Frame(f) = ev {
            let _ = ftx.send(f);
        }
    });
    let (input, input_rx) = mpsc::unbounded_channel();
    let viewer_task = tokio::spawn(viewer::run(vch, sink, input_rx, SessionExtras::default()));
    let (_stop, stop_rx) = watch::channel(false);
    let cap = FakeCapturer { width: 64, height: 64, bgra: Arc::new(Mutex::new([10, 200, 30, 255])) };
    let host_task = tokio::spawn(host::serve(
        hch,
        Box::new(cap),
        Box::new(RecordingInjector::default()),
        SessionExtras::default(),
        host::HostSettings::default(),
        stop_rx,
    ));
    tokio::time::timeout(T, frames.recv()).await.expect("a frame over the direct path").unwrap();
    drop(input);
    tokio::time::timeout(T, viewer_task).await.unwrap().unwrap().unwrap();
    let stats = tokio::time::timeout(T, host_task).await.unwrap().unwrap().unwrap();
    assert!(stats.frames_sent >= 1);
    assert_eq!(ts.relay_bytes.lock().unwrap().len(), 0, "nothing went through the relay");
    ts.stop().await;
}

#[tokio::test]
async fn either_side_can_insist_on_the_relay() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    for viewer_refuses in [true, false] {
        let mut viewer_dev = ts.signup(&format!("viewer{}", viewer_refuses as u8), "correct horse battery", "v").await;
        let mut host_dev = ts.signup(&format!("host{}", viewer_refuses as u8), "correct horse battery", "h").await;
        if viewer_refuses {
            viewer_dev = viewer_dev.relay_only().await;
        } else {
            host_dev = host_dev.relay_only().await;
        }
        let before = ts.relay_bytes.lock().unwrap().len();
        let (vroute, hroute, cands, mut vch, mut hch) = connect(&viewer_dev, &mut host_dev).await;
        assert_eq!((vroute, hroute), (Route::Relay, Route::Relay));
        // Neither side learns the other's addresses.
        assert!(cands.is_empty());
        // And the channel works through the relay.
        vch.sender.send_bytes(b"hello").await.unwrap();
        assert_eq!(hch.receiver.recv_bytes().await.unwrap().unwrap(), b"hello");
        assert!(ts.relay_bytes.lock().unwrap().len() > before);
    }
    ts.stop().await;
}

#[tokio::test]
async fn unreachable_peers_fall_back_to_the_relay_quickly() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let viewer_dev = ts.signup("alice", "correct horse battery", "laptop").await;
    let mut host_dev = ts.signup("bob", "correct horse battery", "desktop").await;
    // Bob's addresses were announced, but now nothing gets through to him directly (as behind a
    // strict firewall): his endpoint refuses peers and he does not dial out.
    host_dev.conn.set_allow_direct(false);
    let started = Instant::now();
    let (vroute, hroute, _, mut vch, mut hch) = connect(&viewer_dev, &mut host_dev).await;
    assert_eq!((vroute, hroute), (Route::Relay, Route::Relay));
    assert!(started.elapsed() < Duration::from_secs(6), "fallback took {:?}", started.elapsed());
    vch.sender.send_bytes(b"over the relay").await.unwrap();
    assert_eq!(hch.receiver.recv_bytes().await.unwrap().unwrap(), b"over the relay");
    ts.stop().await;
}
