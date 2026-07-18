//! Graceful-shutdown test for the tuic-client TCP/UDP forwarders.
//!
//! `forward::start` spawns each forwarder into `ctx.tasks`, driven by a child
//! of `ctx.token`. Cancelling the token must break every accept/recv loop so
//! the tracker drains — this is the forwarder half of the client's
//! `run_with_cancel` shutdown path.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tuic_client::{
	config::{TcpForward, UdpForward},
	forward,
};
use wind_core::AppContext;

/// Reserve a free loopback TCP port (the listener is dropped immediately so the
/// forwarder can bind it).
fn free_tcp_addr() -> SocketAddr {
	let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	let a = l.local_addr().unwrap();
	drop(l);
	a
}

/// Reserve a free loopback UDP port.
fn free_udp_addr() -> SocketAddr {
	let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
	let a = s.local_addr().unwrap();
	drop(s);
	a
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarders_drain_on_cancel() {
	let ctx = Arc::new(AppContext::default());

	let tcp = vec![TcpForward {
		listen: free_tcp_addr(),
		// Discard port (9) — never actually dialed; the loops are idle.
		remote: ("127.0.0.1".to_string(), 9),
	}];
	let udp = vec![UdpForward {
		listen: free_udp_addr(),
		remote: ("127.0.0.1".to_string(), 9),
		timeout: Duration::from_secs(60),
	}];

	forward::start(tcp, udp, &ctx).await;

	// Let both forwarder loops bind and reach their `select!`.
	tokio::time::sleep(Duration::from_millis(200)).await;

	// Graceful shutdown: cancel the context token, then drain the tracker.
	ctx.token.cancel();
	ctx.tasks.close();
	tokio::time::timeout(Duration::from_secs(5), ctx.tasks.wait())
		.await
		.expect("forwarder tasks did not drain within 5s of cancellation");
}
