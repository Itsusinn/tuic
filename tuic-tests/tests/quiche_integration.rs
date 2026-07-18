//! End-to-end integration test for the tokio-quiche (`wind-tuiche`) backend.
//!
//! Starts a `tuic-server` with `backend.mode = "quiche"` + a self-signed
//! certificate, connects the quinn-based `tuic-client`, and relays TCP and UDP
//! through the client's SOCKS5 proxy. This exercises the whole quiche path:
//! QUIC handshake, RFC 5705 exporter authentication, the `ApplicationOverQuic`
//! worker, and the channel-bridged TCP/UDP relay.
//!
//! `tuic_client::run` installs a process-global connection, so this file runs a
//! single client and covers both TCP and UDP within one test. (0-RTT lives in a
//! separate test file = separate process; cert hot-reload in another.)

// These e2e tests drive real QUIC sockets; only *run* them on 64-bit hosts
// (cross-emulated 32-bit test execution is unreliable for networking). The
// quiche backend itself now builds on 32-bit too (see patches/tokio-quiche).
#![cfg(target_pointer_width = "64")]

use std::{
	net::{IpAddr, Ipv4Addr, SocketAddr},
	time::Duration,
};

use serial_test::serial;
use tokio::time::timeout;
use tuic_tests::{
	run_tcp_echo_server, run_udp_echo_server, start_quiche_pair, test_tcp_through_socks5, test_udp_through_socks5,
};

#[tokio::test]
#[serial]
#[tracing_test::traced_test]
async fn quiche_tcp_and_udp_relay() -> eyre::Result<()> {
	let socks = start_quiche_pair(8460, 1090, false).await;

	let (tcp_echo, tcp_addr) = run_tcp_echo_server("127.0.0.1:0", "Quiche TCP").await;
	tokio::time::sleep(Duration::from_millis(200)).await;
	let tcp_ok = timeout(
		Duration::from_secs(10),
		test_tcp_through_socks5(&socks, tcp_addr, b"hello over the quiche backend", "Quiche TCP"),
	)
	.await
	.expect("TCP relay timed out");
	tcp_echo.abort();
	assert!(tcp_ok, "TCP echo through the quiche backend did not round-trip");

	// --- UDP relay (native datagram mode) ---
	let (udp_echo, udp_addr, _srv) = run_udp_echo_server("127.0.0.1:0", "Quiche UDP").await;
	tokio::time::sleep(Duration::from_millis(200)).await;
	let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
	let udp_ok = timeout(
		Duration::from_secs(10),
		test_udp_through_socks5(&socks, udp_addr, b"hello udp over quiche", "Quiche UDP", bind),
	)
	.await
	.expect("UDP relay timed out");
	udp_echo.abort();
	assert!(udp_ok, "UDP echo through the quiche backend did not round-trip");

	Ok(())
}
