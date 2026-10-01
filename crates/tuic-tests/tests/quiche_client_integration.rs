//! End-to-end integration test for the tuic-client quiche backend.
//!
//! Starts a quinn-backed `tuic-server` and a `tuic-client` configured with
//! `backend.mode = "quiche"`, then relays TCP and UDP through the client's
//! SOCKS5 proxy. This exercises the whole quiche client path: the
//! `TuicheOutbound` connection + auth, the shared client accept/heartbeat
//! machinery, and the TCP/UDP relay.
//!
//! Quiche e2e tests only run on 64-bit hosts (cross-emulated 32-bit socket
//! tests are unreliable) where the vendored BoringSSL toolchain is available.
#![cfg(all(
	target_pointer_width = "64",
	not(any(target_os = "android", target_os = "freebsd", target_arch = "loongarch64"))
))]

use std::{
	net::{IpAddr, Ipv4Addr, SocketAddr},
	time::Duration,
};

use tokio::time::timeout;
use tuic_tests::{
	run_tcp_echo_server, run_udp_echo_server, start_quiche_client_pair, test_tcp_through_socks5, test_udp_through_socks5,
};

#[tokio::test]
#[tracing_test::traced_test]
async fn quiche_client_tcp_and_udp_relay() -> eyre::Result<()> {
	let pair = start_quiche_client_pair(false).await;
	let socks = pair.socks5_addr();

	let (tcp_echo, tcp_addr) = run_tcp_echo_server("127.0.0.1:0", "Quiche client TCP").await;
	tokio::time::sleep(Duration::from_millis(200)).await;
	let tcp_ok = timeout(
		Duration::from_secs(10),
		test_tcp_through_socks5(&socks, tcp_addr, b"hello over the quiche client", "Quiche client TCP"),
	)
	.await
	.expect("TCP relay timed out");
	tcp_echo.abort();
	assert!(tcp_ok, "TCP echo through the quiche client did not round-trip");

	// --- UDP relay (native datagram mode) ---
	let (udp_echo, udp_addr, _srv) = run_udp_echo_server("127.0.0.1:0", "Quiche client UDP").await;
	tokio::time::sleep(Duration::from_millis(200)).await;
	let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
	let udp_ok = timeout(
		Duration::from_secs(10),
		test_udp_through_socks5(
			&socks,
			udp_addr,
			b"hello udp over the quiche client",
			"Quiche client UDP",
			bind,
		),
	)
	.await
	.expect("UDP relay timed out");
	udp_echo.abort();
	assert!(udp_ok, "UDP echo through the quiche client did not round-trip");

	pair.shutdown().await;
	Ok(())
}
