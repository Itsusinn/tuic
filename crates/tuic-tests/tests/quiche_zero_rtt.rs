//! 0-RTT integration test for the tokio-quiche (`wind-tuiche`) backend.
//!
//! Runs in its own test binary (separate process) because `tuic_client::run`
//! installs a process-global connection. 0-RTT early data is enabled on both
//! the server (`enable_early_data`) and the client (`zero_rtt_handshake`); the
//! test verifies the 0-RTT-enabled config path handshakes and relays both TCP
//! and UDP correctly (mirrors `quinn_zero_rtt.rs` for backend parity).
//!
//! It does not assert that early data was actually replayed on a resumed
//! handshake — that would require a custom resumption client; the first
//! connection is always 1-RTT.

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
async fn quiche_zero_rtt_tcp_and_udp_relay() -> eyre::Result<()> {
	let socks = start_quiche_pair(8464, 1094, true).await;

	// --- TCP relay ---
	let (tcp_echo, tcp_addr) = run_tcp_echo_server("127.0.0.1:0", "Quiche 0-RTT TCP").await;
	tokio::time::sleep(Duration::from_millis(200)).await;
	let tcp_ok = timeout(
		Duration::from_secs(10),
		test_tcp_through_socks5(&socks, tcp_addr, b"hello 0-rtt over quiche", "Quiche 0-RTT TCP"),
	)
	.await
	.expect("0-RTT TCP relay timed out");
	tcp_echo.abort();
	assert!(tcp_ok, "TCP echo through the 0-RTT quiche backend did not round-trip");

	// --- UDP relay (native datagram mode) ---
	let (udp_echo, udp_addr, _srv) = run_udp_echo_server("127.0.0.1:0", "Quiche 0-RTT UDP").await;
	tokio::time::sleep(Duration::from_millis(200)).await;
	let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
	let udp_ok = timeout(
		Duration::from_secs(10),
		test_udp_through_socks5(&socks, udp_addr, b"hello udp 0-rtt over quiche", "Quiche 0-RTT UDP", bind),
	)
	.await
	.expect("0-RTT UDP relay timed out");
	udp_echo.abort();
	assert!(udp_ok, "UDP echo through the 0-RTT quiche backend did not round-trip");

	Ok(())
}
