//! 0-RTT *config-path* integration test for the quinn (`wind-tuic`) backend —
//! the default backend, which until now had no 0-RTT coverage (only the quiche
//! backend did).
//!
//! Runs in its own test binary (separate process). 0-RTT early data is enabled
//! on the server via `zero_rtt_handshake`, which wires into the inbound's
//! `max_early_data_size` and the `into_0rtt()` accept path (see
//! `wind_tuic::quinn::inbound`). The test verifies that the 0-RTT-enabled
//! *configuration* path still handshakes and relays TCP and UDP correctly.
//!
//! Note: this only proves the config path works over a fresh 1-RTT connection.
//! Whether early data is actually *accepted* on a resumed handshake is covered
//! by `quinn_zero_rtt_resumption.rs`.

use std::{
	net::{IpAddr, Ipv4Addr, SocketAddr},
	time::Duration,
};

use tokio::time::timeout;
use tuic_tests::{
	run_tcp_echo_server, run_udp_echo_server, start_quinn_pair, test_tcp_through_socks5, test_udp_through_socks5,
};

#[tokio::test]
#[tracing_test::traced_test]
async fn quinn_zero_rtt_config_tcp_and_udp_relay() -> eyre::Result<()> {
	let pair = start_quinn_pair(true).await;
	let socks = pair.socks5_addr();

	// --- TCP relay ---
	let (tcp_echo, tcp_addr) = run_tcp_echo_server("127.0.0.1:0", "Quinn 0-RTT TCP").await;
	tokio::time::sleep(Duration::from_millis(200)).await;
	let tcp_ok = timeout(
		Duration::from_secs(10),
		test_tcp_through_socks5(&socks, tcp_addr, b"hello 0-rtt over quinn", "Quinn 0-RTT TCP"),
	)
	.await
	.expect("0-RTT TCP relay timed out");
	tcp_echo.abort();
	assert!(tcp_ok, "TCP echo through the 0-RTT quinn backend did not round-trip");

	// --- UDP relay (native datagram mode) ---
	let (udp_echo, udp_addr, _srv) = run_udp_echo_server("127.0.0.1:0", "Quinn 0-RTT UDP").await;
	tokio::time::sleep(Duration::from_millis(200)).await;
	let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
	let udp_ok = timeout(
		Duration::from_secs(10),
		test_udp_through_socks5(&socks, udp_addr, b"hello udp 0-rtt over quinn", "Quinn 0-RTT UDP", bind),
	)
	.await
	.expect("0-RTT UDP relay timed out");
	udp_echo.abort();
	assert!(udp_ok, "UDP echo through the 0-RTT quinn backend did not round-trip");

	pair.shutdown().await;
	Ok(())
}
