//! Dropping a `TestPair` without calling `shutdown` must still stop the server
//! and client tasks: a test that unwinds from a panic between `start` and
//! `shutdown` relies on the guards' `Drop` impls, which are the last-resort
//! teardown documented on `TestPair`.

use std::{
	net::{SocketAddr, UdpSocket},
	time::{Duration, Instant},
};

use tuic_tests::{Backend, TestPair};

/// How long the OS may take to release the sockets once the cancellation
/// tokens fire.
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn dropping_a_pair_without_shutdown_stops_both_processes() {
	let pair = TestPair::start(Backend::Quinn, false).await;
	let quic: SocketAddr = pair.server_addr();
	let socks5 = pair.socks5_addr();

	drop(pair);

	// Both sockets must become observably free: the client's SOCKS5 listener
	// stops accepting and the server's QUIC UDP port can be bound again.
	let deadline = Instant::now() + TEARDOWN_TIMEOUT;
	loop {
		let socks5_closed = tokio::net::TcpStream::connect(socks5.as_str()).await.is_err();
		let quic_released = UdpSocket::bind(quic).is_ok();
		if socks5_closed && quic_released {
			return;
		}
		assert!(
			Instant::now() < deadline,
			"dropping the pair left the processes running: socks5 {socks5} closed={socks5_closed}, quic {quic} \
			 released={quic_released}"
		);
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
}
