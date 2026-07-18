//! Graceful-shutdown test for the tuic-client TCP/UDP forwarders.
//!
//! Each forwarder runs until its `cancel` token fires, then the accept/recv
//! loop exits and the spawned tasks drain.

use std::{net::SocketAddr, time::Duration};

use tuic_client::{config::{TcpForward, UdpForward}, forward, shared::SharedOutbound};

fn free_tcp_addr() -> SocketAddr {
	let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	let a = l.local_addr().unwrap();
	drop(l);
	a
}

fn free_udp_addr() -> SocketAddr {
	let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
	let a = s.local_addr().unwrap();
	drop(s);
	a
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarders_drain_on_cancel() {
	let cancel = tokio_util::sync::CancellationToken::new();
	let outbound = SharedOutbound::new();

	let tcp = vec![TcpForward {
		listen: free_tcp_addr(),
		remote: ("127.0.0.1".to_string(), 9),
	}];
	let udp = vec![UdpForward {
		listen: free_udp_addr(),
		remote: ("127.0.0.1".to_string(), 9),
		timeout: Duration::from_secs(60),
	}];

	let join = tokio::spawn(forward::start_shared(tcp, udp, outbound, cancel.clone()));

	tokio::time::sleep(Duration::from_millis(200)).await;

	cancel.cancel();

	tokio::time::timeout(Duration::from_secs(5), join)
		.await
		.expect("forwarder tasks did not drain within 5s of cancellation")
		.expect("join error");
}
