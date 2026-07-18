//! Graceful-shutdown test for the tuic-client tunnel inbounds.
//!
//! Each tunnel inbound (TCP/UDP) runs until its `cancel` token fires, then
//! the accept/recv loop exits and spawned tasks drain.

use std::{net::SocketAddr, time::Duration};

use tokio_util::sync::CancellationToken;
use tuic_client::tunnel::{TunnelTcpInbound, TunnelUdpInbound};
use wind_core::{AbstractInbound, InboundCallback, types::TargetAddr, udp::UdpStream};

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

/// No-op callback for testing inbound lifecycle.
#[derive(Clone)]
struct NoopCallback;

impl InboundCallback for NoopCallback {
	async fn handle_tcpstream(
		&self,
		_target_addr: TargetAddr,
		_stream: impl wind_core::tcp::AbstractTcpStream + 'static,
	) -> eyre::Result<()> {
		Ok(())
	}

	async fn handle_udpstream(&self, _udp_stream: UdpStream) -> eyre::Result<()> {
		Ok(())
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_tunnel_drains_on_cancel() {
	let cancel = CancellationToken::new();
	let inbound = TunnelTcpInbound::new(
		free_tcp_addr(),
		("127.0.0.1".to_string(), 9),
		cancel.clone(),
	);

	let join = tokio::spawn(async move { inbound.listen(&NoopCallback).await });

	tokio::time::sleep(Duration::from_millis(100)).await;
	cancel.cancel();

	tokio::time::timeout(Duration::from_secs(5), join)
		.await
		.expect("tcp tunnel did not drain within 5s of cancellation")
		.expect("listen error")
		.expect("listen returned error");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_tunnel_drains_on_cancel() {
	let cancel = CancellationToken::new();
	let inbound = TunnelUdpInbound::new(
		free_udp_addr(),
		("127.0.0.1".to_string(), 9),
		Duration::from_secs(60),
		cancel.clone(),
	)
	.expect("create udp tunnel");

	let join = tokio::spawn(async move { inbound.listen(&NoopCallback).await });

	tokio::time::sleep(Duration::from_millis(100)).await;
	cancel.cancel();

	tokio::time::timeout(Duration::from_secs(5), join)
		.await
		.expect("udp tunnel did not drain within 5s of cancellation")
		.expect("listen error")
		.expect("listen returned error");
}
