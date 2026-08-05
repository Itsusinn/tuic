//! Graceful-shutdown test for the tuic-client tunnel inbounds.
//!
//! Each tunnel inbound (TCP/UDP) runs until its `cancel` token fires, then
//! the accept/recv loop exits and spawned tasks drain.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio_util::sync::CancellationToken;
use tuic_client::tunnel::{TunnelTcpInbound, TunnelUdpInbound};
use wind_core::{AbstractInbound, Dispatcher, FlowContext, Outbound, RouteAction, Router, udp::UdpStream};

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

/// Router that forwards everything to the `"default"` outbound handler.
struct ForwardRouter;

impl Router for ForwardRouter {
	#[allow(clippy::manual_async_fn)]
	fn route(&self, _ctx: &FlowContext) -> impl std::future::Future<Output = eyre::Result<RouteAction>> + Send {
		async { Ok(RouteAction::Forward("default".to_string())) }
	}
}

/// No-op outbound handler for testing inbound lifecycle.
struct NoopOutbound;

#[async_trait::async_trait]
impl Outbound for NoopOutbound {
	async fn handle_tcp(
		&self,
		_ctx: FlowContext,
		_stream: Box<dyn wind_core::tcp::AbstractTcpStream + 'static>,
	) -> eyre::Result<()> {
		Ok(())
	}

	async fn handle_udp(&self, _ctx: FlowContext, _udp_stream: UdpStream) -> eyre::Result<()> {
		Ok(())
	}
}

fn dispatcher() -> Dispatcher<ForwardRouter> {
	let mut d = Dispatcher::new(ForwardRouter);
	d.add_handler("default", Arc::new(NoopOutbound));
	d
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_tunnel_drains_on_cancel() {
	let cancel = CancellationToken::new();
	let inbound = TunnelTcpInbound::new(free_tcp_addr(), ("127.0.0.1".to_string(), 9), cancel.clone());

	let d = dispatcher();
	let join = tokio::spawn(async move { inbound.listen(&d).await });

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

	let d = dispatcher();
	let join = tokio::spawn(async move { inbound.listen(&d).await });

	tokio::time::sleep(Duration::from_millis(100)).await;
	cancel.cancel();

	tokio::time::timeout(Duration::from_secs(5), join)
		.await
		.expect("udp tunnel did not drain within 5s of cancellation")
		.expect("listen error")
		.expect("listen returned error");
}
