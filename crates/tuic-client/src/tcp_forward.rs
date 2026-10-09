//! Client-owned TCP forward listeners, bound before the runtime starts.
//!
//! Wind's public tunnel inbound binds in `listen`, where `App` can only log
//! failures. This private adapter keeps startup ownership of the bound socket
//! so a failed forwarder aborts the build without a bind/unbind race.

use std::net::{SocketAddr, TcpListener as StdTcpListener};

use async_trait::async_trait;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpListener;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{Instrument, info, warn};
use wind_core::{
	AbstractInbound, Dispatcher, FlowContext, InboundCallback, Protocol as WindProtocol, Router, rule::NetworkType,
	types::TargetAddr,
};

pub(crate) struct BoundTcpForwardInbound {
	listener: TcpListener,
	remote: (String, u16),
	cancel: CancellationToken,
}

impl BoundTcpForwardInbound {
	pub(crate) fn bind(listen: SocketAddr, remote: (String, u16), cancel: CancellationToken) -> std::io::Result<Self> {
		// Keep Wind's tunnel socket options and accept backlog.
		let socket = Socket::new(Domain::for_address(listen), Type::STREAM, Some(Protocol::TCP))?;
		socket.set_reuse_address(true)?;
		socket.set_nonblocking(true)?;
		socket.bind(&SockAddr::from(listen))?;
		socket.listen(i32::MAX)?;
		let listener = TcpListener::from_std(StdTcpListener::from(socket))?;
		Ok(Self {
			listener,
			remote,
			cancel,
		})
	}
}

#[async_trait]
impl<R: Router> AbstractInbound<R> for BoundTcpForwardInbound {
	async fn listen(&self, cb: &Dispatcher<R>) -> eyre::Result<()> {
		let listen = self.listener.local_addr()?;
		info!("[tunnel-tcp] listening on {listen} -> {remote:?}", remote = self.remote);
		let conn_tasks = TaskTracker::new();
		loop {
			tokio::select! {
				_ = self.cancel.cancelled() => {
					info!("[tunnel-tcp] cancellation received, shutting down");
					break;
				}
				res = self.listener.accept() => match res {
					Ok((stream, peer)) => {
						let cb = cb.clone();
						let ctx = FlowContext {
							target: TargetAddr::Domain(self.remote.0.clone(), self.remote.1),
							network: NetworkType::Tcp,
							source: Some(peer),
							inbound_tag: "tunnel".into(),
							protocol: WindProtocol::Tunnel,
							user: None,
							inbound_port: Some(listen.port()),
							inbound_type: None,
						};
						let conn_cancel = self.cancel.child_token();
						conn_tasks.spawn(
							async move {
								tokio::select! {
									_ = conn_cancel.cancelled() => {}
									res = cb.handle_tcpstream(ctx, stream) => {
										if let Err(e) = res {
											warn!("[tunnel-tcp] [{peer}] error: {e}");
										}
									}
								}
							}
							.in_current_span(),
						);
					}
					Err(err) => warn!("[tunnel-tcp] accept error: {err}"),
				}
			}
		}
		conn_tasks.close();
		conn_tasks.wait().await;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use std::{
		sync::{
			Arc,
			atomic::{AtomicUsize, Ordering},
		},
		time::Duration,
	};

	use tokio::{
		io::{AsyncReadExt, AsyncWriteExt},
		net::TcpStream,
		sync::mpsc,
	};
	use tokio_util::task::AbortOnDropHandle;
	use wind_core::{Outbound, RouteAction, tcp::AbstractTcpStream, udp::UdpStream};

	use super::*;

	struct InspectRouter(mpsc::UnboundedSender<FlowContext>);

	impl Router for InspectRouter {
		async fn route(&self, ctx: &FlowContext) -> eyre::Result<RouteAction> {
			self.0.send(ctx.clone())?;
			Ok(RouteAction::Forward("default".into()))
		}
	}

	struct ActiveRelay(Arc<AtomicUsize>);

	impl Drop for ActiveRelay {
		fn drop(&mut self) {
			self.0.fetch_sub(1, Ordering::SeqCst);
		}
	}

	struct LoopbackOutbound(Arc<AtomicUsize>);

	#[async_trait]
	impl Outbound for LoopbackOutbound {
		async fn handle_tcp(&self, ctx: FlowContext, mut stream: Box<dyn AbstractTcpStream + 'static>) -> eyre::Result<()> {
			self.0.fetch_add(1, Ordering::SeqCst);
			let _active = ActiveRelay(self.0.clone());
			let TargetAddr::Domain(host, port) = ctx.target else {
				return Err(eyre::eyre!("forward target must remain a domain target"));
			};
			let mut remote = TcpStream::connect((host.as_str(), port)).await?;
			tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
			Ok(())
		}

		async fn handle_udp(&self, _ctx: FlowContext, _stream: UdpStream) -> eyre::Result<()> {
			Err(eyre::eyre!("unexpected UDP dispatch"))
		}
	}

	#[tokio::test]
	async fn prebound_forward_relays_bytes_preserves_context_and_drains_active_connections() -> eyre::Result<()> {
		tokio::time::timeout(Duration::from_secs(5), async {
			let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
			let remote = echo_listener.local_addr()?;
			let echo = AbortOnDropHandle::new(tokio::spawn(async move {
				let (mut stream, _) = echo_listener.accept().await?;
				let mut buffer = [0u8; 64];
				loop {
					let count = stream.read(&mut buffer).await?;
					if count == 0 {
						break;
					}
					stream.write_all(&buffer[..count]).await?;
				}
				Ok::<_, std::io::Error>(())
			}));
			let cancel = CancellationToken::new();
			let _cancel_on_drop = cancel.clone().drop_guard();
			let inbound = BoundTcpForwardInbound::bind(
				SocketAddr::from(([127, 0, 0, 1], 0)),
				(remote.ip().to_string(), remote.port()),
				cancel.clone(),
			)?;
			let listen = inbound.listener.local_addr()?;
			assert!(std::net::TcpListener::bind(listen).is_err());
			let (context_tx, mut context_rx) = mpsc::unbounded_channel();
			let active = Arc::new(AtomicUsize::new(0));
			let mut dispatcher = Dispatcher::new(InspectRouter(context_tx));
			dispatcher.add_handler("default", Arc::new(LoopbackOutbound(active.clone())));
			let inbound_task = AbortOnDropHandle::new(tokio::spawn(async move { inbound.listen(&dispatcher).await }));
			let mut client = TcpStream::connect(listen).await?;
			let peer = client.local_addr()?;
			client.write_all(b"forwarded").await?;
			let mut response = [0u8; 9];
			client.read_exact(&mut response).await?;
			assert_eq!(&response, b"forwarded");
			let ctx = context_rx.recv().await.ok_or_else(|| eyre::eyre!("no routing context"))?;
			assert!(matches!(ctx.target, TargetAddr::Domain(ref host, port) if host == "127.0.0.1" && port == remote.port()));
			assert_eq!(ctx.source, Some(peer));
			assert_eq!(ctx.network, NetworkType::Tcp);
			assert_eq!(ctx.protocol, WindProtocol::Tunnel);
			assert_eq!(&*ctx.inbound_tag, "tunnel");
			assert_eq!(ctx.inbound_port, Some(listen.port()));
			assert!(ctx.user.is_none());
			assert!(ctx.inbound_type.is_none());
			assert_eq!(active.load(Ordering::SeqCst), 1);
			cancel.cancel();
			inbound_task.await??;
			assert_eq!(active.load(Ordering::SeqCst), 0, "listen must drain active dispatch tasks");
			assert_eq!(client.read(&mut response).await?, 0);
			echo.await??;
			let _rebound = std::net::TcpListener::bind(listen)?;
			Ok::<_, eyre::Report>(())
		})
		.await?
	}
}
