//! Assemble a generic UDP tunnel and SOCKS outbound for the TUIC transport.

use std::{
	net::{IpAddr, SocketAddr},
	sync::Arc,
	time::Duration,
};

use async_trait::async_trait;
use wind_base::tunnel::TunnelUdpInbound;
use wind_core::{
	AppContext, Dispatcher, FlowContext, Outbound, RunningInbound, tcp::AbstractTcpStream, types::TargetAddr, udp::UdpStream,
};
use wind_socks::{
	action::{SocksOutbound, SocksOutboundOpts},
	udp_outbound::SocksUdpOptions,
};
use wind_tuic::quinn::outbound::UdpSocketFactory;

use crate::{config::Relay, plugin::ClientRouter};

const TUNNEL_TAG: &str = "__GENERATED_CHAINPROXY__tuic";
const SOCKS_TAG: &str = "SOCKS_UPSTREAM";

pub(crate) struct ProxyChain {
	pub peer_addr: SocketAddr,
	pub socket_factory: UdpSocketFactory,
	pub ctx: Arc<AppContext>,
	_running: RunningInbound,
}

impl ProxyChain {
	pub fn new(parent: &AppContext, relay: &Relay) -> eyre::Result<Self> {
		let proxy = relay.proxy.as_ref().ok_or_else(|| eyre::eyre!("missing upstream proxy"))?;
		let ctx = Arc::new(AppContext {
			tasks: parent.tasks.clone(),
			token: parent.token.child_token(),
		});
		let host = proxy.server.0.trim_start_matches('[').trim_end_matches(']');
		let addr = match host.parse::<IpAddr>() {
			Ok(ip) => SocketAddr::new(ip, proxy.server.1).to_string(),
			Err(_) => format!("{host}:{}", proxy.server.1),
		};
		let outbound = SocksOutbound::new(SocksOutboundOpts {
			addr,
			username: proxy.username.clone(),
			password: proxy.password.clone(),
			allow_udp: Some(true),
			stream_timeout: Duration::ZERO,
			tcp_keepalive: None,
		})
		.with_udp_options(
			SocksUdpOptions {
				timeout: relay.timeout,
				buffer_size: proxy.udp_buffer_size,
				reconnect: relay.reconnect,
				initial_backoff: relay.reconnect_initial_backoff,
				max_backoff: relay.reconnect_max_backoff,
			},
			ctx.token.clone(),
		)?;
		let host = relay.server.0.trim_start_matches('[').trim_end_matches(']');
		let target = match relay.ip.or_else(|| host.parse().ok()) {
			Some(ip) => SocketAddr::new(ip, relay.server.1).into(),
			None => TargetAddr::Domain(host.to_owned(), relay.server.1),
		};
		let endpoint = std::net::UdpSocket::bind("127.0.0.1:0")?;
		endpoint.set_nonblocking(true)?;
		let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
		let peer_addr = socket.local_addr()?;
		socket.connect(endpoint.local_addr()?)?;
		let inbound =
			TunnelUdpInbound::from_socket(socket, target, Duration::from_secs(60), ctx.token.clone())?.with_tag(TUNNEL_TAG);
		let mut dispatcher = Dispatcher::new(ClientRouter).context(ctx.clone());
		dispatcher.add_handler(SOCKS_TAG, Arc::new(outbound));
		let dispatcher = dispatcher.with_outbound(SOCKS_TAG)?;
		let running = RunningInbound::start(ctx.clone(), inbound, dispatcher);
		Ok(Self {
			peer_addr,
			socket_factory: Arc::new(move |_| endpoint.try_clone()),
			ctx,
			_running: running,
		})
	}

	pub fn wrap(self, outbound: Arc<dyn Outbound>) -> Arc<dyn Outbound> {
		Arc::new(ChainedOutbound { outbound, _chain: self })
	}
}

struct ChainedOutbound {
	outbound: Arc<dyn Outbound>,
	_chain: ProxyChain,
}

#[async_trait]
impl Outbound for ChainedOutbound {
	async fn handle_tcp(&self, ctx: FlowContext, stream: Box<dyn AbstractTcpStream + 'static>) -> eyre::Result<()> {
		self.outbound.handle_tcp(ctx, stream).await
	}

	async fn handle_udp(&self, ctx: FlowContext, stream: UdpStream) -> eyre::Result<()> {
		self.outbound.handle_udp(ctx, stream).await
	}
}

#[cfg(test)]
mod tests;
