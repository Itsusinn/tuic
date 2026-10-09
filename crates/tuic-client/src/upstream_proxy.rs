//! A bounded, single-peer UDP bridge for QUIC over SOCKS5 UDP ASSOCIATE.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use eyre::WrapErr;
use fast_socks5::{AuthenticationMethod, Socks5Command, client::Socks5Stream, util::target_addr::TargetAddr};
use tokio::{
	io::AsyncReadExt,
	net::{TcpStream, UdpSocket},
};
use tokio_util::sync::{CancellationToken, DropGuard};
use wind_core::{AppContext, FlowContext, Outbound, tcp::AbstractTcpStream, udp::UdpStream};
use wind_tuic::quinn::outbound::{ReconnectConfig, TuicOutbound, UdpSocketFactory};

use crate::config::ProxyConfig;

// Receive whole UDP datagrams, independent of the configured allocation hint.
// Quinn's default discovery ceiling is 1452 bytes; the SOCKS header adds at
// most 22 bytes for our resolved IP target. A full-size receive buffer also
// prevents a malformed oversized reply from being silently truncated.
const UDP_BUFFER_SIZE: usize = 65536;

struct Association {
	control: TcpStream,
	udp: UdpSocket,
}

impl Association {
	async fn connect(proxy: &ProxyConfig) -> eyre::Result<Self> {
		let auth = match (&proxy.username, &proxy.password) {
			(Some(username), Some(password)) if (1..=255).contains(&username.len()) && (1..=255).contains(&password.len()) => {
				Some(AuthenticationMethod::Password {
					username: username.clone(),
					password: password.clone(),
				})
			}
			(Some(_), Some(_)) => {
				return Err(eyre::eyre!(
					"upstream SOCKS5 username and password must each contain 1 to 255 bytes"
				));
			}
			(None, None) => None,
			_ => {
				return Err(eyre::eyre!(
					"upstream SOCKS5 username and password must be configured together"
				));
			}
		};
		let control = TcpStream::connect((proxy.server.0.as_str(), proxy.server.1))
			.await
			.wrap_err("failed to connect to upstream SOCKS5 proxy")?;
		let peer = control.peer_addr()?;
		let mut socks = Socks5Stream::use_stream(control, auth, Default::default()).await
			// The library's authentication error can contain the username.
			.map_err(|_| eyre::eyre!("upstream SOCKS5 authentication failed"))?;
		let unspecified: SocketAddr = if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse()?;
		let bound = socks
			.request(Socks5Command::UDPAssociate, TargetAddr::Ip(unspecified))
			.await
			.wrap_err("upstream SOCKS5 UDP ASSOCIATE failed")?;
		let mut relay = match bound {
			TargetAddr::Ip(addr) => addr,
			TargetAddr::Domain(host, port) => tokio::net::lookup_host((host.as_str(), port))
				.await?
				.next()
				.ok_or_else(|| eyre::eyre!("upstream SOCKS5 UDP relay has no address"))?,
		};
		if relay.port() == 0 {
			return Err(eyre::eyre!("upstream SOCKS5 UDP relay port must be nonzero"));
		}
		if relay.ip().is_unspecified() {
			relay.set_ip(peer.ip());
		}
		let bind: SocketAddr = if relay.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse()?;
		let udp = UdpSocket::bind(bind).await?;
		// The kernel filters packets from any other UDP relay/source.
		udp.connect(relay).await?;
		Ok(Self {
			control: socks.get_socket(),
			udp,
		})
	}
}

async fn associate(proxy: &ProxyConfig, timeout: Duration, token: &CancellationToken) -> eyre::Result<Association> {
	tokio::select! {
		_ = token.cancelled() => Err(eyre::eyre!("upstream SOCKS5 setup cancelled")),
		result = tokio::time::timeout(timeout, Association::connect(proxy)) => {
			result.wrap_err("upstream SOCKS5 setup timed out")?
		}
	}
}

pub(crate) struct ProxyBridge {
	pub peer_addr: SocketAddr,
	pub socket_factory: UdpSocketFactory,
	pub ctx: Arc<AppContext>,
	_guard: DropGuard,
}

impl ProxyBridge {
	pub async fn new(
		ctx: &AppContext,
		proxy: ProxyConfig,
		target: SocketAddr,
		timeout: Duration,
		reconnect: ReconnectConfig,
	) -> eyre::Result<Self> {
		if timeout.is_zero() {
			return Err(eyre::eyre!(
				"relay timeout must be positive when using an upstream SOCKS5 proxy"
			));
		}
		if reconnect.enabled && (reconnect.initial_backoff.is_zero() || reconnect.max_backoff.is_zero()) {
			return Err(eyre::eyre!("upstream SOCKS5 reconnect backoff must be positive"));
		}
		let token = ctx.token.child_token();
		let guard = token.clone().drop_guard();
		let association = associate(&proxy, timeout, &token).await?;
		// Pin both sides before the first packet. A local sender cannot claim
		// the bridge, and the bridge never accepts an arbitrary destination.
		let endpoint = std::net::UdpSocket::bind("127.0.0.1:0")?;
		endpoint.set_nonblocking(true)?;
		let local = UdpSocket::bind("127.0.0.1:0").await?;
		let peer_addr = local.local_addr()?;
		local.connect(endpoint.local_addr()?).await?;
		let socket_factory: UdpSocketFactory = Arc::new(move |_| endpoint.try_clone());
		let scoped = Arc::new(AppContext {
			tasks: ctx.tasks.clone(),
			token: token.clone(),
		});
		ctx.tasks.spawn(async move {
			// A permanently failed association must also stop its QUIC session.
			let _task_guard = token.clone().drop_guard();
			let mut association = association;
			loop {
				let result = tokio::select! {
					_ = token.cancelled() => return,
					result = relay_datagrams(&local, &mut association, target, proxy.udp_buffer_size) => result,
				};
				drop(association);
				if !reconnect.enabled || token.is_cancelled() {
					return;
				}
				if let Err(error) = result {
					tracing::warn!("upstream SOCKS5 association lost: {error}");
				}
				let mut backoff = reconnect.initial_backoff.min(reconnect.max_backoff);
				loop {
					tokio::select! {
						_ = token.cancelled() => return,
						_ = tokio::time::sleep(backoff) => {},
					}
					match associate(&proxy, timeout, &token).await {
						Ok(next) => {
							association = next;
							break;
						}
						Err(_) if token.is_cancelled() => return,
						Err(error) => tracing::warn!("upstream SOCKS5 reconnect failed: {error}"),
					}
					backoff = backoff.saturating_mul(2).min(reconnect.max_backoff);
				}
			}
		});
		Ok(Self {
			peer_addr,
			socket_factory,
			ctx: scoped,
			_guard: guard,
		})
	}

	pub fn wrap(self, outbound: TuicOutbound) -> Arc<dyn Outbound> {
		Arc::new(ProxiedOutbound { outbound, _bridge: self })
	}
}

async fn relay_datagrams(
	local: &UdpSocket,
	association: &mut Association,
	target: SocketAddr,
	buffer_hint: usize,
) -> eyre::Result<()> {
	let mut outgoing = vec![0; UDP_BUFFER_SIZE];
	let mut incoming = vec![0; UDP_BUFFER_SIZE];
	let header = fast_socks5::new_udp_header(target)?;
	// Treat the historical buffer setting as a bounded allocation hint. It
	// cannot truncate a QUIC packet or request an unbounded allocation.
	let mut packet = Vec::with_capacity(buffer_hint.clamp(2048, UDP_BUFFER_SIZE));
	let mut control_byte = [0];
	loop {
		tokio::select! {
			result = association.control.read(&mut control_byte) => {
				result?;
				return Err(eyre::eyre!("upstream SOCKS5 control connection closed or sent unexpected data"));
			}
			result = local.recv(&mut outgoing) => {
				let size = result?;
				if size + header.len() > 65507 { continue; }
				packet.clear();
				packet.extend_from_slice(&header);
				packet.extend_from_slice(&outgoing[..size]);
				association.udp.send(&packet).await?;
			}
			result = association.udp.recv(&mut incoming) => {
				let size = result?;
				if let Ok((0, TargetAddr::Ip(source), payload)) = fast_socks5::parse_udp_request(&incoming[..size]).await {
					if source == target { local.send(payload).await?; }
				}
			}
		}
	}
}

struct ProxiedOutbound {
	outbound: TuicOutbound,
	_bridge: ProxyBridge,
}

#[async_trait]
impl Outbound for ProxiedOutbound {
	async fn handle_tcp(&self, ctx: FlowContext, stream: Box<dyn AbstractTcpStream + 'static>) -> eyre::Result<()> {
		self.outbound.handle_tcp(ctx, stream).await
	}

	async fn handle_udp(&self, ctx: FlowContext, stream: UdpStream) -> eyre::Result<()> {
		self.outbound.handle_udp(ctx, stream).await
	}
}

#[cfg(test)]
mod tests;
