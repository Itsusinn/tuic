//! Wind framework [`Plugin`] for the TUIC client.
//!
//! Creates a TUIC outbound connection, SOCKS5 inbound (via wind-socks),
//! tunnel inbounds, and wires them together through App/Plugin builder.

use std::{net::SocketAddr, sync::Arc};

use eyre::WrapErr;
use tokio::sync::watch;
use wind_base::LazyOutbound;
use wind_core::{App, AppContext, InboundHooks, Outbound, Plugin};
use wind_socks::inbound::{AuthMode, SocksInbound, SocksInboundOpt};
use wind_tuic::quinn::outbound::{ReconnectConfig, TuicOutbound, TuicOutboundOpts};

use crate::{
	config::{BackendMode, Relay},
	tcp_forward::BoundTcpForwardInbound,
	tls::{TlsConfigError, build_client_config},
	tunnel::TunnelUdpInbound,
	upstream_proxy::ProxyChain,
};

/// Simple router: everything goes to the TUIC outbound.
pub struct ClientRouter;

impl wind_core::Router for ClientRouter {
	#[allow(clippy::manual_async_fn)]
	fn route(
		&self,
		_ctx: &wind_core::FlowContext,
	) -> impl std::future::Future<Output = eyre::Result<wind_core::RouteAction>> + Send {
		async { Ok(wind_core::RouteAction::Forward("default".to_string())) }
	}
}

/// Resolve the server's socket address and derive the TLS SNI.
///
/// Shared by both backends: an explicit `ip` short-circuits DNS, and an
/// IP-literal server without a configured `sni` falls back to a placeholder
/// (with a warning) so certificate verification fails loudly rather than
/// silently accepting the wrong name.
async fn resolve_peer(relay: &Relay) -> eyre::Result<(SocketAddr, String)> {
	let server_addr = if let Some(ip) = relay.ip {
		SocketAddr::new(ip, relay.server.1)
	} else {
		let addrs = tokio::net::lookup_host(format!("{}:{}", relay.server.0, relay.server.1)).await?;
		addrs
			.into_iter()
			.next()
			.ok_or_else(|| eyre::eyre!("Failed to resolve server address"))?
	};

	Ok((server_addr, server_name(relay)))
}

fn server_name(relay: &Relay) -> String {
	match relay.sni.clone() {
		Some(s) => s,
		None => {
			let host = relay.server.0.trim_start_matches('[').trim_end_matches(']');
			if host.parse::<std::net::IpAddr>().is_ok() {
				tracing::warn!(
					"relay server `{}` is an IP literal but no `sni` was configured; TLS verification will likely fail. Set \
					 `sni = \"<hostname>\"` in the relay config to fix.",
					relay.server.0,
				);
				"invalid.sni.placeholder".to_string()
			} else {
				relay.server.0.clone()
			}
		}
	}
}

/// Build the outbound selected by `backend.mode`.
async fn build_outbound(ctx: Arc<AppContext>, relay: Relay) -> eyre::Result<Arc<dyn Outbound>> {
	match relay.backend_mode {
		BackendMode::Quinn => build_quinn_outbound(ctx, relay).await,
		BackendMode::Quiche => build_quiche_outbound(ctx, relay).await,
	}
}

/// Install the process-wide rustls crypto provider exactly once. Mirrors
/// `wind-tuic`'s own installation so library users (integration tests, other
/// binaries) get a working provider even when `main` never ran.
fn install_crypto_provider() {
	static PROVIDER_INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
	PROVIDER_INSTALLED.get_or_init(|| {
		#[cfg(feature = "aws-lc-rs")]
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		#[cfg(feature = "ring")]
		let _ = rustls::crypto::ring::default_provider().install_default();
	});
}

/// Build a [`TuicOutbound`] (quinn backend) from the relay configuration.
///
/// Public so integration tests can exercise the real configuration path
/// (including `crate::tls` and the rustls client configuration it builds)
/// without duplicating it.
pub async fn build_quinn_outbound(ctx: Arc<AppContext>, relay: Relay) -> eyre::Result<Arc<dyn Outbound>> {
	install_crypto_provider();
	let proxy_chain = relay.proxy.as_ref().map(|_| ProxyChain::new(&ctx, &relay)).transpose()?;
	let (server_addr, sni) = match &proxy_chain {
		Some(chain) => (chain.peer_addr, server_name(&relay)),
		None => resolve_peer(&relay).await?,
	};

	let password: Arc<[u8]> = relay.password.clone();

	let reconnect = ReconnectConfig {
		enabled: relay.reconnect,
		initial_backoff: relay.reconnect_initial_backoff,
		max_backoff: relay.reconnect_max_backoff,
	};

	// The whole rustls configuration is built here, because `[tls]
	// disable_sni`, `disable_native_certs`, and `certificates` have no
	// counterpart in wind's built-in configuration. `TuicOutboundOpts` uses a
	// supplied `client_config` verbatim, so the ALPN list, the 0-RTT flag, and
	// the skip-verify branch are reproduced by `crate::tls` (see its module
	// docs and tests).
	let client_config = build_client_config(&relay).map_err(|source| match source {
		err @ (TlsConfigError::CertificateIo { .. }
		| TlsConfigError::NoCertificate { .. }
		| TlsConfigError::NoUsableCertificate { .. }) => {
			eyre::Report::new(err).wrap_err("invalid `[tls] certificates` configuration")
		}
		err => eyre::Report::new(err),
	})?;

	let opts = TuicOutboundOpts {
		peer_addr: server_addr,
		peer_resolver: None,
		sni,
		auth: (relay.uuid, password),
		zero_rtt_handshake: relay.zero_rtt_handshake,
		heartbeat: relay.heartbeat,
		gc_interval: relay.gc_interval,
		gc_lifetime: relay.gc_lifetime,
		skip_cert_verify: relay.skip_cert_verify,
		alpn: relay
			.alpn
			.into_iter()
			.map(|v| String::from_utf8_lossy(&v).to_string())
			.collect(),
		reconnect,
		client_config: Some(Arc::new(client_config)),
		congestion_control: relay.congestion_control,
		max_concurrent_bi_streams: None,
		max_concurrent_uni_streams: None,
		send_window: Some(relay.send_window),
		stream_receive_window: Some(u64::from(relay.receive_window)),
		max_idle_time: None,
		udp_relay_mode: relay.udp_relay_mode,
		socket_factory: proxy_chain.as_ref().map(|chain| chain.socket_factory.clone()),
	};

	let outbound = match &proxy_chain {
		Some(chain) => tokio::select! {
			_ = chain.ctx.token.cancelled() => return Err(eyre::eyre!("proxied TUIC setup cancelled")),
			result = tokio::time::timeout(relay.timeout, TuicOutbound::new(chain.ctx.clone(), opts)) => {
				result.wrap_err("proxied TUIC handshake timed out")??
			}
		},
		None => TuicOutbound::new(ctx, opts).await?,
	};

	outbound.start_poll().await?;

	Ok(match proxy_chain {
		Some(chain) => chain.wrap(Arc::new(outbound)),
		None => Arc::new(outbound) as Arc<dyn Outbound>,
	})
}

/// Build a `wind-tuic` quiche-backend outbound.
///
/// The quiche client consumes the `backend.quiche` transport tuning plus the
/// shared `[tls]`/relay fields. `[tls] disable_sni`, `[tls]
/// disable_native_certs`, and the `[tls] certificates` list have no counterpart
/// in the quiche TLS settings, so they are named in a warning instead of being
/// ignored silently (they do work on the quinn backend).
#[cfg(feature = "quiche")]
async fn build_quiche_outbound(ctx: Arc<AppContext>, relay: Relay) -> eyre::Result<Arc<dyn Outbound>> {
	use wind_tuic::quiche::{
		CongestionControl as QuicheCongestionControl, ConnectionOpts, ReconnectConfig as QuicheReconnect, TuicheOutbound,
		TuicheOutboundOpts, UdpRelayMode as QuicheUdpRelayMode,
	};

	use crate::utils::{CongestionControl, UdpRelayMode};

	let proxy_chain = relay.proxy.as_ref().map(|_| ProxyChain::new(&ctx, &relay)).transpose()?;
	let (peer_addr, sni) = match &proxy_chain {
		Some(chain) => (chain.peer_addr, server_name(&relay)),
		None => resolve_peer(&relay).await?,
	};

	if relay.disable_sni || relay.disable_native_certs || !relay.certificates.is_empty() {
		tracing::warn!(
			"the quiche backend cannot honour `[tls] disable_sni`, `[tls] disable_native_certs`, or `[tls] certificates`; \
			 they only take effect on the quinn backend (the default)"
		);
	}

	let congestion_control = match relay.quiche.congestion_control.controller {
		CongestionControl::Cubic => QuicheCongestionControl::Cubic,
		CongestionControl::Bbr | CongestionControl::Bbr3 => QuicheCongestionControl::Bbr,
		CongestionControl::NewReno => QuicheCongestionControl::Reno,
	};

	let connection = ConnectionOpts {
		max_idle_timeout: relay.quiche.max_idle_time,
		max_concurrent_bi_streams: relay.quiche.max_concurrent_bi_streams,
		max_concurrent_uni_streams: relay.quiche.max_concurrent_uni_streams,
		send_window: relay.quiche.send_window,
		receive_window: relay.quiche.receive_window,
		congestion_control,
		udp_relay_mode: match relay.udp_relay_mode {
			UdpRelayMode::Native => QuicheUdpRelayMode::Datagram,
			UdpRelayMode::Quic => QuicheUdpRelayMode::Stream,
		},
		enable_0rtt: relay.zero_rtt_handshake || relay.quiche.zero_rtt,
		..Default::default()
	};

	let opts = TuicheOutboundOpts {
		peer_addr,
		sni,
		auth: (relay.uuid, relay.password.clone()),
		verify_certificate: !relay.skip_cert_verify,
		alpn: relay.alpn.clone(),
		heartbeat: relay.heartbeat,
		gc_interval: relay.gc_interval,
		gc_lifetime: relay.gc_lifetime,
		reconnect: QuicheReconnect {
			enabled: relay.reconnect,
			initial_backoff: relay.reconnect_initial_backoff,
			max_backoff: relay.reconnect_max_backoff,
		},
		connection,
	};

	let outbound = match &proxy_chain {
		Some(chain) => tokio::select! {
			_ = chain.ctx.token.cancelled() => return Err(eyre::eyre!("proxied TUIC setup cancelled")),
			result = tokio::time::timeout(relay.timeout, TuicheOutbound::new_with_socket_factory(chain.ctx.clone(), opts, Some(chain.socket_factory.clone()))) => {
				result.wrap_err("proxied TUIC handshake timed out")??
			},
		},
		None => TuicheOutbound::new(ctx, opts).await?,
	};
	outbound.start_poll().await?;

	Ok(match proxy_chain {
		Some(chain) => chain.wrap(Arc::new(outbound)),
		None => Arc::new(outbound) as Arc<dyn Outbound>,
	})
}

/// Mirror of `build_quiche_outbound` for builds without the `quiche` feature:
/// selecting the backend in config is always valid, but starting requires it.
#[cfg(not(feature = "quiche"))]
async fn build_quiche_outbound(_ctx: Arc<AppContext>, _relay: Relay) -> eyre::Result<Arc<dyn Outbound>> {
	Err(eyre::eyre!("backend.mode = \"quiche\" requires the `quiche` feature"))
}

/// Wind framework plugin that wires a TUIC client's full runtime.
pub struct TuicClientPlugin {
	cfg: crate::Config,
	bound_addr: Option<watch::Sender<Option<SocketAddr>>>,
}

impl TuicClientPlugin {
	pub fn new(cfg: crate::Config) -> Self {
		Self { cfg, bound_addr: None }
	}

	/// Report the actually-bound SOCKS5 address (OS-assigned when
	/// `local.server` binds to port 0) through this watch channel.
	pub fn with_bound_addr(mut self, tx: watch::Sender<Option<SocketAddr>>) -> Self {
		self.bound_addr = Some(tx);
		self
	}
}

impl Plugin<ClientRouter> for TuicClientPlugin {
	async fn build(self, app: App<ClientRouter>) -> eyre::Result<App<ClientRouter>> {
		let ctx = app.context().clone();
		let local = self.cfg.local;
		// Bind every forwarder before eager relay setup can start background
		// tasks. These owned inbounds release their sockets if any later bind
		// or relay setup fails, and reserve the ports continuously on success.
		let mut tcp_inbounds = Vec::new();
		for entry in local.tcp_forward {
			let listen = entry.listen;
			let inbound = BoundTcpForwardInbound::bind(listen, entry.remote, ctx.token.clone())
				.wrap_err_with(|| format!("failed to bind the TCP forward listener {listen}"))?;
			tcp_inbounds.push(inbound);
		}
		let mut udp_inbounds = Vec::new();
		for entry in local.udp_forward {
			let listen = entry.listen;
			let inbound = TunnelUdpInbound::new(listen, entry.remote, entry.timeout, ctx.token.clone())
				.wrap_err_with(|| format!("failed to bind the UDP forward listener {listen}"))?;
			udp_inbounds.push(inbound);
		}
		let relay = self.cfg.relay;
		let lazy = relay.lazy;
		// Kept for the error context below: `relay` is moved into the factory.
		let relay_server = format!("{}:{}", relay.server.0, relay.server.1);

		let handler: Arc<dyn Outbound> = if lazy {
			// Lazy mode: defer QUIC connection until first traffic.
			let setup_ctx = ctx.clone();
			Arc::new(LazyOutbound::new(Box::pin(
				async move { build_outbound(setup_ctx, relay).await },
			)))
		} else {
			// Eager mode: establish the QUIC connection immediately, and report
			// a failure as a startup error. `build` already returns a `Result`,
			// so panicking here would abort this task instead of failing the
			// caller with the reason the relay could not be reached.
			build_outbound(ctx.clone(), relay).await.wrap_err_with(|| {
				format!(
					"TUIC outbound setup failed in eager mode (`relay.lazy = false`, server {})",
					relay_server
				)
			})?
		};

		let app = app.add_outbound("default", handler);
		let app = app.set_router(ClientRouter);

		// SOCKS5 inbound
		let auth = match (&local.username, &local.password) {
			(Some(u), Some(p)) => AuthMode::Password {
				username: String::from_utf8_lossy(u).into_owned(),
				password: String::from_utf8_lossy(p).into_owned(),
			},
			_ => AuthMode::NoAuth,
		};
		let listen_addr = local.server;
		let bound_addr = self.bound_addr;

		let app = app.add_inbound_with(move |hooks: InboundHooks, ctx: Arc<AppContext>| {
			let opts = SocksInboundOpt {
				listen_addr,
				public_addr: None,
				auth,
				skip_auth: false,
				allow_udp: true,
				inbound_tag: "socks-local".into(),
				hooks,
				bound_addr,
			};
			SocksInbound::new(opts, ctx.token.clone())
		});

		// TCP tunnel inbounds
		let mut app = app;
		for inbound in tcp_inbounds {
			app = app.add_inbound_with(move |_: InboundHooks, _: Arc<AppContext>| inbound);
		}

		// UDP tunnel inbounds
		for inbound in udp_inbounds {
			app = app.add_inbound_with(move |_: InboundHooks, _: Arc<AppContext>| inbound);
		}

		Ok(app)
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use super::*;
	use crate::config::UdpForward;

	/// Occupy a loopback UDP port and keep the socket open, so the address
	/// stays taken for the duration of the test.
	fn occupied_udp_addr() -> (std::net::UdpSocket, SocketAddr) {
		let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback UDP socket");
		let addr = socket.local_addr().expect("read the bound address");
		(socket, addr)
	}

	/// A config that needs no relay: the QUIC connection stays lazy, so only
	/// the local inbounds are exercised.
	fn config_with_udp_forward(listen: SocketAddr) -> crate::Config {
		let mut cfg = crate::Config::default();
		cfg.local.server = "127.0.0.1:0".parse().expect("parse the SOCKS5 listen address");
		cfg.local.udp_forward.push(UdpForward {
			listen,
			remote: ("127.0.0.1".to_string(), 9),
			timeout: Duration::from_secs(60),
		});
		cfg
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn udp_forward_port_conflict_fails_the_plugin_build() {
		let (_occupied, listen) = occupied_udp_addr();

		let result = App::new()
			.add_plugin(TuicClientPlugin::new(config_with_udp_forward(listen)))
			.await;

		let err = result
			.err()
			.expect("building the plugin must fail when the UDP forward port is taken");
		let message = err.to_string();
		assert!(
			message.contains("UDP forward listener"),
			"the failure must name the UDP forward listener, got: {message}"
		);
		assert!(
			message.contains(&listen.to_string()),
			"the failure must name the conflicting address {listen}, got: {message}"
		);
	}

	/// A config in eager mode (`relay.lazy = false`) whose relay setup cannot
	/// succeed, so the outbound build has to fail.
	fn eager_config_that_cannot_be_set_up() -> crate::Config {
		let mut cfg = crate::Config::default();
		cfg.relay.lazy = false;
		cfg.relay.server = ("127.0.0.1".to_string(), 4433);
		// A `[tls] certificates` entry that does not exist: the failure happens
		// while the QUIC endpoint is being prepared, i.e. inside the eager
		// outbound build, and it is immediate rather than dependent on network
		// timing. The relay address above is only named in the error context —
		// it is never dialed, because the certificate is read first.
		cfg.relay.certificates = vec![std::path::PathBuf::from("no-such-ca-certificate.pem")];
		cfg.local.server = "127.0.0.1:0".parse().expect("parse the SOCKS5 listen address");
		cfg
	}

	/// Eager mode must surface a failed outbound build as a startup error
	/// carrying the reason. It used to `expect(...)` inside the plugin build,
	/// which unwound the build instead of telling the caller why the relay
	/// could not be set up.
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn eager_relay_setup_failure_is_reported_as_a_startup_error() {
		let result = tokio::time::timeout(
			Duration::from_secs(30),
			App::new().add_plugin(TuicClientPlugin::new(eager_config_that_cannot_be_set_up())),
		)
		.await
		.expect("building the plugin must not hang while the eager relay setup fails");

		let err = result
			.err()
			.expect("building the plugin must fail when the eager relay connection cannot be established");
		// `Report`'s `Display` only renders the outermost context, so the
		// assertions below walk the whole chain: the context must be added
		// *without* swallowing the underlying reason.
		let message = std::iter::once(err.to_string())
			.chain(err.chain().skip(1).map(ToString::to_string))
			.collect::<Vec<_>>()
			.join(": ");
		assert!(
			message.contains("eager mode"),
			"the failure must say that the eager connection could not be set up, got: {message}"
		);
		assert!(
			message.contains("127.0.0.1:4433"),
			"the failure must name the relay address, got: {message}"
		);
		assert!(
			message.contains("no-such-ca-certificate.pem"),
			"the failure must keep the underlying reason, got: {message}"
		);
	}
}
