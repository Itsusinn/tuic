//! Wind framework [`Plugin`] for the TUIC client.
//!
//! Creates a TUIC outbound connection, SOCKS5 inbound (via wind-socks),
//! tunnel inbounds, and wires them together through App/Plugin builder.

use std::{net::SocketAddr, sync::Arc};

use tokio::sync::watch;
use wind_base::LazyOutbound;
use wind_core::{App, AppContext, InboundHooks, Outbound, Plugin};
use wind_socks::inbound::{AuthMode, SocksInbound, SocksInboundOpt};
use wind_tuic::quinn::outbound::{ReconnectConfig, TuicOutbound, TuicOutboundOpts};

use crate::{
	config::{BackendMode, Relay},
	tunnel::{TunnelTcpInbound, TunnelUdpInbound},
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

	let sni = match relay.sni.clone() {
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
	};

	Ok((server_addr, sni))
}

/// Build the outbound selected by `backend.mode`.
async fn build_outbound(ctx: Arc<AppContext>, relay: Relay) -> eyre::Result<Arc<dyn Outbound>> {
	match relay.backend_mode {
		BackendMode::Quinn => Ok(Arc::new(build_quinn_outbound(ctx, relay).await?) as Arc<dyn Outbound>),
		BackendMode::Quiche => build_quiche_outbound(ctx, relay).await,
	}
}

/// Build a [`TuicOutbound`] (quinn backend) from the relay configuration.
async fn build_quinn_outbound(ctx: Arc<AppContext>, relay: Relay) -> eyre::Result<TuicOutbound> {
	let (server_addr, sni) = resolve_peer(&relay).await?;

	let password: Arc<[u8]> = relay.password.clone();

	let reconnect = ReconnectConfig {
		enabled: relay.reconnect,
		initial_backoff: relay.reconnect_initial_backoff,
		max_backoff: relay.reconnect_max_backoff,
	};

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
		client_config: None,
		congestion_control: relay.congestion_control,
		max_concurrent_bi_streams: None,
		max_concurrent_uni_streams: None,
		send_window: Some(relay.send_window),
		stream_receive_window: Some(u64::from(relay.receive_window)),
		max_idle_time: None,
		udp_relay_mode: relay.udp_relay_mode,
		socket_factory: None,
	};

	let outbound: TuicOutbound = TuicOutbound::new(ctx, opts).await?;

	outbound.start_poll().await?;

	Ok(outbound)
}

/// Build a `wind-tuic` quiche-backend outbound.
///
/// The quiche client only consumes the `backend.quiche` transport tuning plus
/// the shared `[tls]`/relay fields; options the file-based boring TLS path
/// cannot express (`disable_sni`, `disable_native_certs`, client certificates)
/// are ignored with a warning.
#[cfg(feature = "quiche")]
async fn build_quiche_outbound(ctx: Arc<AppContext>, relay: Relay) -> eyre::Result<Arc<dyn Outbound>> {
	use wind_tuic::quiche::{
		CongestionControl as QuicheCongestionControl, ConnectionOpts, ReconnectConfig as QuicheReconnect, TuicheOutbound,
		TuicheOutboundOpts, UdpRelayMode as QuicheUdpRelayMode,
	};

	use crate::utils::{CongestionControl, UdpRelayMode};

	let (peer_addr, sni) = resolve_peer(&relay).await?;

	if relay.disable_sni || relay.disable_native_certs || !relay.certificates.is_empty() {
		tracing::warn!(
			"the quiche backend ignores `disable_sni`, `disable_native_certs`, and client certificates; these are only \
			 honored by the quinn backend"
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

	let outbound = TuicheOutbound::new(ctx, opts).await?;
	outbound.start_poll().await?;

	Ok(Arc::new(outbound) as Arc<dyn Outbound>)
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
		let relay = self.cfg.relay;
		let lazy = relay.lazy;

		let handler: Arc<dyn Outbound> = if lazy {
			// Lazy mode: defer QUIC connection until first traffic.
			let setup_ctx = ctx.clone();
			Arc::new(LazyOutbound::new(Box::pin(
				async move { build_outbound(setup_ctx, relay).await },
			)))
		} else {
			// Eager mode: establish the QUIC connection immediately.
			build_outbound(ctx.clone(), relay)
				.await
				.expect("TUIC outbound setup failed in eager mode")
		};

		let app = app.add_outbound("default", handler);
		let app = app.set_router(ClientRouter);

		// SOCKS5 inbound
		let local = self.cfg.local;
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
		for entry in local.tcp_forward {
			let listen = entry.listen;
			let remote = entry.remote;
			app = app.add_inbound_with(move |_: InboundHooks, ctx: Arc<AppContext>| {
				TunnelTcpInbound::new(listen, remote, ctx.token.clone())
			});
		}

		// UDP tunnel inbounds
		for entry in local.udp_forward {
			let listen = entry.listen;
			let remote = entry.remote;
			let timeout = entry.timeout;
			app = app.add_inbound_with(move |_: InboundHooks, ctx: Arc<AppContext>| {
				TunnelUdpInbound::new(listen, remote, timeout, ctx.token.clone()).expect("bind tunnel UDP socket")
			});
		}

		Ok(app)
	}
}
