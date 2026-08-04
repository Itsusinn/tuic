//! Wind framework [`Plugin`] for the TUIC client.
//!
//! Creates a TUIC outbound connection, SOCKS5 inbound (via wind-socks),
//! tunnel inbounds, and wires them together through App/Plugin builder.

use std::{net::SocketAddr, sync::Arc};

use wind_base::LazyOutbound;
use wind_core::{App, AppContext, InboundHooks, Outbound, Plugin};
use wind_socks::inbound::{AuthMode, SocksInbound, SocksInboundOpt};
use wind_tuic::quinn::outbound::{ReconnectConfig, TuicOutbound, TuicOutboundOpts};

use crate::{
	config::Relay,
	tunnel::{TunnelTcpInbound, TunnelUdpInbound},
};

/// Simple router: everything goes to the TUIC outbound.
struct ClientRouter;

impl wind_core::Router for ClientRouter {
	async fn route(&self, _ctx: &wind_core::FlowContext) -> eyre::Result<wind_core::RouteAction> {
		Ok(wind_core::RouteAction::Forward("default".to_string()))
	}
}

/// Build a [`TuicOutbound`] from the relay configuration.
///
/// Resolves the server address (IP literal or DNS), derives the SNI, and
/// translates the relay config into [`TuicOutboundOpts`].
async fn build_tuic_outbound(ctx: Arc<AppContext>, relay: Relay) -> eyre::Result<TuicOutbound> {
	let server_addr = if let Some(ip) = relay.ip {
		SocketAddr::new(ip, relay.server.1)
	} else {
		let addrs = tokio::net::lookup_host(format!("{}:{}", relay.server.0, relay.server.1)).await?;
		addrs
			.into_iter()
			.next()
			.ok_or_else(|| eyre::eyre!("Failed to resolve server address"))?
	};

	let password: Arc<[u8]> = relay.password.clone();

	let sni = match relay.sni.clone() {
		Some(s) => s,
		None => {
			let host = relay.server.0.trim_start_matches('[').trim_end_matches(']');
			if host.parse::<std::net::IpAddr>().is_ok() {
				tracing::warn!(
					"relay server `{}` is an IP literal but no `sni` was configured; TLS verification will likely fail. \
					 Set `sni = \"<hostname>\"` in the relay config to fix.",
					relay.server.0,
				);
				"invalid.sni.placeholder".to_string()
			} else {
				relay.server.0.clone()
			}
		}
	};

	let reconnect = ReconnectConfig {
		enabled: relay.reconnect,
		initial_backoff: relay.reconnect_initial_backoff,
		max_backoff: relay.reconnect_max_backoff,
	};

	let opts = TuicOutboundOpts {
		peer_addr: server_addr,
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
	};

	let outbound: TuicOutbound = TuicOutbound::new(ctx, opts).await?;

	outbound.start_poll().await?;

	Ok(outbound)
}

/// Wind framework plugin that wires a TUIC client's full runtime.
pub struct TuicClientPlugin {
	cfg: crate::Config,
}

impl TuicClientPlugin {
	pub fn new(cfg: crate::Config) -> Self {
		Self { cfg }
	}
}

impl Plugin for TuicClientPlugin {
	async fn build(self, app: App) -> eyre::Result<App> {
		let ctx = app.context().clone();
		let relay = self.cfg.relay;
		let lazy = relay.lazy;

		let handler: Arc<dyn Outbound> = if lazy {
			// Lazy mode: defer QUIC connection until first traffic.
			let setup_ctx = ctx.clone();
			Arc::new(LazyOutbound::new(Box::pin(async move {
				let outbound = build_tuic_outbound(setup_ctx, relay).await?;
				Ok(Arc::new(outbound) as Arc<dyn Outbound>)
			})))
		} else {
			// Eager mode: establish the QUIC connection immediately.
			let outbound = build_tuic_outbound(ctx.clone(), relay)
				.await
				.expect("TUIC outbound setup failed in eager mode");
			Arc::new(outbound)
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

		let app = app.add_inbound_with(move |hooks: InboundHooks, ctx: Arc<AppContext>| {
			let opts = SocksInboundOpt {
				listen_addr,
				public_addr: None,
				auth,
				skip_auth: false,
				allow_udp: true,
				inbound_tag: "socks-local".into(),
				hooks,
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
