//! Wind framework [`Plugin`] for the TUIC client.
//!
//! Creates a TUIC outbound connection, SOCKS5 inbound (via wind-socks),
//! tunnel inbounds, and wires them together through App/Plugin builder.

use std::sync::Arc;

use wind_base::LazyOutbound;
use wind_core::{App, AppContext, InboundHooks, Plugin, dispatcher::OutboundAsAction};
use wind_socks::inbound::{AuthMode, SocksInbound, SocksInboundOpt};

use crate::{
	tunnel::{TunnelTcpInbound, TunnelUdpInbound},
	wind_adapter::TuicOutboundAdapter,
};

/// Simple router: everything goes to the TUIC outbound.
struct ClientRouter;

impl wind_core::Router for ClientRouter {
	async fn route(&self, _ctx: &wind_core::FlowContext) -> eyre::Result<wind_core::RouteAction> {
		Ok(wind_core::RouteAction::Forward("default".to_string()))
	}
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

		let handler: Arc<dyn wind_core::OutboundAction> = if lazy {
			// Lazy mode: defer QUIC connection until first traffic.
			let setup_ctx = ctx.clone();
			Arc::new(LazyOutbound::new(Box::pin(async move {
				let adapter = TuicOutboundAdapter::new(setup_ctx, relay).await?;
				Ok(Arc::new(OutboundAsAction { inner: adapter }) as Arc<dyn wind_core::OutboundAction>)
			})))
		} else {
			// Eager mode: establish the QUIC connection immediately.
			let adapter = TuicOutboundAdapter::new(ctx.clone(), relay)
				.await
				.expect("TUIC outbound setup failed in eager mode");
			Arc::new(OutboundAsAction { inner: adapter })
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
