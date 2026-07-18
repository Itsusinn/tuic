//! Wind framework [`Plugin`] for the TUIC client.
//!
//! Creates a TUIC outbound connection, SOCKS5 inbound (via wind-socks),
//! and wires them together through App/Plugin builder.

use std::sync::Arc;

use wind_core::{
	AbstractOutbound, App, AppContext, InboundHooks, OutboundAction, Plugin,
	types::TargetAddr,
	udp::UdpStream,
};
use wind_socks::inbound::{AuthMode, SocksInbound, SocksInboundOpt};

use crate::{
	forward,
	shared::SharedOutbound,
	wind_adapter::TuicOutboundAdapter,
};

/// Simple router: everything goes to the TUIC outbound.
struct ClientRouter;

impl wind_core::Router for ClientRouter {
	async fn route(&self, _target: &TargetAddr, _is_tcp: bool) -> eyre::Result<wind_core::RouteAction> {
		Ok(wind_core::RouteAction::Forward("default".to_string()))
	}
}

/// [`OutboundAction`] adapter that lazily resolves a [`SharedOutbound`].
struct LazyHandler {
	shared: Arc<SharedOutbound>,
}

#[async_trait::async_trait]
impl OutboundAction for LazyHandler {
	async fn handle_tcp(
		&self,
		target: TargetAddr,
		stream: Box<dyn wind_core::tcp::AbstractTcpStream>,
	) -> eyre::Result<()> {
		let out = self.shared.get().await?;
		out.handle_tcp(target, stream, Option::<crate::wind_adapter::TuicOutboundAdapter>::None).await
	}

	async fn handle_udp(&self, stream: UdpStream) -> eyre::Result<()> {
		let out = self.shared.get().await?;
		out.handle_udp(stream, Option::<crate::wind_adapter::TuicOutboundAdapter>::None).await
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
	fn build(self, app: App) -> App {
		// ── Shared outbound handle ────────────────────────────────────────
		let shared = SharedOutbound::new();

		// Spawn outbound connection setup (async) as a tracked task.
		let ctx = app.context().clone();
		let relay = self.cfg.relay.clone();
		let shared_for_task = shared.clone();
		let setup_ctx = ctx.clone();
		ctx.tasks.spawn(async move {
			match TuicOutboundAdapter::new(setup_ctx, relay).await {
				Ok(adapter) => shared_for_task.set(adapter),
				Err(e) => {
					tracing::error!("Failed to create TUIC outbound: {e}");
				}
			}
		});

		// ── Outbound handler for the dispatcher ───────────────────────────
		let handler = Arc::new(LazyHandler { shared: shared.clone() });
		let app = app.add_outbound("default", handler);

		// ── Router ───────────────────────────────────────────────────────
		let app = app.set_router(ClientRouter);

		// ── SOCKS5 inbound ────────────────────────────────────────────────
		let local = self.cfg.local.clone();
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
				hooks,
			};
			SocksInbound::new(opts, ctx.token.clone())
		});

		// ── TCP/UDP forwarders ────────────────────────────────────────────
		let tcp_fwd = self.cfg.local.tcp_forward.clone();
		let udp_fwd = self.cfg.local.udp_forward.clone();
		let fwd_token = app.context().token.child_token();
		let fwd_shared = shared.clone();
		ctx.tasks.spawn(async move {
			forward::start_shared(tcp_fwd, udp_fwd, fwd_shared, fwd_token).await;
		});

		app
	}
}
