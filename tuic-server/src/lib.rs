use std::sync::Arc;

use tokio_util::sync::CancellationToken;
// The legacy ACL dialect (space-separated `<outbound> [address] [ports]
// [hijack]`) is specific to tuic-server — it is not Hysteria's ACL despite the
// superficial resemblance. The parser lives in this crate's `legacy` module.
pub mod legacy;
use wind_core::{AbstractInbound, ActiveConnections, InboundHooks, StatsCollector};
pub mod config;
pub mod error;
pub mod log;
pub mod restful;
pub mod tls;
pub mod utils;
pub mod wind_adapter;

pub use config::{Cli, Config, Control};

pub struct AppContext {
	pub cfg: Config,
	pub cancel: CancellationToken,
}

/// Run the TUIC server with the given configuration (using wind-tuic).
///
/// Constructs its own [`CancellationToken`] internally; callers that want to
/// drive a graceful shutdown from outside should use [`run_with_cancel`].
pub async fn run(cfg: Config) -> eyre::Result<()> {
	run_with_cancel(cfg, CancellationToken::new()).await
}

/// Run the TUIC server with a caller-owned cancel token.
///
/// Cancelling `cancel` causes the listen loop to exit and every spawned
/// connection/UDP-session handler to wind down via its child token. Pair with
/// `tokio::select!` on [`wind_core::shutdown_signal`] so signal-triggered
/// shutdown (Ctrl-C / SIGTERM) is graceful instead of relying on runtime drop.
pub async fn run_with_cancel(cfg: Config, cancel: CancellationToken) -> eyre::Result<()> {
	let ctx = Arc::new(AppContext { cancel, cfg });

	// ── Wind hooks: traffic stats, connection tracking, active registry ──────
	let stats = Arc::new(StatsCollector::new());

	let active = if ctx.cfg.restful.maximum_clients_per_user > 0 || ctx.cfg.restful.enabled {
		Some(ActiveConnections::new())
	} else {
		None
	};

	let tracker = if ctx.cfg.restful.enabled {
		Some(Arc::new(restful::ConnectionTracker::new()))
	} else {
		None
	};

	// Aggregate connection hooks: the tracker watches connections for the
	// detailed_online endpoint; the active registry kicks connections and
	// enforces per-user limits (wired via wind-tuic's `opts.active`).
	let connection: Option<Arc<dyn wind_core::hooks::ConnectionHooks>> = match &tracker {
		Some(t) => Some(t.clone()),
		None => None,
	};

	let hooks = InboundHooks {
		connection,
		stats: Some(stats.clone()),
		sample_interval: std::time::Duration::from_secs(60),
		..Default::default()
	};

	let (inbound, dispatcher) = wind_adapter::create_inbound(ctx.clone(), hooks, active.clone()).await?;

	// ── Start RESTful API server ─────────────────────────────────────────────
	if ctx.cfg.restful.enabled {
		let rf_active: Arc<dyn restful::KickConnections> = match &active {
			Some(a) => Arc::new(a.clone()) as Arc<dyn restful::KickConnections>,
			None => Arc::new(restful::NoopConnections),
		};
		let rf_state = Arc::new(restful::RestfulState {
			active: rf_active,
			stats: Some(stats),
			tracker: tracker.clone(),
			secret: ctx.cfg.restful.secret.clone(),
			users: ctx.cfg.users.clone(),
		});
		let rf_addr = ctx.cfg.restful.addr;
		let rf_cancel = ctx.cancel.child_token();
		tokio::spawn(async move {
			if let Err(e) = restful::serve(rf_state, rf_addr, rf_cancel).await {
				tracing::warn!("RESTful API server stopped: {e}");
			}
		});
	}

	tracing::info!("Starting TUIC server");

	inbound.listen(&dispatcher).await
}
