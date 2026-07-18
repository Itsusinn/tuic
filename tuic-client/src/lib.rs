// Library interface for tuic-client
// This allows the client to be used as a library in integration tests

use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use wind_core::AppContext;

pub mod config;
pub mod error;
pub mod forward;
pub mod socks5;
pub mod utils;
pub mod wind_adapter;

pub use config::Config;

/// Run the TUIC client with the given configuration (using wind-tuic).
///
/// Constructs its own [`CancellationToken`] internally; callers that want to
/// drive a graceful shutdown from outside should use [`run_with_cancel`].
pub async fn run(cfg: Config) -> eyre::Result<()> {
	run_with_cancel(cfg, CancellationToken::new()).await
}

/// Run the TUIC client with a caller-owned cancel token.
///
/// Cancelling `cancel` stops the SOCKS5 accept loop and the TCP/UDP
/// forwarders, closes the TUIC connection (so the server sees the client go
/// away immediately instead of waiting out its idle timeout), and waits for
/// tracked background tasks to drain. Pair with `tokio::select!` on
/// [`wind_core::shutdown_signal`] so signal-triggered shutdown (Ctrl-C /
/// SIGTERM) is graceful instead of relying on runtime drop.
pub async fn run_with_cancel(cfg: Config, cancel: CancellationToken) -> eyre::Result<()> {
	// The context token is the caller's token, so the outbound's heartbeat poll
	// task (which closes the QUIC connection on cancellation) and every UDP
	// session task wind down from the same `cancel()`.
	let ctx = Arc::new(AppContext {
		tasks: tokio_util::task::TaskTracker::new(),
		token: cancel.clone(),
	});
	wind_adapter::create_connection(ctx.clone(), cfg.relay).await?;

	tracing::info!("TUIC client initialized with wind-tuic backend");

	// Start forwarders (tracked in ctx.tasks, cancelled via ctx.token).
	forward::start(cfg.local.tcp_forward.clone(), cfg.local.udp_forward.clone(), &ctx).await;

	// Start SOCKS5 server
	match socks5::Server::set_config(cfg.local) {
		Ok(()) => {}
		Err(err) => {
			return Err(err.into());
		}
	}

	socks5::Server::start(cancel.clone()).await;

	// `start` only returns once cancelled; drain the tracked background tasks
	// (heartbeat poll, forwarder loops, UDP sessions) before returning so the
	// QUIC close frames flush while the runtime is still alive.
	ctx.tasks.close();
	ctx.tasks.wait().await;
	Ok(())
}
