//! TUIC server — wind framework plugin.
//!
//! The server is assembled via [`TuicServerPlugin`], which implements
//! [`wind_core::Plugin`] and can be used with [`wind_core::App`].

pub mod config;
pub mod legacy;
pub mod log;
pub mod plugin;
pub mod restful;
pub mod tls;
pub mod utils;
pub mod wind_adapter;

pub use config::{Cli, Config, Control};
pub use plugin::TuicServerPlugin;
use std::{net::SocketAddr, time::Duration};
use tokio_util::sync::CancellationToken;
use wind_core::App;

/// Handle to a running TUIC server: the OS-assigned bound address (useful when
/// `config.server` binds to port `0`) plus the cancellation token for graceful
/// shutdown.
pub struct ServerGuard {
	pub local_addr: SocketAddr,
	pub restful_addr: Option<SocketAddr>,
	pub cancel: CancellationToken,
	run_task: tokio::task::JoinHandle<eyre::Result<()>>,
	bridge: tokio::task::JoinHandle<()>,
}

impl ServerGuard {
	/// Cancel the server and wait (bounded) for it to drain.
	pub async fn shutdown(mut self) {
		self.cancel.cancel();
		if tokio::time::timeout(Duration::from_secs(10), &mut self.run_task)
			.await
			.is_err()
		{
			self.run_task.abort();
		}
		self.bridge.abort();
	}
}

impl Drop for ServerGuard {
	fn drop(&mut self) {
		// Last-resort teardown if the caller never calls `shutdown`.
		self.cancel.cancel();
		self.run_task.abort();
		self.bridge.abort();
	}
}

/// Run the TUIC server with the given configuration.
///
/// Constructs a wind [`App`], registers the [`TuicServerPlugin`], and returns
/// a [`ServerGuard`] once the inbound has bound its listen socket — driving the
/// server in the background until the guard's token is cancelled.
pub async fn run(cfg: Config) -> eyre::Result<ServerGuard> {
	run_with_cancel(cfg, CancellationToken::new()).await
}

/// Run the TUIC server with a caller-owned cancel token (for tests).
///
/// Returns once the inbound has reported its actually-bound address, so a
/// caller can bind to `0.0.0.0:0` and read the OS-assigned port without a
/// bind/unbind race.
pub async fn run_with_cancel(cfg: Config, cancel: CancellationToken) -> eyre::Result<ServerGuard> {
	let restful_enabled = cfg.restful.enabled;
	let (addr_tx, mut addr_rx) = tokio::sync::watch::channel(None::<SocketAddr>);
	let (restful_addr_tx, mut restful_addr_rx) = tokio::sync::watch::channel(None::<SocketAddr>);
	let app = App::new()
		.add_plugin(
			TuicServerPlugin::new(cfg)
				.with_bound_addr(addr_tx)
				.with_restful_bound_addr(restful_addr_tx),
		)
		.await?;
	let ctx = app.context().clone();

	// Bridge the caller's token into the App's context token: `App::run`
	// already selects on `ctx.token.cancelled()`, so firing the internal token
	// unwinds it exactly like a shutdown signal.
	let bridge = tokio::spawn({
		let cancel = cancel.clone();
		async move {
			cancel.cancelled().await;
			ctx.token.cancel();
		}
	});

	let mut run_task = tokio::spawn(async move { app.run().await });

	// Wait for the inbound to report its bound address, or for the server to
	// exit early (a real failure worth surfacing).
	let local_addr = tokio::select! {
		res = addr_rx.wait_for(|a| a.is_some()) => match res {
			Ok(r) => r.expect("wait_for predicate guarantees Some"),
			Err(_) => return Err(eyre::eyre!("server exited before reporting its bound address")),
		},
		res = &mut run_task => match res {
			Ok(Ok(())) => return Err(eyre::eyre!("server exited before reporting its bound address")),
			Ok(Err(e)) => return Err(e),
			Err(e) => return Err(eyre::eyre!("server task panicked: {e}")),
		},
	};

	// If the RESTful API is enabled, also wait for its bound address (the
	// RESTful task is spawned during plugin build, so it may already be set).
	let restful_addr = if restful_enabled {
		match restful_addr_rx.wait_for(|a| a.is_some()).await {
			Ok(r) => Some(r.expect("wait_for predicate guarantees Some")),
			Err(_) => None,
		}
	} else {
		None
	};

	Ok(ServerGuard {
		local_addr,
		restful_addr,
		cancel,
		run_task,
		bridge,
	})
}
