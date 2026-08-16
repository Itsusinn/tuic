//! Library interface for tuic-client.
//!
//! The client is assembled via [`TuicClientPlugin`], which implements
//! [`wind_core::Plugin`] and can be used with [`wind_core::App`].

use std::{net::SocketAddr, time::Duration};

use tokio_util::sync::CancellationToken;
use wind_core::App;

pub mod config;
pub mod plugin;
pub mod tunnel;
pub mod utils;

pub use config::Config;
pub use plugin::TuicClientPlugin;

/// Handle to a running TUIC client: the OS-assigned SOCKS5 bound address
/// (useful when `local.server` binds to port `0`) plus the cancellation token
/// for graceful shutdown.
pub struct ClientGuard {
	pub socks5_addr: SocketAddr,
	pub cancel: CancellationToken,
	run_task: tokio::task::JoinHandle<eyre::Result<()>>,
	bridge: tokio::task::JoinHandle<()>,
}

impl ClientGuard {
	/// Cancel the client and wait (bounded) for it to drain.
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

impl Drop for ClientGuard {
	fn drop(&mut self) {
		// Last-resort teardown if the caller never calls `shutdown`.
		self.cancel.cancel();
		self.run_task.abort();
		self.bridge.abort();
	}
}

/// Run the TUIC client with the given configuration.
///
/// Constructs a wind [`App`], registers the [`TuicClientPlugin`], and returns
/// a [`ClientGuard`] once the SOCKS5 inbound has bound its listen socket.
pub async fn run(cfg: Config) -> eyre::Result<ClientGuard> {
	run_with_cancel(cfg, CancellationToken::new()).await
}

/// Run the TUIC client with a caller-owned cancel token (for tests).
///
/// Returns once the SOCKS5 inbound has reported its actually-bound address, so
/// a caller can bind to `127.0.0.1:0` and read the OS-assigned port without a
/// bind/unbind race.
pub async fn run_with_cancel(cfg: Config, cancel: CancellationToken) -> eyre::Result<ClientGuard> {
	let (addr_tx, mut addr_rx) = tokio::sync::watch::channel(None::<SocketAddr>);
	let app = App::new()
		.add_plugin(TuicClientPlugin::new(cfg).with_bound_addr(addr_tx))
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

	// Wait for the SOCKS5 inbound to report its bound address, or for the
	// client to exit early (a real failure worth surfacing).
	let socks5_addr = tokio::select! {
		res = addr_rx.wait_for(|a| a.is_some()) => match res {
			Ok(r) => r.expect("wait_for predicate guarantees Some"),
			Err(_) => return Err(eyre::eyre!("client exited before reporting its SOCKS5 address")),
		},
		res = &mut run_task => match res {
			Ok(Ok(())) => return Err(eyre::eyre!("client exited before reporting its SOCKS5 address")),
			Ok(Err(e)) => return Err(e),
			Err(e) => return Err(eyre::eyre!("client task panicked: {e}")),
		},
	};

	Ok(ClientGuard {
		socks5_addr,
		cancel,
		run_task,
		bridge,
	})
}
