//! TUIC server — wind framework plugin.
//!
//! The server is assembled via [`TuicServerPlugin`], which implements
//! [`wind_core::Plugin`] and can be used with [`wind_core::App`].

pub mod config;
mod connection_limit;
mod destination_guard;
pub mod legacy;
pub mod log;
pub mod plugin;
pub mod restful;
pub mod utils;
pub mod wind_adapter;

use std::net::SocketAddr;

pub use config::{Cli, Config, Control};
pub use plugin::TuicServerPlugin;
use tokio_util::sync::CancellationToken;
use wind_core::App;

#[path = "../../runtime.rs"]
mod runtime;

use runtime::Runtime;

/// Handle to a running TUIC server: the OS-assigned bound address (useful when
/// `config.server` binds to port `0`) plus the cancellation token for graceful
/// shutdown.
pub struct ServerGuard {
	pub local_addr: SocketAddr,
	pub restful_addr: Option<SocketAddr>,
	pub cancel: CancellationToken,
	runtime: Runtime,
}

impl ServerGuard {
	/// Cancel the server and wait (bounded) for it to drain.
	pub async fn shutdown(mut self) {
		self.cancel.cancel();
		self.runtime.shutdown().await;
	}
}

impl Drop for ServerGuard {
	fn drop(&mut self) {
		self.cancel.cancel();
		// Runtime's Drop also cancels the internal token and aborts its
		// handles.
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
	let (restful_addr_tx, mut restful_addr_rx) = restful::restful_addr_channel();
	let app = App::new();
	let app_token = app.context().token.clone();
	let mut runtime = Runtime::new(app.context().clone(), cancel.clone());
	let startup = async {
		let app = tokio::select! {
			result = app.add_plugin(
				TuicServerPlugin::new(cfg)
					.with_bound_addr(addr_tx)
					.with_restful_bound_addr(restful_addr_tx),
			) => result?,
			_ = app_token.cancelled() => return Err(eyre::eyre!("server startup cancelled")),
		};
		runtime.start(async move { app.run().await });
		let local_addr = runtime.bound_address(&mut addr_rx, "server TUIC inbound").await?;

		// An enabled management API must publish its socket or bind failure
		// before startup succeeds. Cancellation also ends this handshake.
		let restful_addr = if restful_enabled {
			Some(
				runtime
					.bound_address(&mut restful_addr_rx, "server RESTful API")
					.await?
					.map_err(|reason| eyre::eyre!("{reason}"))?,
			)
		} else {
			None
		};
		Ok((local_addr, restful_addr))
	}
	.await;

	match startup {
		Ok((local_addr, restful_addr)) => Ok(ServerGuard {
			local_addr,
			restful_addr,
			cancel,
			runtime,
		}),
		Err(error) => {
			runtime.shutdown().await;
			Err(error)
		}
	}
}
