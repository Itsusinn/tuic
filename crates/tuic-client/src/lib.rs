//! Library interface for tuic-client.
//!
//! The client is assembled via [`TuicClientPlugin`], which implements
//! [`wind_core::Plugin`] and can be used with [`wind_core::App`].

use std::net::SocketAddr;

use tokio_util::sync::CancellationToken;
use wind_core::App;

#[path = "../../runtime.rs"]
mod runtime;

use runtime::Runtime;

pub mod config;
pub mod plugin;
mod tcp_forward;
pub mod tls;
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
	runtime: Runtime,
}

impl ClientGuard {
	/// Cancel the client and wait (bounded) for it to drain.
	pub async fn shutdown(mut self) {
		self.cancel.cancel();
		self.runtime.shutdown().await;
	}
}

impl Drop for ClientGuard {
	fn drop(&mut self) {
		self.cancel.cancel();
		// Runtime's Drop also cancels the internal token and aborts its
		// handles.
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
	let app = App::new();
	let app_token = app.context().token.clone();
	let mut runtime = Runtime::new(app.context().clone(), cancel.clone());
	let startup = async {
		let app = tokio::select! {
			result = app.add_plugin(TuicClientPlugin::new(cfg).with_bound_addr(addr_tx)) => result?,
			_ = app_token.cancelled() => return Err(eyre::eyre!("client startup cancelled")),
		};
		runtime.start(async move { app.run().await });
		runtime.bound_address(&mut addr_rx, "client SOCKS5 inbound").await
	}
	.await;

	match startup {
		Ok(socks5_addr) => Ok(ClientGuard {
			socks5_addr,
			cancel,
			runtime,
		}),
		Err(error) => {
			runtime.shutdown().await;
			Err(error)
		}
	}
}
