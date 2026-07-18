//! Library interface for tuic-client.
//!
//! The client is assembled via [`TuicClientPlugin`], which implements
//! [`wind_core::Plugin`] and can be used with [`wind_core::App`].

use wind_core::App;

pub mod config;
pub mod error;
pub mod forward;
pub mod plugin;
pub mod shared;
pub mod utils;
pub mod wind_adapter;

pub use config::Config;
pub use plugin::TuicClientPlugin;

/// Run the TUIC client with the given configuration.
///
/// Constructs a wind [`App`], registers the [`TuicClientPlugin`], and drives
/// it until Ctrl-C / SIGTERM.
pub async fn run(cfg: Config) -> eyre::Result<()> {
	App::new()
		.add_plugin(TuicClientPlugin::new(cfg))
		.run()
		.await
}

/// Run the TUIC client with a caller-owned cancel token (for tests).
pub async fn run_with_cancel(cfg: Config, _cancel: tokio_util::sync::CancellationToken) -> eyre::Result<()> {
	// NOTE: plugin-based client ignores the external cancel token; shutdown is
	// handled by wind_core::App::run() internally (Ctrl-C / SIGTERM).
	run(cfg).await
}
