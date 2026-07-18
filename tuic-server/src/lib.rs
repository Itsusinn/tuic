//! TUIC server — wind framework plugin.
//!
//! The server is assembled via [`TuicServerPlugin`], which implements
//! [`wind_core::Plugin`] and can be used with [`wind_core::App`].

pub mod config;
pub mod error;
pub mod legacy;
pub mod log;
pub mod plugin;
pub mod restful;
pub mod tls;
pub mod utils;
pub mod wind_adapter;

pub use config::{Cli, Config, Control};
pub use plugin::TuicServerPlugin;
use wind_core::App;

/// Run the TUIC server with the given configuration.
///
/// Constructs a wind [`App`], registers the [`TuicServerPlugin`], and drives
/// it until Ctrl-C / SIGTERM.
pub async fn run(cfg: Config) -> eyre::Result<()> {
	App::new().add_plugin(TuicServerPlugin::new(cfg)).run().await
}
