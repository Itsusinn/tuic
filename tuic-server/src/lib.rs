use std::sync::Arc;

use tokio_util::sync::CancellationToken;
// The legacy ACL dialect (space-separated `<outbound> [address] [ports]
// [hijack]`) is specific to tuic-server — it is not Hysteria's ACL despite the
// superficial resemblance. The parser lives in this crate's `legacy` module.
pub mod legacy;
use wind_core::AbstractInbound;
pub mod config;
pub mod error;
pub mod log;
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

	let (inbound, adapter) = wind_adapter::create_inbound(ctx).await?;

	tracing::info!("Starting TUIC server");

	inbound.listen(&adapter).await
}
