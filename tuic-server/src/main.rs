use std::{process, time::Duration};

use clap::Parser;
#[cfg(feature = "jemallocator")]
use tikv_jemallocator::Jemalloc;
use tokio_util::sync::CancellationToken;
use tuic_server::config::{Cli, Control, EnvState, parse_config};

#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> eyre::Result<()> {
	#[cfg(feature = "aws-lc-rs")]
	{
		_ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	}

	#[cfg(feature = "ring")]
	{
		_ = rustls::crypto::ring::default_provider().install_default();
	}
	let cli = Cli::parse();
	let env_state = EnvState::from_system();
	let cfg = match parse_config(cli, env_state).await {
		Ok(cfg) => cfg,
		Err(err) => {
			if let Some(control) = err.downcast_ref::<Control>() {
				println!("{}", control);
				process::exit(0);
			}
			return Err(err);
		}
	};
	let _guards = tuic_server::log::init(&cfg)?;

	// Own the cancel token here so the ctrl-c branch can actually trigger a
	// graceful shutdown of the running server. Previously `tuic_server::run`
	// constructed its own token internally, so the `select!` "Received Ctrl-C"
	// arm dropped straight into `Ok(())` and the listen task + every spawned
	// connection handler were left to be killed by runtime drop — log guards
	// never flushed, in-flight QUIC streams got reset instead of cleanly closed.
	let cancel = CancellationToken::new();
	let mut server = tokio::spawn(tuic_server::run_with_cancel(cfg, cancel.clone()));

	tokio::select! {
		res = &mut server => {
			match res {
				Ok(Ok(())) => {}
				Ok(Err(err)) => {
					tracing::error!("Server exited with error: {err}");
					return Err(err);
				}
				Err(join_err) => {
					tracing::error!("Server task panicked or was cancelled: {join_err}");
					return Err(eyre::eyre!("Server task panicked or was cancelled: {join_err}"));
				}
			}
		}
		_ = wind_core::shutdown_signal() => {
			tracing::info!("Received shutdown signal, shutting down.");
			cancel.cancel();

			// Give the server up to 10 seconds to drain in-flight connections
			// before we drop out of main and force the runtime to abort
			// anything still running. The bound here is the same as the
			// per-connection idle timeout; tune via configuration if longer
			// drains become normal.
			match tokio::time::timeout(Duration::from_secs(10), server).await {
				Ok(Ok(Ok(()))) => {}
				Ok(Ok(Err(err))) => tracing::warn!("Server drained with error: {err}"),
				Ok(Err(join_err)) => tracing::warn!("Server task drain join error: {join_err}"),
				Err(_) => tracing::warn!(
					"Server did not drain within 10s of shutdown signal; aborting outstanding tasks"
				),
			}
		}
	}
	Ok(())
}
