use std::{process, str::FromStr, time::Duration};

use chrono::{Offset, TimeZone};
use clap::Parser;
#[cfg(feature = "jemallocator")]
use tikv_jemallocator::Jemalloc;
use tokio_util::sync::CancellationToken;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tuic_client::config::{Cli, Config, EnvState};
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

	let cfg = match Config::parse(cli, env_state) {
		Ok(cfg) => cfg,
		Err(err) => {
			eprintln!("Error: {err}");
			process::exit(1);
		}
	};
	let level = tracing::Level::from_str(&cfg.log_level)?;
	// Cover the crates and custom targets the client actually logs under. The
	// old list (`tuic`, `tuic_quinn`) predated the wind-tuic split, so relay
	// debug (emitted under `wind_tuic` / the `tuic_out` and `udp` targets) fell
	// through to the default INFO filter and `log_level = "debug"` was
	// ineffective for it.
	let filter = tracing_subscriber::filter::Targets::new()
		.with_targets(vec![
			("tuic_client", level),
			("tuic_core", level),
			("tuic_out", level),
			("udp", level),
			("wind_core", level),
			("wind_quic", level),
			("wind_tuic", level),
		])
		.with_default(LevelFilter::INFO);
	let registry = tracing_subscriber::registry();
	registry
		.with(filter)
		.with(
			tracing_subscriber::fmt::layer()
				.with_target(true)
				.with_timer(tracing_subscriber::fmt::time::OffsetTime::new(
					time::UtcOffset::from_whole_seconds(
						chrono::Local.timestamp_opt(0, 0).unwrap().offset().fix().local_minus_utc(),
					)
					.unwrap_or(time::UtcOffset::UTC),
					time::macros::format_description!("[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"),
				)),
		)
		.try_init()?;
	// Own the cancel token here so the ctrl-c branch can trigger a graceful
	// shutdown: stop the SOCKS5/forwarder accept loops, close the TUIC
	// connection (the server learns we left instead of waiting out its idle
	// timeout), and drain background tasks — same structure as tuic-server.
	let cancel = CancellationToken::new();
	let mut client = tokio::spawn(tuic_client::run_with_cancel(cfg, cancel.clone()));

	tokio::select! {
		res = &mut client => {
			match res {
				Ok(Ok(())) => {}
				Ok(Err(err)) => {
					tracing::error!("Client exited with error: {err}");
					return Err(err);
				}
				Err(join_err) => {
					tracing::error!("Client task panicked or was cancelled: {join_err}");
					return Err(eyre::eyre!("Client task panicked or was cancelled: {join_err}"));
				}
			}
		}
		_ = wind_core::shutdown_signal() => {
			tracing::info!("Received shutdown signal, shutting down.");
			cancel.cancel();

			// Give in-flight sessions up to 10 seconds to drain before dropping
			// out of main and letting runtime teardown abort the rest.
			match tokio::time::timeout(Duration::from_secs(10), client).await {
				Ok(Ok(Ok(()))) => {}
				Ok(Ok(Err(err))) => tracing::warn!("Client drained with error: {err}"),
				Ok(Err(join_err)) => tracing::warn!("Client task drain join error: {join_err}"),
				Err(_) => tracing::warn!("Client did not drain within 10s of shutdown signal; aborting outstanding tasks"),
			}
		}
	}
	Ok(())
}
