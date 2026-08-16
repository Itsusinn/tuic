use std::{process, str::FromStr};

use chrono::{Offset, TimeZone};
use clap::Parser;
#[cfg(feature = "jemallocator")]
use tikv_jemallocator::Jemalloc;
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
	// Logging targets for client-related crates.
	let filter = tracing_subscriber::filter::Targets::new()
		.with_targets(vec![
			("tuic_client", level),
			("wind_tuic", level),
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
	// Graceful shutdown: run until a shutdown signal, then cancel the client's
	// token and let in-flight sessions drain.
	let guard = tuic_client::run(cfg).await?;
	tracing::info!("TUIC client SOCKS5 server listening on {}", guard.socks5_addr);
	wind_core::shutdown_signal().await;
	tracing::info!("Received shutdown signal, shutting down.");
	guard.shutdown().await;
	Ok(())
}
