#![feature(ip)]

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
	let filter = tracing_subscriber::filter::Targets::new()
		.with_targets(vec![("tuic", level), ("tuic_quinn", level), ("tuic_client", level)])
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
	tuic_client::run(cfg).await
}
