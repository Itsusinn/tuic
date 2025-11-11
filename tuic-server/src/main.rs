use std::process;

use clap::Parser;
#[cfg(feature = "jemallocator")]
use tikv_jemallocator::Jemalloc;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::time::LocalTime, layer::SubscriberExt, util::SubscriberInitExt};
use tuic_server::config::{Cli, Control, EnvState, parse_config};

#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> eyre::Result<()> {
	let cli = Cli::parse();
	let env_state = EnvState::from_system();
	let cfg = match parse_config(cli, env_state).await {
		Ok(cfg) => cfg,
		Err(err) => {
			// Check if it's a Control error (Help or Version)
			if let Some(control) = err.downcast_ref::<Control>() {
				println!("{}", control);
				process::exit(0);
			}
			return Err(err);
		}
	};
	let filter = tracing_subscriber::filter::Targets::new()
		.with_targets(vec![
			("tuic", cfg.log_level),
			("tuic_quinn", cfg.log_level),
			("tuic_server", cfg.log_level),
		])
		.with_default(LevelFilter::INFO);
	let registry = tracing_subscriber::registry();
	registry
		.with(filter)
		.with(
			tracing_subscriber::fmt::layer()
				.with_target(true)
				.with_timer(LocalTime::new(time::macros::format_description!(
					"[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"
				))),
		)
		.try_init()?;
	tokio::select! {
		res = tuic_server::run(cfg) => {
			if let Err(err) = res {
				tracing::error!("Server exited with error: {err}");
				return Err(err);
			}
		}
		res = tokio::signal::ctrl_c() => {
			if let Err(err) = res {
				tracing::error!("Failed to listen for Ctrl-C: {err}");
				return Err(eyre::eyre!("Failed to listen for Ctrl-C: {err}"));
			} else {
				tracing::info!("Received Ctrl-C, shutting down.");
			}
		}
	}
	Ok(())
}
