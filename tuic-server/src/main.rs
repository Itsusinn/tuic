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
			eprintln!("{}", err);
			process::exit(1);
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
	tokio::spawn(async move {
		if let Err(err) = tuic_server::run(cfg).await {
			eprintln!("{err}");
			process::exit(1);
		}
	});
	tokio::signal::ctrl_c().await.expect("failed to listen for event");
	Ok(())
}
