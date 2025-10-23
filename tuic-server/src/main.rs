use std::process;

#[cfg(feature = "jemallocator")]
use tikv_jemallocator::Jemalloc;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::time::LocalTime, layer::SubscriberExt, util::SubscriberInitExt};
use tuic_server::{config::parse_config, old_config::ConfigError};
#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> eyre::Result<()> {
	let cfg = match parse_config(lexopt::Parser::from_env()).await {
		Ok(cfg) => cfg,
		Err(ConfigError::Version(msg) | ConfigError::Help(msg)) => {
			println!("{msg}");
			process::exit(0);
		}
		Err(err) => {
			eprintln!("{err}");
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
