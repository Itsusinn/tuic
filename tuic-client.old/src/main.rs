use std::{process, str::FromStr};

use chrono::{Offset, TimeZone};
use clap::Parser;
#[cfg(all(feature = "jemallocator", not(feature = "dhat-heap")))]
use tikv_jemallocator::Jemalloc;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tuic_client::config::{Cli, Config, EnvState, ResolvedRuntime};
// dhat takes over the global allocator to trace every heap allocation, so it
// must be the sole `#[global_allocator]`; jemalloc is disabled whenever
// `dhat-heap` is enabled.
#[cfg(all(feature = "jemallocator", not(feature = "dhat-heap")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() -> eyre::Result<()> {
	// Profile the whole process. Dropping the guard on graceful shutdown writes
	// `dhat-heap.json`; its at-exit ("t-end") stats show allocations still live
	// at exit, i.e. leaked resources.
	#[cfg(feature = "dhat-heap")]
	let _dhat = dhat::Profiler::new_heap();

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

	let mut builder = match cfg.tokio_runtime.resolve() {
		ResolvedRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread(),
		ResolvedRuntime::CurrentThread => tokio::runtime::Builder::new_current_thread(),
	};

	let rt = builder.enable_all().build()?;

	// `run` never returns on its own (the SOCKS5 accept loop runs forever), so a
	// plain Ctrl-C would hard-kill the process and skip the profiler's `Drop`.
	// Under `dhat-heap`, race it against Ctrl-C so shutdown is graceful and
	// `dhat-heap.json` gets written.
	#[cfg(feature = "dhat-heap")]
	let result = rt.block_on(async move {
		tokio::select! {
			res = tuic_client::run(cfg) => res,
			_ = tokio::signal::ctrl_c() => {
				tracing::info!("Received Ctrl-C, shutting down.");
				Ok(())
			}
		}
	});

	#[cfg(not(feature = "dhat-heap"))]
	let result = rt.block_on(async move { tuic_client::run(cfg).await });

	// Drop the runtime (aborting spawned tasks and freeing their resources)
	// before `_dhat` falls out of scope, so the leak report reflects a clean
	// shutdown rather than in-flight work.
	drop(rt);
	result
}
