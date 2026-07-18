use std::process;

use clap::Parser;
#[cfg(all(feature = "jemallocator", not(feature = "dhat-heap")))]
use tikv_jemallocator::Jemalloc;
use tuic_server::{
	config::{Cli, Control, EnvState, ResolvedRuntime, parse_config},
	log,
};

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

	// Create a temporary single-threaded runtime just to parse config
	// asynchronously
	let cfg = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()?
		.block_on(async { parse_config(cli, env_state).await });

	let cfg = match cfg {
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
	let _log_guards = log::init(&cfg)?;

	let mut builder = match cfg.tokio_runtime.resolve() {
		ResolvedRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread(),
		ResolvedRuntime::CurrentThread => tokio::runtime::Builder::new_current_thread(),
	};

	let rt = builder.enable_all().build()?;

	rt.block_on(async move {
		let guard = tuic_server::run(cfg).await?;
		tokio::signal::ctrl_c().await?;
		guard.cancel.cancel();
		tracing::info!("Received Ctrl-C, shutting down.");
		Ok(())
	})
}
