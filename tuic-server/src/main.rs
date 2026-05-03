use std::process;

use clap::Parser;
#[cfg(feature = "jemallocator")]
use tikv_jemallocator::Jemalloc;
use tuic_server::{
	config::{Cli, Control, EnvState, ResolvedRuntime, parse_config},
	log,
};

#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() -> eyre::Result<()> {
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
	})
}
