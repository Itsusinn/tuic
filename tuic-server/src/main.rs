use std::process;

use clap::Parser;
#[cfg(feature = "jemallocator")]
use tikv_jemallocator::Jemalloc;
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

	tuic_server::run(cfg).await
}
