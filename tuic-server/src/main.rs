use std::{env, process, sync::Arc};

use config::{Config, parse_config};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::time::LocalTime, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{old_config::ConfigError, server::Server};

mod config;
mod connection;
mod error;
mod io;
mod old_config;
mod restful;
mod server;
mod tls;
mod utils;

#[cfg(feature = "jemallocator")]
use tikv_jemallocator::Jemalloc;

#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

struct AppContext {
    pub cfg: Config,
    pub config_path: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let (cfg, config_path) = match parse_config(env::args_os()).await {
        Ok((cfg, config_path)) => (cfg, config_path),
        Err(ConfigError::Version(msg) | ConfigError::Help(msg)) => {
            println!("{msg}");
            process::exit(0);
        }
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    };
    let ctx = Arc::new(AppContext { cfg, config_path });

    let filter = tracing_subscriber::filter::Targets::new()
        .with_targets(vec![
            ("tuic", ctx.cfg.log_level),
            ("tuic_quinn", ctx.cfg.log_level),
            ("tuic_server", ctx.cfg.log_level),
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
        match Server::init(ctx.clone()).await {
            Ok(server) => server.start().await,
            Err(err) => {
                eprintln!("{err}");
                process::exit(1);
            }
        }
    });
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for event");
    Ok(())
}
