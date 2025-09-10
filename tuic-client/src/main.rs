use std::{env, process, str::FromStr};

use chrono::{Offset, TimeZone};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    config::{Config, ConfigError},
    connection::Connection,
    socks5::Server as Socks5Server,
};

mod config;
mod connection;
mod error;
mod forward;
mod socks5;
mod utils;

#[cfg(feature = "jemallocator")]
use tikv_jemallocator::Jemalloc;

#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cfg = match Config::parse(env::args_os()) {
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
    let level = tracing::Level::from_str(&cfg.log_level)?;
    let filter = tracing_subscriber::filter::Targets::new()
        .with_targets(vec![
            ("tuic", level),
            ("tuic_quinn", level),
            ("tuic_client", level),
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
                        chrono::Local
                            .timestamp_opt(0, 0)
                            .unwrap()
                            .offset()
                            .fix()
                            .local_minus_utc(),
                    )
                    .unwrap_or(time::UtcOffset::UTC),
                    time::macros::format_description!(
                        "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"
                    ),
                )),
        )
        .try_init()?;

    match Connection::set_config(cfg.relay).await {
        Ok(()) => {}
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    }

    forward::start(cfg.local.tcp_forward.clone(), cfg.local.udp_forward.clone()).await;

    match Socks5Server::set_config(cfg.local) {
        Ok(()) => {}
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    }

    Socks5Server::start().await;
    Ok(())
}
